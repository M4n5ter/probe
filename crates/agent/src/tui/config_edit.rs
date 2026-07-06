use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use probe_config::{
    AgentConfig, ConfigError, DEFAULT_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS, default_admin_socket_path,
    default_storage_path,
};
use rustix::{
    fs::{FlockOperation, Gid, Mode, OFlags, Uid, fchmod, fchown, flock},
    process::geteuid,
};
use thiserror::Error;

use super::config_render::render_preserving_config;
use super::generated_resources::ensure_generated_local_paths;
use super::local_profile::LocalProbeProfile;

#[derive(Debug, Error)]
pub(crate) enum TuiError {
    #[error("failed to read TUI config {path}: {source}")]
    ReadConfig {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse editable TOML document {path}: {source}")]
    ParseTomlDocument {
        path: String,
        source: toml_edit::TomlError,
    },
    #[error("failed to serialize editable TOML: {0}")]
    SerializeToml(#[from] toml_edit::ser::Error),
    #[error("failed to serialize TUI runtime config: {0}")]
    SerializeRuntimeConfig(#[from] toml::ser::Error),
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("runtime config error: {0}")]
    Runtime(#[from] runtime::RuntimeError),
    #[error("config changed on disk; reload before saving")]
    ConcurrentModification,
    #[error("TUI cannot safely preserve this TOML shape: {0}")]
    UnsupportedTomlShape(String),
    #[error("invalid config path for atomic save: {0}")]
    InvalidConfigPath(String),
    #[error("TUI config path must be a direct file path, not a symlink: {0}")]
    SymlinkConfigPath(String),
    #[error("failed to write TUI config {path}: {source}")]
    WriteConfig {
        path: String,
        source: std::io::Error,
    },
    #[error("terminal error: {0}")]
    Terminal(#[from] std::io::Error),
    #[error("{task} task failed: {message}")]
    TaskFailed { task: &'static str, message: String },
    #[error("failed to {action}: {source}")]
    AgentSupervisor {
        action: &'static str,
        source: std::io::Error,
    },
    #[error("TUI managed agent exited during startup: {status}; log {log_path}; tail: {log_tail}")]
    ManagedAgentExited {
        status: std::process::ExitStatus,
        log_path: PathBuf,
        log_tail: String,
    },
    #[error(
        "timed out waiting for TUI managed agent admin socket {socket_path}; log {log_path}; tail: {log_tail}"
    )]
    ManagedAgentStartupTimeout {
        socket_path: String,
        log_path: PathBuf,
        log_tail: String,
    },
    #[error("timed out waiting for TUI managed agent admin socket {socket_path} to stop")]
    ManagedAgentShutdownTimeout { socket_path: String },
    #[error("TUI managed agent admin socket {socket_path} exists but did not respond")]
    ManagedAgentAdminUnresponsive { socket_path: String },
    #[error("TUI managed agent startup cancelled")]
    ManagedAgentStartupCancelled,
}

impl TuiError {
    pub(crate) fn managed_agent_log_path(&self) -> Option<&Path> {
        match self {
            Self::ManagedAgentExited { log_path, .. }
            | Self::ManagedAgentStartupTimeout { log_path, .. } => Some(log_path.as_path()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedTuiConfig {
    pub(crate) source: String,
    pub(crate) config: AgentConfig,
}

pub(crate) fn load_config(path: &Path) -> Result<LoadedTuiConfig, TuiError> {
    reject_symlink_config_path(path)?;
    let source = fs::read_to_string(path).map_err(|source| TuiError::ReadConfig {
        path: path.display().to_string(),
        source,
    })?;
    let config = AgentConfig::from_toml_str(&source)?;
    Ok(LoadedTuiConfig { source, config })
}

pub(crate) fn load_or_create_config(path: &Path) -> Result<LoadedTuiConfig, TuiError> {
    match load_config(path) {
        Ok(loaded) => Ok(loaded),
        Err(TuiError::ReadConfig { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            create_minimal_config(path)
        }
        Err(error) => Err(error),
    }
}

fn create_minimal_config(path: &Path) -> Result<LoadedTuiConfig, TuiError> {
    let source = minimal_config_source();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| TuiError::WriteConfig {
        path: parent.display().to_string(),
        source,
    })?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return load_config(path);
        }
        Err(source) => {
            return Err(TuiError::WriteConfig {
                path: path.display().to_string(),
                source,
            });
        }
    };
    file.write_all(source.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        })?;
    sync_directory(parent)?;
    let config = AgentConfig::from_toml_str(&source)?;
    Ok(LoadedTuiConfig { source, config })
}

fn minimal_config_source() -> String {
    format!(
        r#"agent_id = "traffic-probe"
config_version = "local"

[capture]
selection = "auto"

[storage]
path = "{}"

[export.worker]
enabled = true

[runtime_reload]
watch_config = true
debounce_ms = {}

[enforcement]
mode = "audit_only"
backend = "none"

[admin]
enabled = false
socket_path = "{}"
"#,
        default_storage_path().display(),
        DEFAULT_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS,
        default_admin_socket_path().display()
    )
}

pub(crate) fn save_config(
    path: &Path,
    original_source: &str,
    config: &AgentConfig,
) -> Result<String, TuiError> {
    save_config_with_local_profile(path, original_source, config, &LocalProbeProfile::default())
}

fn save_config_with_local_profile(
    path: &Path,
    original_source: &str,
    config: &AgentConfig,
    profile: &LocalProbeProfile,
) -> Result<String, TuiError> {
    reject_symlink_config_path(path)?;
    let _lock = ConfigSaveLock::acquire(path)?;
    let current_source = fs::read_to_string(path).map_err(|source| TuiError::ReadConfig {
        path: path.display().to_string(),
        source,
    })?;
    if current_source != original_source {
        return Err(TuiError::ConcurrentModification);
    }
    let rendered = render_preserving_config(&current_source, config, path)?;
    let roundtrip = AgentConfig::from_toml_str(&rendered)?;
    if &roundtrip != config {
        return Err(TuiError::UnsupportedTomlShape(
            "rendered config does not match the TUI-edited config".to_string(),
        ));
    }
    runtime::validate_static_runtime_config(&roundtrip)?;
    roundtrip.validate_l7_mitm_contract()?;
    ensure_generated_local_paths(&roundtrip, profile)?;
    atomic_write(path, rendered.as_bytes())?;
    Ok(rendered)
}

fn reject_symlink_config_path(path: &Path) -> Result<(), TuiError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| TuiError::ReadConfig {
        path: path.display().to_string(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(TuiError::SymlinkConfigPath(path.display().to_string()));
    }
    Ok(())
}

struct ConfigSaveLock {
    file: File,
}

impl ConfigSaveLock {
    fn acquire(config_path: &Path) -> Result<Self, TuiError> {
        let lock_path = lock_path_for(config_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&lock_path)
            .map_err(|source| TuiError::WriteConfig {
                path: lock_path.display().to_string(),
                source,
            })?;
        set_file_mode_on_file(&lock_path, &file, 0o600)?;
        flock(&file, FlockOperation::LockExclusive).map_err(|source| TuiError::WriteConfig {
            path: lock_path.display().to_string(),
            source: source.into(),
        })?;
        Ok(Self { file })
    }
}

impl Drop for ConfigSaveLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

fn lock_path_for(config_path: &Path) -> Result<PathBuf, TuiError> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = config_path
        .file_name()
        .ok_or_else(|| TuiError::InvalidConfigPath(config_path.display().to_string()))?
        .to_string_lossy();
    Ok(parent.join(format!(".{file_name}.lock")))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), TuiError> {
    let original_metadata = fs::metadata(path).map_err(|source| TuiError::ReadConfig {
        path: path.display().to_string(),
        source,
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| TuiError::InvalidConfigPath(path.display().to_string()))?
        .to_string_lossy();
    let (temp_path, temp_file) = create_temp_file(parent, &file_name)?;
    let write_result = preserve_temp_file_metadata(&temp_path, &temp_file, &original_metadata)
        .and_then(|()| write_temp_file(&temp_path, temp_file, bytes))
        .and_then(|()| rename_synced(&temp_path, path))
        .and_then(|()| sync_directory(parent));
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

fn create_temp_file(parent: &Path, file_name: &str) -> Result<(PathBuf, File), TuiError> {
    for attempt in 0..100 {
        let candidate = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(TuiError::WriteConfig {
                    path: candidate.display().to_string(),
                    source,
                });
            }
        }
    }
    Err(TuiError::InvalidConfigPath(format!(
        "could not allocate temp file beside {}",
        parent.join(file_name).display()
    )))
}

fn preserve_temp_file_metadata(
    path: &Path,
    file: &File,
    original: &Metadata,
) -> Result<(), TuiError> {
    let mode = original.permissions().mode() & 0o7777;
    set_file_mode_on_file(path, file, mode)?;
    let temp = file.metadata().map_err(|source| TuiError::WriteConfig {
        path: path.display().to_string(),
        source,
    })?;
    if temp.uid() == original.uid() && temp.gid() == original.gid() {
        return Ok(());
    }
    if !geteuid().is_root() {
        return Err(TuiError::WriteConfig {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "cannot preserve config owner {}:{} without root privileges",
                    original.uid(),
                    original.gid()
                ),
            ),
        });
    }
    fchown(
        file,
        Some(Uid::from_raw(original.uid())),
        Some(Gid::from_raw(original.gid())),
    )
    .map_err(|source| TuiError::WriteConfig {
        path: path.display().to_string(),
        source: source.into(),
    })?;
    set_file_mode_on_file(path, file, mode)
}

fn set_file_mode_on_file(path: &Path, file: &File, mode: u32) -> Result<(), TuiError> {
    fchmod(file, Mode::from_raw_mode(mode)).map_err(|source| TuiError::WriteConfig {
        path: path.display().to_string(),
        source: source.into(),
    })
}

fn write_temp_file(path: &Path, mut file: File, bytes: &[u8]) -> Result<(), TuiError> {
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        })
}

fn rename_synced(from: &Path, to: &Path) -> Result<(), TuiError> {
    fs::rename(from, to).map_err(|source| TuiError::WriteConfig {
        path: to.display().to_string(),
        source,
    })
}

pub(super) fn sync_directory(path: &Path) -> Result<(), TuiError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use probe_config::{
        AgentConfig, CaptureSelection, CompressionCodecName, ExporterConfig,
        ExporterTransportConfig, ObservationDataPathMode, ProcessObservationConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{Direction, EnforcementMode, ProcessSelector, Selector, TrafficSelector};
    use tempfile::TempDir;

    use super::super::{
        app::TuiTab,
        fields::{
            FieldApplyOutcome, FieldId, apply_field, apply_text_field, editable_text_value,
            fields_for_tab,
        },
    };
    use super::*;

    #[test]
    fn save_does_not_create_empty_storage_retention_tables_for_absent_record_limits()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/events.jsonl"
codec = "zstd"
"#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.agent_id = "probe-edited".to_string();

        let rendered = save_config(&path, source, &config)?;
        let reloaded = AgentConfig::from_toml_str(&rendered)?;

        assert!(!rendered.contains("[storage.retention.ingress]"));
        assert!(!rendered.contains("[storage.retention.export]"));
        assert_eq!(reloaded.storage.retention.ingress.max_records, None);
        assert_eq!(reloaded.storage.retention.export.max_records, None);
        Ok(())
    }

    #[test]
    fn save_removes_storage_record_limit_keys_when_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/events.jsonl"
codec = "zstd"

[storage.retention.ingress]
max_records = 10000

[storage.retention.export]
max_records = 10000
"#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.storage.retention.ingress.max_records = None;
        config.storage.retention.export.max_records = None;

        let rendered = save_config(&path, source, &config)?;
        let reloaded = AgentConfig::from_toml_str(&rendered)?;

        assert!(!rendered.contains("max_records"));
        assert_eq!(reloaded.storage.retention.ingress.max_records, None);
        assert_eq!(reloaded.storage.retention.export.max_records, None);
        Ok(())
    }

    #[test]
    fn save_updates_exporter_transport_target_and_removes_stale_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/old.jsonl"
codec = "zstd"
"#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.exporters[0].transport = ExporterTransportConfig::Webhook {
            endpoint: "http://127.0.0.1:18080/events".to_string(),
            headers: Default::default(),
            tls: Default::default(),
        };

        let rendered = save_config(&path, source, &config)?;
        let reloaded = AgentConfig::from_toml_str(&rendered)?;

        assert!(rendered.contains("transport = \"webhook\""));
        assert!(rendered.contains("endpoint = \"http://127.0.0.1:18080/events\""));
        assert!(!rendered.contains("path = \"/tmp/old.jsonl\""));
        assert_eq!(reloaded, config);
        Ok(())
    }

    #[test]
    fn save_removes_stale_exporter_headers_and_tls_when_transport_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "webhook"
endpoint = "https://collector.example/batches"
headers = { "x-probe-node" = "node-a" }
codec = "zstd"

[exporters.tls]
trust_anchor_refs = ["collector-ca"]
"#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.exporters[0].transport = ExporterTransportConfig::UnixHttp {
            socket_path: PathBuf::from("/tmp/probe-sidecar.sock"),
            endpoint: "/batches".to_string(),
            headers: BTreeMap::new(),
        };

        let rendered = save_config(&path, source, &config)?;
        let reloaded = AgentConfig::from_toml_str(&rendered)?;

        assert!(rendered.contains("transport = \"unix_http\""));
        assert!(rendered.contains("socket_path = \"/tmp/probe-sidecar.sock\""));
        assert!(!rendered.contains("x-probe-node"));
        assert!(!rendered.contains("[exporters.tls]"));
        assert_eq!(reloaded, config);
        Ok(())
    }

    #[test]
    fn save_creates_exporter_table_when_tui_adds_default_exporter()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"
agent_id = "probe"
config_version = "local"
"#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        let export_path = temp.path().join("events.jsonl");
        config.exporters.push(ExporterConfig {
            transport: ExporterTransportConfig::File {
                path: export_path.clone(),
            },
            ..ExporterConfig::default()
        });

        let rendered = save_config(&path, source, &config)?;
        let reloaded = AgentConfig::from_toml_str(&rendered)?;

        assert!(rendered.contains("[[exporters]]"));
        assert!(rendered.contains("transport = \"file\""));
        assert!(rendered.contains(&format!("path = \"{}\"", export_path.display())));
        assert_eq!(reloaded, config);
        Ok(())
    }

    #[test]
    fn save_creates_generated_default_admin_socket_parent() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let socket_path = temp.path().join("run").join("admin.sock");
        let source = format!(
            r#"
agent_id = "probe"
config_version = "local"

[admin]
enabled = false
socket_path = "{}"
"#,
            socket_path.display()
        );
        fs::write(&path, &source)?;
        let mut config = AgentConfig::from_toml_str(&source)?;
        config.admin.enabled = true;

        let profile = LocalProbeProfile {
            admin_socket: socket_path.clone(),
            ..LocalProbeProfile::with_root(temp.path())
        };
        let rendered = save_config_with_local_profile(&path, &source, &config, &profile)?;
        let reloaded = AgentConfig::from_toml_str(&rendered)?;

        assert!(socket_path.parent().expect("admin socket parent").is_dir());
        assert_eq!(
            fs::metadata(socket_path.parent().expect("admin socket parent"))?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(reloaded.admin.enabled);
        Ok(())
    }

    #[test]
    fn save_rejects_l7_mitm_contract_failure_without_writing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/events.jsonl"
codec = "zstd"
"#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.selector = Some(exe_selector("/usr/bin/curl"));
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm;

        let error = save_config(&path, source, &config)
            .expect_err("invalid MITM contract must not be written");

        assert!(matches!(error, TuiError::Runtime(_)));
        assert!(
            error
                .to_string()
                .contains("MITM interception requires either a CA certificate/private key pair")
        );
        assert_eq!(fs::read_to_string(&path)?, source);
        Ok(())
    }

    #[test]
    fn save_rejects_runtime_static_validation_failure_without_writing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"agent_id = "probe""#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;

        let error = save_config(&path, source, &config)
            .expect_err("runtime-invalid config must not be written");

        assert!(matches!(error, TuiError::Runtime(_)));
        assert_eq!(fs::read_to_string(&path)?, source);
        Ok(())
    }

    #[test]
    fn save_rejects_concurrent_config_modification_without_writing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"agent_id = "probe""#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.agent_id = "probe-edited".to_string();
        let external_source = r#"agent_id = "external""#;
        fs::write(&path, external_source)?;

        let error = save_config(&path, source, &config)
            .expect_err("stale TUI state must not overwrite external edits");

        assert!(matches!(error, TuiError::ConcurrentModification));
        assert_eq!(fs::read_to_string(&path)?, external_source);
        Ok(())
    }

    #[test]
    fn save_rejects_inline_exporter_arrays_that_cannot_be_preserved()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"
agent_id = "probe"
exporters = [{ id = "default", transport = "file", path = "/tmp/events.jsonl", codec = "zstd" }]
"#;
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.exporters[0].codec = CompressionCodecName::Gzip;

        let error = save_config(&path, source, &config)
            .expect_err("unsupported inline exporter shape must fail closed");

        assert!(matches!(error, TuiError::UnsupportedTomlShape(_)));
        assert_eq!(fs::read_to_string(&path)?, source);
        Ok(())
    }

    #[test]
    fn save_uses_atomic_temp_file_and_updates_loaded_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"agent_id = "probe""#;
        fs::write(&path, source)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.agent_id = "probe-edited".to_string();

        let rendered = save_config(&path, source, &config)?;

        assert_eq!(fs::read_to_string(&path)?, rendered);
        assert!(rendered.contains("agent_id = \"probe-edited\""));
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(temp.path().join(".agent.toml.lock"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let leftovers = fs::read_dir(temp.path())?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty());
        Ok(())
    }

    #[test]
    fn load_and_save_reject_symlink_config_paths() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let target = temp.path().join("target.toml");
        let link = temp.path().join("agent.toml");
        let source = r#"agent_id = "probe""#;
        fs::write(&target, source)?;
        symlink(&target, &link)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.agent_id = "probe-edited".to_string();

        let load_error =
            load_config(&link).expect_err("symlink config path must not be loaded by TUI");
        let save_error =
            save_config(&link, source, &config).expect_err("symlink config path must not be saved");

        assert!(matches!(load_error, TuiError::SymlinkConfigPath(_)));
        assert!(matches!(save_error, TuiError::SymlinkConfigPath(_)));
        assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
        assert_eq!(fs::read_to_string(&target)?, source);
        Ok(())
    }

    #[test]
    fn save_rejects_symlink_lock_path_without_writing() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let lock_target = temp.path().join("lock-target");
        let lock_link = temp.path().join(".agent.toml.lock");
        let source = r#"agent_id = "probe""#;
        fs::write(&path, source)?;
        fs::write(&lock_target, "not a lock\n")?;
        symlink(&lock_target, &lock_link)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.agent_id = "probe-edited".to_string();

        let error =
            save_config(&path, source, &config).expect_err("symlink lock path must fail closed");

        assert!(matches!(error, TuiError::WriteConfig { .. }));
        assert!(fs::symlink_metadata(&lock_link)?.file_type().is_symlink());
        assert_eq!(fs::read_to_string(&path)?, source);
        assert_eq!(fs::read_to_string(&lock_target)?, "not a lock\n");
        Ok(())
    }

    #[test]
    fn editable_fields_persist_through_save_and_reload() -> Result<(), Box<dyn std::error::Error>> {
        let base_config = AgentConfig::from_toml_str(field_persistence_base_source())?;
        let fields = TuiTab::ALL
            .into_iter()
            .flat_map(|tab| fields_for_tab(tab, &base_config))
            .collect::<Vec<_>>();

        for field in fields {
            let temp = TempDir::new()?;
            let path = temp.path().join("agent.toml");
            let source = field_persistence_source(field);
            fs::write(&path, source)?;
            let mut config = AgentConfig::from_toml_str(source)?;
            prepare_field_persistence_config(field, &mut config);

            let outcome = if editable_text_value(&config, field).is_some() {
                apply_text_field(&mut config, field, field_persistence_text_value(field))
            } else {
                apply_field(&mut config, field, 1, Some(exe_selector("/usr/bin/curl")))
            };
            assert_ne!(outcome, FieldApplyOutcome::Unchanged, "field {field:?}");
            let rendered = save_config(&path, source, &config)?;
            let reloaded = AgentConfig::from_toml_str(&rendered)?;

            assert_eq!(reloaded, config, "field {field:?}");
        }
        Ok(())
    }

    #[test]
    fn save_tls_enable_keeps_embedded_object_out_of_durable_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = field_persistence_base_source();
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;

        let outcome = apply_field(&mut config, FieldId::TlsPlaintextEnabled, 1, None);

        assert_eq!(
            outcome,
            FieldApplyOutcome::Changed("TLS plaintext hooks toggled")
        );
        let rendered = save_config(&path, source, &config)?;
        assert!(rendered.contains("enabled = true"));
        assert!(!rendered.contains("libssl_uprobe_object_path"));
        let reloaded = AgentConfig::from_toml_str(&rendered)?;
        assert!(reloaded.tls.plaintext.instrumentation.enabled);
        assert!(
            reloaded
                .tls
                .plaintext
                .instrumentation
                .libssl_uprobe_object_path
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn process_observation_persists_through_save_and_reload()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = field_persistence_base_source();
        fs::write(&path, source)?;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.observations.push(ProcessObservationConfig {
            id: "curl".to_string(),
            selector: exe_selector("/usr/bin/curl"),
            data_path: ObservationDataPathMode::Libpcap,
            directions: vec![Direction::Inbound, Direction::Outbound],
        });

        let rendered = save_config(&path, source, &config)?;
        let reloaded = AgentConfig::from_toml_str(&rendered)?;

        assert!(rendered.contains("[[observations]]"));
        assert!(rendered.contains("data_path = \"libpcap\""));
        assert!(rendered.contains("directions = [\"inbound\", \"outbound\"]"));
        assert_eq!(reloaded, config);
        Ok(())
    }

    #[test]
    fn exporter_target_text_fields_persist_through_save_and_reload()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                FieldId::ExporterWebhookEndpoint(0),
                r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "webhook"
endpoint = "http://127.0.0.1:8080/events"
codec = "zstd"
"#,
            ),
            (
                FieldId::ExporterFilePath(0),
                r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/events.jsonl"
codec = "zstd"
"#,
            ),
            (
                FieldId::ExporterUnixSocketPath(0),
                r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "unix_http"
socket_path = "/tmp/probe-export.sock"
endpoint = "/events"
codec = "zstd"
"#,
            ),
            (
                FieldId::ExporterUnixHttpEndpoint(0),
                r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "unix_http"
socket_path = "/tmp/probe-export.sock"
endpoint = "/events"
codec = "zstd"
"#,
            ),
        ];

        for (field, source) in cases {
            let temp = TempDir::new()?;
            let path = temp.path().join("agent.toml");
            fs::write(&path, source)?;
            let mut config = AgentConfig::from_toml_str(source)?;

            let outcome = apply_text_field(&mut config, field, field_persistence_text_value(field));
            assert_ne!(outcome, FieldApplyOutcome::Unchanged, "field {field:?}");
            let rendered = save_config(&path, source, &config)?;
            let reloaded = AgentConfig::from_toml_str(&rendered)?;

            assert_eq!(reloaded, config, "field {field:?}");
        }
        Ok(())
    }

    #[test]
    fn load_config_returns_source_and_parsed_config() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("agent.toml");
        let source = r#"agent_id = "probe""#;
        fs::write(&path, source)?;

        let loaded = load_config(&path)?;

        assert_eq!(loaded.source, source);
        assert_eq!(loaded.config.agent_id, "probe");
        Ok(())
    }

    #[test]
    fn load_or_create_config_creates_minimal_safe_config() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = TempDir::new()?;
        let path = temp.path().join("nested").join("agent.toml");

        let loaded = load_or_create_config(&path)?;

        assert_eq!(fs::read_to_string(&path)?, loaded.source);
        assert_eq!(loaded.config.agent_id, "traffic-probe");
        assert_eq!(loaded.config.capture.selection, CaptureSelection::Auto);
        assert_eq!(loaded.config.storage.path, default_storage_path());
        assert!(loaded.config.exporters.is_empty());
        assert!(loaded.config.runtime_reload.watch_config);
        assert_eq!(
            loaded.config.runtime_reload.debounce_ms,
            DEFAULT_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS
        );
        assert_eq!(loaded.config.enforcement.mode, EnforcementMode::AuditOnly);
        assert!(!loaded.config.admin.enabled);
        assert_eq!(loaded.config.admin.socket_path, default_admin_socket_path());
        assert!(loaded.source.contains("[runtime_reload]"));
        assert!(loaded.source.contains("[admin]"));
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        loaded.config.validate_basic()?;
        Ok(())
    }

    fn prepare_field_persistence_config(field: FieldId, config: &mut AgentConfig) {
        if matches!(field, FieldId::InterceptionStrategy) {
            config.enforcement.mode = EnforcementMode::Enforce;
            config.enforcement.interception.selector = Some(exe_selector("/usr/bin/curl"));
        }
    }

    fn field_persistence_source(field: FieldId) -> &'static str {
        if matches!(field, FieldId::InterceptionStrategy) {
            return r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/events.jsonl"
codec = "zstd"

[enforcement]
mode = "enforce"

[enforcement.interception.proxy]
listen_port = 15001

[enforcement.policy.source]
kind = "file"
path = "/tmp/enforcement-policy.toml"
"#;
        }
        if matches!(
            field,
            FieldId::AdminEnabled | FieldId::AdminSocketPath | FieldId::AdminPrometheusEnabled
        ) {
            return r#"
agent_id = "probe"
config_version = "local"

[admin]
enabled = false
socket_path = "/tmp/tui-admin.sock"
"#;
        }
        field_persistence_base_source()
    }

    fn field_persistence_text_value(field: FieldId) -> String {
        match field {
            FieldId::AdminSocketPath => "/tmp/tui-admin-edited.sock".to_string(),
            FieldId::ExporterWebhookEndpoint(_) => "http://127.0.0.1:18080/events".to_string(),
            FieldId::ExporterFilePath(_) => "/tmp/tui-events.jsonl".to_string(),
            FieldId::ExporterUnixSocketPath(_) => "/tmp/tui-export.sock".to_string(),
            FieldId::ExporterUnixHttpEndpoint(_) => "/events".to_string(),
            FieldId::TlsPlaintextObjectPath => {
                "/var/lib/traffic-probe/artifacts/ebpf/custom-tls-plaintext.bpf.o".to_string()
            }
            _ => String::new(),
        }
    }

    fn field_persistence_base_source() -> &'static str {
        r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/events.jsonl"
codec = "zstd"
"#
    }

    fn exe_selector(path: &str) -> Selector {
        Selector::term(
            ProcessSelector {
                exe_path_globs: vec![path.to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
    }
}

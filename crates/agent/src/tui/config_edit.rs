use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};

use probe_config::{AgentConfig, ConfigError, ExporterConfig};
use probe_core::{Direction, Selector, SelectorTerm};
use rustix::{
    fs::{FlockOperation, Gid, Mode, OFlags, Uid, fchmod, fchown, flock},
    process::geteuid,
};
use thiserror::Error;
use toml_edit::{Array, DocumentMut, Item, Table, value};

use super::wire::{
    capture_selection_name, compression_codec_name, connection_backend_name, enforcement_mode_name,
    interception_strategy_name,
};

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

pub(crate) fn save_config(
    path: &Path,
    original_source: &str,
    config: &AgentConfig,
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

fn sync_directory(path: &Path) -> Result<(), TuiError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| TuiError::WriteConfig {
            path: path.display().to_string(),
            source,
        })
}

fn render_preserving_config(
    original_source: &str,
    config: &AgentConfig,
    path: &Path,
) -> Result<String, TuiError> {
    let mut document =
        DocumentMut::from_str(original_source).map_err(|source| TuiError::ParseTomlDocument {
            path: path.display().to_string(),
            source,
        })?;
    set_root_value(&mut document, "agent_id", value(&config.agent_id));
    set_root_value(
        &mut document,
        "config_version",
        value(&config.config_version),
    );
    set_value(
        &mut document,
        &["capture"],
        "selection",
        value(capture_selection_name(config.capture.selection)),
    );
    set_optional_selector(
        &mut document,
        &["capture"],
        "deep_observe_selector",
        config.capture.deep_observe_selector.as_ref(),
    )?;
    set_value(
        &mut document,
        &["export", "worker"],
        "enabled",
        value(config.export.worker.enabled),
    );
    sync_exporter_codecs(&mut document, &config.exporters);
    set_optional_u64(
        &mut document,
        &["storage", "retention", "ingress"],
        "max_records",
        config.storage.retention.ingress.max_records,
    )?;
    set_optional_u64(
        &mut document,
        &["storage", "retention", "export"],
        "max_records",
        config.storage.retention.export.max_records,
    )?;
    set_value(
        &mut document,
        &["enforcement"],
        "mode",
        value(enforcement_mode_name(config.enforcement.mode)),
    );
    set_value(
        &mut document,
        &["enforcement"],
        "backend",
        value(connection_backend_name(config.enforcement.backend)),
    );
    set_optional_selector(
        &mut document,
        &["enforcement"],
        "selector",
        config.enforcement.selector.as_ref(),
    )?;
    set_value(
        &mut document,
        &["enforcement", "interception"],
        "strategy",
        value(interception_strategy_name(
            config.enforcement.interception.strategy,
        )),
    );
    set_optional_selector(
        &mut document,
        &["enforcement", "interception"],
        "selector",
        config.enforcement.interception.selector.as_ref(),
    )?;
    set_value(
        &mut document,
        &["tls", "plaintext", "instrumentation"],
        "enabled",
        value(config.tls.plaintext.instrumentation.enabled),
    );
    set_optional_selector(
        &mut document,
        &["tls", "plaintext", "instrumentation"],
        "selector",
        config.tls.plaintext.instrumentation.selector.as_ref(),
    )?;
    Ok(document.to_string())
}

fn sync_exporter_codecs(document: &mut DocumentMut, exporters: &[ExporterConfig]) {
    let Some(exporters_item) = document.as_table_mut().get_mut("exporters") else {
        return;
    };
    let Some(array) = exporters_item.as_array_of_tables_mut() else {
        return;
    };
    for (index, exporter) in exporters.iter().enumerate() {
        let Some(table) = array.get_mut(index) else {
            continue;
        };
        set_table_item(
            table,
            "codec",
            value(compression_codec_name(exporter.codec)),
        );
    }
}

fn set_root_value(document: &mut DocumentMut, key: &str, item: Item) {
    set_table_item(document.as_table_mut(), key, item);
}

fn set_value(document: &mut DocumentMut, table_path: &[&str], key: &str, item: Item) {
    set_table_item(table_at_path(document, table_path), key, item);
}

fn set_optional_selector(
    document: &mut DocumentMut,
    table_path: &[&str],
    key: &str,
    selector: Option<&Selector>,
) -> Result<(), TuiError> {
    let table = table_at_path(document, table_path);
    match selector {
        Some(selector) => {
            set_table_item(table, key, selector_item(selector)?);
        }
        None => {
            table.remove(key);
        }
    }
    Ok(())
}

fn set_optional_u64(
    document: &mut DocumentMut,
    table_path: &[&str],
    key: &str,
    records: Option<u64>,
) -> Result<(), TuiError> {
    match records {
        Some(records) => {
            let records = i64::try_from(records).map_err(|_| {
                TuiError::UnsupportedTomlShape(format!(
                    "{key} value {records} does not fit a TOML integer"
                ))
            })?;
            let table = table_at_path(document, table_path);
            set_table_item(table, key, value(records));
        }
        None => {
            if let Some(table) = table_at_existing_path_mut(document, table_path) {
                table.remove(key);
            }
        }
    }
    Ok(())
}

fn selector_item(selector: &Selector) -> Result<Item, TuiError> {
    if let Selector::Match { term } = selector {
        return Ok(Item::Table(selector_match_table(term)));
    }
    Ok(Item::Table(
        toml_edit::ser::to_document(selector)?.into_table(),
    ))
}

fn set_table_item(table: &mut Table, key: &str, item: Item) {
    if let Some(existing) = table.get_mut(key) {
        replace_item_preserving_value_decor(existing, item);
    } else {
        table.insert(key, item);
    }
}

fn replace_item_preserving_value_decor(existing: &mut Item, item: Item) {
    match (existing.as_value_mut(), item) {
        (Some(current), Item::Value(mut next)) => {
            let decor = current.decor().clone();
            *next.decor_mut() = decor;
            *current = next;
        }
        (_, item) => {
            *existing = item;
        }
    }
}

fn selector_match_table(term: &SelectorTerm) -> Table {
    let mut table = Table::new();
    table.insert("op", value("match"));

    let mut term_table = Table::new();
    term_table.insert("process", Item::Table(process_selector_table(term)));
    term_table.insert("traffic", Item::Table(traffic_selector_table(term)));
    table.insert("term", Item::Table(term_table));
    table
}

fn process_selector_table(term: &SelectorTerm) -> Table {
    let process = &term.process;
    let mut table = Table::new();
    table.insert("pids", value(array_u32(&process.pids)));
    table.insert("uids", value(array_u32(&process.uids)));
    table.insert("gids", value(array_u32(&process.gids)));
    table.insert("names", value(array_strings(&process.names)));
    table.insert(
        "exe_path_globs",
        value(array_strings(&process.exe_path_globs)),
    );
    table.insert(
        "cmdline_regexes",
        value(array_strings(&process.cmdline_regexes)),
    );
    table.insert(
        "systemd_services",
        value(array_strings(&process.systemd_services)),
    );
    table.insert(
        "container_ids",
        value(array_strings(&process.container_ids)),
    );
    table.insert("cgroup_paths", value(array_strings(&process.cgroup_paths)));
    table
}

fn traffic_selector_table(term: &SelectorTerm) -> Table {
    let traffic = &term.traffic;
    let mut table = Table::new();
    table.insert("local_ports", value(array_u16(&traffic.local_ports)));
    table.insert("remote_ports", value(array_u16(&traffic.remote_ports)));
    table.insert("directions", value(array_directions(&traffic.directions)));
    table.insert(
        "remote_addresses",
        value(array_strings(&traffic.remote_addresses)),
    );
    table
}

fn array_strings(values: &[String]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(value.as_str());
    }
    array
}

fn array_u16(values: &[u16]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(i64::from(*value));
    }
    array
}

fn array_u32(values: &[u32]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(i64::from(*value));
    }
    array
}

fn array_directions(values: &[Direction]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(match value {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        });
    }
    array
}

fn table_at_path<'a>(document: &'a mut DocumentMut, path: &[&str]) -> &'a mut Table {
    let mut table = document.as_table_mut();
    for key in path {
        let item = table
            .entry(key)
            .or_insert_with(|| Item::Table(Table::new()));
        if item.as_table_mut().is_none() {
            *item = Item::Table(Table::new());
        }
        let Some(next_table) = item.as_table_mut() else {
            unreachable!("table item was just initialized");
        };
        table = next_table;
    }
    table
}

fn table_at_existing_path_mut<'a>(
    document: &'a mut DocumentMut,
    path: &[&str],
) -> Option<&'a mut Table> {
    let mut table = document.as_table_mut();
    for key in path {
        let item = table.get_mut(key)?;
        table = item.as_table_mut()?;
    }
    Some(table)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use probe_config::{
        AgentConfig, CaptureSelection, CompressionCodecName, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{EnforcementMode, ProcessSelector, Selector, TrafficSelector};
    use tempfile::TempDir;

    use super::super::{
        app::TuiTab,
        fields::{FieldApplyOutcome, FieldId, apply_field, fields_for_tab},
    };
    use super::*;

    #[test]
    fn preserving_save_keeps_comments_and_updates_tui_managed_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = r#"
# keep this comment
agent_id = "old"
config_version = "local"

[capture]
selection = "auto"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/events.jsonl"
codec = "zstd"

[export.worker]
enabled = true

[storage.retention.ingress]
max_records = 10000

[storage.retention.export]
max_records = 10000
"#;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.agent_id = "probe-a".to_string();
        config.capture.selection = CaptureSelection::Libpcap;
        config.export.worker.enabled = false;
        config.exporters[0].codec = CompressionCodecName::Gzip;
        config.storage.retention.ingress.max_records = Some(100_000);
        config.storage.retention.export.max_records = Some(1_000_000);

        let rendered = render_preserving_config(source, &config, Path::new("/tmp/agent.toml"))?;

        assert!(rendered.contains("# keep this comment"));
        assert!(rendered.contains("agent_id = \"probe-a\""));
        assert!(rendered.contains("selection = \"libpcap\""));
        assert!(rendered.contains("enabled = false"));
        assert!(rendered.contains("codec = \"gzip\""));
        assert!(rendered.contains("[storage.retention.ingress]"));
        assert!(rendered.contains("[storage.retention.export]"));
        assert!(rendered.contains("max_records = 100000"));
        assert!(rendered.contains("max_records = 1000000"));
        AgentConfig::from_toml_str(&rendered)?.validate_basic()?;
        Ok(())
    }

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
    fn process_selector_is_written_as_human_readable_selector_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = r#"
agent_id = "probe"
config_version = "local"

[capture]
selection = "auto"
"#;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.capture.deep_observe_selector = Some(Selector::term(
            ProcessSelector {
                exe_path_globs: vec!["/usr/bin/curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        ));

        let rendered = render_preserving_config(source, &config, Path::new("/tmp/agent.toml"))?;

        assert!(rendered.contains("[capture.deep_observe_selector]"));
        assert!(rendered.contains("op = \"match\""));
        assert!(rendered.contains("[capture.deep_observe_selector.term.process]"));
        assert!(rendered.contains("exe_path_globs = [\"/usr/bin/curl\"]"));
        AgentConfig::from_toml_str(&rendered)?.validate_basic()?;
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

            let outcome = apply_field(&mut config, field, 1, Some(exe_selector("/usr/bin/curl")));
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
    fn selector_item_uses_existing_selector_contract() -> Result<(), Box<dyn std::error::Error>> {
        let item = selector_item(&Selector::default())?;

        assert!(item.to_string().contains("op = \"match\""));
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
        field_persistence_base_source()
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

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use ebpf_object::EbpfObjectArtifact;
#[cfg(test)]
use probe_config::CaptureSelection;
use probe_config::{AgentConfig, CaptureBackend, probe_home_path};
use rustix::fs::OFlags;
use thiserror::Error;

const PROCESS_OBSERVATION_OBJECT_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ebpf-process-observation"));
const TLS_UPROBE_OBJECT_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ebpf-tls-plaintext"));
const EBPF_OBJECT_HASH_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArtifactHydration {
    NotNeeded,
    AlreadyConfigured,
    Materialized,
}

#[derive(Debug, Error)]
pub(crate) enum ArtifactError {
    #[error("failed to {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("generated artifact directory must be a real directory: {0}")]
    InvalidDirectory(PathBuf),
}

pub(crate) fn hydrate_runtime_artifact_paths(
    config: &mut AgentConfig,
) -> Result<(), ArtifactError> {
    let _ = hydrate_process_observation_object_path(config)?;
    let _ = hydrate_tls_uprobe_object_path(config)?;
    Ok(())
}

pub(crate) fn project_runtime_artifact_paths(config: &mut AgentConfig) {
    project_process_observation_object_path(config);
    project_tls_uprobe_object_path(config);
}

pub(crate) fn normalize_embedded_artifact_paths_for_comparison(config: &mut AgentConfig) {
    normalize_path_if_embedded(
        &mut config.capture.ebpf.object_path,
        EbpfObjectArtifact::ProcessObservation,
    );
    normalize_path_if_embedded(
        &mut config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path,
        EbpfObjectArtifact::TlsPlaintext,
    );
}

pub(crate) fn hydrate_process_observation_object_path(
    config: &mut AgentConfig,
) -> Result<ArtifactHydration, ArtifactError> {
    hydrate_process_observation_object_path_in(config, default_ebpf_artifact_directory())
}

pub(crate) fn hydrate_tls_uprobe_object_path(
    config: &mut AgentConfig,
) -> Result<ArtifactHydration, ArtifactError> {
    hydrate_tls_uprobe_object_path_in(config, default_ebpf_artifact_directory())
}

fn hydrate_process_observation_object_path_in(
    config: &mut AgentConfig,
    directory: PathBuf,
) -> Result<ArtifactHydration, ArtifactError> {
    if !config.capture.may_use_backend(CaptureBackend::Ebpf) {
        return Ok(ArtifactHydration::NotNeeded);
    }
    if config
        .capture
        .ebpf
        .object_path
        .as_ref()
        .is_some_and(|path| !path.as_os_str().is_empty())
    {
        return Ok(ArtifactHydration::AlreadyConfigured);
    }
    let path =
        materialize_embedded_ebpf_object_in(directory, EbpfObjectArtifact::ProcessObservation)?;
    config.capture.ebpf.object_path = Some(path);
    Ok(ArtifactHydration::Materialized)
}

fn hydrate_tls_uprobe_object_path_in(
    config: &mut AgentConfig,
    directory: PathBuf,
) -> Result<ArtifactHydration, ArtifactError> {
    let instrumentation = &mut config.tls.plaintext.instrumentation;
    if !instrumentation.enabled {
        return Ok(ArtifactHydration::NotNeeded);
    }
    if instrumentation
        .libssl_uprobe_object_path
        .as_ref()
        .is_some_and(|path| !path.as_os_str().is_empty())
    {
        return Ok(ArtifactHydration::AlreadyConfigured);
    }
    let path = materialize_embedded_ebpf_object_in(directory, EbpfObjectArtifact::TlsPlaintext)?;
    instrumentation.libssl_uprobe_object_path = Some(path);
    Ok(ArtifactHydration::Materialized)
}

fn materialize_embedded_ebpf_object_in(
    directory: PathBuf,
    artifact: EbpfObjectArtifact,
) -> Result<PathBuf, ArtifactError> {
    ensure_private_directory(&directory)?;
    let bytes = artifact.bytes();
    let path = directory.join(artifact.file_name());
    if artifact_file_matches(&path, bytes)? {
        return Ok(path);
    }

    write_artifact_atomically(&directory, &path, bytes)?;
    Ok(path)
}

fn project_process_observation_object_path(config: &mut AgentConfig) {
    project_process_observation_object_path_in(config, default_ebpf_artifact_directory());
}

fn project_process_observation_object_path_in(config: &mut AgentConfig, directory: PathBuf) {
    if !config.capture.may_use_backend(CaptureBackend::Ebpf) {
        return;
    }
    if config
        .capture
        .ebpf
        .object_path
        .as_ref()
        .is_some_and(|path| !path.as_os_str().is_empty())
    {
        return;
    }
    config.capture.ebpf.object_path =
        Some(directory.join(EbpfObjectArtifact::ProcessObservation.file_name()));
}

fn project_tls_uprobe_object_path(config: &mut AgentConfig) {
    project_tls_uprobe_object_path_in(config, default_ebpf_artifact_directory());
}

fn project_tls_uprobe_object_path_in(config: &mut AgentConfig, directory: PathBuf) {
    let instrumentation = &mut config.tls.plaintext.instrumentation;
    if !instrumentation.enabled {
        return;
    }
    if instrumentation
        .libssl_uprobe_object_path
        .as_ref()
        .is_some_and(|path| !path.as_os_str().is_empty())
    {
        return;
    }
    instrumentation.libssl_uprobe_object_path =
        Some(directory.join(EbpfObjectArtifact::TlsPlaintext.file_name()));
}

fn normalize_path_if_embedded(path: &mut Option<PathBuf>, artifact: EbpfObjectArtifact) {
    if path
        .as_ref()
        .is_some_and(|path| path == &embedded_ebpf_object_path(artifact))
    {
        *path = None;
    }
}

fn embedded_ebpf_object_path(artifact: EbpfObjectArtifact) -> PathBuf {
    default_ebpf_artifact_directory().join(artifact.file_name())
}

#[cfg(test)]
pub(crate) fn embedded_process_observation_object_path_for_test() -> PathBuf {
    embedded_ebpf_object_path(EbpfObjectArtifact::ProcessObservation)
}

fn default_ebpf_artifact_directory() -> PathBuf {
    probe_home_path(PathBuf::from("artifacts").join("ebpf"))
}

trait EmbeddedEbpfObjectExt {
    fn bytes(self) -> &'static [u8];
    fn file_name(self) -> String;
    fn file_prefix(self) -> &'static str;
}

impl EmbeddedEbpfObjectExt for EbpfObjectArtifact {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::ProcessObservation => PROCESS_OBSERVATION_OBJECT_BYTES,
            Self::TlsPlaintext => TLS_UPROBE_OBJECT_BYTES,
        }
    }

    fn file_name(self) -> String {
        let hash = blake3::hash(self.bytes()).to_hex().to_string();
        let prefix = &hash[..EBPF_OBJECT_HASH_BYTES];
        format!("{}-{prefix}.bpf.o", self.file_prefix())
    }

    fn file_prefix(self) -> &'static str {
        match self {
            Self::ProcessObservation => "process-observation",
            Self::TlsPlaintext => "tls-plaintext",
        }
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), ArtifactError> {
    fs::create_dir_all(path).map_err(|source| ArtifactError::Io {
        action: "create artifact directory",
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| ArtifactError::Io {
        action: "inspect artifact directory",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ArtifactError::InvalidDirectory(path.to_path_buf()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ArtifactError::Io {
            action: "secure artifact directory",
            path: path.to_path_buf(),
            source,
        }
    })
}

fn write_artifact_atomically(
    directory: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), ArtifactError> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("embedded-ebpf-object.bpf.o");
    let temp_path = directory.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let write_result = create_private_file(&temp_path)
        .and_then(|mut file| {
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| ArtifactError::Io {
                    action: "write embedded eBPF object",
                    path: temp_path.clone(),
                    source,
                })
        })
        .and_then(|()| {
            fs::rename(&temp_path, path).map_err(|source| ArtifactError::Io {
                action: "install embedded eBPF object",
                path: path.to_path_buf(),
                source,
            })
        })
        .and_then(|()| sync_directory(directory));
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

fn artifact_file_matches(path: &Path, bytes: &[u8]) -> Result<bool, ArtifactError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(ArtifactError::Io {
                action: "inspect embedded eBPF object",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ArtifactError::Io {
            action: "inspect embedded eBPF object",
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "artifact path exists but is not a regular file",
            ),
        });
    }
    fs::read(path)
        .map(|existing| existing == bytes)
        .map_err(|source| ArtifactError::Io {
            action: "read embedded eBPF object",
            path: path.to_path_buf(),
            source,
        })
}

fn create_private_file(path: &Path) -> Result<File, ArtifactError> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|source| ArtifactError::Io {
            action: "create embedded eBPF object",
            path: path.to_path_buf(),
            source,
        })
}

fn sync_directory(path: &Path) -> Result<(), ArtifactError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| ArtifactError::Io {
            action: "sync artifact directory",
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
#[test]
fn process_observation_hydration_materializes_default_object() -> Result<(), ArtifactError> {
    let (_temp, directory) = temp_artifact_directory();
    let mut config = AgentConfig::default();

    let outcome = hydrate_process_observation_object_path_in(&mut config, directory.clone())?;

    assert_eq!(outcome, ArtifactHydration::Materialized);
    let path = config
        .capture
        .ebpf
        .object_path
        .as_ref()
        .expect("process observation object path should be configured");
    assert!(path.starts_with(&directory));
    assert!(
        path.file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("process-observation-"))
    );
    assert_eq!(read_artifact(path)?, PROCESS_OBSERVATION_OBJECT_BYTES);
    Ok(())
}

#[cfg(test)]
#[test]
fn process_observation_projection_sets_path_without_materializing_object() {
    let (temp, directory) = temp_artifact_directory();
    let mut config = AgentConfig::default();

    project_process_observation_object_path_in(&mut config, directory.clone());

    let path = config
        .capture
        .ebpf
        .object_path
        .as_ref()
        .expect("process observation object path should be projected");
    assert!(path.starts_with(&directory));
    assert!(!directory.exists());
    assert!(
        temp.path()
            .read_dir()
            .expect("temp dir should be readable")
            .next()
            .is_none()
    );
}

#[cfg(test)]
#[test]
fn process_observation_hydration_ignores_non_ebpf_capture_selection() -> Result<(), ArtifactError> {
    let (_temp, directory) = temp_artifact_directory();
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Libpcap;

    let outcome = hydrate_process_observation_object_path_in(&mut config, directory)?;

    assert_eq!(outcome, ArtifactHydration::NotNeeded);
    assert!(config.capture.ebpf.object_path.is_none());
    Ok(())
}

#[cfg(test)]
#[test]
fn process_observation_hydration_keeps_explicit_object_path() -> Result<(), ArtifactError> {
    let (_temp, directory) = temp_artifact_directory();
    let mut config = AgentConfig::default();
    let path = PathBuf::from("/var/lib/traffic-probe/artifacts/ebpf/custom-process.bpf.o");
    config.capture.ebpf.object_path = Some(path.clone());

    let outcome = hydrate_process_observation_object_path_in(&mut config, directory)?;

    assert_eq!(outcome, ArtifactHydration::AlreadyConfigured);
    assert_eq!(config.capture.ebpf.object_path, Some(path));
    Ok(())
}

#[cfg(test)]
#[test]
fn embedded_artifact_normalization_ignores_generated_runtime_paths() {
    let mut config = AgentConfig::default();
    config.capture.ebpf.object_path = Some(embedded_ebpf_object_path(
        EbpfObjectArtifact::ProcessObservation,
    ));
    config
        .tls
        .plaintext
        .instrumentation
        .libssl_uprobe_object_path =
        Some(embedded_ebpf_object_path(EbpfObjectArtifact::TlsPlaintext));

    normalize_embedded_artifact_paths_for_comparison(&mut config);

    assert!(config.capture.ebpf.object_path.is_none());
    assert!(
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path
            .is_none()
    );
}

#[cfg(test)]
#[test]
fn embedded_artifact_normalization_keeps_custom_paths() {
    let mut config = AgentConfig::default();
    let process_path = PathBuf::from("/opt/probe/custom-process.bpf.o");
    let tls_path = PathBuf::from("/opt/probe/custom-tls.bpf.o");
    config.capture.ebpf.object_path = Some(process_path.clone());
    config
        .tls
        .plaintext
        .instrumentation
        .libssl_uprobe_object_path = Some(tls_path.clone());

    normalize_embedded_artifact_paths_for_comparison(&mut config);

    assert_eq!(config.capture.ebpf.object_path, Some(process_path));
    assert_eq!(
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path,
        Some(tls_path)
    );
}

#[cfg(test)]
#[test]
fn tls_uprobe_hydration_ignores_disabled_instrumentation() -> Result<(), ArtifactError> {
    let mut config = AgentConfig::default();

    let outcome = hydrate_tls_uprobe_object_path(&mut config)?;

    assert_eq!(outcome, ArtifactHydration::NotNeeded);
    assert!(
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path
            .is_none()
    );
    Ok(())
}

#[cfg(test)]
#[test]
fn tls_uprobe_hydration_keeps_explicit_object_path() -> Result<(), ArtifactError> {
    let mut config = AgentConfig::default();
    let path = PathBuf::from("/var/lib/traffic-probe/artifacts/ebpf/custom-tls-plaintext.bpf.o");
    config.tls.plaintext.instrumentation.enabled = true;
    config
        .tls
        .plaintext
        .instrumentation
        .libssl_uprobe_object_path = Some(path.clone());

    let outcome = hydrate_tls_uprobe_object_path(&mut config)?;

    assert_eq!(outcome, ArtifactHydration::AlreadyConfigured);
    assert_eq!(
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path,
        Some(path)
    );
    Ok(())
}

#[cfg(test)]
#[test]
fn tls_uprobe_projection_sets_path_without_materializing_object() {
    let (temp, directory) = temp_artifact_directory();
    let mut config = AgentConfig::default();
    config.tls.plaintext.instrumentation.enabled = true;

    project_tls_uprobe_object_path_in(&mut config, directory.clone());

    let path = config
        .tls
        .plaintext
        .instrumentation
        .libssl_uprobe_object_path
        .as_ref()
        .expect("TLS uprobe object path should be projected");
    assert!(path.starts_with(&directory));
    assert!(!directory.exists());
    assert!(
        temp.path()
            .read_dir()
            .expect("temp dir should be readable")
            .next()
            .is_none()
    );
}

#[cfg(test)]
fn temp_artifact_directory() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let directory = temp.path().join("artifacts/ebpf");
    (temp, directory)
}

#[cfg(test)]
fn read_artifact(path: &Path) -> Result<Vec<u8>, ArtifactError> {
    fs::read(path).map_err(|source| ArtifactError::Io {
        action: "read materialized eBPF object",
        path: path.to_path_buf(),
        source,
    })
}

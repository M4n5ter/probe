use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use probe_config::{AgentConfig, probe_home_path};
use rustix::fs::OFlags;
use thiserror::Error;

const TLS_UPROBE_OBJECT_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ebpf-tls-plaintext"));
const TLS_UPROBE_OBJECT_HASH_BYTES: usize = 16;

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

pub(crate) fn hydrate_tls_uprobe_object_path(
    config: &mut AgentConfig,
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
    let path = materialize_embedded_tls_uprobe_object()?;
    instrumentation.libssl_uprobe_object_path = Some(path);
    Ok(ArtifactHydration::Materialized)
}

pub(crate) fn materialize_embedded_tls_uprobe_object() -> Result<PathBuf, ArtifactError> {
    let directory = probe_home_path(PathBuf::from("artifacts").join("ebpf"));
    ensure_private_directory(&directory)?;
    let path = directory.join(tls_uprobe_object_file_name());
    if artifact_file_matches(&path, TLS_UPROBE_OBJECT_BYTES)? {
        return Ok(path);
    }

    write_artifact_atomically(&directory, &path, TLS_UPROBE_OBJECT_BYTES)?;
    Ok(path)
}

fn tls_uprobe_object_file_name() -> String {
    let hash = blake3::hash(TLS_UPROBE_OBJECT_BYTES).to_hex().to_string();
    let prefix = &hash[..TLS_UPROBE_OBJECT_HASH_BYTES];
    format!("tls-plaintext-{prefix}.bpf.o")
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
        .unwrap_or("tls-plaintext.bpf.o");
    let temp_path = directory.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let write_result = create_private_file(&temp_path)
        .and_then(|mut file| {
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| ArtifactError::Io {
                    action: "write embedded TLS uprobe object",
                    path: temp_path.clone(),
                    source,
                })
        })
        .and_then(|()| {
            fs::rename(&temp_path, path).map_err(|source| ArtifactError::Io {
                action: "install embedded TLS uprobe object",
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
                action: "inspect embedded TLS uprobe object",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ArtifactError::Io {
            action: "inspect embedded TLS uprobe object",
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
            action: "read embedded TLS uprobe object",
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
            action: "create embedded TLS uprobe object",
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

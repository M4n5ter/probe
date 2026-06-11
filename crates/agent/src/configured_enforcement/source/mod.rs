use std::{
    fs::{self, File, Metadata},
    io::Read,
    path::{Path, PathBuf},
};

use probe_config::EnforcementPolicyManifest;
use probe_core::RuntimeMode;
use runtime::EnforcementPolicySourcePlan;
use rustix::fs::{Mode, OFlags, open};
use thiserror::Error;

pub const MAX_ENFORCEMENT_POLICY_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedEnforcementPolicySource {
    pub path: PathBuf,
    pub manifest: EnforcementPolicyManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementPolicySourceInspection {
    pub mode: RuntimeMode,
    pub reason: Option<String>,
    pub manifest: Option<EnforcementPolicyManifest>,
}

#[derive(Debug, Error)]
pub enum EnforcementPolicySourceError {
    #[error("remote enforcement policy source is reserved but not implemented: {endpoint}")]
    RemoteSource { endpoint: String },
    #[error("enforcement policy source path does not exist: {path}")]
    NotFound { path: PathBuf },
    #[error("failed to inspect enforcement policy source {path}: {source}")]
    Inspect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to open enforcement policy source {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read enforcement policy source {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("enforcement policy source path is a symlink: {path}")]
    Symlink { path: PathBuf },
    #[error("enforcement policy source is not a regular file: {path}")]
    NotRegular { path: PathBuf },
    #[error("enforcement policy manifest is too large: {path} has {size} bytes, limit {limit}")]
    TooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },
    #[error("failed to parse enforcement policy manifest {path}: {source}")]
    ManifestToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid enforcement policy manifest: {reason}")]
    InvalidManifest { reason: String },
}

pub fn load_enforcement_policy_source(
    source: &EnforcementPolicySourcePlan,
) -> Result<Option<LoadedEnforcementPolicySource>, EnforcementPolicySourceError> {
    let Some(path) = manifest_path_for_source(source)? else {
        return Ok(None);
    };
    let manifest = read_enforcement_policy_manifest(&path)?;
    Ok(Some(LoadedEnforcementPolicySource { path, manifest }))
}

pub fn inspect_enforcement_policy_source(
    source: &EnforcementPolicySourcePlan,
) -> EnforcementPolicySourceInspection {
    match load_enforcement_policy_source(source) {
        Ok(Some(loaded)) => EnforcementPolicySourceInspection {
            mode: RuntimeMode::Available,
            reason: None,
            manifest: Some(loaded.manifest),
        },
        Ok(None) => EnforcementPolicySourceInspection {
            mode: RuntimeMode::Available,
            reason: None,
            manifest: None,
        },
        Err(error) => EnforcementPolicySourceInspection {
            mode: RuntimeMode::Unavailable,
            reason: Some(error.to_string()),
            manifest: None,
        },
    }
}

fn manifest_path_for_source(
    source: &EnforcementPolicySourcePlan,
) -> Result<Option<PathBuf>, EnforcementPolicySourceError> {
    match source {
        EnforcementPolicySourcePlan::None => Ok(None),
        EnforcementPolicySourcePlan::LocalManifest { path, .. } => Ok(Some(path.clone())),
        EnforcementPolicySourcePlan::Remote { endpoint } => {
            Err(EnforcementPolicySourceError::RemoteSource {
                endpoint: endpoint.clone(),
            })
        }
    }
}

fn read_enforcement_policy_manifest(
    path: &Path,
) -> Result<EnforcementPolicyManifest, EnforcementPolicySourceError> {
    let content = read_regular_policy_file(path)?;
    toml::from_str::<EnforcementPolicyManifest>(&content)
        .map_err(|source| EnforcementPolicySourceError::ManifestToml {
            path: path.to_path_buf(),
            source,
        })
        .and_then(validate_enforcement_policy_manifest)
}

fn validate_enforcement_policy_manifest(
    manifest: EnforcementPolicyManifest,
) -> Result<EnforcementPolicyManifest, EnforcementPolicySourceError> {
    if manifest.id.trim().is_empty() {
        return Err(EnforcementPolicySourceError::InvalidManifest {
            reason: "enforcement policy id cannot be empty".to_string(),
        });
    }
    if manifest.version.trim().is_empty() {
        return Err(EnforcementPolicySourceError::InvalidManifest {
            reason: "enforcement policy version cannot be empty".to_string(),
        });
    }
    if let Some(selector) = &manifest.selector {
        selector
            .compile()
            .map_err(|error| EnforcementPolicySourceError::InvalidManifest {
                reason: format!("invalid enforcement policy selector: {error}"),
            })?;
    }
    Ok(manifest)
}

fn read_regular_policy_file(path: &Path) -> Result<String, EnforcementPolicySourceError> {
    let file = open_regular_policy_file(path)?;
    validate_file_size(
        path,
        &file
            .metadata()
            .map_err(|source| EnforcementPolicySourceError::Inspect {
                path: path.to_path_buf(),
                source,
            })?,
    )?;
    read_file_to_string(path, file)
}

fn open_regular_policy_file(path: &Path) -> Result<File, EnforcementPolicySourceError> {
    reject_symlink(path)?;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| EnforcementPolicySourceError::Open {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|source| EnforcementPolicySourceError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.is_file() {
        Ok(file)
    } else {
        Err(EnforcementPolicySourceError::NotRegular {
            path: path.to_path_buf(),
        })
    }
}

fn validate_file_size(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), EnforcementPolicySourceError> {
    if metadata.len() > MAX_ENFORCEMENT_POLICY_MANIFEST_BYTES {
        return Err(EnforcementPolicySourceError::TooLarge {
            path: path.to_path_buf(),
            size: metadata.len(),
            limit: MAX_ENFORCEMENT_POLICY_MANIFEST_BYTES,
        });
    }
    Ok(())
}

fn read_file_to_string(path: &Path, file: File) -> Result<String, EnforcementPolicySourceError> {
    let mut reader = file.take(MAX_ENFORCEMENT_POLICY_MANIFEST_BYTES.saturating_add(1));
    let mut content = String::new();
    reader
        .read_to_string(&mut content)
        .map_err(|source| EnforcementPolicySourceError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if content.len() as u64 > MAX_ENFORCEMENT_POLICY_MANIFEST_BYTES {
        return Err(EnforcementPolicySourceError::TooLarge {
            path: path.to_path_buf(),
            size: content.len() as u64,
            limit: MAX_ENFORCEMENT_POLICY_MANIFEST_BYTES,
        });
    }
    Ok(content)
}

fn reject_symlink(path: &Path) -> Result<(), EnforcementPolicySourceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            EnforcementPolicySourceError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            EnforcementPolicySourceError::Inspect {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if metadata.file_type().is_symlink() {
        Err(EnforcementPolicySourceError::Symlink {
            path: path.to_path_buf(),
        })
    } else {
        Ok(())
    }
}

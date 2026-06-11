use std::{
    fs::{self, File, Metadata},
    io::Read,
    path::{Path, PathBuf},
};

use policy::{POLICY_HOOKS, PolicyHook, PolicyManifest};
use probe_config::PolicyConfig;
use probe_core::RuntimeMode;
use rustix::fs::{Mode, OFlags, open};
use serde::Serialize;

use super::ConfiguredPolicyError;

pub const MAX_POLICY_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_POLICY_MANIFEST_BYTES: u64 = 64 * 1024;

const BUNDLE_MANIFEST_FILE: &str = "manifest.toml";
const BUNDLE_MAIN_FILE: &str = "main.lua";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySourceInspection {
    pub mode: RuntimeMode,
    pub reason: Option<String>,
}

pub struct LoadedPolicySource {
    pub manifest: PolicyManifest,
    pub source: String,
    pub require_declared_hooks: bool,
}

pub fn load_policy_source(
    config_version: &str,
    policy: &PolicyConfig,
) -> Result<LoadedPolicySource, ConfiguredPolicyError> {
    discover_policy_source(&policy.path)
        .and_then(|location| location.load(config_version, policy))
        .map_err(|error| error.into_configured_error(&policy.path))
}

pub fn inspect_policy_source(path: &Path, expected_id: &str) -> PolicySourceInspection {
    match discover_policy_source(path).and_then(|location| location.inspect(expected_id)) {
        Ok(()) => PolicySourceInspection {
            mode: RuntimeMode::Available,
            reason: None,
        },
        Err(error) => PolicySourceInspection {
            mode: RuntimeMode::Unavailable,
            reason: Some(error.reason()),
        },
    }
}

enum PolicySourceLocation {
    LegacyFile { path: PathBuf },
    BundleDirectory { root: PathBuf },
}

impl PolicySourceLocation {
    fn load(
        self,
        config_version: &str,
        policy: &PolicyConfig,
    ) -> Result<LoadedPolicySource, PolicySourceValidationError> {
        match self {
            Self::LegacyFile { path } => read_legacy_policy_file(&path, config_version, policy),
            Self::BundleDirectory { root } => {
                read_policy_bundle_directory(&root, policy.id.as_str())
            }
        }
    }

    fn inspect(self, expected_id: &str) -> Result<(), PolicySourceValidationError> {
        match self {
            Self::LegacyFile { path } => {
                check_regular_policy_file(&path, MAX_POLICY_SOURCE_BYTES, "source")
            }
            Self::BundleDirectory { root } => {
                let manifest = read_policy_manifest(&manifest_path(&root))?;
                validate_policy_manifest(manifest, expected_id)?;
                check_regular_policy_file(&main_path(&root), MAX_POLICY_SOURCE_BYTES, "source")
            }
        }
    }
}

fn discover_policy_source(
    path: &Path,
) -> Result<PolicySourceLocation, PolicySourceValidationError> {
    let metadata = symlink_safe_metadata(path)?;
    if metadata.is_file() {
        return Ok(PolicySourceLocation::LegacyFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.is_dir() {
        return Ok(PolicySourceLocation::BundleDirectory {
            root: path.to_path_buf(),
        });
    }

    Err(PolicySourceValidationError::UnsupportedPathKind {
        path: path.to_path_buf(),
    })
}

fn read_legacy_policy_file(
    path: &Path,
    config_version: &str,
    policy: &PolicyConfig,
) -> Result<LoadedPolicySource, PolicySourceValidationError> {
    let source = read_regular_policy_file(path, MAX_POLICY_SOURCE_BYTES, "source")?;

    Ok(LoadedPolicySource {
        manifest: PolicyManifest {
            id: policy.id.clone(),
            version: config_version.to_string(),
            hooks: POLICY_HOOKS.to_vec(),
        },
        source,
        require_declared_hooks: false,
    })
}

fn read_policy_bundle_directory(
    root: &Path,
    expected_id: &str,
) -> Result<LoadedPolicySource, PolicySourceValidationError> {
    let manifest = read_policy_manifest(&manifest_path(root))
        .and_then(|manifest| validate_policy_manifest(manifest, expected_id))?;
    let source = read_regular_policy_file(&main_path(root), MAX_POLICY_SOURCE_BYTES, "source")?;

    Ok(LoadedPolicySource {
        manifest,
        source,
        require_declared_hooks: true,
    })
}

fn read_policy_manifest(path: &Path) -> Result<PolicyManifest, PolicySourceValidationError> {
    let content = read_regular_policy_file(path, MAX_POLICY_MANIFEST_BYTES, "manifest")?;

    toml::from_str::<PolicyManifest>(&content).map_err(|source| {
        PolicySourceValidationError::ManifestToml {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn validate_policy_manifest(
    manifest: PolicyManifest,
    expected_id: &str,
) -> Result<PolicyManifest, PolicySourceValidationError> {
    if manifest.id.trim().is_empty() {
        return Err(PolicySourceValidationError::InvalidManifest {
            reason: "policy id cannot be empty".to_string(),
        });
    }
    if manifest.version.trim().is_empty() {
        return Err(PolicySourceValidationError::InvalidManifest {
            reason: "policy version cannot be empty".to_string(),
        });
    }
    if manifest.id != expected_id {
        return Err(PolicySourceValidationError::ManifestIdMismatch {
            expected: expected_id.to_string(),
            actual: manifest.id,
        });
    }
    if manifest.hooks.is_empty() {
        return Err(PolicySourceValidationError::InvalidManifest {
            reason: "policy manifest must register at least one hook".to_string(),
        });
    }
    let mut seen = Vec::<PolicyHook>::new();
    for hook in &manifest.hooks {
        if seen.contains(hook) {
            return Err(PolicySourceValidationError::InvalidManifest {
                reason: format!("policy hook {hook} is registered more than once"),
            });
        }
        seen.push(*hook);
    }
    Ok(manifest)
}

fn read_regular_policy_file(
    path: &Path,
    limit: u64,
    kind: &'static str,
) -> Result<String, PolicySourceValidationError> {
    let file = open_regular_policy_file(path)?;
    validate_file_size(
        path,
        kind,
        limit,
        &file
            .metadata()
            .map_err(|source| PolicySourceValidationError::Inspect {
                path: path.to_path_buf(),
                source,
            })?,
    )?;
    read_file_to_string(path, kind, limit, file)
}

fn check_regular_policy_file(
    path: &Path,
    limit: u64,
    kind: &'static str,
) -> Result<(), PolicySourceValidationError> {
    let file = open_regular_policy_file(path)?;
    validate_file_size(
        path,
        kind,
        limit,
        &file
            .metadata()
            .map_err(|source| PolicySourceValidationError::Inspect {
                path: path.to_path_buf(),
                source,
            })?,
    )
}

fn open_regular_policy_file(path: &Path) -> Result<File, PolicySourceValidationError> {
    reject_symlink(path)?;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| PolicySourceValidationError::Open {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|source| PolicySourceValidationError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.is_file() {
        Ok(file)
    } else {
        Err(PolicySourceValidationError::NotRegular {
            path: path.to_path_buf(),
        })
    }
}

fn read_file_to_string(
    path: &Path,
    kind: &'static str,
    limit: u64,
    file: File,
) -> Result<String, PolicySourceValidationError> {
    let mut reader = file.take(limit.saturating_add(1));
    let mut content = String::new();
    reader
        .read_to_string(&mut content)
        .map_err(|source| PolicySourceValidationError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if content.len() as u64 > limit {
        return Err(PolicySourceValidationError::TooLarge {
            path: path.to_path_buf(),
            size: content.len() as u64,
            limit,
            kind,
        });
    }
    Ok(content)
}

fn validate_file_size(
    path: &Path,
    kind: &'static str,
    limit: u64,
    metadata: &Metadata,
) -> Result<(), PolicySourceValidationError> {
    if metadata.len() > limit {
        return Err(PolicySourceValidationError::TooLarge {
            path: path.to_path_buf(),
            size: metadata.len(),
            limit,
            kind,
        });
    }
    Ok(())
}

fn symlink_safe_metadata(path: &Path) -> Result<Metadata, PolicySourceValidationError> {
    reject_symlink(path)?;
    fs::metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PolicySourceValidationError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            PolicySourceValidationError::Inspect {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn reject_symlink(path: &Path) -> Result<(), PolicySourceValidationError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PolicySourceValidationError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            PolicySourceValidationError::Inspect {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(PolicySourceValidationError::Symlink {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join(BUNDLE_MANIFEST_FILE)
}

fn main_path(root: &Path) -> PathBuf {
    root.join(BUNDLE_MAIN_FILE)
}

enum PolicySourceValidationError {
    NotFound {
        path: PathBuf,
    },
    Inspect {
        path: PathBuf,
        source: std::io::Error,
    },
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Symlink {
        path: PathBuf,
    },
    NotRegular {
        path: PathBuf,
    },
    UnsupportedPathKind {
        path: PathBuf,
    },
    TooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
        kind: &'static str,
    },
    ManifestToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    InvalidManifest {
        reason: String,
    },
    ManifestIdMismatch {
        expected: String,
        actual: String,
    },
}

impl PolicySourceValidationError {
    fn reason(&self) -> String {
        match self {
            Self::NotFound { path } => {
                format!("policy source path does not exist: {}", path.display())
            }
            Self::Inspect { path, source } => {
                format!(
                    "failed to inspect policy source {}: {source}",
                    path.display()
                )
            }
            Self::Open { path, source } => {
                format!("failed to open policy source {}: {source}", path.display())
            }
            Self::Read { path, source } => {
                format!("failed to read policy source {}: {source}", path.display())
            }
            Self::Symlink { path } => {
                format!(
                    "policy source path {} must not be a symlink",
                    path.display()
                )
            }
            Self::NotRegular { path } => {
                format!(
                    "policy source path {} is not a regular file",
                    path.display()
                )
            }
            Self::UnsupportedPathKind { path } => format!(
                "policy source path {} must be a legacy Lua file or bundle directory",
                path.display()
            ),
            Self::TooLarge {
                path,
                size,
                limit,
                kind,
            } => format!(
                "policy {kind} {} is {size} bytes, exceeding the {limit} byte limit",
                path.display()
            ),
            Self::ManifestToml { path, source } => {
                format!(
                    "failed to parse policy bundle manifest {}: {source}",
                    path.display()
                )
            }
            Self::InvalidManifest { reason } => format!("invalid policy bundle manifest: {reason}"),
            Self::ManifestIdMismatch { expected, actual } => format!(
                "policy bundle manifest id {actual} does not match configured policy id {expected}"
            ),
        }
    }

    fn into_configured_error(self, policy_path: &Path) -> ConfiguredPolicyError {
        match self {
            Self::Inspect { path, source }
            | Self::Open { path, source }
            | Self::Read { path, source } => ConfiguredPolicyError::ReadPolicy {
                path: path.display().to_string(),
                source,
            },
            error => ConfiguredPolicyError::InvalidPolicySource {
                path: policy_path.display().to_string(),
                reason: error.reason(),
            },
        }
    }
}

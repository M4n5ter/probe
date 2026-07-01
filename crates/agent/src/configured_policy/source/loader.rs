use std::{
    fs::{self, Metadata},
    path::{Path, PathBuf},
    time::Duration,
};

use policy::PolicyManifest;
use probe_config::{
    DEFAULT_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES, PolicyConfig, PolicySourceConfig,
    RemotePolicyBundleBodyLimitBytes, RemotePolicyBundleBodyLimitError,
};
use probe_core::RuntimeMode;
use probe_http::HttpConnectionOptions;
use serde::{Deserialize, Serialize};

use probe_io::{
    BoundedFileError, BoundedFileErrorKind, RootedBoundedFileError,
    check_bounded_regular_file_under_root as probe_io_check_bounded_regular_file_under_root,
    read_bounded_regular_file_to_string_under_root as probe_io_read_bounded_regular_file_to_string_under_root,
};

use crate::remote_source::{RemoteTextFetchConfig, RemoteTextFetchError, fetch_remote_text};

use super::super::ConfiguredPolicyError;
use super::bundle::{
    DeclaredModules, PolicyBundleManifest, PolicyBundleManifestError, RemotePolicyModuleError,
    RemotePolicyModuleSource, ValidPolicyBundleManifest,
};

pub const MAX_POLICY_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_POLICY_MANIFEST_BYTES: u64 = 64 * 1024;
const REMOTE_POLICY_BUNDLE_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const REMOTE_POLICY_BUNDLE_ACCEPT: &str = "application/toml, text/plain;q=0.9, */*;q=0.1";

const BUNDLE_MANIFEST_FILE: &str = "manifest.toml";
const BUNDLE_MAIN_FILE: &str = "main.lua";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySourceInspection {
    pub mode: RuntimeMode,
    pub source: PolicySourceSnapshot,
    pub manifest: Option<PolicyManifestMetadata>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyManifestMetadata {
    pub id: String,
    pub version: String,
    pub module_count: u64,
}

pub struct LoadedPolicySource {
    pub source: PolicySourceSnapshot,
    pub manifest: PolicyManifest,
    pub main: String,
    pub modules: Vec<policy::PolicyModule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySourceLoadContext {
    remote_http_connection: HttpConnectionOptions,
}

impl PolicySourceLoadContext {
    pub fn with_remote_http_connection(remote_http_connection: HttpConnectionOptions) -> Self {
        Self {
            remote_http_connection,
        }
    }

    pub fn remote_http_connection(self) -> HttpConnectionOptions {
        self.remote_http_connection
    }
}

impl Default for PolicySourceLoadContext {
    fn default() -> Self {
        Self {
            remote_http_connection: HttpConnectionOptions::new(REMOTE_POLICY_BUNDLE_FETCH_TIMEOUT),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PolicySourceSnapshot {
    LocalDirectory {
        path: PathBuf,
    },
    RemoteBundle {
        endpoint: String,
        max_body_bytes: u64,
    },
}

impl PolicySourceSnapshot {
    pub fn reference(&self) -> String {
        match self {
            Self::LocalDirectory { path } => path.display().to_string(),
            Self::RemoteBundle { endpoint, .. } => endpoint.clone(),
        }
    }
}

impl From<&PolicySourceConfig> for PolicySourceSnapshot {
    fn from(source: &PolicySourceConfig) -> Self {
        source_snapshot(source)
    }
}

pub async fn load_policy_source_with_context(
    policy: &PolicyConfig,
    context: PolicySourceLoadContext,
) -> Result<LoadedPolicySource, ConfiguredPolicyError> {
    read_policy_source(&policy.source, policy.id.as_str(), context)
        .await
        .map_err(|error| error.into_configured_error(policy))
}

pub fn inspect_policy_source(
    source: &PolicySourceSnapshot,
    expected_id: &str,
) -> PolicySourceInspection {
    match source {
        PolicySourceSnapshot::RemoteBundle { .. } => PolicySourceInspection {
            mode: RuntimeMode::Degraded,
            source: source.clone(),
            manifest: None,
            reason: Some(
                "remote policy bundle source is configured, but offline status does not fetch remote policy"
                    .to_string(),
            ),
        },
        PolicySourceSnapshot::LocalDirectory { path } => {
            match inspect_policy_bundle_directory(path, expected_id) {
                Ok(manifest) => PolicySourceInspection {
                    mode: RuntimeMode::Available,
                    source: PolicySourceSnapshot::LocalDirectory {
                        path: path.to_path_buf(),
                    },
                    manifest: Some(PolicyManifestMetadata {
                        id: manifest.id().to_string(),
                        version: manifest.version().to_string(),
                        module_count: manifest.module_count() as u64,
                    }),
                    reason: None,
                },
                Err(error) => PolicySourceInspection {
                    mode: RuntimeMode::Unavailable,
                    source: source.clone(),
                    manifest: None,
                    reason: Some(error.reason()),
                },
            }
        },
    }
}

fn ensure_policy_bundle_directory(path: &Path) -> Result<(), PolicySourceValidationError> {
    let metadata = symlink_safe_metadata(path)?;
    if !metadata.is_dir() {
        return Err(PolicySourceValidationError::UnsupportedPathKind {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn read_policy_bundle_directory(
    root: &Path,
    expected_id: &str,
) -> Result<LoadedPolicySource, PolicySourceValidationError> {
    ensure_policy_bundle_directory(root)?;
    let manifest = read_policy_manifest(root)
        .and_then(|manifest| validate_policy_manifest(manifest, expected_id))?;
    let modules = read_policy_modules(root, manifest.modules())?;
    let main = read_regular_policy_file_under_root(
        root,
        Path::new(BUNDLE_MAIN_FILE),
        MAX_POLICY_SOURCE_BYTES,
        "source",
    )?;

    Ok(LoadedPolicySource {
        source: PolicySourceSnapshot::LocalDirectory {
            path: root.to_path_buf(),
        },
        manifest: manifest.into_policy(),
        main,
        modules,
    })
}

fn inspect_policy_bundle_directory(
    root: &Path,
    expected_id: &str,
) -> Result<ValidPolicyBundleManifest, PolicySourceValidationError> {
    ensure_policy_bundle_directory(root)?;
    let manifest = read_policy_manifest(root)?;
    let manifest = validate_policy_manifest(manifest, expected_id)?;
    check_policy_modules(root, manifest.modules())?;
    check_regular_policy_file_under_root(
        root,
        Path::new(BUNDLE_MAIN_FILE),
        MAX_POLICY_SOURCE_BYTES,
        "source",
    )?;
    Ok(manifest)
}

async fn read_policy_source(
    source: &PolicySourceConfig,
    expected_id: &str,
    context: PolicySourceLoadContext,
) -> Result<LoadedPolicySource, PolicySourceValidationError> {
    match source {
        PolicySourceConfig::LocalDirectory { path } => {
            read_policy_bundle_directory(path, expected_id)
        }
        PolicySourceConfig::RemoteBundle {
            endpoint,
            max_body_bytes,
        } => read_remote_policy_bundle(endpoint, *max_body_bytes, expected_id, context).await,
    }
}

fn source_snapshot(source: &PolicySourceConfig) -> PolicySourceSnapshot {
    match source {
        PolicySourceConfig::LocalDirectory { path } => PolicySourceSnapshot::LocalDirectory {
            path: path.to_path_buf(),
        },
        PolicySourceConfig::RemoteBundle {
            endpoint,
            max_body_bytes,
        } => PolicySourceSnapshot::RemoteBundle {
            endpoint: endpoint.clone(),
            max_body_bytes: max_body_bytes.unwrap_or(DEFAULT_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES),
        },
    }
}

async fn read_remote_policy_bundle(
    endpoint: &str,
    max_body_bytes: Option<u64>,
    expected_id: &str,
    context: PolicySourceLoadContext,
) -> Result<LoadedPolicySource, PolicySourceValidationError> {
    let max_body_bytes = remote_body_limit(max_body_bytes)
        .map_err(|source| PolicySourceValidationError::RemoteBodyLimit {
            endpoint: endpoint.to_string(),
            source,
        })?
        .get();
    let content = fetch_remote_text(
        endpoint,
        RemoteTextFetchConfig {
            accept: REMOTE_POLICY_BUNDLE_ACCEPT,
            timeout: REMOTE_POLICY_BUNDLE_FETCH_TIMEOUT,
            max_body_bytes,
            connection: context.remote_http_connection,
        },
    )
    .await
    .map_err(|source| PolicySourceValidationError::RemoteFetch {
        endpoint: endpoint.to_string(),
        source,
    })?;
    let bundle = toml::from_str::<RemotePolicyBundleDocument>(&content).map_err(|source| {
        PolicySourceValidationError::RemoteBundleToml {
            endpoint: endpoint.to_string(),
            source,
        }
    })?;
    validate_remote_policy_source_size(endpoint, &bundle.source)?;
    let manifest = validate_policy_manifest(bundle.manifest, expected_id)?;
    let modules = manifest
        .modules()
        .resolve_remote_sources(
            bundle
                .modules
                .into_iter()
                .map(|module| RemotePolicyModuleSource {
                    name: module.name,
                    source: module.source,
                }),
            MAX_POLICY_SOURCE_BYTES,
        )
        .map_err(|source| remote_policy_module_error(endpoint, source))?;
    Ok(LoadedPolicySource {
        source: PolicySourceSnapshot::RemoteBundle {
            endpoint: endpoint.to_string(),
            max_body_bytes,
        },
        manifest: manifest.into_policy(),
        main: bundle.source,
        modules,
    })
}

fn validate_remote_policy_source_size(
    endpoint: &str,
    source: &str,
) -> Result<(), PolicySourceValidationError> {
    let size = source.len() as u64;
    if size > MAX_POLICY_SOURCE_BYTES {
        return Err(PolicySourceValidationError::RemoteSourceTooLarge {
            endpoint: endpoint.to_string(),
            size,
            limit: MAX_POLICY_SOURCE_BYTES,
        });
    }
    Ok(())
}

fn remote_body_limit(
    max_body_bytes: Option<u64>,
) -> Result<RemotePolicyBundleBodyLimitBytes, RemotePolicyBundleBodyLimitError> {
    RemotePolicyBundleBodyLimitBytes::from_config(max_body_bytes)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemotePolicyBundleDocument {
    manifest: PolicyBundleManifest,
    source: String,
    #[serde(default)]
    modules: Vec<RemotePolicyBundleModuleDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemotePolicyBundleModuleDocument {
    name: String,
    source: String,
}

fn read_policy_manifest(root: &Path) -> Result<PolicyBundleManifest, PolicySourceValidationError> {
    let content = read_regular_policy_file_under_root(
        root,
        Path::new(BUNDLE_MANIFEST_FILE),
        MAX_POLICY_MANIFEST_BYTES,
        "manifest",
    )?;

    toml::from_str::<PolicyBundleManifest>(&content).map_err(|source| {
        PolicySourceValidationError::ManifestToml {
            path: root.join(BUNDLE_MANIFEST_FILE),
            source,
        }
    })
}

fn validate_policy_manifest(
    manifest: PolicyBundleManifest,
    expected_id: &str,
) -> Result<ValidPolicyBundleManifest, PolicySourceValidationError> {
    manifest
        .validate(expected_id)
        .map_err(policy_bundle_manifest_error)
}

fn read_policy_modules(
    root: &Path,
    modules: &DeclaredModules,
) -> Result<Vec<policy::PolicyModule>, PolicySourceValidationError> {
    modules
        .iter()
        .map(|name| {
            let relative_path = name.relative_path();
            read_regular_policy_file_under_root(
                root,
                &relative_path,
                MAX_POLICY_SOURCE_BYTES,
                "module",
            )
            .map(|source| policy::PolicyModule {
                name: name.as_str().to_string(),
                source,
            })
        })
        .collect()
}

fn check_policy_modules(
    root: &Path,
    modules: &DeclaredModules,
) -> Result<(), PolicySourceValidationError> {
    for name in modules.iter() {
        check_regular_policy_file_under_root(
            root,
            &name.relative_path(),
            MAX_POLICY_SOURCE_BYTES,
            "module",
        )?;
    }
    Ok(())
}

fn policy_bundle_manifest_error(error: PolicyBundleManifestError) -> PolicySourceValidationError {
    match error {
        PolicyBundleManifestError::IdMismatch { expected, actual } => {
            PolicySourceValidationError::ManifestIdMismatch { expected, actual }
        }
        error => PolicySourceValidationError::InvalidManifest {
            reason: error.to_string(),
        },
    }
}

fn remote_policy_module_error(
    endpoint: &str,
    error: RemotePolicyModuleError,
) -> PolicySourceValidationError {
    match error {
        RemotePolicyModuleError::NotDeclared { module } => {
            PolicySourceValidationError::RemoteModuleNotDeclared {
                endpoint: endpoint.to_string(),
                module,
            }
        }
        RemotePolicyModuleError::Duplicate { module } => {
            PolicySourceValidationError::RemoteModuleDuplicate {
                endpoint: endpoint.to_string(),
                module,
            }
        }
        RemotePolicyModuleError::Missing { module } => {
            PolicySourceValidationError::RemoteModuleMissing {
                endpoint: endpoint.to_string(),
                module,
            }
        }
        RemotePolicyModuleError::TooLarge {
            module,
            size,
            limit,
        } => PolicySourceValidationError::RemoteModuleTooLarge {
            endpoint: endpoint.to_string(),
            module,
            size,
            limit,
        },
    }
}

fn read_regular_policy_file_under_root(
    root: &Path,
    relative: &Path,
    limit: u64,
    kind: &'static str,
) -> Result<String, PolicySourceValidationError> {
    probe_io_read_bounded_regular_file_to_string_under_root(root, relative, limit)
        .map_err(|error| rooted_policy_source_file_error(error, kind))
}

fn check_regular_policy_file_under_root(
    root: &Path,
    relative: &Path,
    limit: u64,
    kind: &'static str,
) -> Result<(), PolicySourceValidationError> {
    probe_io_check_bounded_regular_file_under_root(root, relative, limit)
        .map_err(|error| rooted_policy_source_file_error(error, kind))
}

fn rooted_policy_source_file_error(
    error: RootedBoundedFileError,
    kind: &'static str,
) -> PolicySourceValidationError {
    match error {
        RootedBoundedFileError::Bounded(error) => policy_source_file_error(error, kind),
        RootedBoundedFileError::OpenRoot { root, source, .. } => {
            PolicySourceValidationError::Inspect { path: root, source }
        }
        RootedBoundedFileError::RelativePathDisallowed { path }
        | RootedBoundedFileError::OutsideAllowedRoots { path } => {
            PolicySourceValidationError::Open {
                path,
                source: std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "policy source path is outside the policy bundle root",
                ),
            }
        }
    }
}

fn policy_source_file_error(
    error: BoundedFileError,
    kind: &'static str,
) -> PolicySourceValidationError {
    let mut parts = error.into_parts();
    match parts.kind {
        BoundedFileErrorKind::NotFound => {
            PolicySourceValidationError::NotFound { path: parts.path }
        }
        BoundedFileErrorKind::Inspect => {
            let source = parts.expect_source();
            PolicySourceValidationError::Inspect {
                path: parts.path,
                source,
            }
        }
        BoundedFileErrorKind::Open => {
            let source = parts.expect_source();
            PolicySourceValidationError::Open {
                path: parts.path,
                source,
            }
        }
        BoundedFileErrorKind::Read => {
            let source = parts.expect_source();
            PolicySourceValidationError::Read {
                path: parts.path,
                source,
            }
        }
        BoundedFileErrorKind::Symlink => PolicySourceValidationError::Symlink { path: parts.path },
        BoundedFileErrorKind::Directory | BoundedFileErrorKind::NotRegular => {
            PolicySourceValidationError::NotRegular { path: parts.path }
        }
        BoundedFileErrorKind::TooLarge => {
            let size_limit = parts.expect_size_limit();
            PolicySourceValidationError::TooLarge {
                path: parts.path,
                size: size_limit.size,
                limit: size_limit.limit,
                kind,
            }
        }
    }
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
    RemoteFetch {
        endpoint: String,
        source: RemoteTextFetchError,
    },
    RemoteBodyLimit {
        endpoint: String,
        source: RemotePolicyBundleBodyLimitError,
    },
    RemoteBundleToml {
        endpoint: String,
        source: toml::de::Error,
    },
    RemoteSourceTooLarge {
        endpoint: String,
        size: u64,
        limit: u64,
    },
    RemoteModuleNotDeclared {
        endpoint: String,
        module: String,
    },
    RemoteModuleDuplicate {
        endpoint: String,
        module: String,
    },
    RemoteModuleMissing {
        endpoint: String,
        module: String,
    },
    RemoteModuleTooLarge {
        endpoint: String,
        module: String,
        size: u64,
        limit: u64,
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
                "policy source path {} must be a policy bundle directory",
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
            Self::RemoteFetch { endpoint, source } => {
                format!("failed to fetch remote policy bundle {endpoint}: {source}")
            }
            Self::RemoteBodyLimit { endpoint, source } => {
                format!("invalid remote policy bundle body limit for {endpoint}: {source}")
            }
            Self::RemoteBundleToml { endpoint, source } => {
                format!("failed to parse remote policy bundle {endpoint}: {source}")
            }
            Self::RemoteSourceTooLarge {
                endpoint,
                size,
                limit,
            } => {
                format!(
                    "remote policy bundle source {endpoint} is {size} bytes, exceeding the {limit} byte limit"
                )
            }
            Self::RemoteModuleNotDeclared { endpoint, module } => format!(
                "remote policy bundle {endpoint} includes module {module}, but manifest does not declare it"
            ),
            Self::RemoteModuleDuplicate { endpoint, module } => {
                format!("remote policy bundle {endpoint} includes module {module} more than once")
            }
            Self::RemoteModuleMissing { endpoint, module } => format!(
                "remote policy bundle {endpoint} declares module {module}, but does not include its source"
            ),
            Self::RemoteModuleTooLarge {
                endpoint,
                module,
                size,
                limit,
            } => format!(
                "remote policy bundle module {module} from {endpoint} is {size} bytes, exceeding the {limit} byte limit"
            ),
            Self::InvalidManifest { reason } => format!("invalid policy bundle manifest: {reason}"),
            Self::ManifestIdMismatch { expected, actual } => format!(
                "policy bundle manifest id {actual} does not match configured policy id {expected}"
            ),
        }
    }

    fn into_configured_error(self, policy: &PolicyConfig) -> ConfiguredPolicyError {
        let source_ref = source_snapshot(&policy.source).reference();
        match self {
            Self::Inspect { path, source }
            | Self::Open { path, source }
            | Self::Read { path, source } => ConfiguredPolicyError::ReadPolicy {
                id: policy.id.clone(),
                source_ref: path.display().to_string(),
                source,
            },
            error => ConfiguredPolicyError::InvalidPolicySource {
                id: policy.id.clone(),
                source_ref,
                reason: error.reason(),
            },
        }
    }
}

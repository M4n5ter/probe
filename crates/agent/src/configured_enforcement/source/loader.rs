use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use http::StatusCode;
use probe_config::EnforcementPolicyManifest;
use probe_core::ResolvedSelector;
use probe_http::HttpConnectionOptions;
use runtime::{EnforcementPolicySourceKind, EnforcementPolicySourcePlan};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use probe_io::{BoundedFileError, BoundedFileErrorKind, read_bounded_regular_file_to_string};

use crate::remote_source::{RemoteTextFetchConfig, RemoteTextFetchError, fetch_remote_text};

pub const LOCAL_ENFORCEMENT_POLICY_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const REMOTE_ENFORCEMENT_POLICY_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const REMOTE_ENFORCEMENT_POLICY_ACCEPT: &str = "application/toml, text/plain;q=0.9, */*;q=0.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedEnforcementPolicySource {
    origin: LoadedEnforcementPolicySourceOrigin,
    pub manifest: EnforcementPolicyManifest,
    resolved_selector: Option<ResolvedSelector>,
}

impl LoadedEnforcementPolicySource {
    pub fn local(path: impl Into<PathBuf>, manifest: EnforcementPolicyManifest) -> Self {
        let resolved_selector = resolved_manifest_selector(&manifest);
        Self {
            origin: LoadedEnforcementPolicySourceOrigin::LocalPath(path.into()),
            manifest,
            resolved_selector,
        }
    }

    pub fn remote(
        endpoint: impl Into<String>,
        max_body_bytes: u64,
        manifest: EnforcementPolicyManifest,
    ) -> Self {
        let resolved_selector = resolved_manifest_selector(&manifest);
        Self {
            origin: LoadedEnforcementPolicySourceOrigin::RemoteEndpoint {
                endpoint: endpoint.into(),
                max_body_bytes,
            },
            manifest,
            resolved_selector,
        }
    }

    pub fn resolved_selector(&self) -> Option<&ResolvedSelector> {
        self.resolved_selector.as_ref()
    }

    pub fn snapshot(&self) -> LoadedEnforcementPolicySourceSnapshot {
        match &self.origin {
            LoadedEnforcementPolicySourceOrigin::LocalPath(path) => {
                LoadedEnforcementPolicySourceSnapshot::Local {
                    path: path.to_path_buf(),
                }
            }
            LoadedEnforcementPolicySourceOrigin::RemoteEndpoint {
                endpoint,
                max_body_bytes,
            } => LoadedEnforcementPolicySourceSnapshot::Remote {
                endpoint: endpoint.clone(),
                max_body_bytes: *max_body_bytes,
            },
        }
    }
}

fn resolved_manifest_selector(manifest: &EnforcementPolicyManifest) -> Option<ResolvedSelector> {
    manifest.selector.as_ref().map(|selector| {
        selector
            .resolve_refs_with_registry(&manifest.selectors)
            .expect("enforcement policy manifest selector should be validated before loading")
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LoadedEnforcementPolicySourceSnapshot {
    Local {
        path: PathBuf,
    },
    Remote {
        endpoint: String,
        max_body_bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LoadedEnforcementPolicySourceOrigin {
    LocalPath(PathBuf),
    RemoteEndpoint {
        endpoint: String,
        max_body_bytes: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementPolicySourceLoadContext {
    remote_http_connection: HttpConnectionOptions,
}

impl EnforcementPolicySourceLoadContext {
    pub fn with_remote_http_connection(remote_http_connection: HttpConnectionOptions) -> Self {
        Self {
            remote_http_connection,
        }
    }

    pub fn remote_http_connection(self) -> HttpConnectionOptions {
        self.remote_http_connection
    }
}

impl Default for EnforcementPolicySourceLoadContext {
    fn default() -> Self {
        Self {
            remote_http_connection: HttpConnectionOptions::new(
                REMOTE_ENFORCEMENT_POLICY_FETCH_TIMEOUT,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementPolicySourceInspection {
    NotConfigured,
    LocalMetadata {
        manifest: EnforcementPolicyManifest,
    },
    RemoteConfigured {
        endpoint: String,
        max_body_bytes: u64,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Error)]
pub enum EnforcementPolicySourceError {
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
    #[error("enforcement policy source directory path is a symlink: {path}")]
    DirectorySymlink { path: PathBuf },
    #[error("enforcement policy source directory is not a directory: {path}")]
    DirectoryNotDirectory { path: PathBuf },
    #[error("enforcement policy source is too large: {path} has {size} bytes, limit {limit}")]
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
    #[error("failed to build remote enforcement policy HTTP client: {reason}")]
    RemoteClient { reason: String },
    #[error("failed to fetch remote enforcement policy source {endpoint}: {reason}")]
    RemoteFetch { endpoint: String, reason: String },
    #[error("remote enforcement policy source {endpoint} timed out after {timeout_ms} ms")]
    RemoteTimeout { endpoint: String, timeout_ms: u128 },
    #[error("remote enforcement policy source {endpoint} returned HTTP status {status}")]
    RemoteStatus {
        endpoint: String,
        status: StatusCode,
    },
    #[error("failed to read remote enforcement policy source {endpoint}: {reason}")]
    RemoteRead { endpoint: String, reason: String },
    #[error(
        "remote enforcement policy source is too large: {endpoint} has at least {size} bytes, limit {limit}"
    )]
    RemoteTooLarge {
        endpoint: String,
        size: u64,
        limit: u64,
    },
    #[error("remote enforcement policy manifest {endpoint} is not UTF-8: {source}")]
    RemoteUtf8 {
        endpoint: String,
        source: std::string::FromUtf8Error,
    },
    #[error("failed to parse remote enforcement policy manifest {endpoint}: {source}")]
    RemoteManifestToml {
        endpoint: String,
        source: toml::de::Error,
    },
    #[error("invalid enforcement policy manifest: {reason}")]
    InvalidManifest { reason: String },
}

impl EnforcementPolicySourceError {
    fn from_remote_fetch(endpoint: &str, error: RemoteTextFetchError) -> Self {
        match error {
            RemoteTextFetchError::Client { reason } => Self::RemoteClient { reason },
            RemoteTextFetchError::Fetch { reason } => Self::RemoteFetch {
                endpoint: endpoint.to_string(),
                reason,
            },
            RemoteTextFetchError::Timeout { timeout_ms } => Self::RemoteTimeout {
                endpoint: endpoint.to_string(),
                timeout_ms,
            },
            RemoteTextFetchError::Status { status } => Self::RemoteStatus {
                endpoint: endpoint.to_string(),
                status,
            },
            RemoteTextFetchError::Read { reason } => Self::RemoteRead {
                endpoint: endpoint.to_string(),
                reason,
            },
            RemoteTextFetchError::TooLarge { size, limit } => Self::RemoteTooLarge {
                endpoint: endpoint.to_string(),
                size,
                limit,
            },
            RemoteTextFetchError::Utf8 { source } => Self::RemoteUtf8 {
                endpoint: endpoint.to_string(),
                source,
            },
        }
    }
}

#[cfg(test)]
async fn load_enforcement_policy_source(
    source: &EnforcementPolicySourcePlan,
) -> Result<Option<LoadedEnforcementPolicySource>, EnforcementPolicySourceError> {
    load_enforcement_policy_source_with_context(
        source,
        EnforcementPolicySourceLoadContext::default(),
    )
    .await
}

pub async fn load_enforcement_policy_source_with_context(
    source: &EnforcementPolicySourcePlan,
    context: EnforcementPolicySourceLoadContext,
) -> Result<Option<LoadedEnforcementPolicySource>, EnforcementPolicySourceError> {
    match source {
        EnforcementPolicySourcePlan::None => Ok(None),
        EnforcementPolicySourcePlan::LocalManifest { source_kind, path } => {
            let manifest = read_enforcement_policy_manifest_source(*source_kind, path)?;
            Ok(Some(LoadedEnforcementPolicySource::local(
                path.clone(),
                manifest,
            )))
        }
        EnforcementPolicySourcePlan::Remote {
            endpoint,
            max_body_bytes,
        } => {
            let max_body_bytes = max_body_bytes.get();
            let manifest = fetch_remote_enforcement_policy_manifest(
                endpoint,
                max_body_bytes,
                context.remote_http_connection,
            )
            .await?;
            Ok(Some(LoadedEnforcementPolicySource::remote(
                endpoint.clone(),
                max_body_bytes,
                manifest,
            )))
        }
    }
}

pub fn inspect_enforcement_policy_source(
    source: &EnforcementPolicySourcePlan,
) -> EnforcementPolicySourceInspection {
    match source {
        EnforcementPolicySourcePlan::None => EnforcementPolicySourceInspection::NotConfigured,
        EnforcementPolicySourcePlan::LocalManifest { source_kind, path } => {
            match read_enforcement_policy_manifest_source(*source_kind, path) {
                Ok(manifest) => EnforcementPolicySourceInspection::LocalMetadata { manifest },
                Err(error) => EnforcementPolicySourceInspection::Unavailable {
                    reason: error.to_string(),
                },
            }
        }
        EnforcementPolicySourcePlan::Remote {
            endpoint,
            max_body_bytes,
        } => EnforcementPolicySourceInspection::RemoteConfigured {
            endpoint: endpoint.clone(),
            max_body_bytes: max_body_bytes.get(),
        },
    }
}

fn read_enforcement_policy_manifest_source(
    source_kind: EnforcementPolicySourceKind,
    path: &Path,
) -> Result<EnforcementPolicyManifest, EnforcementPolicySourceError> {
    validate_local_manifest_source_path(source_kind, path)?;
    read_enforcement_policy_manifest(path)
}

fn validate_local_manifest_source_path(
    source_kind: EnforcementPolicySourceKind,
    path: &Path,
) -> Result<(), EnforcementPolicySourceError> {
    if source_kind == EnforcementPolicySourceKind::Directory {
        validate_manifest_directory(path)?;
    }
    Ok(())
}

fn validate_manifest_directory(path: &Path) -> Result<(), EnforcementPolicySourceError> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(directory).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            EnforcementPolicySourceError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            EnforcementPolicySourceError::Inspect {
                path: directory.to_path_buf(),
                source,
            }
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(EnforcementPolicySourceError::DirectorySymlink {
            path: directory.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(EnforcementPolicySourceError::DirectoryNotDirectory {
            path: directory.to_path_buf(),
        });
    }
    Ok(())
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

async fn fetch_remote_enforcement_policy_manifest(
    endpoint: &str,
    max_body_bytes: u64,
    connection: HttpConnectionOptions,
) -> Result<EnforcementPolicyManifest, EnforcementPolicySourceError> {
    fetch_remote_enforcement_policy_manifest_with_timeout(
        endpoint,
        REMOTE_ENFORCEMENT_POLICY_FETCH_TIMEOUT,
        max_body_bytes,
        connection,
    )
    .await
}

async fn fetch_remote_enforcement_policy_manifest_with_timeout(
    endpoint: &str,
    timeout: Duration,
    max_body_bytes: u64,
    connection: HttpConnectionOptions,
) -> Result<EnforcementPolicyManifest, EnforcementPolicySourceError> {
    let content = fetch_remote_text(
        endpoint,
        RemoteTextFetchConfig {
            accept: REMOTE_ENFORCEMENT_POLICY_ACCEPT,
            timeout,
            max_body_bytes,
            connection,
        },
    )
    .await
    .map_err(|error| EnforcementPolicySourceError::from_remote_fetch(endpoint, error))?;
    toml::from_str::<EnforcementPolicyManifest>(&content)
        .map_err(|source| EnforcementPolicySourceError::RemoteManifestToml {
            endpoint: endpoint.to_string(),
            source,
        })
        .and_then(validate_enforcement_policy_manifest)
}

pub(crate) fn validate_enforcement_policy_manifest(
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
    for (name, selector) in manifest.selectors.iter() {
        if name.trim().is_empty() {
            return Err(EnforcementPolicySourceError::InvalidManifest {
                reason: "enforcement policy selector name cannot be empty".to_string(),
            });
        }
        selector
            .resolve_refs_with_registry(&manifest.selectors)
            .map_err(|error| EnforcementPolicySourceError::InvalidManifest {
                reason: format!("invalid enforcement policy selector {name}: {error}"),
            })?;
    }
    if let Some(selector) = &manifest.selector {
        selector
            .resolve_refs_with_registry(&manifest.selectors)
            .map_err(|error| EnforcementPolicySourceError::InvalidManifest {
                reason: format!("invalid enforcement policy selector: {error}"),
            })?;
    }
    Ok(manifest)
}

fn read_regular_policy_file(path: &Path) -> Result<String, EnforcementPolicySourceError> {
    read_bounded_regular_file_to_string(path, LOCAL_ENFORCEMENT_POLICY_SOURCE_BYTES)
        .map_err(enforcement_policy_file_error)
}

fn enforcement_policy_file_error(error: BoundedFileError) -> EnforcementPolicySourceError {
    let mut parts = error.into_parts();
    match parts.kind {
        BoundedFileErrorKind::NotFound => {
            EnforcementPolicySourceError::NotFound { path: parts.path }
        }
        BoundedFileErrorKind::Inspect => {
            let source = parts.expect_source();
            EnforcementPolicySourceError::Inspect {
                path: parts.path,
                source,
            }
        }
        BoundedFileErrorKind::Open => {
            let source = parts.expect_source();
            EnforcementPolicySourceError::Open {
                path: parts.path,
                source,
            }
        }
        BoundedFileErrorKind::Read => {
            let source = parts.expect_source();
            EnforcementPolicySourceError::Read {
                path: parts.path,
                source,
            }
        }
        BoundedFileErrorKind::Symlink => EnforcementPolicySourceError::Symlink { path: parts.path },
        BoundedFileErrorKind::Directory | BoundedFileErrorKind::NotRegular => {
            EnforcementPolicySourceError::NotRegular { path: parts.path }
        }
        BoundedFileErrorKind::TooLarge => {
            let size_limit = parts.expect_size_limit();
            EnforcementPolicySourceError::TooLarge {
                path: parts.path,
                size: size_limit.size,
                limit: size_limit.limit,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use probe_config::EnforcementPolicyManifest;
    use probe_core::{Action, ProtectiveActionProfile};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    const TEST_REMOTE_BODY_LIMIT_BYTES: u64 = 4096;

    #[tokio::test]
    async fn directory_source_rejects_symlink_manifest_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let real_dir = temp.path().join("real.d");
        let symlink_dir = temp.path().join("enforcement.d");
        std::fs::create_dir_all(&real_dir)?;
        write_enforcement_manifest(&real_dir.join("manifest.toml"))?;
        symlink(&real_dir, &symlink_dir)?;

        let error = load_enforcement_policy_source(&EnforcementPolicySourcePlan::LocalManifest {
            source_kind: EnforcementPolicySourceKind::Directory,
            path: symlink_dir.join("manifest.toml"),
        })
        .await
        .expect_err("directory source must reject symlink manifest directory");

        assert!(matches!(
            error,
            EnforcementPolicySourceError::DirectorySymlink { path } if path == symlink_dir
        ));
        Ok(())
    }

    #[tokio::test]
    async fn remote_source_fetches_and_validates_manifest() -> Result<(), Box<dyn std::error::Error>>
    {
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selectors: Default::default(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        let body = toml::to_string(&manifest)?;
        let (_server, endpoint) = remote_enforcement_source(200, body).await;

        let loaded = load_enforcement_policy_source(&remote_plan(endpoint.clone()))
            .await?
            .expect("remote source should load a manifest");

        assert_eq!(
            loaded.snapshot(),
            LoadedEnforcementPolicySourceSnapshot::Remote {
                endpoint: endpoint.clone(),
                max_body_bytes: TEST_REMOTE_BODY_LIMIT_BYTES,
            }
        );
        assert_eq!(loaded.manifest.id, "managed-apps");
        assert_eq!(
            loaded.manifest.protective_actions.actions(),
            &[Action::Deny]
        );
        Ok(())
    }

    #[tokio::test]
    async fn remote_source_timeout_covers_body_read() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selectors: Default::default(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        let body = toml::to_string(&manifest)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/enforcement", listener.local_addr()?);

        let server = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await;
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(headers.as_bytes()).await;
            let _ = stream.flush().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = stream.write_all(body.as_bytes()).await;
        });

        let error = fetch_remote_enforcement_policy_manifest_with_timeout(
            &endpoint,
            Duration::from_millis(30),
            TEST_REMOTE_BODY_LIMIT_BYTES,
            HttpConnectionOptions::new(Duration::from_millis(30)),
        )
        .await
        .expect_err("the timeout must cover delayed response bodies");
        server.abort();

        assert!(matches!(
            error,
            EnforcementPolicySourceError::RemoteTimeout { endpoint: actual, timeout_ms: 30 }
                if actual == endpoint
        ));
        Ok(())
    }

    #[tokio::test]
    async fn remote_source_rejects_error_status() -> Result<(), Box<dyn std::error::Error>> {
        let (_server, endpoint) = remote_enforcement_source(503, "").await;

        let error = load_enforcement_policy_source(&remote_plan(endpoint.clone()))
            .await
            .expect_err("remote status errors must reject the source");

        assert!(matches!(
            error,
            EnforcementPolicySourceError::RemoteStatus { endpoint: actual, status }
                if actual == endpoint && status.as_u16() == 503
        ));
        Ok(())
    }

    #[tokio::test]
    async fn remote_source_rejects_oversized_manifest() -> Result<(), Box<dyn std::error::Error>> {
        const BODY_LIMIT: u64 = 64;
        let body = "x".repeat(BODY_LIMIT as usize + 1);
        let (_server, endpoint) = remote_enforcement_source(200, body).await;

        let error = load_enforcement_policy_source(&EnforcementPolicySourcePlan::Remote {
            endpoint: endpoint.clone(),
            max_body_bytes: test_body_limit(BODY_LIMIT),
        })
        .await
        .expect_err("oversized remote manifests must be rejected");

        assert!(matches!(
            error,
            EnforcementPolicySourceError::RemoteTooLarge {
                endpoint: actual,
                size: 65,
                limit: BODY_LIMIT,
            } if actual == endpoint
        ));
        Ok(())
    }

    #[test]
    fn remote_source_inspection_does_not_fetch() {
        let endpoint = "https://control.example/enforcement".to_string();

        let inspection = inspect_enforcement_policy_source(&EnforcementPolicySourcePlan::Remote {
            endpoint: endpoint.clone(),
            max_body_bytes: test_body_limit(TEST_REMOTE_BODY_LIMIT_BYTES),
        });

        assert_eq!(
            inspection,
            EnforcementPolicySourceInspection::RemoteConfigured {
                endpoint,
                max_body_bytes: TEST_REMOTE_BODY_LIMIT_BYTES,
            }
        );
    }

    async fn remote_enforcement_source(
        status: u16,
        body: impl Into<String>,
    ) -> (MockServer, String) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/enforcement"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body.into()))
            .expect(1)
            .mount(&server)
            .await;
        let endpoint = format!("{}/enforcement", server.uri());
        (server, endpoint)
    }

    fn remote_plan(endpoint: String) -> EnforcementPolicySourcePlan {
        EnforcementPolicySourcePlan::Remote {
            endpoint,
            max_body_bytes: test_body_limit(TEST_REMOTE_BODY_LIMIT_BYTES),
        }
    }

    fn test_body_limit(limit: u64) -> runtime::RemoteEnforcementPolicyBodyLimitBytes {
        runtime::RemoteEnforcementPolicyBodyLimitBytes::from_config(Some(limit))
            .expect("test remote body limit should be valid")
    }

    fn write_enforcement_manifest(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selectors: Default::default(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        std::fs::write(path, toml::to_string(&manifest)?)?;
        Ok(())
    }
}

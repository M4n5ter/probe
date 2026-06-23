use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use http::{Method, Request, StatusCode, header::ACCEPT};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use probe_config::EnforcementPolicyManifest;
use runtime::EnforcementPolicySourcePlan;
use rustls::pki_types::CertificateDer;
use thiserror::Error;

use probe_io::{BoundedFileError, BoundedFileErrorKind, read_bounded_regular_file_to_string};

pub const MAX_ENFORCEMENT_POLICY_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const REMOTE_ENFORCEMENT_POLICY_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const REMOTE_ENFORCEMENT_POLICY_ACCEPT: &str = "application/toml, text/plain;q=0.9, */*;q=0.1";
type RemotePolicyHttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedEnforcementPolicySource {
    origin: LoadedEnforcementPolicySourceOrigin,
    pub manifest: EnforcementPolicyManifest,
}

impl LoadedEnforcementPolicySource {
    pub fn local(path: impl Into<PathBuf>, manifest: EnforcementPolicyManifest) -> Self {
        Self {
            origin: LoadedEnforcementPolicySourceOrigin::LocalPath(path.into()),
            manifest,
        }
    }

    pub fn remote(endpoint: impl Into<String>, manifest: EnforcementPolicyManifest) -> Self {
        Self {
            origin: LoadedEnforcementPolicySourceOrigin::RemoteEndpoint(endpoint.into()),
            manifest,
        }
    }

    pub fn origin(&self) -> LoadedEnforcementPolicySourceOriginRef<'_> {
        match &self.origin {
            LoadedEnforcementPolicySourceOrigin::LocalPath(path) => {
                LoadedEnforcementPolicySourceOriginRef::LocalPath(path)
            }
            LoadedEnforcementPolicySourceOrigin::RemoteEndpoint(endpoint) => {
                LoadedEnforcementPolicySourceOriginRef::RemoteEndpoint(endpoint)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadedEnforcementPolicySourceOriginRef<'a> {
    LocalPath(&'a Path),
    RemoteEndpoint(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LoadedEnforcementPolicySourceOrigin {
    LocalPath(PathBuf),
    RemoteEndpoint(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementPolicySourceInspection {
    NotConfigured,
    LocalMetadata { manifest: EnforcementPolicyManifest },
    RemoteConfigured { endpoint: String },
    Unavailable { reason: String },
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

pub async fn load_enforcement_policy_source(
    source: &EnforcementPolicySourcePlan,
) -> Result<Option<LoadedEnforcementPolicySource>, EnforcementPolicySourceError> {
    match source {
        EnforcementPolicySourcePlan::None => Ok(None),
        EnforcementPolicySourcePlan::LocalManifest { path, .. } => {
            let manifest = read_enforcement_policy_manifest(path)?;
            Ok(Some(LoadedEnforcementPolicySource::local(
                path.clone(),
                manifest,
            )))
        }
        EnforcementPolicySourcePlan::Remote { endpoint } => {
            let manifest = fetch_remote_enforcement_policy_manifest(endpoint).await?;
            Ok(Some(LoadedEnforcementPolicySource::remote(
                endpoint.clone(),
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
        EnforcementPolicySourcePlan::LocalManifest { path, .. } => {
            match read_enforcement_policy_manifest(path) {
                Ok(manifest) => EnforcementPolicySourceInspection::LocalMetadata { manifest },
                Err(error) => EnforcementPolicySourceInspection::Unavailable {
                    reason: error.to_string(),
                },
            }
        }
        EnforcementPolicySourcePlan::Remote { endpoint } => {
            EnforcementPolicySourceInspection::RemoteConfigured {
                endpoint: endpoint.clone(),
            }
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

async fn fetch_remote_enforcement_policy_manifest(
    endpoint: &str,
) -> Result<EnforcementPolicyManifest, EnforcementPolicySourceError> {
    fetch_remote_enforcement_policy_manifest_with_timeout(
        endpoint,
        REMOTE_ENFORCEMENT_POLICY_FETCH_TIMEOUT,
    )
    .await
}

async fn fetch_remote_enforcement_policy_manifest_with_timeout(
    endpoint: &str,
    timeout: Duration,
) -> Result<EnforcementPolicyManifest, EnforcementPolicySourceError> {
    let client = remote_policy_http_client()?;
    let request = Request::builder()
        .method(Method::GET)
        .uri(endpoint)
        .header(ACCEPT, REMOTE_ENFORCEMENT_POLICY_ACCEPT)
        .body(Empty::<Bytes>::new())
        .map_err(|source| EnforcementPolicySourceError::RemoteFetch {
            endpoint: endpoint.to_string(),
            reason: source.to_string(),
        })?;

    let content = tokio::time::timeout(
        timeout,
        fetch_remote_enforcement_policy_content(endpoint, client, request),
    )
    .await
    .map_err(|_| EnforcementPolicySourceError::RemoteTimeout {
        endpoint: endpoint.to_string(),
        timeout_ms: timeout.as_millis(),
    })??;
    toml::from_str::<EnforcementPolicyManifest>(&content)
        .map_err(|source| EnforcementPolicySourceError::RemoteManifestToml {
            endpoint: endpoint.to_string(),
            source,
        })
        .and_then(validate_enforcement_policy_manifest)
}

async fn fetch_remote_enforcement_policy_content(
    endpoint: &str,
    client: RemotePolicyHttpClient,
    request: Request<Empty<Bytes>>,
) -> Result<String, EnforcementPolicySourceError> {
    let response = client.request(request).await.map_err(|source| {
        EnforcementPolicySourceError::RemoteFetch {
            endpoint: endpoint.to_string(),
            reason: source.to_string(),
        }
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(EnforcementPolicySourceError::RemoteStatus {
            endpoint: endpoint.to_string(),
            status,
        });
    }

    let mut body = Vec::new();
    let mut incoming = response.into_body();
    while let Some(frame) = incoming.frame().await.transpose().map_err(|source| {
        EnforcementPolicySourceError::RemoteRead {
            endpoint: endpoint.to_string(),
            reason: source.to_string(),
        }
    })? {
        if let Ok(chunk) = frame.into_data() {
            let new_size = body.len().saturating_add(chunk.len()) as u64;
            if new_size > MAX_ENFORCEMENT_POLICY_SOURCE_BYTES {
                return Err(EnforcementPolicySourceError::RemoteTooLarge {
                    endpoint: endpoint.to_string(),
                    size: new_size,
                    limit: MAX_ENFORCEMENT_POLICY_SOURCE_BYTES,
                });
            }
            body.extend_from_slice(&chunk);
        }
    }
    let content =
        String::from_utf8(body).map_err(|source| EnforcementPolicySourceError::RemoteUtf8 {
            endpoint: endpoint.to_string(),
            source,
        })?;
    Ok(content)
}

fn remote_policy_http_client() -> Result<RemotePolicyHttpClient, EnforcementPolicySourceError> {
    let tls = remote_policy_tls_config()?;
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

fn remote_policy_tls_config() -> Result<rustls::ClientConfig, EnforcementPolicySourceError> {
    remote_policy_tls_config_with_native_roots(rustls_native_certs::load_native_certs().certs)
}

fn remote_policy_tls_config_with_native_roots(
    native_roots: Vec<CertificateDer<'static>>,
) -> Result<rustls::ClientConfig, EnforcementPolicySourceError> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in native_roots {
        roots
            .add(certificate)
            .map_err(|source| EnforcementPolicySourceError::RemoteClient {
                reason: source.to_string(),
            })?;
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
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
    read_bounded_regular_file_to_string(path, MAX_ENFORCEMENT_POLICY_SOURCE_BYTES)
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

    #[tokio::test]
    async fn remote_source_fetches_and_validates_manifest() -> Result<(), Box<dyn std::error::Error>>
    {
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        let body = toml::to_string(&manifest)?;
        let (_server, endpoint) = remote_enforcement_source(200, body).await;

        let loaded = load_enforcement_policy_source(&EnforcementPolicySourcePlan::Remote {
            endpoint: endpoint.clone(),
        })
        .await?
        .expect("remote source should load a manifest");

        assert_eq!(
            loaded.origin(),
            LoadedEnforcementPolicySourceOriginRef::RemoteEndpoint(endpoint.as_str())
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

        let error = load_enforcement_policy_source(&EnforcementPolicySourcePlan::Remote {
            endpoint: endpoint.clone(),
        })
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
        let body = "x".repeat(MAX_ENFORCEMENT_POLICY_SOURCE_BYTES as usize + 1);
        let (_server, endpoint) = remote_enforcement_source(200, body).await;

        let error = load_enforcement_policy_source(&EnforcementPolicySourcePlan::Remote {
            endpoint: endpoint.clone(),
        })
        .await
        .expect_err("oversized remote manifests must be rejected");

        assert!(matches!(
            error,
            EnforcementPolicySourceError::RemoteTooLarge { endpoint: actual, .. }
                if actual == endpoint
        ));
        Ok(())
    }

    #[test]
    fn remote_source_inspection_does_not_fetch() {
        let endpoint = "https://control.example/enforcement".to_string();

        let inspection = inspect_enforcement_policy_source(&EnforcementPolicySourcePlan::Remote {
            endpoint: endpoint.clone(),
        });

        assert_eq!(
            inspection,
            EnforcementPolicySourceInspection::RemoteConfigured { endpoint }
        );
    }

    #[test]
    fn remote_policy_tls_config_allows_empty_native_roots() {
        let result = remote_policy_tls_config_with_native_roots(Vec::new());

        assert!(result.is_ok());
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
}

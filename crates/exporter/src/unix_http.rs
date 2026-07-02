use std::{
    fs,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    str::FromStr,
};

use async_trait::async_trait;
use http::uri::PathAndQuery;
use probe_http::UnixHttpConnector;
use proto::BatchEnvelope;

use crate::{
    BatchExporter, CompressionCodec, ExportAck, ExportError,
    webhook::{HyperWebhookTransport, WebhookExporter},
};

const UNIX_HTTP_AUTHORITY: &str = "probe-unix.local";

#[derive(Debug, Clone)]
pub struct UnixHttpExporter {
    socket_path: PathBuf,
    inner: WebhookExporter,
}

impl UnixHttpExporter {
    pub fn with_headers(
        socket_path: impl Into<PathBuf>,
        endpoint: impl AsRef<str>,
        codec: CompressionCodec,
        headers: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ExportError> {
        let socket_path = socket_path.into();
        validate_socket_config_path(&socket_path)?;
        let endpoint = unix_http_request_endpoint(endpoint.as_ref())?;
        let transport =
            HyperWebhookTransport::from_connector(UnixHttpConnector::new(socket_path.clone()));
        let inner = WebhookExporter::with_transport(endpoint, codec, headers, transport)?;
        Ok(Self { socket_path, inner })
    }

    pub fn preflight_socket_path(path: impl AsRef<Path>) -> Result<(), ExportError> {
        preflight_socket_path(path.as_ref())
    }
}

#[async_trait]
impl BatchExporter for UnixHttpExporter {
    async fn send_batch(&self, batch: &BatchEnvelope) -> Result<ExportAck, ExportError> {
        preflight_socket_path(&self.socket_path)?;
        self.inner.send_batch(batch).await.map_err(unix_http_error)
    }
}

fn unix_http_error(error: ExportError) -> ExportError {
    match error {
        ExportError::HttpTransport { reason } => ExportError::UnixHttpTransport { reason },
        error => error,
    }
}

fn unix_http_request_endpoint(endpoint: &str) -> Result<String, ExportError> {
    let endpoint = parse_endpoint(endpoint)?;
    Ok(format!("http://{UNIX_HTTP_AUTHORITY}{endpoint}"))
}

fn parse_endpoint(endpoint: &str) -> Result<PathAndQuery, ExportError> {
    let invalid = |reason: &str| ExportError::InvalidUnixHttpEndpoint {
        endpoint: endpoint.to_string(),
        reason: reason.to_string(),
    };
    if endpoint.trim().is_empty() {
        return Err(invalid("endpoint cannot be empty"));
    }
    if !endpoint.starts_with('/') {
        return Err(invalid(
            "endpoint must be an absolute path with optional query",
        ));
    }
    if endpoint.starts_with("//") {
        return Err(invalid("endpoint must not start with //"));
    }
    if endpoint.contains('#') {
        return Err(invalid("endpoint must not contain a fragment"));
    }
    if endpoint.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        return Err(invalid(
            "endpoint must not contain control characters or spaces",
        ));
    }
    PathAndQuery::from_str(endpoint).map_err(|source| invalid(&source.to_string()))
}

fn validate_socket_config_path(path: &Path) -> Result<(), ExportError> {
    if path.as_os_str().is_empty() {
        return Err(ExportError::UnixHttpSocketPathEmpty);
    }
    if !path.is_absolute() {
        return Err(ExportError::UnixHttpSocketPathRelative {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn preflight_socket_path(path: &Path) -> Result<(), ExportError> {
    validate_socket_config_path(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| ExportError::UnixHttpSocketUnavailable {
            path: path.to_path_buf(),
            source,
        })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(ExportError::UnixHttpSocketSymlink {
            path: path.to_path_buf(),
        });
    }
    if !file_type.is_socket() {
        return Err(ExportError::UnixHttpSocketNotSocket {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::{fs::symlink, net::UnixListener};

    use super::*;

    #[test]
    fn unix_http_exporter_rejects_invalid_endpoint() {
        for endpoint in [
            "",
            "relative",
            "//collector",
            "/bad fragment#part",
            "/bad path",
        ] {
            let result = UnixHttpExporter::with_headers(
                "/tmp/traffic-probe-export.sock",
                endpoint,
                CompressionCodec::None,
                [],
            );

            assert!(
                matches!(result, Err(ExportError::InvalidUnixHttpEndpoint { .. })),
                "{endpoint:?} should be rejected"
            );
        }
    }

    #[test]
    fn unix_http_exporter_rejects_invalid_socket_path() {
        let empty = UnixHttpExporter::with_headers("", "/batches", CompressionCodec::None, []);
        assert!(matches!(empty, Err(ExportError::UnixHttpSocketPathEmpty)));

        let relative = UnixHttpExporter::with_headers(
            "collector.sock",
            "/batches",
            CompressionCodec::None,
            [],
        );
        assert!(matches!(
            relative,
            Err(ExportError::UnixHttpSocketPathRelative { .. })
        ));
    }

    #[test]
    fn unix_http_exporter_maps_http_transport_errors() {
        let mapped = unix_http_error(ExportError::HttpTransport {
            reason: "connection refused".to_string(),
        });

        assert!(matches!(
            mapped,
            ExportError::UnixHttpTransport { reason } if reason == "connection refused"
        ));
    }

    #[test]
    fn unix_http_endpoint_parser_accepts_path_and_query() {
        let endpoint = parse_endpoint("/probe/batches?tenant=local")
            .expect("path and query endpoint should parse");

        assert_eq!(endpoint.as_str(), "/probe/batches?tenant=local");
    }

    #[tokio::test]
    async fn unix_http_exporter_rejects_symlink_socket_on_send()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("collector.sock");
        let link_path = temp.path().join("collector-link.sock");
        let _listener = UnixListener::bind(&socket_path)?;
        symlink(&socket_path, &link_path)?;
        let exporter =
            UnixHttpExporter::with_headers(&link_path, "/batches", CompressionCodec::None, [])?;

        let error = exporter
            .send_batch(&BatchEnvelope {
                batch_id: "batch-1".to_string(),
                agent_id: "agent-1".to_string(),
                codec: "none".to_string(),
                events: Vec::new(),
            })
            .await
            .expect_err("symlink socket path must be rejected before send");

        assert!(matches!(error, ExportError::UnixHttpSocketSymlink { .. }));
        Ok(())
    }
}

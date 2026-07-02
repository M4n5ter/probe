use std::{fmt, io::Cursor, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use http::{
    Method, Request,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Response,
    body::{Body, Incoming},
};
use hyper_util::{
    client::legacy::{Client, connect::Connection},
    rt::TokioExecutor,
};
use probe_core::{
    RESERVED_WEBHOOK_HEADERS, WEBHOOK_CODEC_HEADER, WEBHOOK_CONTENT_TYPE_HEADER,
    WEBHOOK_CONTENT_TYPE_PROTOBUF, WEBHOOK_IDEMPOTENCY_KEY_HEADER,
};
use probe_http::{
    HttpConnectionOptions, ProbeHttpsConnector, https_connector, root_cert_store_with_native_roots,
};
use proto::BatchEnvelope;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tower_service::Service;

use crate::{BatchExporter, CompressionCodec, ExportAck, ExportError, WebhookAck};

const MAX_WEBHOOK_ACK_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct WebhookExporter {
    transport: Arc<dyn WebhookTransport>,
    endpoint: String,
    codec: CompressionCodec,
    headers: HeaderMap,
}

impl WebhookExporter {
    pub fn with_headers(
        endpoint: impl Into<String>,
        codec: CompressionCodec,
        headers: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ExportError> {
        Self::with_tls_config(endpoint, codec, headers, WebhookTlsConfig::default())
    }

    pub fn with_tls_config(
        endpoint: impl Into<String>,
        codec: CompressionCodec,
        headers: impl IntoIterator<Item = (String, String)>,
        tls: WebhookTlsConfig,
    ) -> Result<Self, ExportError> {
        let transport = HyperWebhookTransport::with_tls_config(tls)?;
        Self::with_transport(endpoint, codec, headers, transport)
    }

    pub fn with_connection_options(
        endpoint: impl Into<String>,
        codec: CompressionCodec,
        headers: impl IntoIterator<Item = (String, String)>,
        tls: WebhookTlsConfig,
        connection: WebhookConnectionOptions,
    ) -> Result<Self, ExportError> {
        let transport = HyperWebhookTransport::with_connection_options(tls, connection)?;
        Self::with_transport(endpoint, codec, headers, transport)
    }

    pub(crate) fn with_transport(
        endpoint: impl Into<String>,
        codec: CompressionCodec,
        headers: impl IntoIterator<Item = (String, String)>,
        transport: impl WebhookTransport + 'static,
    ) -> Result<Self, ExportError> {
        Ok(Self {
            transport: Arc::new(transport),
            endpoint: endpoint.into(),
            codec,
            headers: parse_headers(headers)?,
        })
    }
}

pub type WebhookConnectionOptions = HttpConnectionOptions;

#[async_trait]
pub(crate) trait WebhookTransport: fmt::Debug + Send + Sync {
    async fn send(&self, request: WebhookRequest) -> Result<WebhookResponse, ExportError>;
}

#[derive(Debug, Clone)]
pub(crate) struct WebhookRequest {
    endpoint: String,
    codec: CompressionCodec,
    batch_id: String,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebhookResponse {
    success: bool,
    failure_reason: String,
    body: String,
}

#[derive(Clone)]
pub(crate) struct HyperWebhookTransport<C = ProbeHttpsConnector> {
    client: Client<C, Full<Bytes>>,
}

impl<C> fmt::Debug for HyperWebhookTransport<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HyperWebhookTransport")
            .finish_non_exhaustive()
    }
}

impl HyperWebhookTransport {
    fn with_tls_config(tls: WebhookTlsConfig) -> Result<Self, ExportError> {
        Self::with_connection_options(tls, WebhookConnectionOptions::default())
    }
}

impl<C> HyperWebhookTransport<C>
where
    C: Service<http::Uri> + Clone + Send + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Connection + Unpin + Send + 'static,
    C::Future: Send + Unpin + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub(crate) fn from_connector(connector: C) -> Self {
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self { client }
    }
}

impl HyperWebhookTransport<ProbeHttpsConnector> {
    fn with_connection_options(
        tls: WebhookTlsConfig,
        connection: WebhookConnectionOptions,
    ) -> Result<Self, ExportError> {
        let tls = webhook_tls_config(tls)?;
        Ok(Self::from_connector(https_connector(tls, connection)))
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct WebhookTlsConfig {
    pub trust_anchor_pems: Vec<Vec<u8>>,
    pub identity_pem: Option<Vec<u8>>,
}

impl fmt::Debug for WebhookTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookTlsConfig")
            .field("trust_anchor_count", &self.trust_anchor_pems.len())
            .field(
                "identity_pem",
                &self.identity_pem.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn webhook_tls_config(tls: WebhookTlsConfig) -> Result<rustls::ClientConfig, ExportError> {
    webhook_tls_config_with_native_roots(tls, rustls_native_certs::load_native_certs().certs)
}

fn webhook_tls_config_with_native_roots(
    tls: WebhookTlsConfig,
    native_roots: Vec<CertificateDer<'static>>,
) -> Result<rustls::ClientConfig, ExportError> {
    let WebhookTlsConfig {
        trust_anchor_pems,
        identity_pem,
    } = tls;
    let mut roots = root_cert_store_with_native_roots(native_roots).map_err(|source| {
        ExportError::InvalidWebhookTlsMaterial {
            reason: source.to_string(),
        }
    })?;
    for pem in trust_anchor_pems {
        let certificates = parse_certificates(&pem)?;
        if certificates.is_empty() {
            return Err(ExportError::EmptyTrustAnchorBundle);
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|source| ExportError::InvalidWebhookTlsMaterial {
                    reason: source.to_string(),
                })?;
        }
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    if let Some(identity_pem) = identity_pem {
        let certificates = parse_certificates(&identity_pem)?;
        if certificates.is_empty() {
            return Err(ExportError::InvalidWebhookTlsMaterial {
                reason: "client identity did not contain a certificate".to_string(),
            });
        }
        let private_key = parse_private_key(&identity_pem)?;
        builder
            .with_client_auth_cert(certificates, private_key)
            .map_err(|source| ExportError::InvalidWebhookTlsMaterial {
                reason: source.to_string(),
            })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

fn parse_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, ExportError> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ExportError::InvalidWebhookTlsMaterial {
            reason: source.to_string(),
        })
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, ExportError> {
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .map_err(|source| ExportError::InvalidWebhookTlsMaterial {
            reason: source.to_string(),
        })?
        .ok_or_else(|| ExportError::InvalidWebhookTlsMaterial {
            reason: "client identity did not contain a private key".to_string(),
        })
}

#[async_trait]
impl BatchExporter for WebhookExporter {
    async fn send_batch(&self, batch: &BatchEnvelope) -> Result<ExportAck, ExportError> {
        let encoded = batch.encode_to_vec();
        let body = self.codec.encode(&encoded)?;
        let response = self
            .transport
            .send(WebhookRequest {
                endpoint: self.endpoint.clone(),
                codec: self.codec,
                batch_id: batch.batch_id.clone(),
                headers: self.headers.clone(),
                body,
            })
            .await?;

        let ack = serde_json::from_str::<WebhookAck>(&response.body)
            .map_err(|source| ExportError::InvalidAckResponse { source })?;
        ack.into_export_ack(batch, response.success, || response.failure_reason)
    }
}

#[async_trait]
impl<C> WebhookTransport for HyperWebhookTransport<C>
where
    C: Service<http::Uri> + Clone + Send + Sync + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Connection + Unpin + Send + 'static,
    C::Future: Send + Unpin + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    async fn send(&self, request: WebhookRequest) -> Result<WebhookResponse, ExportError> {
        let response = self
            .client
            .request(request.into_http_request()?)
            .await
            .map_err(|source| ExportError::HttpTransport {
                reason: source.to_string(),
            })?;
        webhook_response_from_http_response(response).await
    }
}

impl WebhookRequest {
    fn into_http_request(self) -> Result<Request<Full<Bytes>>, ExportError> {
        let Self {
            endpoint,
            codec,
            batch_id,
            headers,
            body,
        } = self;
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(endpoint)
            .header(WEBHOOK_CONTENT_TYPE_HEADER, WEBHOOK_CONTENT_TYPE_PROTOBUF)
            .header(WEBHOOK_CODEC_HEADER, codec.wire_name())
            .header(WEBHOOK_IDEMPOTENCY_KEY_HEADER, batch_id)
            .body(Full::new(body))
            .map_err(|source| ExportError::HttpTransport {
                reason: source.to_string(),
            })?;
        for (name, value) in headers {
            if let Some(name) = name {
                request.headers_mut().append(name, value);
            }
        }
        Ok(request)
    }
}

async fn webhook_response_from_http_response(
    response: Response<Incoming>,
) -> Result<WebhookResponse, ExportError> {
    let status = response.status();
    let body = read_webhook_response_body(response.into_body()).await?;
    Ok(WebhookResponse {
        success: status.is_success(),
        failure_reason: format!("HTTP status {status}"),
        body,
    })
}

async fn read_webhook_response_body<B>(mut body: B) -> Result<String, ExportError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: fmt::Display,
{
    let mut bytes = Vec::new();
    while let Some(frame) =
        body.frame()
            .await
            .transpose()
            .map_err(|source| ExportError::HttpTransport {
                reason: source.to_string(),
            })?
    {
        if let Ok(chunk) = frame.into_data() {
            let new_size = bytes.len().saturating_add(chunk.len()) as u64;
            if new_size > MAX_WEBHOOK_ACK_RESPONSE_BYTES {
                return Err(ExportError::AckResponseTooLarge {
                    size: new_size,
                    limit: MAX_WEBHOOK_ACK_RESPONSE_BYTES,
                });
            }
            bytes.extend_from_slice(&chunk);
        }
    }
    String::from_utf8(bytes).map_err(|source| ExportError::HttpTransport {
        reason: source.to_string(),
    })
}

fn parse_headers(
    headers: impl IntoIterator<Item = (String, String)>,
) -> Result<HeaderMap, ExportError> {
    let mut parsed = HeaderMap::new();
    for (name, value) in headers {
        if reserved_webhook_header(&name) {
            return Err(ExportError::ReservedHeaderName { name });
        }
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|source| {
            ExportError::InvalidHeaderName {
                name: name.clone(),
                source,
            }
        })?;
        let header_value = HeaderValue::from_str(&value)
            .map_err(|source| ExportError::InvalidHeaderValue { name, source })?;
        parsed.insert(header_name, header_value);
    }
    Ok(parsed)
}

fn reserved_webhook_header(name: &str) -> bool {
    RESERVED_WEBHOOK_HEADERS
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_exporter_rejects_invalid_headers() {
        let result = WebhookExporter::with_headers(
            "https://collector.example/batches",
            CompressionCodec::Zstd,
            [("bad header".to_string(), "node-a".to_string())],
        );

        assert!(matches!(result, Err(ExportError::InvalidHeaderName { .. })));
    }

    #[test]
    fn webhook_exporter_rejects_reserved_protocol_headers() {
        let result = WebhookExporter::with_headers(
            "https://collector.example/batches",
            CompressionCodec::Zstd,
            [("x-traffic-probe-codec".to_string(), "none".to_string())],
        );

        assert!(matches!(
            result,
            Err(ExportError::ReservedHeaderName { name }) if name == "x-traffic-probe-codec"
        ));
    }

    #[test]
    fn webhook_exporter_rejects_empty_trust_anchor_bundle() {
        let result = WebhookExporter::with_tls_config(
            "https://collector.example/batches",
            CompressionCodec::Zstd,
            [],
            WebhookTlsConfig {
                trust_anchor_pems: vec![b"not a certificate".to_vec()],
                identity_pem: None,
            },
        );

        assert!(matches!(result, Err(ExportError::EmptyTrustAnchorBundle)));
    }

    #[test]
    fn webhook_tls_config_debug_redacts_identity_material() {
        let config = WebhookTlsConfig {
            trust_anchor_pems: vec![b"ca-secret".to_vec()],
            identity_pem: Some(b"client-secret".to_vec()),
        };

        let rendered = format!("{config:?}");

        assert!(rendered.contains("trust_anchor_count"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("ca-secret"));
        assert!(!rendered.contains("client-secret"));
    }

    #[test]
    fn webhook_tls_config_allows_empty_native_roots() {
        let result = webhook_tls_config_with_native_roots(WebhookTlsConfig::default(), Vec::new());

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_response_rejects_oversized_ack_body() {
        let body = Full::new(Bytes::from(vec![
            b'x';
            MAX_WEBHOOK_ACK_RESPONSE_BYTES as usize + 1
        ]));

        let error = read_webhook_response_body(body)
            .await
            .expect_err("oversized ack response must be rejected");

        assert!(matches!(
            error,
            ExportError::AckResponseTooLarge { size, limit }
                if size == MAX_WEBHOOK_ACK_RESPONSE_BYTES + 1
                    && limit == MAX_WEBHOOK_ACK_RESPONSE_BYTES
        ));
    }
}

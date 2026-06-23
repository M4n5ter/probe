use std::{
    fmt,
    future::Future,
    io::{self, Cursor},
    net::{SocketAddr, TcpStream as StdTcpStream},
    num::NonZeroU32,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{
    Method, Request, Uri,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Response,
    body::{Body, Incoming},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connection, HttpConnector},
    },
    rt::{TokioExecutor, TokioIo},
};
use probe_io::{TcpConnectOptions, TcpSocketMark, connect_tcp};
use proto::BatchEnvelope;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpStream, lookup_host};
use tower_service::Service;

use crate::{BatchExporter, CompressionCodec, ExportAck, ExportError, WebhookAck};

const RESERVED_WEBHOOK_HEADERS: &[&str] = &["content-type", "idempotency-key", "x-sssa-codec"];
const WEBHOOK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
        let connector = WebhookHttpConnector::new(connection);
        let transport = HyperWebhookTransport::with_connector(connector, tls)?;
        Self::with_transport(endpoint, codec, headers, transport)
    }

    fn with_transport(
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebhookConnectionOptions {
    connect_timeout: Duration,
    socket_mark: Option<TcpSocketMark>,
}

impl WebhookConnectionOptions {
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub fn with_socket_mark(mut self, mark: NonZeroU32) -> Self {
        self.socket_mark = Some(TcpSocketMark::new(mark));
        self
    }

    fn connect_options(self) -> TcpConnectOptions {
        let mut options = TcpConnectOptions::new(self.connect_timeout);
        if let Some(mark) = self.socket_mark {
            options = options.with_socket_mark(mark);
        }
        options
    }
}

impl Default for WebhookConnectionOptions {
    fn default() -> Self {
        Self {
            connect_timeout: WEBHOOK_CONNECT_TIMEOUT,
            socket_mark: None,
        }
    }
}

#[async_trait]
trait WebhookTransport: fmt::Debug + Send + Sync {
    async fn send(&self, request: WebhookRequest) -> Result<WebhookResponse, ExportError>;
}

#[derive(Debug, Clone)]
struct WebhookRequest {
    endpoint: String,
    codec: CompressionCodec,
    batch_id: String,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookResponse {
    success: bool,
    failure_reason: String,
    body: String,
}

#[derive(Clone, Debug)]
struct WebhookHttpConnector {
    connection: WebhookConnectionOptions,
}

impl WebhookHttpConnector {
    fn new(connection: WebhookConnectionOptions) -> Self {
        Self { connection }
    }
}

impl Service<Uri> for WebhookHttpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connection = self.connection;
        Box::pin(async move { connect_uri(uri, connection).await.map(TokioIo::new) })
    }
}

#[derive(Clone)]
struct HyperWebhookTransport<C = HttpConnector> {
    client: Client<HttpsConnector<C>, Full<Bytes>>,
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
        let connector = default_webhook_connector(tls)?;
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self { client })
    }
}

impl<C> HyperWebhookTransport<C>
where
    C: Service<Uri> + Clone + Send + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Connection + Unpin + Send + 'static,
    C::Future: Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn with_connector(connector: C, tls: WebhookTlsConfig) -> Result<Self, ExportError> {
        let tls = webhook_tls_config(tls)?;
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .wrap_connector(connector);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self { client })
    }
}

fn default_webhook_connector(
    tls: WebhookTlsConfig,
) -> Result<HttpsConnector<HttpConnector>, ExportError> {
    let tls = webhook_tls_config(tls)?;
    Ok(HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build())
}

async fn connect_uri(uri: Uri, connection: WebhookConnectionOptions) -> io::Result<TcpStream> {
    let (host, port) = endpoint_host_port(&uri)?;
    let addresses = lookup_host((host.as_str(), port))
        .await?
        .collect::<Vec<_>>();
    let mut last_error = None;
    for address in addresses {
        match connect_address(address, connection).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no socket addresses resolved for {host}:{port}"),
        )
    }))
}

fn endpoint_host_port(uri: &Uri) -> io::Result<(String, u16)> {
    let scheme = uri.scheme_str().unwrap_or("http");
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported webhook HTTP scheme {other}"),
            ));
        }
    };
    let host = uri.host().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "webhook HTTP endpoint is missing a host",
        )
    })?;
    Ok((host.to_string(), uri.port_u16().unwrap_or(default_port)))
}

async fn connect_address(
    address: SocketAddr,
    connection: WebhookConnectionOptions,
) -> io::Result<TcpStream> {
    let options = connection.connect_options();
    let stream = tokio::task::spawn_blocking(move || connect_tcp(address, options))
        .await
        .map_err(|source| io::Error::other(source.to_string()))??;
    stream_to_tokio(stream)
}

fn stream_to_tokio(stream: StdTcpStream) -> io::Result<TcpStream> {
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream)
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
    let mut roots = rustls::RootCertStore::empty();
    for certificate in native_roots {
        roots
            .add(certificate)
            .map_err(|source| ExportError::InvalidWebhookTlsMaterial {
                reason: source.to_string(),
            })?;
    }
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
    C: Service<Uri> + Clone + Send + Sync + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Connection + Unpin + Send + 'static,
    C::Future: Send + 'static,
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
            .header("content-type", "application/x-protobuf")
            .header("x-sssa-codec", codec.wire_name())
            .header("idempotency-key", batch_id)
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
    use tower_service::Service;

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
            [("x-sssa-codec".to_string(), "none".to_string())],
        );

        assert!(matches!(
            result,
            Err(ExportError::ReservedHeaderName { name }) if name == "x-sssa-codec"
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

    #[test]
    fn endpoint_host_port_uses_scheme_defaults() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            endpoint_host_port(&"https://collector.example/batches".parse::<Uri>()?)?,
            ("collector.example".to_string(), 443)
        );
        assert_eq!(
            endpoint_host_port(&"http://collector.example/batches".parse::<Uri>()?)?,
            ("collector.example".to_string(), 80)
        );
        Ok(())
    }

    #[test]
    fn endpoint_host_port_preserves_explicit_port() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            endpoint_host_port(&"https://collector.example:8443/batches".parse::<Uri>()?)?,
            ("collector.example".to_string(), 8443)
        );
        Ok(())
    }

    #[test]
    fn endpoint_host_port_rejects_unsupported_scheme() -> Result<(), Box<dyn std::error::Error>> {
        let error = endpoint_host_port(&"ftp://collector.example/batches".parse::<Uri>()?)
            .expect_err("unsupported scheme should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("unsupported"));
        Ok(())
    }

    #[tokio::test]
    async fn default_webhook_connector_does_not_reject_https_scheme() {
        let mut connector = default_webhook_connector(WebhookTlsConfig::default())
            .expect("default TLS connector should build");
        let uri = "https://127.0.0.1:9/batches"
            .parse::<Uri>()
            .expect("test URI should parse");

        let error = connector
            .call(uri)
            .await
            .expect_err("the unused local port should reject the connection");

        assert!(!error.to_string().contains("scheme is not http"));
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

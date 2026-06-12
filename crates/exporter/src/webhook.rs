use std::fmt;

use async_trait::async_trait;
use proto::BatchEnvelope;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::{BatchExporter, CompressionCodec, ExportAck, ExportError, WebhookAck};

const RESERVED_WEBHOOK_HEADERS: &[&str] = &["content-type", "idempotency-key", "x-sssa-codec"];

#[derive(Debug, Clone)]
pub struct WebhookExporter {
    client: reqwest::Client,
    endpoint: String,
    codec: CompressionCodec,
    headers: HeaderMap,
}

impl WebhookExporter {
    pub fn new(endpoint: impl Into<String>, codec: CompressionCodec) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.into(),
            codec,
            headers: HeaderMap::new(),
        }
    }

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
        let client = webhook_client(tls)?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            codec,
            headers: parse_headers(headers)?,
        })
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

fn webhook_client(tls: WebhookTlsConfig) -> Result<reqwest::Client, ExportError> {
    let WebhookTlsConfig {
        trust_anchor_pems,
        identity_pem,
    } = tls;
    let mut builder = reqwest::Client::builder();
    let mut trust_anchors = Vec::new();
    for pem in trust_anchor_pems {
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)?;
        if certificates.is_empty() {
            return Err(ExportError::EmptyTrustAnchorBundle);
        }
        trust_anchors.extend(certificates);
    }
    if !trust_anchors.is_empty() {
        builder = builder.tls_certs_merge(trust_anchors);
    }
    if let Some(identity_pem) = identity_pem {
        builder = builder.identity(reqwest::Identity::from_pem(&identity_pem)?);
    }
    builder.build().map_err(ExportError::Http)
}

#[async_trait]
impl BatchExporter for WebhookExporter {
    async fn send_batch(&self, batch: &BatchEnvelope) -> Result<ExportAck, ExportError> {
        let encoded = batch.encode_to_vec();
        let body = self.codec.encode(&encoded)?;
        let response = self
            .client
            .post(&self.endpoint)
            .headers(self.headers.clone())
            .header("content-type", "application/x-protobuf")
            .header("x-sssa-codec", self.codec.wire_name())
            .header("idempotency-key", &batch.batch_id)
            .body(body)
            .send()
            .await?;

        let status = response.status();
        let ack = response.json::<WebhookAck>().await?;
        if status.is_success() && ack.accepted {
            ack.into_export_ack(batch)
        } else {
            Err(ExportError::Rejected {
                batch_id: ack.batch_id,
                reason: ack
                    .reason
                    .unwrap_or_else(|| format!("HTTP status {status}")),
            })
        }
    }
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
}

use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read, Write},
};

use async_trait::async_trait;
use bytes::Bytes;
use flate2::{
    Compression,
    read::{DeflateDecoder, GzDecoder},
    write::{DeflateEncoder, GzEncoder},
};
use proto::BatchEnvelope;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const RESERVED_WEBHOOK_HEADERS: &[&str] = &["content-type", "idempotency-key", "x-sssa-codec"];

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("compression failed: {0}")]
    Compression(std::io::Error),
    #[error("zstd compression failed: {0}")]
    Zstd(std::io::Error),
    #[error("http transport failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid HTTP header name {name}: {source}")]
    InvalidHeaderName {
        name: String,
        source: reqwest::header::InvalidHeaderName,
    },
    #[error("invalid HTTP header value for {name}: {source}")]
    InvalidHeaderValue {
        name: String,
        source: reqwest::header::InvalidHeaderValue,
    },
    #[error("HTTP header {name} is reserved by the webhook protocol")]
    ReservedHeaderName { name: String },
    #[error("ack response rejected batch {batch_id}: {reason}")]
    Rejected { batch_id: String, reason: String },
    #[error("ack response batch mismatch: expected {expected}, got {actual}")]
    AckBatchMismatch { expected: String, actual: String },
    #[error("ack response referenced event {event_id} outside batch {batch_id}")]
    AckUnknownEvent { batch_id: String, event_id: String },
    #[error(
        "ack response cursor {cursor} is outside batch {batch_id} range {min_sequence}..={max_sequence}"
    )]
    AckCursorOutOfRange {
        batch_id: String,
        cursor: u64,
        min_sequence: u64,
        max_sequence: u64,
    },
    #[error(
        "ack response marked event {event_id} at sequence {sequence} retryable before committed cursor {cursor}"
    )]
    AckRetryableBeforeCursor {
        event_id: String,
        sequence: u64,
        cursor: u64,
    },
    #[error("ack response marked event {event_id} in batch {batch_id} as both acked and retryable")]
    AckConflictingEventState { batch_id: String, event_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodec {
    None,
    Zstd,
    Gzip,
    Deflate,
}

impl CompressionCodec {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
        }
    }

    pub fn encode(self, bytes: &[u8]) -> Result<Bytes, ExportError> {
        match self {
            Self::None => Ok(Bytes::copy_from_slice(bytes)),
            Self::Zstd => zstd::stream::encode_all(Cursor::new(bytes), 0)
                .map(Bytes::from)
                .map_err(ExportError::Zstd),
            Self::Gzip => {
                encode_with_writer(GzEncoder::new(Vec::new(), Compression::default()), bytes)
            }
            Self::Deflate => encode_with_writer(
                DeflateEncoder::new(Vec::new(), Compression::default()),
                bytes,
            ),
        }
    }

    pub fn decode(self, bytes: &[u8]) -> Result<Bytes, ExportError> {
        match self {
            Self::None => Ok(Bytes::copy_from_slice(bytes)),
            Self::Zstd => zstd::stream::decode_all(Cursor::new(bytes))
                .map(Bytes::from)
                .map_err(ExportError::Zstd),
            Self::Gzip => decode_with_reader(GzDecoder::new(Cursor::new(bytes))),
            Self::Deflate => decode_with_reader(DeflateDecoder::new(Cursor::new(bytes))),
        }
    }
}

fn encode_with_writer<W>(mut writer: W, bytes: &[u8]) -> Result<Bytes, ExportError>
where
    W: Write + FinishVec,
{
    writer.write_all(bytes).map_err(ExportError::Compression)?;
    writer
        .finish_vec()
        .map(Bytes::from)
        .map_err(ExportError::Compression)
}

fn decode_with_reader<R>(mut reader: R) -> Result<Bytes, ExportError>
where
    R: Read,
{
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .map_err(ExportError::Compression)?;
    Ok(Bytes::from(decoded))
}

trait FinishVec {
    fn finish_vec(self) -> std::io::Result<Vec<u8>>;
}

impl FinishVec for GzEncoder<Vec<u8>> {
    fn finish_vec(self) -> std::io::Result<Vec<u8>> {
        self.finish()
    }
}

impl FinishVec for DeflateEncoder<Vec<u8>> {
    fn finish_vec(self) -> std::io::Result<Vec<u8>> {
        self.finish()
    }
}

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
        Ok(Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.into(),
            codec,
            headers: parse_headers(headers)?,
        })
    }
}

#[async_trait]
pub trait ReliableExporter {
    async fn send(&self, batch: &BatchEnvelope) -> Result<ExportAck, ExportError>;
}

#[async_trait]
impl ReliableExporter for WebhookExporter {
    async fn send(&self, batch: &BatchEnvelope) -> Result<ExportAck, ExportError> {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAck {
    pub batch_id: String,
    pub committed_cursor: Option<u64>,
    pub acked_event_ids: Vec<String>,
    pub retryable_event_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookAck {
    pub batch_id: String,
    pub accepted: bool,
    pub acked_cursor: Option<u64>,
    pub acked_event_ids: Vec<String>,
    pub retryable_event_ids: Vec<String>,
    pub reason: Option<String>,
}

impl WebhookAck {
    pub fn into_export_ack(self, batch: &BatchEnvelope) -> Result<ExportAck, ExportError> {
        if self.batch_id != batch.batch_id {
            return Err(ExportError::AckBatchMismatch {
                expected: batch.batch_id.clone(),
                actual: self.batch_id,
            });
        }

        let event_ids = batch
            .events
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<HashSet<_>>();
        let event_sequences = batch
            .events
            .iter()
            .map(|event| (event.event_id.as_str(), event.sequence))
            .collect::<HashMap<_, _>>();
        let min_sequence = batch.events.iter().map(|event| event.sequence).min();
        let max_sequence = batch.events.iter().map(|event| event.sequence).max();
        for event_id in self.acked_event_ids.iter().chain(&self.retryable_event_ids) {
            if !event_ids.contains(event_id.as_str()) {
                return Err(ExportError::AckUnknownEvent {
                    batch_id: batch.batch_id.clone(),
                    event_id: event_id.clone(),
                });
            }
        }
        let acked_event_ids = self
            .acked_event_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        for event_id in &self.retryable_event_ids {
            if acked_event_ids.contains(event_id.as_str()) {
                return Err(ExportError::AckConflictingEventState {
                    batch_id: batch.batch_id.clone(),
                    event_id: event_id.clone(),
                });
            }
        }
        if let (Some(cursor), Some(min_sequence), Some(max_sequence)) =
            (self.acked_cursor, min_sequence, max_sequence)
            && (cursor < min_sequence || cursor > max_sequence)
        {
            return Err(ExportError::AckCursorOutOfRange {
                batch_id: batch.batch_id.clone(),
                cursor,
                min_sequence,
                max_sequence,
            });
        }
        if let Some(cursor) = self.acked_cursor {
            for event_id in &self.retryable_event_ids {
                let Some(sequence) = event_sequences.get(event_id.as_str()).copied() else {
                    continue;
                };
                if sequence <= cursor {
                    return Err(ExportError::AckRetryableBeforeCursor {
                        event_id: event_id.clone(),
                        sequence,
                        cursor,
                    });
                }
            }
        }

        Ok(ExportAck {
            batch_id: self.batch_id,
            committed_cursor: self.acked_cursor,
            acked_event_ids: self.acked_event_ids,
            retryable_event_ids: self.retryable_event_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use proto::{BatchEnvelope, EventRecord, PayloadFormat};

    use crate::{CompressionCodec, ExportError, WebhookAck, WebhookExporter};

    #[test]
    fn codecs_roundtrip_payload() -> Result<(), Box<dyn std::error::Error>> {
        let payload = b"large enough payload large enough payload large enough payload";
        for codec in [
            CompressionCodec::None,
            CompressionCodec::Zstd,
            CompressionCodec::Gzip,
            CompressionCodec::Deflate,
        ] {
            let encoded = codec.encode(payload)?;
            let decoded = codec.decode(&encoded)?;
            assert_eq!(&decoded[..], payload);
        }
        Ok(())
    }

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
    fn webhook_ack_rejects_batch_mismatch() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-2".to_string(),
            accepted: true,
            acked_cursor: Some(1),
            acked_event_ids: vec!["event-1".to_string()],
            retryable_event_ids: Vec::new(),
            reason: None,
        };

        assert!(matches!(
            ack.into_export_ack(&batch),
            Err(ExportError::AckBatchMismatch { expected, actual })
                if expected == "batch-1" && actual == "batch-2"
        ));
    }

    #[test]
    fn webhook_ack_rejects_unknown_event_ids() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: Some(1),
            acked_event_ids: vec!["event-2".to_string()],
            retryable_event_ids: Vec::new(),
            reason: None,
        };

        assert!(matches!(
            ack.into_export_ack(&batch),
            Err(ExportError::AckUnknownEvent { batch_id, event_id })
                if batch_id == "batch-1" && event_id == "event-2"
        ));
    }

    #[test]
    fn webhook_ack_rejects_conflicting_event_state() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: None,
            acked_event_ids: vec!["event-1".to_string()],
            retryable_event_ids: vec!["event-1".to_string()],
            reason: None,
        };

        assert!(matches!(
            ack.into_export_ack(&batch),
            Err(ExportError::AckConflictingEventState { batch_id, event_id })
                if batch_id == "batch-1" && event_id == "event-1"
        ));
    }

    #[test]
    fn webhook_ack_rejects_cursor_beyond_batch() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: Some(2),
            acked_event_ids: vec!["event-1".to_string()],
            retryable_event_ids: Vec::new(),
            reason: None,
        };

        assert!(matches!(
            ack.into_export_ack(&batch),
            Err(ExportError::AckCursorOutOfRange {
                batch_id,
                cursor: 2,
                min_sequence: 1,
                max_sequence: 1,
            }) if batch_id == "batch-1"
        ));
    }

    #[test]
    fn webhook_ack_rejects_cursor_before_batch() {
        let batch = test_batch_from_sequence("batch-1", 2, ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: Some(1),
            acked_event_ids: Vec::new(),
            retryable_event_ids: vec!["event-1".to_string()],
            reason: None,
        };

        assert!(matches!(
            ack.into_export_ack(&batch),
            Err(ExportError::AckCursorOutOfRange {
                batch_id,
                cursor: 1,
                min_sequence: 2,
                max_sequence: 2,
            }) if batch_id == "batch-1"
        ));
    }

    #[test]
    fn webhook_ack_rejects_retryable_events_before_cursor() {
        let batch = test_batch("batch-1", ["event-1", "event-2"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: Some(2),
            acked_event_ids: vec!["event-1".to_string()],
            retryable_event_ids: vec!["event-2".to_string()],
            reason: None,
        };

        assert!(matches!(
            ack.into_export_ack(&batch),
            Err(ExportError::AckRetryableBeforeCursor {
                event_id,
                sequence: 2,
                cursor: 2,
            }) if event_id == "event-2"
        ));
    }

    fn test_batch<const N: usize>(batch_id: &str, event_ids: [&str; N]) -> BatchEnvelope {
        test_batch_from_sequence(batch_id, 1, event_ids)
    }

    fn test_batch_from_sequence<const N: usize>(
        batch_id: &str,
        first_sequence: u64,
        event_ids: [&str; N],
    ) -> BatchEnvelope {
        BatchEnvelope {
            batch_id: batch_id.to_string(),
            agent_id: "agent-1".to_string(),
            codec: "none".to_string(),
            events: event_ids
                .into_iter()
                .enumerate()
                .map(|(index, event_id)| EventRecord {
                    event_id: event_id.to_string(),
                    sequence: first_sequence + index as u64,
                    payload_format: PayloadFormat::Json as i32,
                    payload: Vec::new(),
                    payload_schema: "test.schema".to_string(),
                })
                .collect(),
            schema_version: proto::BATCH_SCHEMA_VERSION,
        }
    }
}

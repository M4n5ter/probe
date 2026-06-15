#[derive(Debug, Error)]
pub enum ExportError {
    #[error("compression failed: {0}")]
    Compression(std::io::Error),
    #[error("zstd compression failed: {0}")]
    Zstd(std::io::Error),
    #[error("http transport failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid ack response body: {source}")]
    InvalidAckResponse { source: serde_json::Error },
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
    #[error("TLS trust anchor PEM bundle contained no certificates")]
    EmptyTrustAnchorBundle,
    #[error("ack response rejected batch {batch_id}: {reason}")]
    Rejected { batch_id: String, reason: String },
    #[error("ack response batch mismatch: expected {expected}, got {actual}")]
    AckBatchMismatch { expected: String, actual: String },
    #[error("ack response for accepted batch {batch_id} did not include acked_cursor")]
    AckMissingCursor { batch_id: String },
    #[error(
        "ack response cursor {cursor} is outside batch {batch_id} range {min_sequence}..={max_sequence}"
    )]
    AckCursorOutOfRange {
        batch_id: String,
        cursor: u64,
        min_sequence: u64,
        max_sequence: u64,
    },
}
use thiserror::Error;

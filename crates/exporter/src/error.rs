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
    #[error("TLS trust anchor PEM bundle contained no certificates")]
    EmptyTrustAnchorBundle,
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
use thiserror::Error;

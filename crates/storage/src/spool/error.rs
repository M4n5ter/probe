use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("fjall storage error: {0}")]
    Fjall(#[from] fjall::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid spool marker at {path}")]
    InvalidSpoolMarker { path: String },
    #[error("invalid cursor sink name utf-8")]
    InvalidCursorSinkName {
        #[source]
        source: std::string::FromUtf8Error,
    },
    #[error("invalid cursor value for sink {sink}: expected 8 bytes, got {len}")]
    InvalidCursor { sink: String, len: usize },
    #[error("invalid metadata value for key {key}: expected 8 bytes, got {len}")]
    InvalidMetadata { key: String, len: usize },
    #[error("spool sequence overflow")]
    SequenceOverflow,
    #[error("export dedup key must not be empty")]
    EmptyExportDedupKey,
    #[error("invalid export dedup index value for key {key}: expected 8 bytes, got {len}")]
    InvalidExportDedupIndex { key: String, len: usize },
    #[error("{lane} sequence lock poisoned")]
    SequenceLockPoisoned { lane: &'static str },
    #[error("{lane} live-record count lock poisoned")]
    LiveRecordCountLockPoisoned { lane: &'static str },
    #[error(
        "{lane} live-record count invariant violated: tried to prune {pruned_count} records from {live_records} live records"
    )]
    LiveRecordCountUnderflow {
        lane: &'static str,
        live_records: u64,
        pruned_count: u64,
    },
    #[error(
        "sink {sink} tried to ack sequence {sequence} beyond last stored sequence {last_sequence}"
    )]
    AckBeyondLastSequence {
        sink: String,
        sequence: u64,
        last_sequence: u64,
    },
    #[error("spool payload schema is too large: {len} bytes")]
    PayloadSchemaTooLarge { len: usize },
    #[error("invalid stored record: expected at least 12 bytes, got {len}")]
    InvalidStoredRecord { len: usize },
    #[error("invalid stored record schema utf-8: {0}")]
    InvalidStoredRecordSchemaUtf8(#[from] std::string::FromUtf8Error),
    #[error("invalid stored record schema: {0}")]
    InvalidStoredRecordSchema(#[from] probe_core::SpoolPayloadSchemaError),
}

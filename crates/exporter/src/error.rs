use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("file transport failed: {0}")]
    File(std::io::Error),
    #[error("file transport task failed: {0}")]
    FileTask(tokio::task::JoinError),
    #[error("file transport target name is invalid: {path}")]
    FileInvalidTargetName { path: PathBuf },
    #[error("file transport path is a symlink: {path}")]
    FileSymlink { path: PathBuf },
    #[error("file transport path is not a regular file: {path}")]
    FileNotRegular { path: PathBuf },
    #[error(
        "file transport path is owned by uid {owner_uid}, expected effective uid {effective_uid}: {path}"
    )]
    FileOwnerMismatch {
        path: PathBuf,
        owner_uid: u32,
        effective_uid: u32,
    },
    #[error("file transport path is not writable: {path}: {source}")]
    FileNotWritable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("file transport parent path is a symlink for {path}: {parent}")]
    FileParentSymlink { path: PathBuf, parent: PathBuf },
    #[error("file transport parent path is unavailable for {path}: {parent}: {source}")]
    FileParentUnavailable {
        path: PathBuf,
        parent: PathBuf,
        source: std::io::Error,
    },
    #[error("file transport parent path is not a directory for {path}: {parent}")]
    FileParentNotDirectory { path: PathBuf, parent: PathBuf },
    #[error("file transport parent path is not writable/searchable for {path}: {parent}: {source}")]
    FileParentNotWritable {
        path: PathBuf,
        parent: PathBuf,
        source: std::io::Error,
    },
    #[error("file transport path has insecure permissions {mode:o}: {path}")]
    FileInsecurePermissions { path: PathBuf, mode: u32 },
    #[error("file transport record serialization failed: {0}")]
    FileRecord(serde_json::Error),
    #[error("cannot export empty batch {batch_id}")]
    EmptyBatch { batch_id: String },
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

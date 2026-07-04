use thiserror::Error;

use super::model::EventDetailTooLargeSnapshot;

#[derive(Debug, Error)]
pub(in crate::admin) enum EventTailError {
    #[error("invalid event tail selector: {0}")]
    Selector(probe_core::SelectorError),
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("export event sequence {sequence} was not found")]
    EventNotFound { sequence: u64 },
    #[error(
        "export event sequence {sequence} payload has {payload_bytes} bytes, exceeding event_detail limit {max_payload_bytes} bytes"
    )]
    EventDetailTooLarge {
        sequence: u64,
        stored_at_unix_ns: u64,
        payload_schema: String,
        payload_bytes: usize,
        max_payload_bytes: usize,
    },
    #[error(
        "unexpected export payload schema at sequence {sequence}: expected {expected}, got {actual}"
    )]
    UnexpectedSchema {
        sequence: u64,
        expected: &'static str,
        actual: String,
    },
    #[error("failed to decode event envelope: {0}")]
    EventJson(#[from] serde_json::Error),
}

impl EventTailError {
    pub(in crate::admin) fn event_detail_too_large_snapshot(
        &self,
    ) -> Option<EventDetailTooLargeSnapshot> {
        match self {
            Self::EventDetailTooLarge {
                sequence,
                stored_at_unix_ns,
                payload_schema,
                payload_bytes,
                max_payload_bytes,
            } => Some(EventDetailTooLargeSnapshot {
                sequence: *sequence,
                stored_at_unix_ns: *stored_at_unix_ns,
                payload_schema: payload_schema.clone(),
                payload_bytes: *payload_bytes,
                max_payload_bytes: *max_payload_bytes,
            }),
            _ => None,
        }
    }
}

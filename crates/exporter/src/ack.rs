use std::collections::{HashMap, HashSet};

use proto::BatchEnvelope;
use serde::{Deserialize, Serialize};

use crate::ExportError;

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

    use super::*;

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

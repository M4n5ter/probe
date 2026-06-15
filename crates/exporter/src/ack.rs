use proto::BatchEnvelope;
use serde::{Deserialize, Serialize};

use crate::ExportError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAck {
    pub batch_id: String,
    pub committed_cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookAck {
    pub batch_id: String,
    pub accepted: bool,
    pub acked_cursor: Option<u64>,
    pub reason: Option<String>,
}

impl WebhookAck {
    pub fn into_export_ack(
        self,
        batch: &BatchEnvelope,
        transport_success: bool,
        transport_reason: impl FnOnce() -> String,
    ) -> Result<ExportAck, ExportError> {
        if self.batch_id != batch.batch_id {
            return Err(ExportError::AckBatchMismatch {
                expected: batch.batch_id.clone(),
                actual: self.batch_id,
            });
        }

        if !transport_success || !self.accepted {
            let reason = self.reason.unwrap_or_else(|| {
                if transport_success {
                    "receiver rejected batch".to_string()
                } else {
                    transport_reason()
                }
            });
            return Err(ExportError::Rejected {
                batch_id: self.batch_id,
                reason,
            });
        }

        let min_sequence = batch.events.iter().map(|event| event.sequence).min();
        let max_sequence = batch.events.iter().map(|event| event.sequence).max();
        let Some(committed_cursor) = self.acked_cursor else {
            return Err(ExportError::AckMissingCursor {
                batch_id: batch.batch_id.clone(),
            });
        };
        if let (Some(min_sequence), Some(max_sequence)) = (min_sequence, max_sequence)
            && (committed_cursor < min_sequence || committed_cursor > max_sequence)
        {
            return Err(ExportError::AckCursorOutOfRange {
                batch_id: batch.batch_id.clone(),
                cursor: committed_cursor,
                min_sequence,
                max_sequence,
            });
        }

        Ok(ExportAck {
            batch_id: self.batch_id,
            committed_cursor,
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
            reason: None,
        };

        assert!(matches!(
            accept(ack, &batch),
            Err(ExportError::AckBatchMismatch { expected, actual })
                if expected == "batch-1" && actual == "batch-2"
        ));
    }

    #[test]
    fn webhook_ack_rejects_event_id_cursor_substitutes() {
        let source = r#"{
            "batch_id": "batch-1",
            "accepted": true,
            "acked_cursor": 1,
            "retryable_event_ids": ["event-1"],
            "reason": null
        }"#;

        assert!(serde_json::from_str::<WebhookAck>(source).is_err());
    }

    #[test]
    fn webhook_ack_rejects_missing_cursor_for_accepted_batch() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: None,
            reason: None,
        };

        assert!(matches!(
            accept(ack, &batch),
            Err(ExportError::AckMissingCursor { batch_id }) if batch_id == "batch-1"
        ));
    }

    #[test]
    fn webhook_ack_rejects_cursor_beyond_batch() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: Some(2),
            reason: None,
        };

        assert!(matches!(
            accept(ack, &batch),
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
            reason: None,
        };

        assert!(matches!(
            accept(ack, &batch),
            Err(ExportError::AckCursorOutOfRange {
                batch_id,
                cursor: 1,
                min_sequence: 2,
                max_sequence: 2,
            }) if batch_id == "batch-1"
        ));
    }

    #[test]
    fn webhook_ack_rejects_unaccepted_ack_before_committing_cursor() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: false,
            acked_cursor: Some(1),
            reason: Some("receiver throttled".to_string()),
        };

        assert!(matches!(
            accept(ack, &batch),
            Err(ExportError::Rejected { batch_id, reason })
                if batch_id == "batch-1" && reason == "receiver throttled"
        ));
    }

    #[test]
    fn webhook_ack_rejects_failed_transport_before_committing_cursor() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: Some(1),
            reason: None,
        };

        assert!(matches!(
            ack.into_export_ack(&batch, false, || {
                "HTTP status 500 Internal Server Error".to_string()
            }),
            Err(ExportError::Rejected { batch_id, reason })
                if batch_id == "batch-1" && reason == "HTTP status 500 Internal Server Error"
        ));
    }

    #[test]
    fn webhook_ack_validates_batch_mismatch_before_rejection() {
        let batch = test_batch("batch-1", ["event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-2".to_string(),
            accepted: false,
            acked_cursor: Some(1),
            reason: Some("receiver rejected".to_string()),
        };

        assert!(matches!(
            accept(ack, &batch),
            Err(ExportError::AckBatchMismatch { expected, actual })
                if expected == "batch-1" && actual == "batch-2"
        ));
    }

    #[test]
    fn webhook_ack_allows_duplicate_event_ids_with_cursor_ack() {
        let batch = test_batch("batch-1", ["event-1", "event-1"]);
        let ack = WebhookAck {
            batch_id: "batch-1".to_string(),
            accepted: true,
            acked_cursor: Some(2),
            reason: None,
        };

        let ack = accept(ack, &batch).expect("cursor ack is valid");

        assert_eq!(ack.committed_cursor, 2);
    }

    fn accept(ack: WebhookAck, batch: &BatchEnvelope) -> Result<ExportAck, ExportError> {
        ack.into_export_ack(batch, true, || "HTTP status 200 OK".to_string())
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
        }
    }
}

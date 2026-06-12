use std::collections::HashSet;

use exporter::{CompressionCodec, ReliableExporter};
use probe_core::SpoolPayloadSchema;
use proto::BatchEnvelope;
use storage::{ExportSpool, StoredEvent};

use super::{ExportDrainError, mode::SinkDrainMode};

pub(super) const EXPORT_BATCH_LIMIT: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExportDrainSummary {
    pub(super) batches: u64,
    pub(super) committed_cursor: Option<u64>,
}

pub(super) async fn drain_export_sink_from_batch(
    spool: &impl ExportSpool,
    agent_id: &str,
    sink: &str,
    codec: CompressionCodec,
    mode: SinkDrainMode,
    exporter: &(impl ReliableExporter + ?Sized),
    first_batch: BatchEnvelope,
) -> Result<ExportDrainSummary, ExportDrainError> {
    let mut summary = ExportDrainSummary {
        batches: 0,
        committed_cursor: None,
    };
    let mut next_batch = Some(first_batch);

    loop {
        let batch = match next_batch.take() {
            Some(batch) => batch,
            None => {
                let events = spool.read_export_batch(sink, EXPORT_BATCH_LIMIT)?;
                let Some(batch) = export_batch_from_events(agent_id, sink, codec, events)? else {
                    return Ok(summary);
                };
                batch
            }
        };
        let ack = exporter.send(&batch).await?;
        summary.batches = summary.batches.saturating_add(1);
        let committed_cursor = ack
            .committed_cursor
            .or_else(|| contiguous_cursor_from_event_ids(&batch, &ack.acked_event_ids));
        let Some(cursor) = committed_cursor else {
            println!(
                "exported sink {sink} batch {} without committed cursor; spool cursor unchanged",
                ack.batch_id
            );
            return Ok(summary);
        };

        spool.ack_export(sink, cursor)?;
        summary.committed_cursor = Some(cursor);
        println!(
            "exported sink {sink} batch {} and committed cursor {cursor}",
            ack.batch_id
        );
        if !mode.can_continue_after(summary.batches) {
            return Ok(summary);
        }
    }
}

pub(super) fn export_batch_from_events(
    agent_id: &str,
    sink: &str,
    codec: CompressionCodec,
    events: Vec<StoredEvent>,
) -> Result<Option<BatchEnvelope>, ExportDrainError> {
    let Some(last_sequence) = events.last().map(|event| event.sequence) else {
        return Ok(None);
    };
    for event in &events {
        if event.payload.schema() != &SpoolPayloadSchema::EventEnvelopeJson {
            return Err(ExportDrainError::UnsupportedSpoolPayloadSchema {
                sequence: event.sequence,
                schema: event.payload.schema_wire().to_string(),
            });
        }
    }

    BatchEnvelope::from_json_payloads(
        format!("{agent_id}:{sink}:{last_sequence}"),
        agent_id,
        codec.wire_name(),
        events
            .iter()
            .map(|event| (event.sequence, event.payload.bytes())),
    )
    .map(Some)
    .map_err(ExportDrainError::Proto)
}

fn contiguous_cursor_from_event_ids(
    batch: &BatchEnvelope,
    acked_event_ids: &[String],
) -> Option<u64> {
    let acked_event_ids = acked_event_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut cursor = None;
    for event in &batch.events {
        if acked_event_ids.contains(event.event_id.as_str()) {
            cursor = Some(event.sequence);
        } else {
            break;
        }
    }
    cursor
}

#[cfg(test)]
mod tests {
    use proto::{BATCH_SCHEMA_VERSION, EventRecord, PayloadFormat};

    use super::*;

    #[test]
    fn acked_event_ids_advance_only_contiguous_cursor_prefix() {
        let batch = batch_with_events(["one", "two", "three"]);

        assert_eq!(
            contiguous_cursor_from_event_ids(&batch, &["one".to_string(), "two".to_string()]),
            Some(2)
        );
        assert_eq!(
            contiguous_cursor_from_event_ids(&batch, &["two".to_string(), "three".to_string()]),
            None
        );
    }

    fn batch_with_events<const N: usize>(event_ids: [&str; N]) -> BatchEnvelope {
        BatchEnvelope {
            batch_id: "batch-1".to_string(),
            agent_id: "agent-1".to_string(),
            codec: "none".to_string(),
            events: event_ids
                .into_iter()
                .enumerate()
                .map(|(index, event_id)| EventRecord {
                    event_id: event_id.to_string(),
                    sequence: (index + 1) as u64,
                    payload_format: PayloadFormat::Json as i32,
                    payload: Vec::new(),
                    payload_schema: "test.schema".to_string(),
                })
                .collect(),
            schema_version: BATCH_SCHEMA_VERSION,
        }
    }
}

use exporter::{BatchExporter, CompressionCodec};
use probe_core::SpoolPayloadSchema;
use proto::BatchEnvelope;
use storage::{ExportSpool, StoredEvent};

use super::{ExportDrainError, mode::SinkDrainMode};

pub(super) const EXPORT_BATCH_LIMIT: usize = 1024;
const EXPORT_BATCH_PAYLOAD_BYTES_LIMIT: usize = 16 * 1024 * 1024;

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
    exporter: &(impl BatchExporter + ?Sized),
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
        let ack = exporter.send_batch(&batch).await?;
        summary.batches = summary.batches.saturating_add(1);
        let cursor = ack.committed_cursor;

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
    export_batch_from_events_with_payload_limit(
        agent_id,
        sink,
        codec,
        events,
        EXPORT_BATCH_PAYLOAD_BYTES_LIMIT,
    )
}

fn export_batch_from_events_with_payload_limit(
    agent_id: &str,
    sink: &str,
    codec: CompressionCodec,
    events: Vec<StoredEvent>,
    payload_bytes_limit: usize,
) -> Result<Option<BatchEnvelope>, ExportDrainError> {
    let Some(first_sequence) = events.first().map(|event| event.sequence) else {
        return Ok(None);
    };
    let selected_events = export_batch_payload_prefix(&events, payload_bytes_limit);
    let last_sequence = selected_events
        .last()
        .map(|event| event.sequence)
        .expect("non-empty event batch has a last sequence");
    for event in selected_events {
        if event.payload.schema() != &SpoolPayloadSchema::EventEnvelopeSubjectOriginJson {
            return Err(ExportDrainError::UnsupportedSpoolPayloadSchema {
                sequence: event.sequence,
                schema: event.payload.schema_wire().to_string(),
            });
        }
    }

    BatchEnvelope::from_json_payloads(
        export_batch_id(agent_id, sink, first_sequence, last_sequence),
        agent_id,
        codec.wire_name(),
        selected_events
            .iter()
            .map(|event| (event.sequence, event.payload.bytes())),
    )
    .map(Some)
    .map_err(ExportDrainError::Proto)
}

fn export_batch_payload_prefix(
    events: &[StoredEvent],
    payload_bytes_limit: usize,
) -> &[StoredEvent] {
    let mut selected = 0;
    let mut payload_bytes = 0usize;

    for event in events {
        let event_bytes = event.payload.bytes().len();
        if selected > 0 && payload_bytes.saturating_add(event_bytes) > payload_bytes_limit {
            break;
        }
        payload_bytes = payload_bytes.saturating_add(event_bytes);
        selected += 1;
    }

    &events[..selected]
}

pub(in crate::export::drain) fn export_batch_id(
    agent_id: &str,
    sink: &str,
    first_sequence: u64,
    last_sequence: u64,
) -> String {
    format!("{agent_id}:{sink}:{first_sequence}-{last_sequence}")
}

#[cfg(test)]
pub(in crate::export::drain) fn batch_id_last_sequence(batch_id: &str) -> Option<u64> {
    batch_id
        .rsplit(':')
        .next()
        .and_then(|range| range.rsplit('-').next())
        .and_then(|sequence| sequence.parse().ok())
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity, Timestamp,
        TransportProtocol,
    };
    use storage::{FjallSpool, SpoolPayload};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn partial_cursor_ack_changes_retry_batch_identity() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        append_export_event(&spool, "/one")?;
        append_export_event(&spool, "/two")?;
        let events = spool.read_export_batch("sink", EXPORT_BATCH_LIMIT)?;
        let first_batch =
            export_batch_from_events("agent-1", "sink", CompressionCodec::None, events)?
                .expect("initial batch");

        spool.ack_export("sink", 1)?;

        let retry_batch = export_batch_from_events(
            "agent-1",
            "sink",
            CompressionCodec::None,
            spool.read_export_batch("sink", EXPORT_BATCH_LIMIT)?,
        )?
        .expect("retry batch");

        assert_eq!(first_batch.batch_id, "agent-1:sink:1-2");
        assert_eq!(retry_batch.batch_id, "agent-1:sink:2-2");
        Ok(())
    }

    #[test]
    fn payload_byte_limit_bounds_batch_to_contiguous_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        append_export_event(&spool, "/one")?;
        append_export_event(&spool, "/two")?;
        append_export_event(&spool, "/three")?;

        let events = spool.read_export_batch("sink", EXPORT_BATCH_LIMIT)?;
        let limit = events[0].payload.bytes().len() + 1;
        let first_batch = export_batch_from_events_with_payload_limit(
            "agent-1",
            "sink",
            CompressionCodec::None,
            events,
            limit,
        )?
        .expect("initial batch");

        spool.ack_export("sink", 1)?;
        let retry_batch = export_batch_from_events_with_payload_limit(
            "agent-1",
            "sink",
            CompressionCodec::None,
            spool.read_export_batch("sink", EXPORT_BATCH_LIMIT)?,
            limit,
        )?
        .expect("retry batch");

        assert_eq!(first_batch.batch_id, "agent-1:sink:1-1");
        assert_eq!(first_batch.events.len(), 1);
        assert_eq!(retry_batch.batch_id, "agent-1:sink:2-2");
        assert_eq!(retry_batch.events.len(), 1);
        Ok(())
    }

    #[test]
    fn payload_byte_limit_sends_single_oversized_event() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        append_export_event(&spool, "/oversized")?;
        append_export_event(&spool, "/later")?;

        let batch = export_batch_from_events_with_payload_limit(
            "agent-1",
            "sink",
            CompressionCodec::None,
            spool.read_export_batch("sink", EXPORT_BATCH_LIMIT)?,
            0,
        )?
        .expect("oversized single-event batch");

        assert_eq!(batch.batch_id, "agent-1:sink:1-1");
        assert_eq!(batch.events.len(), 1);

        spool.ack_export("sink", 1)?;
        let next_batch = export_batch_from_events_with_payload_limit(
            "agent-1",
            "sink",
            CompressionCodec::None,
            spool.read_export_batch("sink", EXPORT_BATCH_LIMIT)?,
            0,
        )?
        .expect("next single-event batch");

        assert_eq!(next_batch.batch_id, "agent-1:sink:2-2");
        assert_eq!(next_batch.events.len(), 1);
        Ok(())
    }

    fn append_export_event(
        spool: &FjallSpool,
        target: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let envelope = EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some(target.to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        );
        let payload = serde_json::to_vec(&envelope)?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            payload,
        ))?;
        Ok(())
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "agent-test".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "agent-test".to_string(),
                cmdline: vec!["agent-test".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(1),
            attribution_confidence: 100,
        }
    }
}

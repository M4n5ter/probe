use probe_core::{EventEnvelope, SpoolPayloadSchema};
use storage::{AppendOutcome, DurableSpool, SpoolPayload};
use thiserror::Error;

use crate::runtime_metrics::PipelineRuntimeMetrics;

#[derive(Debug, Error)]
pub enum ExportEventWriteError {
    #[error("failed to serialize export event envelope: {0}")]
    Json(#[from] serde_json::Error),
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
}

pub struct ExportEventWriter<'a, S> {
    spool: &'a S,
    metrics: Option<PipelineRuntimeMetrics>,
}

impl<'a, S> ExportEventWriter<'a, S>
where
    S: DurableSpool,
{
    pub fn new(spool: &'a S) -> Self {
        Self {
            spool,
            metrics: None,
        }
    }

    pub fn with_runtime_metrics(mut self, metrics: Option<PipelineRuntimeMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn append_once(&self, envelope: &EventEnvelope) -> Result<bool, ExportEventWriteError> {
        let payload = envelope_payload(envelope)?;
        let outcome = self.spool.append_export_once(
            envelope.id().as_str(),
            SpoolPayload::new(SpoolPayloadSchema::EventEnvelopeSubjectOriginJson, payload),
        )?;
        let appended = matches!(outcome, AppendOutcome::Appended(_));
        if appended {
            self.record_written(envelope);
        }
        Ok(appended)
    }

    pub fn append_occurrence(&self, envelope: &EventEnvelope) -> Result<(), ExportEventWriteError> {
        let payload = envelope_payload(envelope)?;
        self.spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            payload,
        ))?;
        self.record_written(envelope);
        Ok(())
    }

    fn record_written(&self, envelope: &EventEnvelope) {
        if let Some(metrics) = &self.metrics {
            metrics.record_export_event_envelope(envelope);
        }
    }
}

fn envelope_payload(envelope: &EventEnvelope) -> Result<Vec<u8>, ExportEventWriteError> {
    serde_json::to_vec(envelope).map_err(ExportEventWriteError::Json)
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, Gap, ProcessContext, ProcessIdentity, Timestamp,
        TransportProtocol,
    };
    use tempfile::tempdir;

    use crate::{ExportEventWriter, PipelineRuntimeMetrics};

    #[test]
    fn append_once_records_event_classification_metrics_only_for_new_envelopes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = storage::FjallSpool::open(temp.path())?;
        let metrics = PipelineRuntimeMetrics::default();
        let writer = ExportEventWriter::new(&spool).with_runtime_metrics(Some(metrics.clone()));
        let envelope = gap_envelope();

        assert!(writer.append_once(&envelope)?);
        assert!(!writer.append_once(&envelope)?);

        let events = metrics.snapshot().events;
        assert_eq!(events.total, 1);
        assert_eq!(events.degraded, 1);
        assert_eq!(events.gaps, 1);
        Ok(())
    }

    #[test]
    fn append_occurrence_records_event_classification_metrics_for_each_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = storage::FjallSpool::open(temp.path())?;
        let metrics = PipelineRuntimeMetrics::default();
        let writer = ExportEventWriter::new(&spool).with_runtime_metrics(Some(metrics.clone()));
        let envelope = gap_envelope();

        writer.append_occurrence(&envelope)?;
        writer.append_occurrence(&envelope)?;

        let events = metrics.snapshot().events;
        assert_eq!(events.total, 2);
        assert_eq!(events.degraded, 2);
        assert_eq!(events.gaps, 2);
        Ok(())
    }

    fn gap_envelope() -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::Gap(Gap {
                direction: Direction::Outbound,
                expected_offset: 5,
                next_offset: Some(9),
                reason: "dropped bytes".to_string(),
            }),
        )
    }

    fn flow() -> FlowContext {
        let process = ProcessContext {
            identity: ProcessIdentity {
                pid: 1,
                tgid: 1,
                start_time_ticks: 1,
                boot_id: "boot".to_string(),
                exe_path: "/bin/demo".to_string(),
                cmdline_hash: "hash".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "demo".to_string(),
            cmdline: vec!["demo".to_string()],
        };
        let local = AddressPort {
            address: "127.0.0.1".parse().expect("valid local address"),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".parse().expect("valid remote address"),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process.identity,
                &local,
                &remote,
                TransportProtocol::Tcp,
                1,
                None,
            ),
            process,
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

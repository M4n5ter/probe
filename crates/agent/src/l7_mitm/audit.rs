use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use pipeline::{ExportEventWriter, PipelineRuntimeMetrics};
use probe_core::{
    CaptureOrigin, CaptureSource, EventEnvelope, EventKind, L7MitmAuditEvent, Timestamp,
};
use storage::DurableSpool;

pub(crate) trait L7MitmAuditSink: Send + Sync {
    fn record(&self, event: L7MitmAuditEvent) -> Result<(), String>;
}

#[cfg(test)]
pub(crate) struct NoopL7MitmAuditSink;

#[cfg(test)]
impl L7MitmAuditSink for NoopL7MitmAuditSink {
    fn record(&self, _event: L7MitmAuditEvent) -> Result<(), String> {
        Ok(())
    }
}

pub(crate) struct DurableL7MitmAuditSink<S> {
    spool: Arc<S>,
    config_version: String,
    metrics: PipelineRuntimeMetrics,
    clock: AtomicU64,
}

impl<S> DurableL7MitmAuditSink<S>
where
    S: DurableSpool + Send + Sync,
{
    pub(crate) fn new(
        spool: Arc<S>,
        config_version: impl Into<String>,
        metrics: PipelineRuntimeMetrics,
    ) -> Self {
        Self {
            spool,
            config_version: config_version.into(),
            metrics,
            clock: AtomicU64::new(audit_clock_seed()),
        }
    }

    #[cfg(test)]
    fn new_with_clock_seed(
        spool: Arc<S>,
        config_version: impl Into<String>,
        metrics: PipelineRuntimeMetrics,
        clock_seed: u64,
    ) -> Self {
        Self {
            spool,
            config_version: config_version.into(),
            metrics,
            clock: AtomicU64::new(clock_seed),
        }
    }

    fn envelope(&self, event: L7MitmAuditEvent) -> EventEnvelope {
        EventEnvelope::from_provider(
            self.next_timestamp(),
            CaptureOrigin::from_source(CaptureSource::L7MitmControlPlane),
            self.config_version.clone(),
            EventKind::L7MitmAudit(event),
        )
    }

    fn next_timestamp(&self) -> Timestamp {
        Timestamp {
            monotonic_ns: self.clock.fetch_add(1, Ordering::Relaxed).saturating_add(1),
            wall_time_unix_ns: wall_time_unix_ns(),
        }
    }
}

impl<S> L7MitmAuditSink for DurableL7MitmAuditSink<S>
where
    S: DurableSpool + Send + Sync,
{
    fn record(&self, event: L7MitmAuditEvent) -> Result<(), String> {
        let envelope = self.envelope(event);
        ExportEventWriter::new(self.spool.as_ref())
            .with_runtime_metrics(Some(self.metrics.clone()))
            .append_occurrence(&envelope)
            .map_err(|error| format!("failed to store L7 MITM audit event: {error}"))?;
        Ok(())
    }
}

fn audit_clock_seed() -> u64 {
    let wall_time = u64::try_from(wall_time_unix_ns()).unwrap_or(0);
    wall_time ^ u64::from(std::process::id()).rotate_left(17)
}

fn wall_time_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use probe_core::{
        EventKind, EventSubject, L7MitmAuditEvent, L7MitmExternalBackendAudit,
        L7MitmReadinessProbeAudit,
    };
    use storage::FjallSpool;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn durable_audit_sink_writes_provider_l7_mitm_audit_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = Arc::new(FjallSpool::open(temp.path())?);
        let metrics = PipelineRuntimeMetrics::default();
        let sink = DurableL7MitmAuditSink::new_with_clock_seed(
            Arc::clone(&spool),
            "test-config",
            metrics.clone(),
            100,
        );

        sink.record(external_health_probe_started_event())?;

        let events = spool.read_export_batch("sink", 10)?;
        assert_eq!(events.len(), 1);
        let envelope = serde_json::from_slice::<EventEnvelope>(events[0].payload.bytes())?;
        assert!(matches!(envelope.subject(), EventSubject::Provider));
        assert!(matches!(envelope.kind(), EventKind::L7MitmAudit(_)));
        assert_eq!(metrics.snapshot().export_events_written, 1);
        Ok(())
    }

    #[test]
    fn durable_audit_sink_preserves_repeated_lifecycle_occurrences()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = Arc::new(FjallSpool::open(temp.path())?);
        let metrics = PipelineRuntimeMetrics::default();
        let first = DurableL7MitmAuditSink::new_with_clock_seed(
            Arc::clone(&spool),
            "test-config",
            metrics.clone(),
            100,
        );
        let second = DurableL7MitmAuditSink::new_with_clock_seed(
            Arc::clone(&spool),
            "test-config",
            metrics.clone(),
            200,
        );

        first.record(external_health_probe_started_event())?;
        second.record(external_health_probe_started_event())?;

        let events = spool.read_export_batch("sink", 10)?;
        assert_eq!(events.len(), 2);
        let first = serde_json::from_slice::<EventEnvelope>(events[0].payload.bytes())?;
        let second = serde_json::from_slice::<EventEnvelope>(events[1].payload.bytes())?;
        assert_ne!(first.id(), second.id());
        assert_eq!(metrics.snapshot().export_events_written, 2);
        Ok(())
    }

    fn external_health_probe_started_event() -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendHealthProbeStarted {
                readiness_probe: L7MitmReadinessProbeAudit {
                    target: "127.0.0.1:15002".to_string(),
                    interval_ms: 1_000,
                    timeout_ms: 100,
                    failure_threshold: 3,
                },
            },
        }
    }
}

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pipeline::{ExportEventWriter, PipelineRuntimeMetrics};
use probe_core::{
    CaptureOrigin, CaptureSource, EventEnvelope, EventKind, L7MitmAuditEvent,
    L7MitmExternalBackendAudit, L7MitmManagedProcessAudit, L7MitmManagedProcessBackendAudit,
    L7MitmReadinessProbeAudit, Timestamp,
};
use runtime::TransparentInterceptionMitmManagedProcessPlan;
use rustix::process::Pid;
use storage::DurableSpool;

use super::{
    backend::L7MitmBackendHealthProbe,
    state::{L7MitmBackendHealthTransition, L7MitmRuntimeHandle},
};
use crate::tcp_health::TcpHealthProbeObserver;

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

#[derive(Clone)]
pub(crate) enum L7MitmAuditContext {
    External(L7MitmExternalAuditContext),
    ManagedProcess(L7MitmManagedProcessAuditContext),
}

impl L7MitmAuditContext {
    pub(crate) fn backend_stopping_event(&self) -> L7MitmAuditEvent {
        match self {
            Self::External(context) => context.backend_stopping_event(),
            Self::ManagedProcess(context) => context.backend_stopping_event(),
        }
    }

    pub(crate) fn backend_stopped_event(&self) -> L7MitmAuditEvent {
        match self {
            Self::External(context) => context.backend_stopped_event(),
            Self::ManagedProcess(context) => context.backend_stopped_event(),
        }
    }

    pub(crate) fn backend_stop_failed_event(&self, reason: String) -> L7MitmAuditEvent {
        match self {
            Self::External(context) => context.backend_stop_failed_event(reason),
            Self::ManagedProcess(context) => context.backend_stop_failed_event(reason),
        }
    }

    fn backend_unhealthy_event(
        &self,
        reason: String,
        consecutive_failures: u64,
    ) -> L7MitmAuditEvent {
        match self {
            Self::External(context) => {
                context.backend_unhealthy_event(reason, consecutive_failures)
            }
            Self::ManagedProcess(context) => {
                context.backend_unhealthy_event(reason, consecutive_failures)
            }
        }
    }

    fn backend_recovered_event(&self) -> L7MitmAuditEvent {
        match self {
            Self::External(context) => context.backend_recovered_event(),
            Self::ManagedProcess(context) => context.backend_recovered_event(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct L7MitmExternalAuditContext {
    readiness_probe: L7MitmReadinessProbeAudit,
}

impl L7MitmExternalAuditContext {
    pub(crate) fn new(readiness_probe: &L7MitmBackendHealthProbe) -> Self {
        Self {
            readiness_probe: readiness_probe_audit(readiness_probe),
        }
    }

    pub(crate) fn backend_starting_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendStarting {
                readiness_probe: self.readiness_probe.clone(),
            },
        }
    }

    pub(crate) fn backend_health_probe_started_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendHealthProbeStarted {
                readiness_probe: self.readiness_probe.clone(),
            },
        }
    }

    fn backend_unhealthy_event(
        &self,
        reason: String,
        consecutive_failures: u64,
    ) -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendUnhealthy {
                readiness_probe: self.readiness_probe.clone(),
                consecutive_failures,
                reason,
            },
        }
    }

    fn backend_recovered_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendRecovered {
                readiness_probe: self.readiness_probe.clone(),
            },
        }
    }

    fn backend_stopping_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendStopping {
                readiness_probe: self.readiness_probe.clone(),
            },
        }
    }

    fn backend_stopped_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendStopped {
                readiness_probe: self.readiness_probe.clone(),
            },
        }
    }

    fn backend_stop_failed_event(&self, reason: String) -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendStopFailed {
                readiness_probe: self.readiness_probe.clone(),
                reason,
            },
        }
    }
}

#[derive(Clone)]
pub(crate) struct L7MitmManagedProcessAuditContext {
    readiness_probe: L7MitmReadinessProbeAudit,
    process: L7MitmManagedProcessAudit,
}

impl L7MitmManagedProcessAuditContext {
    pub(crate) fn new(
        process: &TransparentInterceptionMitmManagedProcessPlan,
        readiness_probe: &L7MitmBackendHealthProbe,
        process_group: Option<Pid>,
    ) -> Self {
        Self {
            readiness_probe: readiness_probe_audit(readiness_probe),
            process: L7MitmManagedProcessAudit {
                program: process.program.display().to_string(),
                args_count: u64::try_from(process.args.len()).unwrap_or(u64::MAX),
                working_dir: process
                    .working_dir
                    .as_ref()
                    .map(|path| path.display().to_string()),
                process_group: process_group.map(Pid::as_raw_pid),
            },
        }
    }

    pub(crate) fn backend_starting_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendStarting {
                readiness_probe: self.readiness_probe.clone(),
                process: self.process.clone(),
            },
        }
    }

    pub(crate) fn backend_ready_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendReady {
                readiness_probe: self.readiness_probe.clone(),
                process: self.process.clone(),
            },
        }
    }

    pub(crate) fn backend_start_failed_event(&self, reason: String) -> L7MitmAuditEvent {
        L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendStartFailed {
                readiness_probe: self.readiness_probe.clone(),
                process: self.process.clone(),
                reason,
            },
        }
    }

    fn backend_unhealthy_event(
        &self,
        reason: String,
        consecutive_failures: u64,
    ) -> L7MitmAuditEvent {
        L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendUnhealthy {
                readiness_probe: self.readiness_probe.clone(),
                process: self.process.clone(),
                consecutive_failures,
                reason,
            },
        }
    }

    fn backend_recovered_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendRecovered {
                readiness_probe: self.readiness_probe.clone(),
                process: self.process.clone(),
            },
        }
    }

    fn backend_stopping_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendStopping {
                readiness_probe: self.readiness_probe.clone(),
                process: self.process.clone(),
            },
        }
    }

    fn backend_stopped_event(&self) -> L7MitmAuditEvent {
        L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendStopped {
                readiness_probe: self.readiness_probe.clone(),
                process: self.process.clone(),
            },
        }
    }

    fn backend_stop_failed_event(&self, reason: String) -> L7MitmAuditEvent {
        L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendStopFailed {
                readiness_probe: self.readiness_probe.clone(),
                process: self.process.clone(),
                reason,
            },
        }
    }
}

#[derive(Clone)]
pub(crate) struct L7MitmBackendHealthAuditObserver {
    runtime: L7MitmRuntimeHandle,
    audit: Arc<dyn L7MitmAuditSink>,
    context: L7MitmAuditContext,
}

impl L7MitmBackendHealthAuditObserver {
    pub(crate) fn new(
        runtime: L7MitmRuntimeHandle,
        audit: Arc<dyn L7MitmAuditSink>,
        context: L7MitmAuditContext,
    ) -> Self {
        Self {
            runtime,
            audit,
            context,
        }
    }

    fn record_best_effort(&self, event: L7MitmAuditEvent) {
        let phase = event.phase();
        if let Err(error) = self.audit.record(event) {
            eprintln!("failed to store L7 MITM backend health audit event {phase:?}: {error}");
        }
    }
}

impl TcpHealthProbeObserver for L7MitmBackendHealthAuditObserver {
    fn record_tcp_health_success(&self) {
        if self.runtime.record_backend_health_success()
            == Some(L7MitmBackendHealthTransition::Recovered)
        {
            self.record_best_effort(self.context.backend_recovered_event());
        }
    }

    fn record_tcp_health_failure(&self, reason: String) {
        if let Some(L7MitmBackendHealthTransition::BecameUnhealthy {
            consecutive_failures,
            reason,
        }) = self.runtime.record_backend_health_failure(reason)
        {
            self.record_best_effort(
                self.context
                    .backend_unhealthy_event(reason, consecutive_failures),
            );
        }
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

fn readiness_probe_audit(readiness_probe: &L7MitmBackendHealthProbe) -> L7MitmReadinessProbeAudit {
    L7MitmReadinessProbeAudit {
        target: readiness_probe.target.to_string(),
        interval_ms: duration_millis(readiness_probe.interval),
        timeout_ms: duration_millis(readiness_probe.timeout),
        failure_threshold: readiness_probe.failure_threshold,
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
    use std::sync::Mutex;

    use probe_core::{
        EventKind, EventSubject, L7MitmAuditEvent, L7MitmAuditPhase, L7MitmExternalBackendAudit,
        L7MitmReadinessProbeAudit,
    };
    use storage::FjallSpool;
    use tempfile::tempdir;

    use super::*;
    use crate::l7_mitm::{
        L7MitmBackendHealthSnapshot, L7MitmPlaintextBridgeSnapshot, L7MitmRuntimeHandle,
    };

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

    #[test]
    fn backend_health_audit_observer_writes_durable_health_transitions()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = Arc::new(FjallSpool::open(temp.path())?);
        let metrics = PipelineRuntimeMetrics::default();
        let sink: Arc<dyn L7MitmAuditSink> = Arc::new(DurableL7MitmAuditSink::new_with_clock_seed(
            Arc::clone(&spool),
            "test-config",
            metrics.clone(),
            100,
        ));
        let runtime = L7MitmRuntimeHandle::for_test(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            2,
        );
        let observer = L7MitmBackendHealthAuditObserver::new(
            runtime,
            sink,
            L7MitmAuditContext::External(L7MitmExternalAuditContext::new(&health_probe())),
        );

        observer.record_tcp_health_failure("connection refused".to_string());
        observer.record_tcp_health_failure("connection refused".to_string());
        observer.record_tcp_health_success();

        let events = spool.read_export_batch("sink", 10)?;
        assert_eq!(events.len(), 2);
        let mut phases = Vec::new();
        for event in events {
            let envelope = serde_json::from_slice::<EventEnvelope>(event.payload.bytes())?;
            match envelope.kind() {
                EventKind::L7MitmAudit(event) => phases.push(event.phase()),
                kind => panic!("expected L7 MITM audit event, got {kind:?}"),
            }
        }
        assert_eq!(
            phases,
            vec![
                L7MitmAuditPhase::BackendUnhealthy,
                L7MitmAuditPhase::BackendRecovered
            ]
        );
        assert_eq!(metrics.snapshot().export_events_written, 2);
        Ok(())
    }

    #[test]
    fn backend_health_audit_records_only_health_transitions()
    -> Result<(), Box<dyn std::error::Error>> {
        let audit = Arc::new(RecordingL7MitmAuditSink::default());
        let audit_sink: Arc<dyn L7MitmAuditSink> = audit.clone();
        let runtime = L7MitmRuntimeHandle::for_test(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            2,
        );
        let observer = L7MitmBackendHealthAuditObserver::new(
            runtime,
            audit_sink,
            L7MitmAuditContext::External(L7MitmExternalAuditContext::new(&health_probe())),
        );

        observer.record_tcp_health_failure("connection refused".to_string());
        observer.record_tcp_health_failure("connection refused".to_string());
        observer.record_tcp_health_failure("connection refused".to_string());
        observer.record_tcp_health_success();
        observer.record_tcp_health_success();

        let events = audit.events();
        assert_eq!(
            events
                .iter()
                .map(L7MitmAuditEvent::phase)
                .collect::<Vec<_>>(),
            vec![
                L7MitmAuditPhase::BackendUnhealthy,
                L7MitmAuditPhase::BackendRecovered
            ]
        );
        match &events[0] {
            L7MitmAuditEvent::External {
                event:
                    L7MitmExternalBackendAudit::BackendUnhealthy {
                        consecutive_failures,
                        reason,
                        ..
                    },
            } => {
                assert_eq!(*consecutive_failures, 2);
                assert_eq!(reason, "connection refused");
            }
            event => panic!("expected external unhealthy audit event, got {event:?}"),
        }
        Ok(())
    }

    #[test]
    fn backend_health_audit_records_managed_process_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let audit = Arc::new(RecordingL7MitmAuditSink::default());
        let audit_sink: Arc<dyn L7MitmAuditSink> = audit.clone();
        let process = TransparentInterceptionMitmManagedProcessPlan {
            program: "/usr/local/bin/traffic-probe-mitm-proxy".into(),
            args: vec!["--listen".to_string(), "127.0.0.1:15002".to_string()],
            working_dir: None,
        };
        let runtime = L7MitmRuntimeHandle::for_test(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            1,
        );
        let observer = L7MitmBackendHealthAuditObserver::new(
            runtime,
            audit_sink,
            L7MitmAuditContext::ManagedProcess(L7MitmManagedProcessAuditContext::new(
                &process,
                &health_probe(),
                Pid::from_raw(42),
            )),
        );

        observer.record_tcp_health_failure("connection refused".to_string());

        let events = audit.events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            L7MitmAuditEvent::ManagedProcess {
                event:
                    L7MitmManagedProcessBackendAudit::BackendUnhealthy {
                        consecutive_failures,
                        reason,
                        process,
                        ..
                    },
            } => {
                assert_eq!(*consecutive_failures, 1);
                assert_eq!(reason, "connection refused");
                assert_eq!(process.args_count, 2);
                assert_eq!(process.process_group, Some(42));
            }
            event => panic!("expected managed-process unhealthy audit event, got {event:?}"),
        }
        Ok(())
    }

    fn external_health_probe_started_event() -> L7MitmAuditEvent {
        L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendHealthProbeStarted {
                readiness_probe: readiness_probe_audit(),
            },
        }
    }

    fn health_probe() -> L7MitmBackendHealthProbe {
        L7MitmBackendHealthProbe {
            target: "127.0.0.1:15002".parse().expect("test target should parse"),
            interval: Duration::from_secs(1),
            timeout: Duration::from_millis(100),
            failure_threshold: 2,
        }
    }

    fn readiness_probe_audit() -> L7MitmReadinessProbeAudit {
        L7MitmReadinessProbeAudit {
            target: "127.0.0.1:15002".to_string(),
            interval_ms: 1_000,
            timeout_ms: 100,
            failure_threshold: 2,
        }
    }

    #[derive(Default)]
    struct RecordingL7MitmAuditSink {
        events: Mutex<Vec<L7MitmAuditEvent>>,
    }

    impl RecordingL7MitmAuditSink {
        fn events(&self) -> Vec<L7MitmAuditEvent> {
            self.events
                .lock()
                .expect("test audit events should not be poisoned")
                .clone()
        }
    }

    impl L7MitmAuditSink for RecordingL7MitmAuditSink {
        fn record(&self, event: L7MitmAuditEvent) -> Result<(), String> {
            self.events
                .lock()
                .expect("test audit events should not be poisoned")
                .push(event);
            Ok(())
        }
    }
}

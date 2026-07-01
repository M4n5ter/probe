use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use capture::CapturePoll;
use probe_core::{
    ConnectionEnforcementSurface, EnforcementExecutionEvidence, EnforcementOutcome, EventEnvelope,
    EventKind, ProxySideEnforcementSurface,
};
use serde::Serialize;

const ENFORCEMENT_EXECUTION_RUNTIME_SURFACE_COUNT: usize = 2;
const ENFORCEMENT_EXECUTION_RUNTIME_SURFACES: [EnforcementExecutionRuntimeSurface;
    ENFORCEMENT_EXECUTION_RUNTIME_SURFACE_COUNT] = [
    EnforcementExecutionRuntimeSurface::ConnectionBackendLinuxSocketDestroy,
    EnforcementExecutionRuntimeSurface::ProxySideHookL7Mitm,
];

#[derive(Debug, Clone, Default)]
pub struct PipelineRuntimeMetrics {
    inner: Arc<PipelineRuntimeMetricsInner>,
}

#[derive(Debug, Default)]
struct PipelineRuntimeMetricsInner {
    capture_poll_events: AtomicCounter,
    capture_poll_progress: AtomicCounter,
    capture_poll_idle: AtomicCounter,
    capture_poll_finished: AtomicCounter,
    capture_events_read: AtomicCounter,
    ingress_records_journaled: AtomicCounter,
    ingress_records_recovered: AtomicCounter,
    ingress_records_processed: AtomicCounter,
    export_events_written: AtomicCounter,
    degraded_event_envelopes: AtomicCounter,
    gap_event_envelopes: AtomicCounter,
    capture_loss_events: AtomicCounter,
    capture_lost_events: AtomicCounter,
    policy_evaluations: AtomicCounter,
    policy_selector_misses: AtomicCounter,
    policy_alerts: AtomicCounter,
    policy_verdicts: AtomicCounter,
    policy_errors: AtomicCounter,
    policy_disabled: AtomicCounter,
    enforcement_disabled: AtomicCounter,
    enforcement_audit_only: AtomicCounter,
    enforcement_dry_run: AtomicCounter,
    enforcement_selector_miss: AtomicCounter,
    enforcement_unsupported: AtomicCounter,
    enforcement_failed: AtomicCounter,
    enforcement_delegated: AtomicCounter,
    enforcement_applied: AtomicCounter,
    enforcement_execution_surfaces: [AtomicCounter; ENFORCEMENT_EXECUTION_RUNTIME_SURFACE_COUNT],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PipelineRuntimeMetricsSnapshot {
    pub capture_polls: CapturePollRuntimeMetricsSnapshot,
    pub capture_events_read: u64,
    pub ingress_records_journaled: u64,
    pub ingress_records_recovered: u64,
    pub ingress_records_processed: u64,
    pub export_events_written: u64,
    pub events: EventRuntimeMetricsSnapshot,
    pub capture_loss: CaptureLossRuntimeMetricsSnapshot,
    pub policy: PolicyRuntimeMetricsSnapshot,
    pub enforcement: EnforcementRuntimeMetricsSnapshot,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CapturePollRuntimeMetricsSnapshot {
    pub total: u64,
    pub events: u64,
    pub progress: u64,
    pub idle: u64,
    pub finished: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EventRuntimeMetricsSnapshot {
    pub total: u64,
    pub degraded: u64,
    pub gaps: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CaptureLossRuntimeMetricsSnapshot {
    pub events: u64,
    pub lost_events: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PolicyRuntimeMetricsSnapshot {
    pub evaluations: u64,
    pub selector_misses: u64,
    pub alerts: u64,
    pub verdicts: u64,
    pub errors: u64,
    pub disabled: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EnforcementRuntimeMetricsSnapshot {
    pub decisions: u64,
    pub disabled: u64,
    pub audit_only: u64,
    pub dry_run: u64,
    pub selector_miss: u64,
    pub unsupported: u64,
    pub failed: u64,
    pub delegated: u64,
    pub applied: u64,
    pub execution: EnforcementExecutionRuntimeMetricsSnapshot,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EnforcementExecutionRuntimeMetricsSnapshot {
    pub connection_backend: ConnectionBackendExecutionRuntimeMetricsSnapshot,
    pub proxy_side_hook: ProxySideHookExecutionRuntimeMetricsSnapshot,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ConnectionBackendExecutionRuntimeMetricsSnapshot {
    pub decisions: u64,
    pub linux_socket_destroy: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ProxySideHookExecutionRuntimeMetricsSnapshot {
    pub decisions: u64,
    pub l7_mitm: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementExecutionRuntimeSurfaceCount {
    pub surface: EnforcementExecutionRuntimeSurface,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementExecutionRuntimeSurface {
    ConnectionBackendLinuxSocketDestroy,
    ProxySideHookL7Mitm,
}

impl EnforcementExecutionRuntimeSurface {
    pub fn kind_label(self) -> &'static str {
        match self {
            Self::ConnectionBackendLinuxSocketDestroy => "connection_backend",
            Self::ProxySideHookL7Mitm => "proxy_side_hook",
        }
    }

    pub fn surface_label(self) -> &'static str {
        match self {
            Self::ConnectionBackendLinuxSocketDestroy => "linux_socket_destroy",
            Self::ProxySideHookL7Mitm => "l7_mitm",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::ConnectionBackendLinuxSocketDestroy => 0,
            Self::ProxySideHookL7Mitm => 1,
        }
    }

    fn count(self, snapshot: EnforcementExecutionRuntimeMetricsSnapshot) -> u64 {
        match self {
            Self::ConnectionBackendLinuxSocketDestroy => {
                snapshot.connection_backend.linux_socket_destroy
            }
            Self::ProxySideHookL7Mitm => snapshot.proxy_side_hook.l7_mitm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnforcementDecisionMetric {
    outcome: EnforcementOutcome,
    execution_surface: Option<EnforcementExecutionRuntimeSurface>,
}

impl EnforcementDecisionMetric {
    pub(crate) fn from_decision_parts(
        outcome: EnforcementOutcome,
        execution: Option<&EnforcementExecutionEvidence>,
    ) -> Self {
        Self {
            outcome,
            execution_surface: execution.map(EnforcementExecutionRuntimeSurface::from_evidence),
        }
    }
}

impl EnforcementExecutionRuntimeMetricsSnapshot {
    pub fn surface_counts(
        &self,
    ) -> impl Iterator<Item = EnforcementExecutionRuntimeSurfaceCount> + '_ {
        ENFORCEMENT_EXECUTION_RUNTIME_SURFACES
            .into_iter()
            .map(|surface| EnforcementExecutionRuntimeSurfaceCount {
                surface,
                count: surface.count(*self),
            })
    }

    fn add_surface_count(&mut self, surface: EnforcementExecutionRuntimeSurface, count: u64) {
        match surface {
            EnforcementExecutionRuntimeSurface::ConnectionBackendLinuxSocketDestroy => {
                self.connection_backend.decisions =
                    self.connection_backend.decisions.saturating_add(count);
                self.connection_backend.linux_socket_destroy = count;
            }
            EnforcementExecutionRuntimeSurface::ProxySideHookL7Mitm => {
                self.proxy_side_hook.decisions =
                    self.proxy_side_hook.decisions.saturating_add(count);
                self.proxy_side_hook.l7_mitm = count;
            }
        }
    }
}

impl EnforcementExecutionRuntimeSurface {
    fn from_evidence(execution: &EnforcementExecutionEvidence) -> Self {
        match execution {
            EnforcementExecutionEvidence::ConnectionBackend { evidence } => {
                match evidence.surface() {
                    ConnectionEnforcementSurface::LinuxSocketDestroy => {
                        Self::ConnectionBackendLinuxSocketDestroy
                    }
                }
            }
            EnforcementExecutionEvidence::ProxySideHook { surface, .. } => match surface {
                ProxySideEnforcementSurface::L7Mitm => Self::ProxySideHookL7Mitm,
            },
        }
    }
}

impl PipelineRuntimeMetrics {
    pub fn snapshot(&self) -> PipelineRuntimeMetricsSnapshot {
        let capture_polls = self.capture_poll_snapshot();
        let enforcement = self.enforcement_snapshot();
        let export_events_written = self.inner.export_events_written.load();
        PipelineRuntimeMetricsSnapshot {
            capture_polls,
            capture_events_read: self.inner.capture_events_read.load(),
            ingress_records_journaled: self.inner.ingress_records_journaled.load(),
            ingress_records_recovered: self.inner.ingress_records_recovered.load(),
            ingress_records_processed: self.inner.ingress_records_processed.load(),
            export_events_written,
            events: EventRuntimeMetricsSnapshot {
                total: export_events_written,
                degraded: self.inner.degraded_event_envelopes.load(),
                gaps: self.inner.gap_event_envelopes.load(),
            },
            capture_loss: CaptureLossRuntimeMetricsSnapshot {
                events: self.inner.capture_loss_events.load(),
                lost_events: self.inner.capture_lost_events.load(),
            },
            policy: PolicyRuntimeMetricsSnapshot {
                evaluations: self.inner.policy_evaluations.load(),
                selector_misses: self.inner.policy_selector_misses.load(),
                alerts: self.inner.policy_alerts.load(),
                verdicts: self.inner.policy_verdicts.load(),
                errors: self.inner.policy_errors.load(),
                disabled: self.inner.policy_disabled.load(),
            },
            enforcement,
        }
    }

    fn capture_poll_snapshot(&self) -> CapturePollRuntimeMetricsSnapshot {
        let events = self.inner.capture_poll_events.load();
        let progress = self.inner.capture_poll_progress.load();
        let idle = self.inner.capture_poll_idle.load();
        let finished = self.inner.capture_poll_finished.load();
        CapturePollRuntimeMetricsSnapshot {
            total: [events, progress, idle, finished]
                .into_iter()
                .fold(0_u64, u64::saturating_add),
            events,
            progress,
            idle,
            finished,
        }
    }

    fn enforcement_snapshot(&self) -> EnforcementRuntimeMetricsSnapshot {
        let disabled = self.inner.enforcement_disabled.load();
        let audit_only = self.inner.enforcement_audit_only.load();
        let dry_run = self.inner.enforcement_dry_run.load();
        let selector_miss = self.inner.enforcement_selector_miss.load();
        let unsupported = self.inner.enforcement_unsupported.load();
        let failed = self.inner.enforcement_failed.load();
        let delegated = self.inner.enforcement_delegated.load();
        let applied = self.inner.enforcement_applied.load();
        EnforcementRuntimeMetricsSnapshot {
            decisions: [
                disabled,
                audit_only,
                dry_run,
                selector_miss,
                unsupported,
                failed,
                delegated,
                applied,
            ]
            .into_iter()
            .fold(0_u64, u64::saturating_add),
            disabled,
            audit_only,
            dry_run,
            selector_miss,
            unsupported,
            failed,
            delegated,
            applied,
            execution: self.enforcement_execution_snapshot(),
        }
    }

    fn enforcement_execution_snapshot(&self) -> EnforcementExecutionRuntimeMetricsSnapshot {
        let mut snapshot = EnforcementExecutionRuntimeMetricsSnapshot::default();
        for surface in ENFORCEMENT_EXECUTION_RUNTIME_SURFACES {
            snapshot.add_surface_count(
                surface,
                self.inner.enforcement_execution_surfaces[surface.index()].load(),
            );
        }
        snapshot
    }

    pub(crate) fn record_capture_poll(&self, poll: &CapturePoll) {
        match poll {
            CapturePoll::Event(_) => self.inner.capture_poll_events.increment(),
            CapturePoll::Progress => self.inner.capture_poll_progress.increment(),
            CapturePoll::Idle => self.inner.capture_poll_idle.increment(),
            CapturePoll::Finished => self.inner.capture_poll_finished.increment(),
        }
    }

    pub(crate) fn record_capture_event_read(&self) {
        self.inner.capture_events_read.increment();
    }

    pub(crate) fn record_ingress_record_journaled(&self) {
        self.inner.ingress_records_journaled.increment();
    }

    pub(crate) fn record_ingress_record_recovered(&self) {
        self.inner.ingress_records_recovered.increment();
    }

    pub(crate) fn record_ingress_record_processed(&self) {
        self.inner.ingress_records_processed.increment();
    }

    pub(crate) fn record_export_event_envelope(&self, envelope: &EventEnvelope) {
        self.inner.export_events_written.increment();
        if envelope.degraded() {
            self.inner.degraded_event_envelopes.increment();
        }
        if matches!(envelope.kind(), EventKind::Gap(_)) {
            self.inner.gap_event_envelopes.increment();
        }
    }

    pub(crate) fn record_capture_loss(&self, lost_events: u64) {
        self.inner.capture_loss_events.increment();
        self.inner.capture_lost_events.add(lost_events);
    }

    pub(crate) fn record_policy_evaluation(&self) {
        self.inner.policy_evaluations.increment();
    }

    pub(crate) fn record_policy_selector_miss(&self) {
        self.inner.policy_selector_misses.increment();
    }

    pub(crate) fn record_policy_alert(&self) {
        self.inner.policy_alerts.increment();
    }

    pub(crate) fn record_policy_verdict(&self) {
        self.inner.policy_verdicts.increment();
    }

    pub(crate) fn record_policy_error(&self) {
        self.inner.policy_errors.increment();
    }

    pub(crate) fn record_policy_disabled(&self) {
        self.inner.policy_disabled.increment();
    }

    pub(crate) fn record_enforcement_decision(&self, metric: EnforcementDecisionMetric) {
        if let Some(surface) = metric.execution_surface {
            self.inner.enforcement_execution_surfaces[surface.index()].increment();
        }
        match metric.outcome {
            EnforcementOutcome::Disabled => self.inner.enforcement_disabled.increment(),
            EnforcementOutcome::AuditOnly => self.inner.enforcement_audit_only.increment(),
            EnforcementOutcome::DryRun => self.inner.enforcement_dry_run.increment(),
            EnforcementOutcome::SelectorMiss => self.inner.enforcement_selector_miss.increment(),
            EnforcementOutcome::Unsupported => self.inner.enforcement_unsupported.increment(),
            EnforcementOutcome::Failed => self.inner.enforcement_failed.increment(),
            EnforcementOutcome::Delegated => self.inner.enforcement_delegated.increment(),
            EnforcementOutcome::Applied => self.inner.enforcement_applied.increment(),
        }
    }
}

#[derive(Debug, Default)]
struct AtomicCounter(AtomicU64);

impl AtomicCounter {
    fn increment(&self) {
        self.add(1);
    }

    fn add(&self, delta: u64) {
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(delta))
            });
    }

    fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_polls_sum_all_recorded_outcomes() {
        let metrics = PipelineRuntimeMetrics::default();

        metrics.record_capture_poll(&CapturePoll::event(capture_loss_event()));
        metrics.record_capture_poll(&CapturePoll::Progress);
        metrics.record_capture_poll(&CapturePoll::Idle);
        metrics.record_capture_poll(&CapturePoll::Finished);

        let polls = metrics.snapshot().capture_polls;

        assert_eq!(
            polls.total,
            polls.events + polls.progress + polls.idle + polls.finished
        );
        assert_eq!(polls.events, 1);
        assert_eq!(polls.progress, 1);
        assert_eq!(polls.idle, 1);
        assert_eq!(polls.finished, 1);
        assert_eq!(polls.total, 4);
    }

    #[test]
    fn enforcement_decisions_sum_all_recorded_outcomes() {
        let metrics = PipelineRuntimeMetrics::default();

        metrics.record_enforcement_decision(metric(EnforcementOutcome::Disabled, None));
        metrics.record_enforcement_decision(metric(EnforcementOutcome::AuditOnly, None));
        metrics.record_enforcement_decision(metric(EnforcementOutcome::DryRun, None));
        metrics.record_enforcement_decision(metric(EnforcementOutcome::SelectorMiss, None));
        metrics.record_enforcement_decision(metric(EnforcementOutcome::Unsupported, None));
        metrics.record_enforcement_decision(metric(EnforcementOutcome::Failed, None));
        metrics.record_enforcement_decision(metric(EnforcementOutcome::Delegated, None));
        metrics.record_enforcement_decision(metric(EnforcementOutcome::Applied, None));

        let enforcement = metrics.snapshot().enforcement;

        assert_eq!(
            enforcement.decisions,
            enforcement.disabled
                + enforcement.audit_only
                + enforcement.dry_run
                + enforcement.selector_miss
                + enforcement.unsupported
                + enforcement.failed
                + enforcement.delegated
                + enforcement.applied
        );
        assert_eq!(enforcement.decisions, 8);
    }

    #[test]
    fn enforcement_execution_metrics_count_backend_and_hook_surfaces() {
        let metrics = PipelineRuntimeMetrics::default();

        metrics.record_enforcement_decision(metric(
            EnforcementOutcome::Applied,
            Some(EnforcementExecutionRuntimeSurface::ConnectionBackendLinuxSocketDestroy),
        ));
        metrics.record_enforcement_decision(metric(
            EnforcementOutcome::Delegated,
            Some(EnforcementExecutionRuntimeSurface::ProxySideHookL7Mitm),
        ));

        let enforcement = metrics.snapshot().enforcement;

        assert_eq!(enforcement.applied, 1);
        assert_eq!(enforcement.delegated, 1);
        assert_eq!(enforcement.execution.connection_backend.decisions, 1);
        assert_eq!(
            enforcement
                .execution
                .connection_backend
                .linux_socket_destroy,
            1
        );
        assert_eq!(enforcement.execution.proxy_side_hook.decisions, 1);
        assert_eq!(enforcement.execution.proxy_side_hook.l7_mitm, 1);
    }

    #[test]
    fn capture_loss_sums_events_and_lost_events() {
        let metrics = PipelineRuntimeMetrics::default();

        metrics.record_capture_loss(2);
        metrics.record_capture_loss(5);

        let capture_loss = metrics.snapshot().capture_loss;

        assert_eq!(capture_loss.events, 2);
        assert_eq!(capture_loss.lost_events, 7);
    }

    fn capture_loss_event() -> capture::CaptureEvent {
        capture::CaptureEvent::Loss(capture::CapturedLoss {
            timestamp: probe_core::Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            origin: probe_core::CaptureOrigin::from_source(probe_core::CaptureSource::Replay),
            enforcement_evidence: probe_core::EnforcementEvidence::default(),
            loss: probe_core::CaptureLoss {
                lost_events: 1,
                reason: "test loss".to_string(),
            },
        })
    }

    fn metric(
        outcome: EnforcementOutcome,
        execution_surface: Option<EnforcementExecutionRuntimeSurface>,
    ) -> EnforcementDecisionMetric {
        EnforcementDecisionMetric {
            outcome,
            execution_surface,
        }
    }
}

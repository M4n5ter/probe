use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use probe_core::EnforcementOutcome;
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct PipelineRuntimeMetrics {
    inner: Arc<PipelineRuntimeMetricsInner>,
}

#[derive(Debug, Default)]
struct PipelineRuntimeMetricsInner {
    capture_events_read: AtomicCounter,
    ingress_records_journaled: AtomicCounter,
    ingress_records_recovered: AtomicCounter,
    ingress_records_processed: AtomicCounter,
    export_events_written: AtomicCounter,
    capture_loss_events: AtomicCounter,
    capture_lost_events: AtomicCounter,
    policy_evaluations: AtomicCounter,
    policy_selector_misses: AtomicCounter,
    policy_alerts: AtomicCounter,
    policy_verdicts: AtomicCounter,
    policy_errors: AtomicCounter,
    enforcement_disabled: AtomicCounter,
    enforcement_audit_only: AtomicCounter,
    enforcement_dry_run: AtomicCounter,
    enforcement_selector_miss: AtomicCounter,
    enforcement_unsupported: AtomicCounter,
    enforcement_failed: AtomicCounter,
    enforcement_applied: AtomicCounter,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PipelineRuntimeMetricsSnapshot {
    pub capture_events_read: u64,
    pub ingress_records_journaled: u64,
    pub ingress_records_recovered: u64,
    pub ingress_records_processed: u64,
    pub export_events_written: u64,
    pub capture_loss: CaptureLossRuntimeMetricsSnapshot,
    pub policy: PolicyRuntimeMetricsSnapshot,
    pub enforcement: EnforcementRuntimeMetricsSnapshot,
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
    pub applied: u64,
}

impl PipelineRuntimeMetrics {
    pub fn snapshot(&self) -> PipelineRuntimeMetricsSnapshot {
        let enforcement = self.enforcement_snapshot();
        PipelineRuntimeMetricsSnapshot {
            capture_events_read: self.inner.capture_events_read.load(),
            ingress_records_journaled: self.inner.ingress_records_journaled.load(),
            ingress_records_recovered: self.inner.ingress_records_recovered.load(),
            ingress_records_processed: self.inner.ingress_records_processed.load(),
            export_events_written: self.inner.export_events_written.load(),
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
            },
            enforcement,
        }
    }

    fn enforcement_snapshot(&self) -> EnforcementRuntimeMetricsSnapshot {
        let disabled = self.inner.enforcement_disabled.load();
        let audit_only = self.inner.enforcement_audit_only.load();
        let dry_run = self.inner.enforcement_dry_run.load();
        let selector_miss = self.inner.enforcement_selector_miss.load();
        let unsupported = self.inner.enforcement_unsupported.load();
        let failed = self.inner.enforcement_failed.load();
        let applied = self.inner.enforcement_applied.load();
        EnforcementRuntimeMetricsSnapshot {
            decisions: [
                disabled,
                audit_only,
                dry_run,
                selector_miss,
                unsupported,
                failed,
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
            applied,
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

    pub(crate) fn record_export_event_written(&self) {
        self.inner.export_events_written.increment();
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

    pub(crate) fn record_enforcement_decision(&self, outcome: EnforcementOutcome) {
        match outcome {
            EnforcementOutcome::Disabled => self.inner.enforcement_disabled.increment(),
            EnforcementOutcome::AuditOnly => self.inner.enforcement_audit_only.increment(),
            EnforcementOutcome::DryRun => self.inner.enforcement_dry_run.increment(),
            EnforcementOutcome::SelectorMiss => self.inner.enforcement_selector_miss.increment(),
            EnforcementOutcome::Unsupported => self.inner.enforcement_unsupported.increment(),
            EnforcementOutcome::Failed => self.inner.enforcement_failed.increment(),
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
    fn enforcement_decisions_sum_all_recorded_outcomes() {
        let metrics = PipelineRuntimeMetrics::default();

        metrics.record_enforcement_decision(EnforcementOutcome::Disabled);
        metrics.record_enforcement_decision(EnforcementOutcome::AuditOnly);
        metrics.record_enforcement_decision(EnforcementOutcome::DryRun);
        metrics.record_enforcement_decision(EnforcementOutcome::SelectorMiss);
        metrics.record_enforcement_decision(EnforcementOutcome::Unsupported);
        metrics.record_enforcement_decision(EnforcementOutcome::Failed);
        metrics.record_enforcement_decision(EnforcementOutcome::Applied);

        let enforcement = metrics.snapshot().enforcement;

        assert_eq!(
            enforcement.decisions,
            enforcement.disabled
                + enforcement.audit_only
                + enforcement.dry_run
                + enforcement.selector_miss
                + enforcement.unsupported
                + enforcement.failed
                + enforcement.applied
        );
        assert_eq!(enforcement.decisions, 7);
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
}

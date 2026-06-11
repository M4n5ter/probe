use probe_core::RuntimeMode;
use runtime::{CapturePlanMode, RuntimePlan};

use super::{
    ExporterStatusSnapshot, HealthSnapshot, SpoolStatusSnapshot,
    policy::{PolicyStatusMode, PolicyStatusSnapshot},
};

pub(super) fn health_snapshot(
    plan: &RuntimePlan,
    spool: &SpoolStatusSnapshot,
    exporters: &[ExporterStatusSnapshot],
    policy: &PolicyStatusSnapshot,
) -> HealthSnapshot {
    fold_health_contributions(
        std::iter::once(capture_health_contribution(plan))
            .chain(std::iter::once(spool_health_contribution(spool)))
            .chain(exporters.iter().map(exporter_health_contribution))
            .chain(std::iter::once(policy_health_contribution(policy))),
    )
}

fn capture_health_contribution(plan: &RuntimePlan) -> HealthContribution {
    if plan.capture.mode == CapturePlanMode::Unavailable {
        return HealthContribution::unavailable(
            plan.capture
                .reason
                .clone()
                .unwrap_or_else(|| "capture plan is unavailable".to_string()),
        );
    }
    HealthContribution::available()
}

fn spool_health_contribution(spool: &SpoolStatusSnapshot) -> HealthContribution {
    match spool.mode {
        RuntimeMode::Available => HealthContribution::available(),
        RuntimeMode::Degraded => HealthContribution::degraded(
            spool
                .reason
                .clone()
                .unwrap_or_else(|| "spool status is degraded".to_string()),
        ),
        RuntimeMode::Unavailable => HealthContribution::unavailable(
            spool
                .reason
                .clone()
                .unwrap_or_else(|| "spool is unavailable".to_string()),
        ),
    }
}

fn exporter_health_contribution(exporter: &ExporterStatusSnapshot) -> HealthContribution {
    match exporter.mode {
        RuntimeMode::Available => HealthContribution::available(),
        RuntimeMode::Degraded => HealthContribution::degraded(exporter_reason(exporter)),
        RuntimeMode::Unavailable => HealthContribution::unavailable(exporter_reason(exporter)),
    }
}

fn exporter_reason(exporter: &ExporterStatusSnapshot) -> String {
    exporter.reason.clone().map_or_else(
        || format!("exporter {} status is {:?}", exporter.id, exporter.mode),
        |reason| format!("exporter {}: {reason}", exporter.id),
    )
}

fn policy_health_contribution(policy: &PolicyStatusSnapshot) -> HealthContribution {
    match policy.mode {
        PolicyStatusMode::Inactive => HealthContribution::available(),
        PolicyStatusMode::MetadataOnly => {
            HealthContribution::degraded(policy_reason(policy, "policy status is metadata-only"))
        }
        PolicyStatusMode::Unavailable => {
            HealthContribution::unavailable(policy_reason(policy, "policy is unavailable"))
        }
    }
}

fn policy_reason(policy: &PolicyStatusSnapshot, fallback: &str) -> String {
    policy.reason.clone().map_or_else(
        || format!("policy: {fallback}"),
        |reason| format!("policy: {reason}"),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HealthContribution {
    mode: RuntimeMode,
    reason: Option<String>,
}

impl HealthContribution {
    fn available() -> Self {
        Self {
            mode: RuntimeMode::Available,
            reason: None,
        }
    }

    fn degraded(reason: impl Into<String>) -> Self {
        Self {
            mode: RuntimeMode::Degraded,
            reason: Some(reason.into()),
        }
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            mode: RuntimeMode::Unavailable,
            reason: Some(reason.into()),
        }
    }
}

fn fold_health_contributions(
    contributions: impl IntoIterator<Item = HealthContribution>,
) -> HealthSnapshot {
    let mut mode = RuntimeMode::Available;
    let mut reasons = Vec::new();

    for contribution in contributions {
        mode = merge_health_mode(mode, contribution.mode);
        if let Some(reason) = contribution.reason {
            reasons.push(reason);
        }
    }

    HealthSnapshot { mode, reasons }
}

fn merge_health_mode(current: RuntimeMode, next: RuntimeMode) -> RuntimeMode {
    match (current, next) {
        (RuntimeMode::Unavailable, _) | (_, RuntimeMode::Unavailable) => RuntimeMode::Unavailable,
        (RuntimeMode::Degraded, _) | (_, RuntimeMode::Degraded) => RuntimeMode::Degraded,
        (RuntimeMode::Available, RuntimeMode::Available) => RuntimeMode::Available,
    }
}

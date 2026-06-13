use probe_core::RuntimeMode;
use runtime::{CapturePlanMode, RuntimePlan};

use super::super::{
    enforcement::{EnforcementPolicySourceStatusSnapshot, EnforcementStatusSnapshot},
    export::ExporterStatusSnapshot,
    policy::{PolicyStatusMode, PolicyStatusSnapshot},
    snapshot::{HealthSnapshot, SpoolStatusSnapshot},
    tls::TlsStatusSnapshot,
};

pub(in crate::status) fn health_snapshot(
    plan: &RuntimePlan,
    spool: &SpoolStatusSnapshot,
    exporters: &[ExporterStatusSnapshot],
    policy: &PolicyStatusSnapshot,
    enforcement: &EnforcementStatusSnapshot,
    tls: &TlsStatusSnapshot,
) -> HealthSnapshot {
    fold_health_contributions(
        std::iter::once(capture_health_contribution(plan))
            .chain(std::iter::once(spool_health_contribution(spool)))
            .chain(exporters.iter().map(exporter_health_contribution))
            .chain(std::iter::once(policy_health_contribution(policy)))
            .chain(std::iter::once(enforcement_health_contribution(
                enforcement,
            )))
            .chain(std::iter::once(tls_health_contribution(tls))),
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

fn enforcement_health_contribution(enforcement: &EnforcementStatusSnapshot) -> HealthContribution {
    match &enforcement.policy.source {
        EnforcementPolicySourceStatusSnapshot::NotConfigured
        | EnforcementPolicySourceStatusSnapshot::Loaded { .. } => HealthContribution::available(),
        EnforcementPolicySourceStatusSnapshot::LocalMetadata { .. }
        | EnforcementPolicySourceStatusSnapshot::RemoteConfigured { .. } => {
            HealthContribution::degraded(enforcement_policy_reason(
                enforcement,
                "enforcement policy status is metadata-only",
            ))
        }
        EnforcementPolicySourceStatusSnapshot::Unavailable { .. } => {
            HealthContribution::unavailable(enforcement_policy_reason(
                enforcement,
                "enforcement policy is unavailable",
            ))
        }
    }
}

fn enforcement_policy_reason(enforcement: &EnforcementStatusSnapshot, fallback: &str) -> String {
    let reason = match &enforcement.policy.source {
        EnforcementPolicySourceStatusSnapshot::LocalMetadata { reason, .. }
        | EnforcementPolicySourceStatusSnapshot::RemoteConfigured { reason, .. }
        | EnforcementPolicySourceStatusSnapshot::Unavailable { reason } => Some(reason.as_str()),
        EnforcementPolicySourceStatusSnapshot::NotConfigured
        | EnforcementPolicySourceStatusSnapshot::Loaded { .. } => None,
    };
    reason.map_or_else(
        || format!("enforcement policy: {fallback}"),
        |reason| format!("enforcement policy: {reason}"),
    )
}

fn tls_health_contribution(tls: &TlsStatusSnapshot) -> HealthContribution {
    let Some(runtime) = &tls.plaintext.runtime else {
        return HealthContribution::available();
    };
    match runtime.mode {
        crate::tls_plaintext::TlsPlaintextRuntimeMode::Disabled => HealthContribution::degraded(
            runtime
                .reason
                .clone()
                .unwrap_or_else(|| "TLS plaintext runtime provider is disabled".to_string()),
        ),
        crate::tls_plaintext::TlsPlaintextRuntimeMode::Pending => {
            HealthContribution::degraded(runtime.reason.clone().unwrap_or_else(|| {
                "TLS plaintext runtime provider has not been built yet".to_string()
            }))
        }
        crate::tls_plaintext::TlsPlaintextRuntimeMode::NotConfigured
        | crate::tls_plaintext::TlsPlaintextRuntimeMode::Enabled => HealthContribution::available(),
    }
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

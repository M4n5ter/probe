use pipeline::CaptureLossRuntimeMetricsSnapshot;
use probe_core::RuntimeMode;
use runtime::{CaptureEvidenceMode, CapturePlanMode};

use crate::l7_mitm::{L7MitmBackendHealthMode, L7MitmPlaintextBridgeMode};
use crate::transparent_interception::{
    TransparentProxyHealthProbeMode, TransparentProxyRuntimeMode,
};

use super::super::{
    capture::CaptureStatusSnapshot,
    enforcement::{EnforcementPolicySourceStatusSnapshot, EnforcementStatusSnapshot},
    export::ExporterStatusSnapshot,
    policy::{PolicyStatusMode, PolicyStatusSnapshot},
    snapshot::HealthSnapshot,
    spool::SpoolStatusSnapshot,
    tls::TlsStatusSnapshot,
};

pub(in crate::status) fn health_snapshot(
    capture: &CaptureStatusSnapshot,
    spool: &SpoolStatusSnapshot,
    exporters: &[ExporterStatusSnapshot],
    policy: &PolicyStatusSnapshot,
    enforcement: &EnforcementStatusSnapshot,
    tls: &TlsStatusSnapshot,
    capture_loss: Option<&CaptureLossRuntimeMetricsSnapshot>,
) -> HealthSnapshot {
    fold_health_contributions(
        std::iter::once(capture_health_contribution(capture))
            .chain(std::iter::once(capture_loss_health_contribution(
                capture_loss,
            )))
            .chain(std::iter::once(spool_health_contribution(spool)))
            .chain(exporters.iter().map(exporter_health_contribution))
            .chain(std::iter::once(policy_health_contribution(policy)))
            .chain(std::iter::once(enforcement_health_contribution(
                enforcement,
            )))
            .chain(std::iter::once(l7_mitm_health_contribution(enforcement)))
            .chain(std::iter::once(transparent_proxy_health_contribution(
                enforcement,
            )))
            .chain(std::iter::once(tls_health_contribution(tls))),
    )
}

fn capture_health_contribution(capture: &CaptureStatusSnapshot) -> HealthContribution {
    if capture.mode == CapturePlanMode::Unavailable {
        return HealthContribution::unavailable(
            capture
                .reason
                .clone()
                .unwrap_or_else(|| "capture plan is unavailable".to_string()),
        );
    }
    if capture.evidence_mode == Some(CaptureEvidenceMode::BestEffort) {
        return HealthContribution::degraded(
            capture
                .evidence_reason
                .clone()
                .unwrap_or_else(|| "capture evidence is best-effort".to_string()),
        );
    }
    HealthContribution::available()
}

fn capture_loss_health_contribution(
    loss: Option<&CaptureLossRuntimeMetricsSnapshot>,
) -> HealthContribution {
    let Some(loss) = loss else {
        return HealthContribution::available();
    };
    if loss.events == 0 && loss.lost_events == 0 {
        return HealthContribution::available();
    }
    HealthContribution::degraded(format!(
        "capture provider reported {} loss event(s) covering {} lost event(s)",
        loss.events, loss.lost_events
    ))
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
        PolicyStatusMode::Inactive | PolicyStatusMode::Available => HealthContribution::available(),
        PolicyStatusMode::MetadataOnly => {
            HealthContribution::degraded(policy_reason(policy, "policy status is metadata-only"))
        }
        PolicyStatusMode::Degraded => {
            HealthContribution::degraded(policy_reason(policy, "policy status is degraded"))
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

fn l7_mitm_health_contribution(enforcement: &EnforcementStatusSnapshot) -> HealthContribution {
    let Some(runtime) = &enforcement.interception.runtime_l7_mitm else {
        return HealthContribution::available();
    };
    let mut reasons = Vec::new();
    let health = &runtime.backend_health;
    if health.mode == L7MitmBackendHealthMode::Unhealthy {
        let reason = health
            .last_failure_reason
            .as_deref()
            .unwrap_or("probe failed");
        reasons.push(format!(
            "L7 MITM backend health probe unhealthy after {} consecutive failure(s): {reason}",
            health.consecutive_failures
        ));
    }
    if runtime.plaintext_bridge.mode == L7MitmPlaintextBridgeMode::DisabledAfterError {
        let reason = runtime
            .plaintext_bridge
            .disable_reason
            .as_deref()
            .unwrap_or("bridge provider disabled");
        reasons.push(format!("L7 MITM plaintext bridge degraded: {reason}"));
    }
    if reasons.is_empty() {
        HealthContribution::available()
    } else {
        HealthContribution::degraded(reasons.join("; "))
    }
}

fn transparent_proxy_health_contribution(
    enforcement: &EnforcementStatusSnapshot,
) -> HealthContribution {
    let Some(proxy) = &enforcement.interception.runtime_proxy else {
        return HealthContribution::available();
    };
    if proxy.mode == TransparentProxyRuntimeMode::Failed {
        return HealthContribution::unavailable(format!(
            "transparent proxy failed: {} listener failure(s)",
            proxy.listener_failures
        ));
    }
    let mut reasons = Vec::new();
    if proxy.mode == TransparentProxyRuntimeMode::Degraded {
        reasons.push(format!(
            "transparent proxy degraded: {} listener failure(s)",
            proxy.listener_failures
        ));
    }
    if proxy.health_probe.mode == TransparentProxyHealthProbeMode::Unhealthy {
        let reason = proxy
            .health_probe
            .last_failure_reason
            .as_deref()
            .unwrap_or("probe failed");
        reasons.push(format!(
            "transparent proxy health probe unhealthy after {} consecutive failure(s): {reason}",
            proxy.health_probe.consecutive_failures
        ));
    }
    if reasons.is_empty() {
        HealthContribution::available()
    } else {
        HealthContribution::degraded(reasons.join("; "))
    }
}

fn tls_health_contribution(tls: &TlsStatusSnapshot) -> HealthContribution {
    let Some(runtime) = &tls.plaintext.instrumentation.runtime else {
        return HealthContribution::available();
    };
    tls_plaintext_runtime_health_contribution(runtime)
}

fn tls_plaintext_runtime_health_contribution(
    runtime: &crate::tls_plaintext::TlsPlaintextRuntimeSnapshot,
) -> HealthContribution {
    match runtime.mode {
        crate::tls_plaintext::TlsPlaintextRuntimeMode::Disabled => HealthContribution::degraded(
            runtime
                .reason
                .clone()
                .unwrap_or_else(|| "TLS plaintext instrumentation is disabled".to_string()),
        ),
        crate::tls_plaintext::TlsPlaintextRuntimeMode::Pending => {
            HealthContribution::degraded(runtime.reason.clone().unwrap_or_else(|| {
                "TLS plaintext instrumentation has not been built yet".to_string()
            }))
        }
        crate::tls_plaintext::TlsPlaintextRuntimeMode::Enabled => {
            match runtime.reconcile_health.mode() {
                crate::tls_plaintext::TlsPlaintextReconcileHealthMode::Available => {
                    HealthContribution::available()
                }
                crate::tls_plaintext::TlsPlaintextReconcileHealthMode::Degraded => {
                    HealthContribution::degraded(tls_reconcile_health_reason(runtime))
                }
            }
        }
        crate::tls_plaintext::TlsPlaintextRuntimeMode::NotConfigured => {
            HealthContribution::available()
        }
    }
}

fn tls_reconcile_health_reason(
    runtime: &crate::tls_plaintext::TlsPlaintextRuntimeSnapshot,
) -> String {
    let failures = runtime.reconcile_health.consecutive_failures();
    runtime
        .reconcile_health
        .last_attempt()
        .map_or_else(
            || "TLS plaintext reconcile loop is degraded".to_string(),
            |attempt| match attempt {
                crate::tls_plaintext::TlsPlaintextReconcileAttemptRuntimeSnapshot::Succeeded {
                    ..
                } => "TLS plaintext reconcile loop is degraded".to_string(),
                crate::tls_plaintext::TlsPlaintextReconcileAttemptRuntimeSnapshot::Failed {
                    reason,
                    ..
                } => format!(
                    "TLS plaintext reconcile loop failed after {failures} consecutive failure(s): {reason}"
                ),
            },
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

#[cfg(test)]
mod tests {
    use probe_config::{CaptureBackend, CaptureSelection};
    use runtime::CapturePlanMode;

    use super::*;
    use crate::tls_plaintext::{
        TlsPlaintextReconcileHealthRuntimeSnapshot, TlsPlaintextRuntimeMode,
        TlsPlaintextRuntimeSnapshot,
    };

    #[test]
    fn degraded_selected_capture_provider_degrades_health() {
        let capture = CaptureStatusSnapshot {
            selection: CaptureSelection::Auto,
            selected_backend: Some(CaptureBackend::Ebpf),
            selected_input_source: None,
            provider_runtime_mode: Some(RuntimeMode::Available),
            mode: CapturePlanMode::Live,
            reason: None,
            evidence_mode: Some(CaptureEvidenceMode::BestEffort),
            evidence_reason: Some("eBPF provider is best-effort".to_string()),
            candidates: Vec::new(),
            auto_mitm_plaintext_bridge_candidate: None,
            open_failures: Vec::new(),
            provider: None,
            input_activity: None,
        };

        let health = fold_health_contributions([capture_health_contribution(&capture)]);

        assert_eq!(health.mode, RuntimeMode::Degraded);
        assert_eq!(health.reasons, ["eBPF provider is best-effort"]);
    }

    #[test]
    fn available_selected_capture_provider_keeps_health_available() {
        let capture = CaptureStatusSnapshot {
            selection: CaptureSelection::Auto,
            selected_backend: Some(CaptureBackend::Libpcap),
            selected_input_source: None,
            provider_runtime_mode: Some(RuntimeMode::Available),
            mode: CapturePlanMode::Live,
            reason: None,
            evidence_mode: Some(CaptureEvidenceMode::Nominal),
            evidence_reason: None,
            candidates: Vec::new(),
            auto_mitm_plaintext_bridge_candidate: None,
            open_failures: Vec::new(),
            provider: None,
            input_activity: None,
        };

        let health = fold_health_contributions([capture_health_contribution(&capture)]);

        assert_eq!(health.mode, RuntimeMode::Available);
        assert!(health.reasons.is_empty());
    }

    #[test]
    fn enabled_tls_plaintext_runtime_with_failed_reconcile_degrades_health() {
        let runtime = TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::Enabled,
            reason: None,
            provider_activity: Default::default(),
            reconcile_health: TlsPlaintextReconcileHealthRuntimeSnapshot::failure(
                5,
                100,
                2,
                "dynamic libssl uprobe attach planning failed",
            ),
            last_reconcile: None,
        };

        let health = tls_plaintext_runtime_health_contribution(&runtime);

        assert_eq!(health.mode, RuntimeMode::Degraded);
        assert!(
            health
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("2 consecutive failure(s)"))
        );
        assert!(
            health
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("attach planning failed"))
        );
    }
}

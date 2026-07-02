use probe_config::CaptureBackend;
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState};
use runtime::RuntimePlan;

use crate::{
    capture_provider::CaptureProviderRuntimeSnapshot,
    tls_plaintext::{TlsPlaintextRuntimeMode, TlsPlaintextRuntimeSnapshot},
};

pub(in crate::status) fn capabilities_with_runtime(
    plan: &RuntimePlan,
    capture: Option<&CaptureProviderRuntimeSnapshot>,
    tls_plaintext: Option<&TlsPlaintextRuntimeSnapshot>,
) -> CapabilityMatrix {
    let mut states = plan.capabilities.states().to_vec();
    if let Some(capture) = capture {
        states.extend(
            capture
                .open_failures
                .iter()
                .filter(|failure| failure.backend != capture.selected_backend)
                .map(|failure| {
                    CapabilityState::unavailable(
                        capture_backend_capability(failure.backend),
                        failure.reason.clone(),
                    )
                }),
        );
    }
    if let Some(runtime) = tls_plaintext
        && runtime.mode == TlsPlaintextRuntimeMode::Disabled
    {
        states.push(CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            runtime
                .reason
                .clone()
                .unwrap_or_else(|| "TLS plaintext instrumentation is disabled".to_string()),
        ));
    }
    CapabilityMatrix::new(states)
}

fn capture_backend_capability(backend: CaptureBackend) -> CapabilityKind {
    match backend {
        CaptureBackend::Replay => CapabilityKind::ReplayCapture,
        CaptureBackend::Ebpf => CapabilityKind::Ebpf,
        CaptureBackend::Libpcap => CapabilityKind::Libpcap,
        CaptureBackend::PlaintextFeed => CapabilityKind::ExternalPlaintextFeed,
        CaptureBackend::CaptureEventFeed => CapabilityKind::CaptureEventFeed,
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::RuntimeMode;
    use runtime::{
        CaptureEvidenceMode, CapturePlanMode, CaptureProviderBuilder, CaptureProviderDescriptor,
        ProviderRegistry, RuntimePlan,
    };

    use super::*;
    use crate::capture_provider::{
        CaptureProviderOpenFailureSnapshot, CaptureProviderRuntimeSnapshot,
    };

    #[test]
    fn capture_open_failure_overlays_capability_after_runtime_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = auto_plan_with_degraded_ebpf_and_available_libpcap()?;
        let runtime = CaptureProviderRuntimeSnapshot {
            selected_backend: CaptureBackend::Libpcap,
            selected_input_source: runtime::CaptureInputSource::LiveHost,
            plan_mode: CapturePlanMode::Live,
            provider_runtime_mode: RuntimeMode::Available,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some("libpcap stream assembly is best-effort".to_string()),
            reason: None,
            open_failures: vec![CaptureProviderOpenFailureSnapshot {
                backend: CaptureBackend::Ebpf,
                reason: "eBPF attach failed".to_string(),
            }],
            provider: None,
        };

        let capabilities = capabilities_with_runtime(&plan, Some(&runtime), None);

        assert_eq!(
            capabilities.mode(CapabilityKind::Ebpf),
            RuntimeMode::Unavailable
        );
        assert!(
            capabilities
                .state(CapabilityKind::Ebpf)
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("eBPF attach failed"))
        );
        Ok(())
    }

    fn auto_plan_with_degraded_ebpf_and_available_libpcap()
    -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Auto;
        RuntimePlan::build(
            config,
            &ProviderRegistry::new(
                vec![
                    degraded_ebpf_descriptor(),
                    CaptureProviderDescriptor::available(
                        CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Libpcap,
                    )
                    .with_best_effort_evidence("libpcap stream assembly is best-effort"),
                ],
                Vec::new(),
            ),
        )
    }

    fn degraded_ebpf_descriptor() -> CaptureProviderDescriptor {
        CaptureProviderDescriptor::degraded(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Ebpf,
            "eBPF process observation evidence is best-effort",
        )
    }
}

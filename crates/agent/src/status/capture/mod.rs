use probe_config::{CaptureBackend, CaptureSelection};
use probe_core::RuntimeMode;
use runtime::{CaptureEvidenceMode, CapturePlanMode, RuntimePlan};
use serde::Serialize;

use crate::capture_provider::CaptureProviderRuntimeSnapshot;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureStatusSnapshot {
    pub selection: CaptureSelection,
    pub selected_backend: Option<CaptureBackend>,
    pub provider_runtime_mode: Option<RuntimeMode>,
    pub mode: CapturePlanMode,
    pub reason: Option<String>,
    pub evidence_mode: Option<CaptureEvidenceMode>,
    pub evidence_reason: Option<String>,
    pub open_failures: Vec<CaptureOpenFailureStatusSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureOpenFailureStatusSnapshot {
    pub backend: CaptureBackend,
    pub reason: String,
}

pub(in crate::status) fn capture_status(
    plan: &RuntimePlan,
    runtime: Option<CaptureProviderRuntimeSnapshot>,
) -> CaptureStatusSnapshot {
    match runtime {
        Some(runtime) => CaptureStatusSnapshot {
            selection: plan.capture.selection,
            selected_backend: Some(runtime.selected_backend),
            provider_runtime_mode: Some(runtime.provider_runtime_mode),
            mode: runtime.plan_mode,
            reason: runtime.reason,
            evidence_mode: Some(runtime.evidence_mode),
            evidence_reason: runtime.evidence_reason,
            open_failures: runtime
                .open_failures
                .into_iter()
                .map(|failure| CaptureOpenFailureStatusSnapshot {
                    backend: failure.backend,
                    reason: failure.reason,
                })
                .collect(),
        },
        None => CaptureStatusSnapshot {
            selection: plan.capture.selection,
            selected_backend: plan.capture.selected_backend,
            provider_runtime_mode: plan.capture.selected_provider_runtime_mode,
            mode: plan.capture.mode,
            reason: plan.capture.reason.clone(),
            evidence_mode: plan.capture.selected_evidence_mode,
            evidence_reason: plan.capture.evidence_reason.clone(),
            open_failures: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};
    use runtime::{
        CapturePlanMode, CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry,
        RuntimePlan,
    };

    use super::*;

    #[test]
    fn capture_status_reports_degraded_selected_provider() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = auto_plan_with_degraded_ebpf_and_available_libpcap()?;

        let status = capture_status(&plan, None);

        assert_eq!(status.selected_backend, Some(CaptureBackend::Ebpf));
        assert_eq!(status.provider_runtime_mode, Some(RuntimeMode::Available));
        assert_eq!(status.evidence_mode, Some(CaptureEvidenceMode::BestEffort));
        assert_eq!(
            status.evidence_reason.as_deref(),
            Some("eBPF provider is best-effort")
        );
        assert_eq!(status.reason, None);
        Ok(())
    }

    #[test]
    fn capture_status_prefers_runtime_backend_after_open_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = auto_plan_with_degraded_ebpf_and_available_libpcap()?;
        let runtime = CaptureProviderRuntimeSnapshot {
            selected_backend: CaptureBackend::Libpcap,
            plan_mode: CapturePlanMode::Live,
            provider_runtime_mode: RuntimeMode::Available,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some("libpcap stream assembly is best-effort".to_string()),
            reason: None,
            open_failures: vec![
                crate::capture_provider::CaptureProviderOpenFailureSnapshot {
                    backend: CaptureBackend::Ebpf,
                    reason: "eBPF attach failed".to_string(),
                },
            ],
        };

        let status = capture_status(&plan, Some(runtime));

        assert_eq!(status.selected_backend, Some(CaptureBackend::Libpcap));
        assert_eq!(status.provider_runtime_mode, Some(RuntimeMode::Available));
        assert_eq!(status.evidence_mode, Some(CaptureEvidenceMode::BestEffort));
        assert_eq!(status.reason, None);
        assert_eq!(status.open_failures.len(), 1);
        assert_eq!(status.open_failures[0].backend, CaptureBackend::Ebpf);
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
                    CaptureProviderDescriptor::degraded(
                        CaptureBackend::Ebpf,
                        CaptureProviderBuilder::Ebpf,
                        "eBPF provider is best-effort",
                    ),
                    CaptureProviderDescriptor::available(
                        CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Libpcap,
                    ),
                ],
                test_platform_capabilities(),
            ),
        )
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
        ]
    }
}

use probe_config::{CaptureBackend, CaptureSelection};
use probe_core::RuntimeMode;
use runtime::{CaptureEvidenceMode, CapturePlanMode, RuntimePlan};
use serde::Serialize;

use crate::capture_provider::{
    CaptureInputActivityRuntimeSnapshot, CaptureProviderRuntimeDetailsSnapshot,
    CaptureProviderRuntimeSnapshot,
};

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
    pub provider: Option<CaptureProviderRuntimeDetailsSnapshot>,
    pub input_activity: Option<CaptureInputActivityRuntimeSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureOpenFailureStatusSnapshot {
    pub backend: CaptureBackend,
    pub reason: String,
}

pub(in crate::status) fn capture_status(
    plan: &RuntimePlan,
    runtime: Option<CaptureProviderRuntimeSnapshot>,
    input_activity: Option<CaptureInputActivityRuntimeSnapshot>,
) -> CaptureStatusSnapshot {
    match runtime {
        Some(runtime) => {
            let provider = runtime
                .provider
                .map(|provider| provider.with_input_activity(input_activity.as_ref()));
            CaptureStatusSnapshot {
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
                provider,
                input_activity,
            }
        }
        None => CaptureStatusSnapshot {
            selection: plan.capture.selection,
            selected_backend: plan.capture.selected_backend,
            provider_runtime_mode: plan.capture.selected_provider_runtime_mode,
            mode: plan.capture.mode,
            reason: plan.capture.reason.clone(),
            evidence_mode: plan.capture.selected_evidence_mode,
            evidence_reason: plan.capture.evidence_reason.clone(),
            open_failures: Vec::new(),
            provider: None,
            input_activity: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::{CapabilityKind, CapabilityState, CaptureProviderKind, RuntimeMode};
    use runtime::{
        CapturePlanMode, CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry,
        RuntimePlan,
    };

    use super::*;
    use crate::capture_provider::{
        CaptureInputPollActivityRuntimeSnapshot, CaptureInputProviderActivityRuntimeSnapshot,
        CaptureInputSignalRuntimeSnapshot,
    };

    #[test]
    fn capture_status_reports_degraded_selected_provider() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = auto_plan_with_degraded_ebpf_and_available_libpcap()?;

        let status = capture_status(&plan, None, None);

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
            provider: None,
        };

        let status = capture_status(&plan, Some(runtime), None);

        assert_eq!(status.selected_backend, Some(CaptureBackend::Libpcap));
        assert_eq!(status.provider_runtime_mode, Some(RuntimeMode::Available));
        assert_eq!(status.evidence_mode, Some(CaptureEvidenceMode::BestEffort));
        assert_eq!(status.reason, None);
        assert_eq!(status.open_failures.len(), 1);
        assert_eq!(status.open_failures[0].backend, CaptureBackend::Ebpf);
        Ok(())
    }

    #[test]
    fn capture_status_reports_ebpf_process_link_ownership() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = auto_plan_with_degraded_ebpf_and_available_libpcap()?;
        let runtime = CaptureProviderRuntimeSnapshot {
            selected_backend: CaptureBackend::Ebpf,
            plan_mode: CapturePlanMode::Live,
            provider_runtime_mode: RuntimeMode::Degraded,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some("eBPF provider is best-effort".to_string()),
            reason: Some("kernel socket-object lifetime is best-effort".to_string()),
            open_failures: Vec::new(),
            provider: Some(ebpf_process_observation_details()),
        };

        let status = capture_status(&plan, Some(runtime), None);

        let value = serde_json::to_value(&status)?;
        let provider = &value["provider"];
        assert_eq!(
            provider["kind"],
            serde_json::json!("ebpf_process_observation")
        );
        assert_eq!(
            provider["link_ownership"]["mode"],
            serde_json::json!("available")
        );
        assert_eq!(provider["link_ownership"]["owned_link_count"], 2);
        assert_eq!(
            provider["kernel_liveness"]["mode"],
            serde_json::json!("unavailable")
        );
        assert!(
            provider["kernel_liveness"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("does not prove kernel-side firing"))
        );
        assert_eq!(
            provider["link_ownership"]["programs"][0]["program_name"],
            serde_json::json!("connect_enter")
        );
        assert_eq!(
            provider["link_ownership"]["programs"][0]["category"],
            serde_json::json!("syscalls")
        );
        assert_eq!(
            provider["link_ownership"]["programs"][0]["tracepoint_name"],
            serde_json::json!("sys_enter_connect")
        );
        assert_eq!(
            provider["optional_tracepoint_pairs"][0]["family_name"],
            serde_json::json!("sendfile")
        );
        assert_eq!(
            provider["optional_tracepoint_pairs"][0]["mode"],
            serde_json::json!("available")
        );
        assert_eq!(
            provider["optional_tracepoint_pairs"][0]["enter_tracepoint_name"],
            serde_json::json!("sys_enter_sendfile")
        );
        assert_eq!(
            provider["optional_tracepoint_pairs"][0]["exit_tracepoint_name"],
            serde_json::json!("sys_exit_sendfile")
        );
        Ok(())
    }

    #[test]
    fn capture_status_reports_ebpf_kernel_activity_after_observed_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = auto_plan_with_degraded_ebpf_and_available_libpcap()?;
        let runtime = CaptureProviderRuntimeSnapshot {
            selected_backend: CaptureBackend::Ebpf,
            plan_mode: CapturePlanMode::Live,
            provider_runtime_mode: RuntimeMode::Degraded,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some("eBPF provider is best-effort".to_string()),
            reason: Some("kernel socket-object lifetime is best-effort".to_string()),
            open_failures: Vec::new(),
            provider: Some(ebpf_process_observation_details()),
        };
        let input_activity = CaptureInputActivityRuntimeSnapshot {
            polls: CaptureInputPollActivityRuntimeSnapshot {
                total: 2,
                events: 1,
                progress: 1,
                idle: 0,
                finished: 0,
            },
            capture_events: 0,
            output_loss_events: 1,
            lost_events: 7,
            providers: vec![CaptureInputProviderActivityRuntimeSnapshot {
                provider: CaptureProviderKind::Ebpf,
                capture_events: 0,
                output_loss_events: 1,
                lost_events: 7,
            }],
            last_signal: Some(CaptureInputSignalRuntimeSnapshot::OutputLoss {
                sequence: 3,
                observed_unix_ns: 100,
                source: probe_core::CaptureSource::EbpfSyscall,
                provider: CaptureProviderKind::Ebpf,
                event_wall_time_unix_ns: 99,
                lost_events: 7,
            }),
        };

        let status = capture_status(&plan, Some(runtime), Some(input_activity));

        let value = serde_json::to_value(&status)?;
        let kernel_liveness = &value["provider"]["kernel_liveness"];
        assert_eq!(kernel_liveness["mode"], serde_json::json!("degraded"));
        assert!(
            kernel_liveness["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("observed eBPF provider output"))
        );
        assert!(
            kernel_liveness["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("0 capture events, 1 output-loss events"))
        );
        assert!(
            kernel_liveness["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("not per-link firing coverage"))
        );
        Ok(())
    }

    fn ebpf_process_observation_details() -> CaptureProviderRuntimeDetailsSnapshot {
        CaptureProviderRuntimeDetailsSnapshot::ebpf_process_observation(
            capture::EbpfProcessObservationProbeSnapshot::from_link_ownership_and_optional_pairs(
                capture::EbpfProcessObservationLinkOwnershipSnapshot::owned_by_programs([
                    capture::EbpfProcessObservationProgramLinkOwnershipSnapshot::new(
                        "connect_enter",
                        "syscalls",
                        "sys_enter_connect",
                        1,
                    ),
                    capture::EbpfProcessObservationProgramLinkOwnershipSnapshot::new(
                        "connect_exit",
                        "syscalls",
                        "sys_exit_connect",
                        1,
                    ),
                ]),
                [
                    capture::EbpfProcessObservationOptionalTracepointPairSnapshot::attached(
                        capture::EBPF_PROCESS_OPTIONAL_TRACEPOINT_PAIR_SPECS[0],
                    ),
                ],
            ),
        )
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

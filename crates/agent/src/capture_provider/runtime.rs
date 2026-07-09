use std::sync::{Arc, RwLock};

use capture::{
    CaptureError, CapturePoll, CaptureProvider, CaptureProviderRuntimeDiagnostics,
    EbpfProcessObservationActiveTracepointLiveness,
    EbpfProcessObservationActiveTracepointLivenessState,
    EbpfProcessObservationLinkOwnershipSnapshot,
    EbpfProcessObservationOptionalTracepointPairSnapshot,
    EbpfProcessObservationOptionalTracepointPairState,
    EbpfProcessObservationOptionalTracepointSnapshot,
    EbpfProcessObservationOptionalTracepointState, EbpfProcessObservationProbeSnapshot,
    EbpfProcessObservationTracepointDiagnostics, EbpfProcessObservationTracepointFiring,
    EbpfProcessPayloadAllowanceDiagnostics, EbpfProcessPayloadGateCounter,
};
use probe_config::CaptureBackend;
use probe_core::{CaptureProviderKind, RuntimeMode};
use runtime::{CaptureEvidenceMode, CaptureInputSource, CapturePlanMode};
use serde::Serialize;

use super::activity::{
    ActivityObservedCaptureInput, CaptureInputActivityRuntimeSnapshot,
    CaptureInputActivityRuntimeState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureProviderRuntimeSnapshot {
    pub(crate) selected_backend: CaptureBackend,
    pub(crate) selected_input_source: CaptureInputSource,
    pub(crate) plan_mode: CapturePlanMode,
    pub(crate) provider_runtime_mode: RuntimeMode,
    pub(crate) evidence_mode: CaptureEvidenceMode,
    pub(crate) evidence_reason: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) open_failures: Vec<CaptureProviderOpenFailureSnapshot>,
    pub(crate) provider: Option<CaptureProviderRuntimeDetailsSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CaptureProviderOpenFailureSnapshot {
    pub(crate) backend: CaptureBackend,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum CaptureProviderRuntimeDetailsSnapshot {
    EbpfProcessObservation {
        link_ownership: EbpfProcessObservationLinkOwnershipRuntimeSnapshot,
        tracepoint_firings: EbpfProcessObservationTracepointFiringRuntimeSnapshot,
        tracepoint_liveness: EbpfProcessObservationTracepointLivenessRuntimeSnapshot,
        process_payload_allowance: EbpfProcessPayloadAllowanceRuntimeSnapshot,
        payload_gate_counters: EbpfProcessPayloadGateRuntimeSnapshot,
        kernel_liveness: EbpfProcessObservationKernelLivenessRuntimeSnapshot,
        optional_tracepoints: Vec<EbpfProcessObservationOptionalTracepointRuntimeSnapshot>,
        optional_tracepoint_pairs: Vec<EbpfProcessObservationOptionalTracepointPairRuntimeSnapshot>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationLinkOwnershipRuntimeSnapshot {
    pub(crate) mode: RuntimeMode,
    pub(crate) owned_link_count: u64,
    pub(crate) programs: Vec<EbpfProcessObservationLinkProgramRuntimeSnapshot>,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationLinkProgramRuntimeSnapshot {
    pub(crate) program_name: &'static str,
    pub(crate) category: &'static str,
    pub(crate) tracepoint_name: &'static str,
    pub(crate) owned_link_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationTracepointFiringRuntimeSnapshot {
    pub(crate) mode: RuntimeMode,
    pub(crate) total_firing_count: u64,
    pub(crate) programs: Vec<EbpfProcessObservationTracepointFiringProgramRuntimeSnapshot>,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationTracepointFiringProgramRuntimeSnapshot {
    pub(crate) program_name: &'static str,
    pub(crate) category: &'static str,
    pub(crate) tracepoint_name: &'static str,
    pub(crate) firing_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessPayloadGateRuntimeSnapshot {
    pub(crate) mode: RuntimeMode,
    pub(crate) total_count: u64,
    pub(crate) counters: Vec<EbpfProcessPayloadGateCounterRuntimeSnapshot>,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessPayloadGateCounterRuntimeSnapshot {
    pub(crate) name: &'static str,
    pub(crate) count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessPayloadAllowanceRuntimeSnapshot {
    pub(crate) selector_configured: bool,
    pub(crate) scanned_processes: u64,
    pub(crate) matched_processes: u64,
    pub(crate) allowed_processes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationTracepointLivenessRuntimeSnapshot {
    pub(crate) diagnostics_available: bool,
    pub(crate) mode: RuntimeMode,
    pub(crate) advanced_program_count: u64,
    pub(crate) not_advanced_program_count: u64,
    pub(crate) unsupported_program_count: u64,
    pub(crate) programs: Vec<EbpfProcessObservationTracepointLivenessProgramRuntimeSnapshot>,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationTracepointLivenessProgramRuntimeSnapshot {
    pub(crate) program_name: &'static str,
    pub(crate) category: &'static str,
    pub(crate) tracepoint_name: &'static str,
    pub(crate) state: EbpfProcessObservationTracepointLivenessProgramState,
    pub(crate) before_firing_count: u64,
    pub(crate) after_firing_count: u64,
    pub(crate) reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EbpfProcessObservationTracepointLivenessProgramState {
    Advanced,
    NotAdvanced,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationKernelLivenessRuntimeSnapshot {
    pub(crate) mode: RuntimeMode,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationOptionalTracepointRuntimeSnapshot {
    pub(crate) family_name: &'static str,
    pub(crate) mode: RuntimeMode,
    pub(crate) category: &'static str,
    pub(crate) tracepoint_name: &'static str,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EbpfProcessObservationOptionalTracepointPairRuntimeSnapshot {
    pub(crate) family_name: &'static str,
    pub(crate) mode: RuntimeMode,
    pub(crate) enter_category: &'static str,
    pub(crate) enter_tracepoint_name: &'static str,
    pub(crate) exit_category: &'static str,
    pub(crate) exit_tracepoint_name: &'static str,
    pub(crate) reason: Option<String>,
}

impl CaptureProviderRuntimeSnapshot {
    pub(crate) fn compact(&self, reason_max_chars: usize) -> Self {
        Self {
            selected_backend: self.selected_backend,
            selected_input_source: self.selected_input_source,
            plan_mode: self.plan_mode,
            provider_runtime_mode: self.provider_runtime_mode,
            evidence_mode: self.evidence_mode,
            evidence_reason: compact_optional_runtime_reason(
                self.evidence_reason.as_deref(),
                reason_max_chars,
            ),
            reason: compact_optional_runtime_reason(self.reason.as_deref(), reason_max_chars),
            open_failures: self
                .open_failures
                .iter()
                .map(|failure| CaptureProviderOpenFailureSnapshot {
                    backend: failure.backend,
                    reason: compact_runtime_reason(&failure.reason, reason_max_chars),
                })
                .collect(),
            provider: self
                .provider
                .as_ref()
                .map(|provider| provider.compact(reason_max_chars)),
        }
    }
}

impl CaptureProviderRuntimeDetailsSnapshot {
    pub(crate) fn compact(&self, reason_max_chars: usize) -> Self {
        match self {
            Self::EbpfProcessObservation {
                link_ownership,
                tracepoint_firings,
                tracepoint_liveness,
                process_payload_allowance,
                payload_gate_counters,
                kernel_liveness,
                optional_tracepoints,
                optional_tracepoint_pairs,
            } => Self::EbpfProcessObservation {
                link_ownership: EbpfProcessObservationLinkOwnershipRuntimeSnapshot {
                    mode: link_ownership.mode,
                    owned_link_count: link_ownership.owned_link_count,
                    programs: Vec::new(),
                    reason: compact_optional_runtime_reason(
                        link_ownership.reason.as_deref(),
                        reason_max_chars,
                    ),
                },
                tracepoint_firings: EbpfProcessObservationTracepointFiringRuntimeSnapshot {
                    mode: tracepoint_firings.mode,
                    total_firing_count: tracepoint_firings.total_firing_count,
                    programs: Vec::new(),
                    reason: compact_optional_runtime_reason(
                        tracepoint_firings.reason.as_deref(),
                        reason_max_chars,
                    ),
                },
                tracepoint_liveness: EbpfProcessObservationTracepointLivenessRuntimeSnapshot {
                    diagnostics_available: tracepoint_liveness.diagnostics_available,
                    mode: tracepoint_liveness.mode,
                    advanced_program_count: tracepoint_liveness.advanced_program_count,
                    not_advanced_program_count: tracepoint_liveness.not_advanced_program_count,
                    unsupported_program_count: tracepoint_liveness.unsupported_program_count,
                    programs: Vec::new(),
                    reason: compact_optional_runtime_reason(
                        tracepoint_liveness.reason.as_deref(),
                        reason_max_chars,
                    ),
                },
                process_payload_allowance: process_payload_allowance.clone(),
                payload_gate_counters: EbpfProcessPayloadGateRuntimeSnapshot {
                    mode: payload_gate_counters.mode,
                    total_count: payload_gate_counters.total_count,
                    counters: payload_gate_counters.counters.clone(),
                    reason: compact_optional_runtime_reason(
                        payload_gate_counters.reason.as_deref(),
                        reason_max_chars,
                    ),
                },
                kernel_liveness: EbpfProcessObservationKernelLivenessRuntimeSnapshot {
                    mode: kernel_liveness.mode,
                    reason: compact_runtime_reason(&kernel_liveness.reason, reason_max_chars),
                },
                optional_tracepoints: optional_tracepoints
                    .iter()
                    .map(
                        |tracepoint| EbpfProcessObservationOptionalTracepointRuntimeSnapshot {
                            family_name: tracepoint.family_name,
                            mode: tracepoint.mode,
                            category: tracepoint.category,
                            tracepoint_name: tracepoint.tracepoint_name,
                            reason: compact_optional_runtime_reason(
                                tracepoint.reason.as_deref(),
                                reason_max_chars,
                            ),
                        },
                    )
                    .collect(),
                optional_tracepoint_pairs: optional_tracepoint_pairs
                    .iter()
                    .map(
                        |pair| EbpfProcessObservationOptionalTracepointPairRuntimeSnapshot {
                            family_name: pair.family_name,
                            mode: pair.mode,
                            enter_category: pair.enter_category,
                            enter_tracepoint_name: pair.enter_tracepoint_name,
                            exit_category: pair.exit_category,
                            exit_tracepoint_name: pair.exit_tracepoint_name,
                            reason: compact_optional_runtime_reason(
                                pair.reason.as_deref(),
                                reason_max_chars,
                            ),
                        },
                    )
                    .collect(),
            },
        }
    }

    pub(crate) fn ebpf_process_observation(probe: EbpfProcessObservationProbeSnapshot) -> Self {
        let (link_ownership, optional_tracepoints, optional_tracepoint_pairs) = probe.into_parts();
        let tracepoint_firings =
            EbpfProcessObservationTracepointFiringRuntimeSnapshot::not_reported();
        let tracepoint_liveness =
            EbpfProcessObservationTracepointLivenessRuntimeSnapshot::not_reported();
        let payload_gate_counters = EbpfProcessPayloadGateRuntimeSnapshot::not_reported();
        let kernel_liveness = EbpfProcessObservationKernelLivenessRuntimeSnapshot::from_capture(
            &link_ownership,
            &tracepoint_firings,
            &tracepoint_liveness,
        );
        Self::EbpfProcessObservation {
            link_ownership: EbpfProcessObservationLinkOwnershipRuntimeSnapshot::from_capture(
                link_ownership,
            ),
            tracepoint_firings,
            tracepoint_liveness,
            process_payload_allowance: EbpfProcessPayloadAllowanceRuntimeSnapshot::default(),
            payload_gate_counters,
            kernel_liveness,
            optional_tracepoints: optional_tracepoints
                .into_iter()
                .map(EbpfProcessObservationOptionalTracepointRuntimeSnapshot::from_capture)
                .collect(),
            optional_tracepoint_pairs: optional_tracepoint_pairs
                .into_iter()
                .map(EbpfProcessObservationOptionalTracepointPairRuntimeSnapshot::from_capture)
                .collect(),
        }
    }

    pub(crate) fn with_input_activity(
        mut self,
        input_activity: Option<&CaptureInputActivityRuntimeSnapshot>,
    ) -> Self {
        match &mut self {
            Self::EbpfProcessObservation {
                tracepoint_firings,
                tracepoint_liveness,
                kernel_liveness,
                ..
            } => kernel_liveness.apply_input_activity(
                tracepoint_firings,
                tracepoint_liveness,
                input_activity,
            ),
        }
        self
    }

    fn apply_diagnostics(&mut self, diagnostics: CaptureProviderRuntimeDiagnostics) {
        let Some(diagnostics) = diagnostics.into_ebpf_process_observation() else {
            return;
        };
        let Self::EbpfProcessObservation {
            link_ownership,
            tracepoint_firings,
            tracepoint_liveness,
            process_payload_allowance,
            payload_gate_counters,
            kernel_liveness,
            ..
        } = self;
        let (updated_tracepoint_firings, updated_tracepoint_liveness) =
            tracepoint_runtime_snapshots_from_diagnostics(diagnostics.tracepoints);
        *tracepoint_firings = updated_tracepoint_firings;
        *tracepoint_liveness = updated_tracepoint_liveness;
        *process_payload_allowance = EbpfProcessPayloadAllowanceRuntimeSnapshot::from_capture(
            diagnostics.process_payload_allowance,
        );
        *payload_gate_counters =
            EbpfProcessPayloadGateRuntimeSnapshot::from_diagnostics(diagnostics.payload_gates);
        *kernel_liveness = EbpfProcessObservationKernelLivenessRuntimeSnapshot::from_runtime(
            link_ownership,
            tracepoint_firings,
            tracepoint_liveness,
        );
    }
}

fn compact_optional_runtime_reason(reason: Option<&str>, max_chars: usize) -> Option<String> {
    reason.map(|reason| compact_runtime_reason(reason, max_chars))
}

fn compact_runtime_reason(reason: &str, max_chars: usize) -> String {
    truncate_str(reason, max_chars)
}

fn truncate_str(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let keep = max_chars.saturating_sub(3);
    let mut truncated = value.chars().take(keep).collect::<String>();
    truncated.push_str("...");
    truncated
}

impl EbpfProcessObservationKernelLivenessRuntimeSnapshot {
    fn from_capture(
        link_ownership: &EbpfProcessObservationLinkOwnershipSnapshot,
        tracepoint_firings: &EbpfProcessObservationTracepointFiringRuntimeSnapshot,
        tracepoint_liveness: &EbpfProcessObservationTracepointLivenessRuntimeSnapshot,
    ) -> Self {
        let link_ownership = EbpfProcessObservationLinkOwnershipRuntimeSnapshot::from_capture(
            link_ownership.clone(),
        );
        Self::from_runtime(&link_ownership, tracepoint_firings, tracepoint_liveness)
    }

    fn from_runtime(
        link_ownership: &EbpfProcessObservationLinkOwnershipRuntimeSnapshot,
        tracepoint_firings: &EbpfProcessObservationTracepointFiringRuntimeSnapshot,
        tracepoint_liveness: &EbpfProcessObservationTracepointLivenessRuntimeSnapshot,
    ) -> Self {
        if tracepoint_liveness.advanced_program_count > 0 {
            return Self {
                mode: tracepoint_liveness.mode,
                reason: format!(
                    "safe active process eBPF tracepoint liveness probe advanced {} tracepoint program(s), left {} supported program(s) not advanced, and marked {} program(s) outside the safe active probe set; this proves runtime kernel activity for the probed handlers, but not complete per-link coverage or strong socket-object lifetime",
                    tracepoint_liveness.advanced_program_count,
                    tracepoint_liveness.not_advanced_program_count,
                    tracepoint_liveness.unsupported_program_count,
                ),
            };
        }
        if tracepoint_firings.total_firing_count > 0 {
            let firing_program_count = tracepoint_firings
                .programs
                .iter()
                .filter(|program| program.firing_count > 0)
                .count();
            return Self {
                mode: RuntimeMode::Degraded,
                reason: format!(
                    "observed process eBPF tracepoint handler firing counters from kernel maps: {} total firings across {} tracepoint program(s); this proves runtime kernel activity for observed handlers, but not complete per-link coverage or strong socket-object lifetime",
                    tracepoint_firings.total_firing_count, firing_program_count
                ),
            };
        }
        let reason = if link_ownership.owned_link_count > 0
            && tracepoint_liveness.diagnostics_available
        {
            "process eBPF tracepoint link ownership does not prove kernel-side firing; safe active tracepoint liveness did not advance any supported handler"
        } else if link_ownership.owned_link_count > 0 {
            "process eBPF tracepoint link ownership does not prove kernel-side firing; safe active tracepoint liveness diagnostics are unavailable"
        } else {
            "process eBPF kernel liveness cannot be evaluated without committed tracepoint link ownership"
        };
        Self {
            mode: RuntimeMode::Unavailable,
            reason: reason.to_string(),
        }
    }

    fn apply_input_activity(
        &mut self,
        tracepoint_firings: &EbpfProcessObservationTracepointFiringRuntimeSnapshot,
        tracepoint_liveness: &EbpfProcessObservationTracepointLivenessRuntimeSnapshot,
        input_activity: Option<&CaptureInputActivityRuntimeSnapshot>,
    ) {
        if tracepoint_liveness.advanced_program_count > 0
            || tracepoint_firings.total_firing_count > 0
        {
            return;
        }
        let Some(activity) = input_activity
            .and_then(|activity| activity.provider_activity(CaptureProviderKind::Ebpf))
        else {
            return;
        };
        self.mode = RuntimeMode::Degraded;
        self.reason = format!(
            "observed eBPF provider output reaching userspace: {} capture events, {} output-loss events, {} lost events; this proves runtime kernel activity for this provider, but not per-link firing coverage or strong socket-object lifetime",
            activity.capture_events, activity.output_loss_events, activity.lost_events,
        );
    }
}

impl EbpfProcessObservationTracepointFiringRuntimeSnapshot {
    fn not_reported() -> Self {
        Self {
            mode: RuntimeMode::Unavailable,
            total_firing_count: 0,
            programs: Vec::new(),
            reason: Some(
                "process eBPF tracepoint firing diagnostics have not been observed".to_string(),
            ),
        }
    }

    fn from_firings(firings: Vec<EbpfProcessObservationTracepointFiring>) -> Self {
        let programs = firings
            .into_iter()
            .map(
                |firing| EbpfProcessObservationTracepointFiringProgramRuntimeSnapshot {
                    program_name: firing.program_name,
                    category: firing.category,
                    tracepoint_name: firing.tracepoint_name,
                    firing_count: firing.firing_count,
                },
            )
            .collect::<Vec<_>>();
        let total_firing_count = programs
            .iter()
            .map(|program| program.firing_count)
            .fold(0_u64, u64::saturating_add);
        Self {
            mode: RuntimeMode::Available,
            total_firing_count,
            programs,
            reason: Some(
                "kernel-side process eBPF tracepoint firing counters were read from the provider"
                    .to_string(),
            ),
        }
    }
}

impl EbpfProcessPayloadGateRuntimeSnapshot {
    fn not_reported() -> Self {
        Self {
            mode: RuntimeMode::Unavailable,
            total_count: 0,
            counters: Vec::new(),
            reason: Some(
                "process eBPF payload gate diagnostics have not been observed".to_string(),
            ),
        }
    }

    fn from_diagnostics(diagnostics: Result<Vec<EbpfProcessPayloadGateCounter>, String>) -> Self {
        match diagnostics {
            Ok(counters) => Self::from_counters(counters),
            Err(reason) => Self {
                mode: RuntimeMode::Unavailable,
                total_count: 0,
                counters: Vec::new(),
                reason: Some(reason),
            },
        }
    }

    fn from_counters(counters: Vec<EbpfProcessPayloadGateCounter>) -> Self {
        let counters = counters
            .into_iter()
            .map(|counter| EbpfProcessPayloadGateCounterRuntimeSnapshot {
                name: counter.name,
                count: counter.count,
            })
            .collect::<Vec<_>>();
        let total_count = counters
            .iter()
            .map(|counter| counter.count)
            .fold(0_u64, u64::saturating_add);
        Self {
            mode: RuntimeMode::Available,
            total_count,
            counters,
            reason: Some(
                "kernel-side process eBPF payload gate counters were read from the provider"
                    .to_string(),
            ),
        }
    }
}

impl EbpfProcessPayloadAllowanceRuntimeSnapshot {
    fn from_capture(diagnostics: EbpfProcessPayloadAllowanceDiagnostics) -> Self {
        Self {
            selector_configured: diagnostics.selector_configured,
            scanned_processes: diagnostics.scanned_processes,
            matched_processes: diagnostics.matched_processes,
            allowed_processes: diagnostics.allowed_processes,
        }
    }
}

fn tracepoint_runtime_snapshots_from_diagnostics(
    diagnostics: Result<EbpfProcessObservationTracepointDiagnostics, String>,
) -> (
    EbpfProcessObservationTracepointFiringRuntimeSnapshot,
    EbpfProcessObservationTracepointLivenessRuntimeSnapshot,
) {
    match diagnostics {
        Ok(diagnostics) => (
            EbpfProcessObservationTracepointFiringRuntimeSnapshot::from_firings(
                diagnostics.firings,
            ),
            EbpfProcessObservationTracepointLivenessRuntimeSnapshot::from_diagnostics(
                diagnostics.active_liveness,
            ),
        ),
        Err(reason) => (
            EbpfProcessObservationTracepointFiringRuntimeSnapshot {
                mode: RuntimeMode::Unavailable,
                total_firing_count: 0,
                programs: Vec::new(),
                reason: Some(reason.clone()),
            },
            EbpfProcessObservationTracepointLivenessRuntimeSnapshot {
                diagnostics_available: false,
                mode: RuntimeMode::Unavailable,
                advanced_program_count: 0,
                not_advanced_program_count: 0,
                unsupported_program_count: 0,
                programs: Vec::new(),
                reason: Some(format!(
                    "process eBPF active tracepoint liveness diagnostics require readable tracepoint firing counters: {reason}"
                )),
            },
        ),
    }
}

impl EbpfProcessObservationTracepointLivenessRuntimeSnapshot {
    fn not_reported() -> Self {
        Self {
            diagnostics_available: false,
            mode: RuntimeMode::Unavailable,
            advanced_program_count: 0,
            not_advanced_program_count: 0,
            unsupported_program_count: 0,
            programs: Vec::new(),
            reason: Some(
                "process eBPF active tracepoint liveness diagnostics have not been observed"
                    .to_string(),
            ),
        }
    }

    fn from_diagnostics(
        diagnostics: Result<EbpfProcessObservationActiveTracepointLiveness, String>,
    ) -> Self {
        match diagnostics {
            Ok(liveness) => Self::from_liveness(liveness),
            Err(reason) => Self {
                diagnostics_available: false,
                mode: RuntimeMode::Unavailable,
                advanced_program_count: 0,
                not_advanced_program_count: 0,
                unsupported_program_count: 0,
                programs: Vec::new(),
                reason: Some(reason),
            },
        }
    }

    fn from_liveness(liveness: EbpfProcessObservationActiveTracepointLiveness) -> Self {
        let programs = liveness
            .programs
            .into_iter()
            .map(
                |program| EbpfProcessObservationTracepointLivenessProgramRuntimeSnapshot {
                    program_name: program.program_name,
                    category: program.category,
                    tracepoint_name: program.tracepoint_name,
                    state: program.state.into(),
                    before_firing_count: program.before_firing_count,
                    after_firing_count: program.after_firing_count,
                    reason: program.reason,
                },
            )
            .collect::<Vec<_>>();
        let advanced_program_count = count_liveness_programs(
            &programs,
            EbpfProcessObservationTracepointLivenessProgramState::Advanced,
        );
        let not_advanced_program_count = count_liveness_programs(
            &programs,
            EbpfProcessObservationTracepointLivenessProgramState::NotAdvanced,
        );
        let unsupported_program_count = count_liveness_programs(
            &programs,
            EbpfProcessObservationTracepointLivenessProgramState::Unsupported,
        );
        let mode = if advanced_program_count > 0 {
            RuntimeMode::Degraded
        } else {
            RuntimeMode::Unavailable
        };
        Self {
            diagnostics_available: true,
            mode,
            advanced_program_count,
            not_advanced_program_count,
            unsupported_program_count,
            programs,
            reason: Some(liveness_reason(
                mode,
                advanced_program_count,
                not_advanced_program_count,
                unsupported_program_count,
            )),
        }
    }
}

impl From<EbpfProcessObservationActiveTracepointLivenessState>
    for EbpfProcessObservationTracepointLivenessProgramState
{
    fn from(state: EbpfProcessObservationActiveTracepointLivenessState) -> Self {
        match state {
            EbpfProcessObservationActiveTracepointLivenessState::Advanced => Self::Advanced,
            EbpfProcessObservationActiveTracepointLivenessState::NotAdvanced => Self::NotAdvanced,
            EbpfProcessObservationActiveTracepointLivenessState::Unsupported => Self::Unsupported,
        }
    }
}

fn count_liveness_programs(
    programs: &[EbpfProcessObservationTracepointLivenessProgramRuntimeSnapshot],
    state: EbpfProcessObservationTracepointLivenessProgramState,
) -> u64 {
    programs
        .iter()
        .filter(|program| program.state == state)
        .count()
        .try_into()
        .expect("tracepoint liveness program count should fit in u64")
}

fn liveness_reason(
    mode: RuntimeMode,
    advanced_program_count: u64,
    not_advanced_program_count: u64,
    unsupported_program_count: u64,
) -> String {
    match mode {
        RuntimeMode::Available => format!(
            "safe active process eBPF tracepoint liveness probe advanced all {advanced_program_count} tracepoint program(s)"
        ),
        RuntimeMode::Degraded => format!(
            "safe active process eBPF tracepoint liveness probe advanced {advanced_program_count} tracepoint program(s), left {not_advanced_program_count} supported program(s) not advanced, and marked {unsupported_program_count} program(s) outside the safe active probe set"
        ),
        RuntimeMode::Unavailable => format!(
            "safe active process eBPF tracepoint liveness probe did not advance any supported tracepoint program; {not_advanced_program_count} supported program(s) did not advance and {unsupported_program_count} program(s) are outside the safe active probe set"
        ),
    }
}

impl EbpfProcessObservationLinkOwnershipRuntimeSnapshot {
    fn from_capture(link_ownership: EbpfProcessObservationLinkOwnershipSnapshot) -> Self {
        let is_reported = link_ownership.is_reported();
        let owned_link_count = link_ownership.owned_link_count();
        let programs = link_ownership.into_programs();
        if !is_reported {
            return Self {
                mode: RuntimeMode::Unavailable,
                owned_link_count: 0,
                programs: Vec::new(),
                reason: Some(
                    "no committed process eBPF tracepoint link ownership was reported".to_string(),
                ),
            };
        }
        Self {
            mode: RuntimeMode::Available,
            owned_link_count: owned_link_count as u64,
            programs: programs
                .into_iter()
                .map(|program| EbpfProcessObservationLinkProgramRuntimeSnapshot {
                    program_name: program.program_name(),
                    category: program.category(),
                    tracepoint_name: program.tracepoint_name(),
                    owned_link_count: program.owned_link_count() as u64,
                })
                .collect(),
            reason: Some(
                "userspace process eBPF loader holds committed tracepoint links".to_string(),
            ),
        }
    }
}

impl EbpfProcessObservationOptionalTracepointRuntimeSnapshot {
    fn from_capture(tracepoint: EbpfProcessObservationOptionalTracepointSnapshot) -> Self {
        let (mode, reason) = optional_tracepoint_mode_and_reason(tracepoint.state());
        Self {
            family_name: tracepoint.family_name(),
            mode,
            category: tracepoint.category(),
            tracepoint_name: tracepoint.tracepoint_name(),
            reason: Some(reason.to_string()),
        }
    }
}

fn optional_tracepoint_mode_and_reason(
    state: EbpfProcessObservationOptionalTracepointState,
) -> (RuntimeMode, &'static str) {
    match state {
        EbpfProcessObservationOptionalTracepointState::Attached => (
            RuntimeMode::Available,
            "kernel exposes this optional tracepoint and the loader attached it",
        ),
        EbpfProcessObservationOptionalTracepointState::KernelMissing => (
            RuntimeMode::Unavailable,
            "kernel does not expose this optional tracepoint",
        ),
    }
}

impl EbpfProcessObservationOptionalTracepointPairRuntimeSnapshot {
    fn from_capture(pair: EbpfProcessObservationOptionalTracepointPairSnapshot) -> Self {
        let (mode, reason) = optional_tracepoint_pair_mode_and_reason(pair.state());
        Self {
            family_name: pair.family_name(),
            mode,
            enter_category: pair.enter_category(),
            enter_tracepoint_name: pair.enter_tracepoint_name(),
            exit_category: pair.exit_category(),
            exit_tracepoint_name: pair.exit_tracepoint_name(),
            reason: Some(reason.to_string()),
        }
    }
}

fn optional_tracepoint_pair_mode_and_reason(
    state: EbpfProcessObservationOptionalTracepointPairState,
) -> (RuntimeMode, &'static str) {
    match state {
        EbpfProcessObservationOptionalTracepointPairState::Attached => (
            RuntimeMode::Available,
            "kernel exposes both optional tracepoints and the loader attached both links",
        ),
        EbpfProcessObservationOptionalTracepointPairState::KernelMissing => (
            RuntimeMode::Unavailable,
            "kernel does not expose this optional tracepoint pair",
        ),
    }
}

#[derive(Clone, Default)]
pub(crate) struct CaptureProviderRuntimeState {
    inner: Arc<CaptureProviderRuntimeStateInner>,
}

#[derive(Default)]
struct CaptureProviderRuntimeStateInner {
    snapshot: RwLock<Option<CaptureProviderRuntimeSnapshot>>,
    input_activity: CaptureInputActivityRuntimeState,
}

impl CaptureProviderRuntimeState {
    pub(crate) fn record(&self, snapshot: CaptureProviderRuntimeSnapshot) {
        self.inner.input_activity.reset();
        *self
            .inner
            .snapshot
            .write()
            .expect("capture runtime lock poisoned") = Some(snapshot);
    }

    pub(crate) fn observe_capture_input(
        &self,
        provider: Box<dyn capture::CaptureProvider>,
    ) -> Box<dyn capture::CaptureProvider> {
        let observed =
            ActivityObservedCaptureInput::new(provider, self.inner.input_activity.clone());
        Box::new(RuntimeObservedCaptureInput {
            inner: observed,
            runtime: self.clone(),
        })
    }

    pub(crate) fn snapshot(&self) -> Option<CaptureProviderRuntimeSnapshot> {
        self.inner
            .snapshot
            .read()
            .expect("capture runtime lock poisoned")
            .clone()
    }

    pub(crate) fn compact_snapshot(
        &self,
        reason_max_chars: usize,
    ) -> Option<CaptureProviderRuntimeSnapshot> {
        self.inner
            .snapshot
            .read()
            .expect("capture runtime lock poisoned")
            .as_ref()
            .map(|snapshot| snapshot.compact(reason_max_chars))
    }

    pub(crate) fn input_activity_snapshot(&self) -> Option<CaptureInputActivityRuntimeSnapshot> {
        self.inner
            .snapshot
            .read()
            .expect("capture runtime lock poisoned")
            .as_ref()?;
        Some(self.inner.input_activity.snapshot())
    }

    fn record_diagnostics(&self, diagnostics: CaptureProviderRuntimeDiagnostics) {
        let mut snapshot = self
            .inner
            .snapshot
            .write()
            .expect("capture runtime lock poisoned");
        let Some(provider) = snapshot
            .as_mut()
            .and_then(|snapshot| snapshot.provider.as_mut())
        else {
            return;
        };
        provider.apply_diagnostics(diagnostics);
    }
}

struct RuntimeObservedCaptureInput {
    inner: ActivityObservedCaptureInput,
    runtime: CaptureProviderRuntimeState,
}

impl CaptureProvider for RuntimeObservedCaptureInput {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn capabilities(&self) -> Vec<probe_core::CapabilityState> {
        self.inner.capabilities()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        let poll = self.inner.poll_next()?;
        self.runtime
            .record_diagnostics(self.inner.runtime_diagnostics());
        Ok(poll)
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        let poll = self.inner.drain_before_handoff()?;
        self.runtime
            .record_diagnostics(self.inner.runtime_diagnostics());
        Ok(poll)
    }

    fn runtime_diagnostics(&mut self) -> CaptureProviderRuntimeDiagnostics {
        self.inner.runtime_diagnostics()
    }
}

#[cfg(test)]
mod tests {
    use capture::{
        CaptureError, CapturePoll, CaptureProvider, CaptureProviderRuntimeDiagnostics,
        EbpfProcessObservationActiveTracepointLiveness,
        EbpfProcessObservationActiveTracepointLivenessProgram,
        EbpfProcessObservationActiveTracepointLivenessState,
        EbpfProcessObservationRuntimeDiagnostics, EbpfProcessObservationTracepointDiagnostics,
        EbpfProcessObservationTracepointFiring,
    };

    use super::*;
    use crate::capture_provider::CaptureInputSignalRuntimeSnapshot;

    #[test]
    fn runtime_state_observes_capture_input_activity() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = CaptureProviderRuntimeState::default();
        runtime.record(runtime_snapshot(CaptureBackend::Libpcap));
        let mut provider = runtime.observe_capture_input(Box::new(ProgressProvider));

        assert_eq!(provider.poll_next()?, CapturePoll::Progress);

        let activity = runtime
            .input_activity_snapshot()
            .expect("recorded runtime should expose capture input activity");
        assert_eq!(activity.polls.total, 1);
        assert_eq!(activity.polls.progress, 1);
        assert!(matches!(
            activity.last_signal,
            Some(CaptureInputSignalRuntimeSnapshot::Progress {
                sequence: 1,
                observed_unix_ns
            }) if observed_unix_ns > 0
        ));
        assert_eq!(
            runtime
                .snapshot()
                .expect("runtime snapshot should be recorded")
                .selected_backend,
            CaptureBackend::Libpcap
        );
        Ok(())
    }

    #[test]
    fn runtime_record_resets_capture_input_activity() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = CaptureProviderRuntimeState::default();
        runtime.record(runtime_snapshot(CaptureBackend::Libpcap));
        let mut provider = runtime.observe_capture_input(Box::new(ProgressProvider));

        assert_eq!(provider.poll_next()?, CapturePoll::Progress);
        runtime.record(runtime_snapshot(CaptureBackend::Ebpf));

        let activity = runtime
            .input_activity_snapshot()
            .expect("recorded runtime should expose capture input activity");
        assert_eq!(activity.polls.total, 0);
        assert!(activity.providers.is_empty());
        assert_eq!(
            runtime
                .snapshot()
                .expect("runtime snapshot should be recorded")
                .selected_backend,
            CaptureBackend::Ebpf
        );
        Ok(())
    }

    #[test]
    fn runtime_state_records_provider_diagnostics() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = CaptureProviderRuntimeState::default();
        runtime.record(ebpf_runtime_snapshot());
        let mut provider = runtime.observe_capture_input(Box::new(DiagnosticProvider));

        assert_eq!(provider.poll_next()?, CapturePoll::Progress);

        let snapshot = runtime
            .snapshot()
            .expect("runtime snapshot should be recorded");
        let Some(CaptureProviderRuntimeDetailsSnapshot::EbpfProcessObservation {
            tracepoint_firings,
            tracepoint_liveness,
            kernel_liveness,
            ..
        }) = snapshot.provider
        else {
            panic!("expected eBPF provider details");
        };
        assert_eq!(tracepoint_firings.mode, RuntimeMode::Available);
        assert_eq!(tracepoint_firings.total_firing_count, 3);
        assert_eq!(tracepoint_firings.programs[0].program_name, "connect_enter");
        assert_eq!(tracepoint_firings.programs[0].category, "syscalls");
        assert_eq!(
            tracepoint_firings.programs[0].tracepoint_name,
            "sys_enter_connect"
        );
        assert_eq!(tracepoint_liveness.mode, RuntimeMode::Degraded);
        assert!(tracepoint_liveness.diagnostics_available);
        assert_eq!(tracepoint_liveness.advanced_program_count, 1);
        assert_eq!(tracepoint_liveness.programs[0].program_name, "write_enter");
        assert_eq!(kernel_liveness.mode, RuntimeMode::Degraded);
        assert!(
            kernel_liveness
                .reason
                .contains("safe active process eBPF tracepoint liveness probe")
        );
        Ok(())
    }

    #[test]
    fn compact_snapshot_drops_high_cardinality_ebpf_program_details() {
        const REASON_MAX_CHARS: usize = 2048;
        let details = CaptureProviderRuntimeDetailsSnapshot::EbpfProcessObservation {
            link_ownership: EbpfProcessObservationLinkOwnershipRuntimeSnapshot {
                mode: RuntimeMode::Available,
                owned_link_count: 10_000,
                programs: repeated_link_programs(10_000),
                reason: Some("owned links".repeat(1_000)),
            },
            tracepoint_firings: EbpfProcessObservationTracepointFiringRuntimeSnapshot {
                mode: RuntimeMode::Available,
                total_firing_count: 20_000,
                programs: repeated_firing_programs(10_000),
                reason: Some("firing counters".repeat(1_000)),
            },
            tracepoint_liveness: EbpfProcessObservationTracepointLivenessRuntimeSnapshot {
                diagnostics_available: true,
                mode: RuntimeMode::Degraded,
                advanced_program_count: 1,
                not_advanced_program_count: 9_999,
                unsupported_program_count: 0,
                programs: repeated_liveness_programs(10_000),
                reason: Some("liveness details".repeat(1_000)),
            },
            process_payload_allowance: EbpfProcessPayloadAllowanceRuntimeSnapshot::default(),
            payload_gate_counters: EbpfProcessPayloadGateRuntimeSnapshot {
                mode: RuntimeMode::Available,
                total_count: 4,
                counters: vec![
                    EbpfProcessPayloadGateCounterRuntimeSnapshot {
                        name: "write_attempt",
                        count: 3,
                    },
                    EbpfProcessPayloadGateCounterRuntimeSnapshot {
                        name: "read_attempt",
                        count: 1,
                    },
                ],
                reason: Some("payload gates".repeat(1_000)),
            },
            kernel_liveness: EbpfProcessObservationKernelLivenessRuntimeSnapshot {
                mode: RuntimeMode::Degraded,
                reason: "kernel liveness".repeat(1_000),
            },
            optional_tracepoints: vec![EbpfProcessObservationOptionalTracepointRuntimeSnapshot {
                family_name: "dup2",
                mode: RuntimeMode::Unavailable,
                category: "syscalls",
                tracepoint_name: "sys_enter_dup2",
                reason: Some("optional tracepoint reason".repeat(1_000)),
            }],
            optional_tracepoint_pairs: vec![
                EbpfProcessObservationOptionalTracepointPairRuntimeSnapshot {
                    family_name: "tcp_retransmit",
                    mode: RuntimeMode::Degraded,
                    enter_category: "tcp",
                    enter_tracepoint_name: "tcp_retransmit_skb",
                    exit_category: "tcp",
                    exit_tracepoint_name: "tcp_retransmit_skb_ret",
                    reason: Some("optional pair reason".repeat(1_000)),
                },
            ],
        };

        let runtime = CaptureProviderRuntimeState::default();
        runtime.record(CaptureProviderRuntimeSnapshot {
            selected_backend: CaptureBackend::Ebpf,
            selected_input_source: CaptureInputSource::LiveHost,
            plan_mode: CapturePlanMode::Live,
            provider_runtime_mode: RuntimeMode::Degraded,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some("evidence reason".repeat(1_000)),
            reason: Some("runtime reason".repeat(1_000)),
            open_failures: vec![CaptureProviderOpenFailureSnapshot {
                backend: CaptureBackend::Libpcap,
                reason: "open failure".repeat(1_000),
            }],
            provider: Some(details),
        });

        let compact = runtime
            .compact_snapshot(REASON_MAX_CHARS)
            .expect("compact runtime snapshot should be recorded");
        let CaptureProviderRuntimeDetailsSnapshot::EbpfProcessObservation {
            link_ownership,
            tracepoint_firings,
            tracepoint_liveness,
            payload_gate_counters,
            kernel_liveness,
            optional_tracepoints,
            optional_tracepoint_pairs,
            ..
        } = compact
            .provider
            .expect("compact snapshot should preserve provider summary");

        assert!(
            compact
                .reason
                .expect("runtime reason should be preserved")
                .len()
                <= REASON_MAX_CHARS
        );
        assert!(compact.open_failures[0].reason.len() <= REASON_MAX_CHARS);
        assert_eq!(link_ownership.owned_link_count, 10_000);
        assert!(link_ownership.programs.is_empty());
        assert_eq!(tracepoint_firings.total_firing_count, 20_000);
        assert!(tracepoint_firings.programs.is_empty());
        assert_eq!(tracepoint_liveness.not_advanced_program_count, 9_999);
        assert!(tracepoint_liveness.programs.is_empty());
        assert_eq!(payload_gate_counters.total_count, 4);
        assert_eq!(payload_gate_counters.counters.len(), 2);
        assert!(
            link_ownership
                .reason
                .expect("link ownership reason should be preserved")
                .len()
                <= REASON_MAX_CHARS
        );
        assert!(
            tracepoint_firings
                .reason
                .expect("tracepoint firing reason should be preserved")
                .len()
                <= REASON_MAX_CHARS
        );
        assert!(
            tracepoint_liveness
                .reason
                .expect("tracepoint liveness reason should be preserved")
                .len()
                <= REASON_MAX_CHARS
        );
        assert!(
            payload_gate_counters
                .reason
                .expect("payload gate reason should be preserved")
                .len()
                <= REASON_MAX_CHARS
        );
        assert!(kernel_liveness.reason.len() <= REASON_MAX_CHARS);
        assert!(
            optional_tracepoints[0]
                .reason
                .as_ref()
                .expect("optional tracepoint reason should be preserved")
                .len()
                <= REASON_MAX_CHARS
        );
        assert!(
            optional_tracepoint_pairs[0]
                .reason
                .as_ref()
                .expect("optional tracepoint pair reason should be preserved")
                .len()
                <= REASON_MAX_CHARS
        );
    }

    struct ProgressProvider;

    impl CaptureProvider for ProgressProvider {
        fn name(&self) -> &'static str {
            "progress"
        }

        fn capabilities(&self) -> Vec<probe_core::CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Progress)
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Idle)
        }
    }

    struct DiagnosticProvider;

    impl CaptureProvider for DiagnosticProvider {
        fn name(&self) -> &'static str {
            "diagnostic"
        }

        fn capabilities(&self) -> Vec<probe_core::CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Progress)
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Idle)
        }

        fn runtime_diagnostics(&mut self) -> CaptureProviderRuntimeDiagnostics {
            CaptureProviderRuntimeDiagnostics::from_ebpf_process_observation(
                EbpfProcessObservationRuntimeDiagnostics {
                    tracepoints: Ok(EbpfProcessObservationTracepointDiagnostics {
                        firings: vec![EbpfProcessObservationTracepointFiring {
                            program_name: "connect_enter",
                            category: "syscalls",
                            tracepoint_name: "sys_enter_connect",
                            firing_count: 3,
                        }],
                        active_liveness: Ok(EbpfProcessObservationActiveTracepointLiveness {
                            programs: vec![EbpfProcessObservationActiveTracepointLivenessProgram {
                                program_name: "write_enter",
                                category: "syscalls",
                                tracepoint_name: "sys_enter_write",
                                state:
                                    EbpfProcessObservationActiveTracepointLivenessState::Advanced,
                                before_firing_count: 10,
                                after_firing_count: 11,
                                reason: "safe active syscall probe advanced this tracepoint firing counter",
                            }],
                        }),
                    }),
                    process_payload_allowance: EbpfProcessPayloadAllowanceDiagnostics::default(),
                    payload_gates: Ok(Vec::new()),
                },
            )
        }
    }

    fn runtime_snapshot(selected_backend: CaptureBackend) -> CaptureProviderRuntimeSnapshot {
        CaptureProviderRuntimeSnapshot {
            selected_backend,
            selected_input_source: runtime_input_source_for_backend(selected_backend),
            plan_mode: CapturePlanMode::Live,
            provider_runtime_mode: RuntimeMode::Available,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some("capture input test".to_string()),
            reason: None,
            open_failures: Vec::new(),
            provider: None,
        }
    }

    fn runtime_input_source_for_backend(backend: CaptureBackend) -> CaptureInputSource {
        match backend {
            CaptureBackend::Ebpf | CaptureBackend::Libpcap => CaptureInputSource::LiveHost,
            CaptureBackend::PlaintextFeed => CaptureInputSource::PlaintextFeed,
            CaptureBackend::CaptureEventFeed => CaptureInputSource::ConfiguredCaptureEventFeed,
            CaptureBackend::Replay => CaptureInputSource::Replay,
        }
    }

    fn ebpf_runtime_snapshot() -> CaptureProviderRuntimeSnapshot {
        CaptureProviderRuntimeSnapshot {
            provider: Some(CaptureProviderRuntimeDetailsSnapshot::ebpf_process_observation(
                capture::EbpfProcessObservationProbeSnapshot::from_link_ownership_and_optional_tracepoints(
                    capture::EbpfProcessObservationLinkOwnershipSnapshot::owned_by_programs([
                        capture::EbpfProcessObservationProgramLinkOwnershipSnapshot::new(
                            "connect_enter",
                            "syscalls",
                            "sys_enter_connect",
                            1,
                        ),
                    ]),
                    [],
                    [],
                ),
            )),
            ..runtime_snapshot(CaptureBackend::Ebpf)
        }
    }

    fn repeated_link_programs(
        count: usize,
    ) -> Vec<EbpfProcessObservationLinkProgramRuntimeSnapshot> {
        (0..count)
            .map(|_| EbpfProcessObservationLinkProgramRuntimeSnapshot {
                program_name: "read_enter",
                category: "syscalls",
                tracepoint_name: "sys_enter_read",
                owned_link_count: 1,
            })
            .collect()
    }

    fn repeated_firing_programs(
        count: usize,
    ) -> Vec<EbpfProcessObservationTracepointFiringProgramRuntimeSnapshot> {
        (0..count)
            .map(
                |_| EbpfProcessObservationTracepointFiringProgramRuntimeSnapshot {
                    program_name: "read_enter",
                    category: "syscalls",
                    tracepoint_name: "sys_enter_read",
                    firing_count: 2,
                },
            )
            .collect()
    }

    fn repeated_liveness_programs(
        count: usize,
    ) -> Vec<EbpfProcessObservationTracepointLivenessProgramRuntimeSnapshot> {
        (0..count)
            .map(
                |_| EbpfProcessObservationTracepointLivenessProgramRuntimeSnapshot {
                    program_name: "read_enter",
                    category: "syscalls",
                    tracepoint_name: "sys_enter_read",
                    state: EbpfProcessObservationTracepointLivenessProgramState::NotAdvanced,
                    before_firing_count: 0,
                    after_firing_count: 0,
                    reason: "not advanced",
                },
            )
            .collect()
    }
}

use std::sync::{Arc, RwLock};

use capture::{
    CaptureError, CapturePoll, CaptureProvider, CaptureProviderRuntimeDiagnostics,
    EbpfProcessObservationActiveTracepointLiveness,
    EbpfProcessObservationActiveTracepointLivenessState,
    EbpfProcessObservationLinkOwnershipSnapshot,
    EbpfProcessObservationOptionalTracepointPairSnapshot,
    EbpfProcessObservationOptionalTracepointPairState, EbpfProcessObservationProbeSnapshot,
    EbpfProcessObservationTracepointDiagnostics, EbpfProcessObservationTracepointFiring,
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
        kernel_liveness: EbpfProcessObservationKernelLivenessRuntimeSnapshot,
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
pub(crate) struct EbpfProcessObservationOptionalTracepointPairRuntimeSnapshot {
    pub(crate) family_name: &'static str,
    pub(crate) mode: RuntimeMode,
    pub(crate) enter_category: &'static str,
    pub(crate) enter_tracepoint_name: &'static str,
    pub(crate) exit_category: &'static str,
    pub(crate) exit_tracepoint_name: &'static str,
    pub(crate) reason: Option<String>,
}

impl CaptureProviderRuntimeDetailsSnapshot {
    pub(crate) fn ebpf_process_observation(probe: EbpfProcessObservationProbeSnapshot) -> Self {
        let (link_ownership, optional_tracepoint_pairs) = probe.into_parts();
        let tracepoint_firings =
            EbpfProcessObservationTracepointFiringRuntimeSnapshot::not_reported();
        let tracepoint_liveness =
            EbpfProcessObservationTracepointLivenessRuntimeSnapshot::not_reported();
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
            kernel_liveness,
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
            kernel_liveness,
            ..
        } = self;
        let (updated_tracepoint_firings, updated_tracepoint_liveness) =
            tracepoint_runtime_snapshots_from_diagnostics(diagnostics.tracepoints);
        *tracepoint_firings = updated_tracepoint_firings;
        *tracepoint_liveness = updated_tracepoint_liveness;
        *kernel_liveness = EbpfProcessObservationKernelLivenessRuntimeSnapshot::from_runtime(
            link_ownership,
            tracepoint_firings,
            tracepoint_liveness,
        );
    }
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
                capture::EbpfProcessObservationProbeSnapshot::from_link_ownership_and_optional_pairs(
                    capture::EbpfProcessObservationLinkOwnershipSnapshot::owned_by_programs([
                        capture::EbpfProcessObservationProgramLinkOwnershipSnapshot::new(
                            "connect_enter",
                            "syscalls",
                            "sys_enter_connect",
                            1,
                        ),
                    ]),
                    [],
                ),
            )),
            ..runtime_snapshot(CaptureBackend::Ebpf)
        }
    }
}

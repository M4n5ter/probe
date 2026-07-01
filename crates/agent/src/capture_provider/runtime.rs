use std::sync::{Arc, RwLock};

use capture::{
    EbpfProcessObservationLinkOwnershipSnapshot,
    EbpfProcessObservationOptionalTracepointPairSnapshot,
    EbpfProcessObservationOptionalTracepointPairState, EbpfProcessObservationProbeSnapshot,
};
use probe_config::CaptureBackend;
use probe_core::RuntimeMode;
use runtime::{CaptureEvidenceMode, CapturePlanMode};
use serde::Serialize;

use super::activity::{
    ActivityObservedCaptureInput, CaptureInputActivityRuntimeSnapshot,
    CaptureInputActivityRuntimeState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureProviderRuntimeSnapshot {
    pub(crate) selected_backend: CaptureBackend,
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
        Self::EbpfProcessObservation {
            link_ownership: EbpfProcessObservationLinkOwnershipRuntimeSnapshot::from_capture(
                link_ownership,
            ),
            optional_tracepoint_pairs: optional_tracepoint_pairs
                .into_iter()
                .map(EbpfProcessObservationOptionalTracepointPairRuntimeSnapshot::from_capture)
                .collect(),
        }
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
        Box::new(ActivityObservedCaptureInput::new(
            provider,
            self.inner.input_activity.clone(),
        ))
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
}

#[cfg(test)]
mod tests {
    use capture::{CaptureError, CapturePoll, CaptureProvider};

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
        assert_eq!(
            runtime
                .snapshot()
                .expect("runtime snapshot should be recorded")
                .selected_backend,
            CaptureBackend::Ebpf
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
    }

    fn runtime_snapshot(selected_backend: CaptureBackend) -> CaptureProviderRuntimeSnapshot {
        CaptureProviderRuntimeSnapshot {
            selected_backend,
            plan_mode: CapturePlanMode::Live,
            provider_runtime_mode: RuntimeMode::Available,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some("capture input test".to_string()),
            reason: None,
            open_failures: Vec::new(),
            provider: None,
        }
    }
}

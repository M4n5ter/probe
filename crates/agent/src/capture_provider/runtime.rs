use std::sync::{Arc, RwLock};

use capture::EbpfProcessObservationLinkOwnershipSnapshot;
use probe_config::CaptureBackend;
use probe_core::RuntimeMode;
use runtime::{CaptureEvidenceMode, CapturePlanMode};
use serde::Serialize;

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

impl CaptureProviderRuntimeDetailsSnapshot {
    pub(crate) fn ebpf_process_observation(
        link_ownership: EbpfProcessObservationLinkOwnershipSnapshot,
    ) -> Self {
        Self::EbpfProcessObservation {
            link_ownership: EbpfProcessObservationLinkOwnershipRuntimeSnapshot::from_capture(
                link_ownership,
            ),
        }
    }
}

impl EbpfProcessObservationLinkOwnershipRuntimeSnapshot {
    fn from_capture(link_ownership: EbpfProcessObservationLinkOwnershipSnapshot) -> Self {
        let owned_link_count = link_ownership.owned_link_count();
        if !link_ownership.is_reported() {
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
            programs: link_ownership
                .into_programs()
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

#[derive(Clone, Default)]
pub(crate) struct CaptureProviderRuntimeState {
    inner: Arc<RwLock<Option<CaptureProviderRuntimeSnapshot>>>,
}

impl CaptureProviderRuntimeState {
    pub(crate) fn record(&self, snapshot: CaptureProviderRuntimeSnapshot) {
        *self.inner.write().expect("capture runtime lock poisoned") = Some(snapshot);
    }

    pub(crate) fn snapshot(&self) -> Option<CaptureProviderRuntimeSnapshot> {
        self.inner
            .read()
            .expect("capture runtime lock poisoned")
            .clone()
    }
}

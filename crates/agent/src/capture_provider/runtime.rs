use std::sync::{Arc, RwLock};

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CaptureProviderOpenFailureSnapshot {
    pub(crate) backend: CaptureBackend,
    pub(crate) reason: String,
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

use enforcement::EnforcementBackend;
use probe_core::{CapabilityKind, CapabilityState};

pub(crate) struct TransparentInterceptionRuntime {
    capability: CapabilityState,
    backend: Option<Box<dyn EnforcementBackend>>,
}

impl TransparentInterceptionRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }

    pub(crate) fn into_backend(self) -> Option<Box<dyn EnforcementBackend>> {
        self.backend
    }

    pub(super) fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            capability: CapabilityState::unavailable(
                CapabilityKind::TransparentInterception,
                reason,
            ),
            backend: None,
        }
    }
}

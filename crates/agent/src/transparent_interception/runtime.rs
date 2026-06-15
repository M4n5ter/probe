use probe_core::{CapabilityKind, CapabilityState};

pub(crate) struct TransparentInterceptionRuntime {
    capability: CapabilityState,
}

impl TransparentInterceptionRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }

    pub(super) fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            capability: CapabilityState::unavailable(
                CapabilityKind::TransparentInterception,
                reason,
            ),
        }
    }
}

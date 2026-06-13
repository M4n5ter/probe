use enforcement::EnforcementBackend;
use probe_core::{CapabilityKind, CapabilityState};

pub(crate) struct ConnectionEnforcementRuntime {
    capability: CapabilityState,
    backend: Option<Box<dyn EnforcementBackend>>,
}

impl ConnectionEnforcementRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }

    pub(crate) fn into_backend(self) -> Option<Box<dyn EnforcementBackend>> {
        self.backend
    }

    pub(super) fn unavailable(reason: impl Into<String>) -> Self {
        Self::without_backend(CapabilityState::unavailable(
            CapabilityKind::ConnectionEnforcement,
            reason,
        ))
    }

    pub(super) fn without_backend(capability: CapabilityState) -> Self {
        Self {
            capability,
            backend: None,
        }
    }

    pub(super) fn available_with_note(
        backend: impl EnforcementBackend + 'static,
        note: impl Into<String>,
    ) -> Self {
        Self {
            capability: CapabilityState {
                kind: CapabilityKind::ConnectionEnforcement,
                mode: probe_core::RuntimeMode::Available,
                reason: Some(note.into()),
            },
            backend: Some(Box::new(backend)),
        }
    }
}

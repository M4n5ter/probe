mod linux_socket_destroy;

use enforcement::EnforcementBackend;
use probe_config::ConnectionEnforcementBackendConfig;
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

    fn unavailable(reason: impl Into<String>) -> Self {
        Self::without_backend(CapabilityState::unavailable(
            CapabilityKind::ConnectionEnforcement,
            reason,
        ))
    }

    fn without_backend(capability: CapabilityState) -> Self {
        Self {
            capability,
            backend: None,
        }
    }

    fn available_with_note(
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

pub(crate) fn resolve(backend: ConnectionEnforcementBackendConfig) -> ConnectionEnforcementRuntime {
    match backend {
        ConnectionEnforcementBackendConfig::None => ConnectionEnforcementRuntime::unavailable(
            "connection-level enforcement backend is not configured",
        ),
        ConnectionEnforcementBackendConfig::LinuxSocketDestroy => linux_socket_destroy::resolve(),
    }
}

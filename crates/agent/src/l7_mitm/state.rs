use std::sync::{Arc, Mutex};

use probe_core::{CapabilityKind, CapabilityState};
use serde::{Deserialize, Serialize};

use super::L7MitmBackendHealthSnapshot;
use crate::tcp_health::TcpHealthMode;

#[derive(Clone)]
pub(crate) struct L7MitmRuntime {
    pub(super) capability: CapabilityState,
    pub(super) handle: L7MitmRuntimeHandle,
}

impl L7MitmRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }

    pub(crate) fn handle(&self) -> L7MitmRuntimeHandle {
        self.handle.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct L7MitmRuntimeSnapshot {
    pub backend_health: L7MitmBackendHealthSnapshot,
    pub plaintext_bridge: L7MitmPlaintextBridgeSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct L7MitmPlaintextBridgeSnapshot {
    pub mode: L7MitmPlaintextBridgeMode,
    pub disable_reason: Option<String>,
}

impl L7MitmPlaintextBridgeSnapshot {
    pub(super) fn not_configured() -> Self {
        Self {
            mode: L7MitmPlaintextBridgeMode::NotConfigured,
            disable_reason: None,
        }
    }

    pub(super) fn configured() -> Self {
        Self {
            mode: L7MitmPlaintextBridgeMode::Configured,
            disable_reason: None,
        }
    }

    fn record_ready(&mut self) {
        self.mode = L7MitmPlaintextBridgeMode::Ready;
        self.disable_reason = None;
    }

    fn record_active(&mut self) {
        self.mode = L7MitmPlaintextBridgeMode::Active;
        self.disable_reason = None;
    }

    fn record_disabled_after_error(&mut self, reason: impl Into<String>) {
        self.mode = L7MitmPlaintextBridgeMode::DisabledAfterError;
        self.disable_reason = Some(reason.into());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum L7MitmPlaintextBridgeMode {
    NotConfigured,
    Configured,
    Ready,
    Active,
    DisabledAfterError,
}

impl L7MitmPlaintextBridgeMode {
    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Configured => "configured",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::DisabledAfterError => "disabled_after_error",
        }
    }
}

#[derive(Clone)]
pub(crate) struct L7MitmRuntimeHandle {
    inner: Arc<Mutex<L7MitmRuntimeState>>,
}

struct L7MitmRuntimeState {
    snapshot: L7MitmRuntimeSnapshot,
    backend_health_failure_threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum L7MitmBackendHealthTransition {
    BecameUnhealthy {
        consecutive_failures: u64,
        reason: String,
    },
    Recovered,
}

impl L7MitmRuntimeHandle {
    pub(super) fn new(
        backend_health: L7MitmBackendHealthSnapshot,
        plaintext_bridge: L7MitmPlaintextBridgeSnapshot,
        backend_health_failure_threshold: u32,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(L7MitmRuntimeState {
                snapshot: L7MitmRuntimeSnapshot {
                    backend_health,
                    plaintext_bridge,
                },
                backend_health_failure_threshold,
            })),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        backend_health: L7MitmBackendHealthSnapshot,
        plaintext_bridge: L7MitmPlaintextBridgeSnapshot,
        backend_health_failure_threshold: u32,
    ) -> Self {
        Self::new(
            backend_health,
            plaintext_bridge,
            backend_health_failure_threshold,
        )
    }

    pub(crate) fn snapshot(&self) -> L7MitmRuntimeSnapshot {
        self.lock().snapshot.clone()
    }

    pub(super) fn record_backend_health_success(&self) -> Option<L7MitmBackendHealthTransition> {
        let mut state = self.lock();
        let previous_mode = state.snapshot.backend_health.mode;
        state.snapshot.backend_health.record_success();
        if previous_mode == TcpHealthMode::Unhealthy
            && state.snapshot.backend_health.mode == TcpHealthMode::Healthy
        {
            Some(L7MitmBackendHealthTransition::Recovered)
        } else {
            None
        }
    }

    pub(super) fn record_backend_health_failure(
        &self,
        reason: impl Into<String>,
    ) -> Option<L7MitmBackendHealthTransition> {
        let mut state = self.lock();
        let failure_threshold = state.backend_health_failure_threshold;
        let previous_mode = state.snapshot.backend_health.mode;
        state
            .snapshot
            .backend_health
            .record_failure(failure_threshold, reason);
        let current = &state.snapshot.backend_health;
        if previous_mode != TcpHealthMode::Unhealthy && current.mode == TcpHealthMode::Unhealthy {
            Some(L7MitmBackendHealthTransition::BecameUnhealthy {
                consecutive_failures: current.consecutive_failures,
                reason: current
                    .last_failure_reason
                    .clone()
                    .expect("unhealthy backend health should keep the last failure reason"),
            })
        } else {
            None
        }
    }

    pub(crate) fn record_plaintext_bridge_disabled(&self, reason: impl Into<String>) {
        let mut state = self.lock();
        state
            .snapshot
            .plaintext_bridge
            .record_disabled_after_error(reason);
    }

    pub(crate) fn record_plaintext_bridge_ready(&self) {
        let mut state = self.lock();
        state.snapshot.plaintext_bridge.record_ready();
    }

    pub(crate) fn record_plaintext_bridge_active(&self) {
        let mut state = self.lock();
        state.snapshot.plaintext_bridge.record_active();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, L7MitmRuntimeState> {
        self.inner
            .lock()
            .expect("L7 MITM runtime state should not be poisoned")
    }
}

pub(super) fn unavailable(
    reason: impl Into<String>,
    plaintext_bridge: L7MitmPlaintextBridgeSnapshot,
) -> L7MitmRuntime {
    L7MitmRuntime {
        capability: CapabilityState::unavailable(CapabilityKind::L7Mitm, reason),
        handle: L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::disabled(),
            plaintext_bridge,
            1,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7_mitm::L7MitmBackendHealthMode;

    #[test]
    fn backend_health_probe_marks_unhealthy_after_failure_threshold() {
        let handle = L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            2,
        );

        assert_eq!(
            handle.record_backend_health_failure("connection refused"),
            None
        );
        let health = handle.snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Healthy);
        assert_eq!(health.check_failures, 1);
        assert_eq!(health.consecutive_failures, 1);

        assert_eq!(
            handle.record_backend_health_failure("connection refused"),
            Some(L7MitmBackendHealthTransition::BecameUnhealthy {
                consecutive_failures: 2,
                reason: "connection refused".to_string(),
            })
        );
        let health = handle.snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Unhealthy);
        assert_eq!(health.check_failures, 2);
        assert_eq!(health.consecutive_failures, 2);
        assert_eq!(
            health.last_failure_reason.as_deref(),
            Some("connection refused")
        );
        assert_eq!(
            handle.record_backend_health_failure("connection refused"),
            None
        );
    }

    #[test]
    fn backend_health_probe_success_clears_unhealthy_state() {
        let handle = L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            1,
        );

        assert_eq!(
            handle.record_backend_health_failure("connection refused"),
            Some(L7MitmBackendHealthTransition::BecameUnhealthy {
                consecutive_failures: 1,
                reason: "connection refused".to_string(),
            })
        );
        assert_eq!(
            handle.snapshot().backend_health.mode,
            L7MitmBackendHealthMode::Unhealthy
        );

        assert_eq!(
            handle.record_backend_health_success(),
            Some(L7MitmBackendHealthTransition::Recovered)
        );

        let health = handle.snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Healthy);
        assert_eq!(health.check_successes, 2);
        assert_eq!(health.check_failures, 1);
        assert_eq!(health.consecutive_failures, 0);
        assert_eq!(health.last_failure_reason, None);
        assert_eq!(handle.record_backend_health_success(), None);
    }
}

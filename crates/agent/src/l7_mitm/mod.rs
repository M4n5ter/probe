mod backend;
mod lifecycle;
mod listener_owner;
mod state;

use probe_config::AgentConfig;

pub(crate) use crate::tcp_health::{
    TcpHealthMode as L7MitmBackendHealthMode, TcpHealthProbeGuard as L7MitmBackendHealthProbeGuard,
    TcpHealthSnapshot as L7MitmBackendHealthSnapshot,
};
pub(crate) use lifecycle::{L7MitmBackendLifecycleGuard, start_backend_lifecycle};
pub(crate) use state::{
    L7MitmPlaintextBridgeMode, L7MitmPlaintextBridgeSnapshot, L7MitmRuntime, L7MitmRuntimeHandle,
    L7MitmRuntimeSnapshot,
};

pub(crate) fn resolve(config: &AgentConfig) -> L7MitmRuntime {
    backend::resolve(config)
}

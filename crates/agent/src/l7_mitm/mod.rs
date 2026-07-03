mod audit;
mod backend;
mod lifecycle;
mod listener_owner;
mod output;
mod policy_hook;
mod state;

use probe_config::AgentConfig;

pub(crate) use crate::tcp_health::{
    TcpHealthMode as L7MitmBackendHealthMode, TcpHealthProbeGuard as L7MitmBackendHealthProbeGuard,
    TcpHealthSnapshot as L7MitmBackendHealthSnapshot,
};
pub(crate) use audit::DurableL7MitmAuditSink;
#[cfg(test)]
pub(crate) use audit::NoopL7MitmAuditSink;
pub(crate) use lifecycle::{L7MitmBackendLifecycleGuard, start_backend_lifecycle};
pub(crate) use policy_hook::{
    L7MitmPolicyHookConnectionOptions, L7MitmPolicyHookError,
    hook_from_plan as policy_hook_from_plan,
};
pub(crate) use state::{
    L7MitmClientTrustMaterialMode, L7MitmClientTrustMode, L7MitmClientTrustSnapshot,
    L7MitmPlaintextBridgeMode, L7MitmPlaintextBridgeSnapshot, L7MitmRuntime, L7MitmRuntimeHandle,
    L7MitmRuntimeSnapshot,
};

pub(crate) fn resolve(config: &AgentConfig) -> L7MitmRuntime {
    backend::resolve(config)
}

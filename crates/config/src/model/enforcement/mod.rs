use std::net::IpAddr;

use probe_core::{EnforcementMode, Selector};
use serde::{Deserialize, Serialize};

mod health_probe;
mod mitm;
mod policy;
mod proxy;

pub use mitm::{
    DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD,
    DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS,
    DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS,
    DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES,
    DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS,
    MAX_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD,
    MAX_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS,
    MAX_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS,
    MAX_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES,
    MAX_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS,
    MIN_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD,
    MIN_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS,
    MIN_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS,
    MIN_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES,
    MIN_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS, TransparentInterceptionMitmBackendConfig,
    TransparentInterceptionMitmBackendIntent,
    TransparentInterceptionMitmBackendReadinessProbeConfig,
    TransparentInterceptionMitmBackendReadinessProbeIntent,
    TransparentInterceptionMitmClientTrustConfig, TransparentInterceptionMitmClientTrustIntent,
    TransparentInterceptionMitmClientTrustModeConfig, TransparentInterceptionMitmConfig,
    TransparentInterceptionMitmIntentViolation, TransparentInterceptionMitmManagedProcessConfig,
    TransparentInterceptionMitmManagedProcessIntent,
    TransparentInterceptionMitmPlaintextBridgeConfig,
    TransparentInterceptionMitmPlaintextBridgeIntent,
    TransparentInterceptionMitmPlaintextBridgeModeConfig,
    TransparentInterceptionMitmPolicyHookConfig,
    TransparentInterceptionMitmPolicyHookEndpointIntent,
    TransparentInterceptionMitmPolicyHookIntent, TransparentInterceptionMitmPolicyHookModeConfig,
};
pub use policy::{
    DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES, EnforcementPolicyConfig,
    EnforcementPolicyManifest, EnforcementPolicySourceConfig,
    MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES, RemoteEnforcementPolicyBodyLimitBytes,
    RemoteEnforcementPolicyBodyLimitError,
};
pub use proxy::{
    DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
    DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS,
    DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
    MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
    MAX_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
    MIN_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
    MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, MIN_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
    TransparentInterceptionDirectionConfig, TransparentInterceptionDisabledProxyIntent,
    TransparentInterceptionEnabledProxyIntent, TransparentInterceptionIntentViolation,
    TransparentInterceptionL7ModeConfig, TransparentInterceptionOutboundProxyIntent,
    TransparentInterceptionOutboundProxyModeIntent,
    TransparentInterceptionOutboundProxySelfBypassIntent, TransparentInterceptionProxyConfig,
    TransparentInterceptionProxyHealthProbeConfig, TransparentInterceptionProxyHealthProbeIntent,
    TransparentInterceptionProxyIntent, TransparentInterceptionProxyIntentViolation,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionProxySelfBypassConfig,
    TransparentInterceptionStrategyConfig, TransparentInterceptionStrategyDescriptor,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementConfig {
    pub mode: EnforcementMode,
    pub backend: ConnectionEnforcementBackendConfig,
    pub selector: Option<Selector>,
    pub interception: EnforcementInterceptionConfig,
    pub policy: EnforcementPolicyConfig,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::AuditOnly,
            backend: ConnectionEnforcementBackendConfig::None,
            selector: None,
            interception: EnforcementInterceptionConfig::default(),
            policy: EnforcementPolicyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionEnforcementBackendConfig {
    #[default]
    None,
    LinuxSocketDestroy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementInterceptionConfig {
    pub strategy: TransparentInterceptionStrategyConfig,
    pub selector: Option<Selector>,
    pub proxy: TransparentInterceptionProxyConfig,
    pub mitm: TransparentInterceptionMitmConfig,
}

fn normalized_ip_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
    }
}

fn intent_violation(
    field: &'static str,
    reason: impl Into<String>,
) -> TransparentInterceptionProxyIntentViolation {
    proxy::intent_violation(field, reason)
}

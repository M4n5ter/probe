use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use url::Url;

use probe_core::{
    ApplicationProtocol, ApplicationProtocolPolicy, UpstreamRoute, UpstreamRouteHostPattern,
    socket_addr_points_to_listener,
};

use super::{
    EnforcementInterceptionConfig, TransparentInterceptionIntentViolation,
    health_probe::{
        DEFAULT_TCP_HEALTH_PROBE_FAILURE_THRESHOLD, DEFAULT_TCP_HEALTH_PROBE_INTERVAL_MS,
        DEFAULT_TCP_HEALTH_PROBE_TIMEOUT_MS, MAX_TCP_HEALTH_PROBE_FAILURE_THRESHOLD,
        MAX_TCP_HEALTH_PROBE_INTERVAL_MS, MAX_TCP_HEALTH_PROBE_TIMEOUT_MS,
        MIN_TCP_HEALTH_PROBE_FAILURE_THRESHOLD, MIN_TCP_HEALTH_PROBE_INTERVAL_MS,
        MIN_TCP_HEALTH_PROBE_TIMEOUT_MS, TcpHealthProbeTimingFields,
        validate_tcp_health_probe_timing,
    },
    intent_violation, normalized_ip_address,
};

pub const DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS: u64 =
    DEFAULT_TCP_HEALTH_PROBE_TIMEOUT_MS;
pub const DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS: u64 =
    DEFAULT_TCP_HEALTH_PROBE_INTERVAL_MS;
pub const DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD: u32 =
    DEFAULT_TCP_HEALTH_PROBE_FAILURE_THRESHOLD;
pub const MIN_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS: u64 = MIN_TCP_HEALTH_PROBE_TIMEOUT_MS;
pub const MAX_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS: u64 = MAX_TCP_HEALTH_PROBE_TIMEOUT_MS;
pub const MIN_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS: u64 =
    MIN_TCP_HEALTH_PROBE_INTERVAL_MS;
pub const MAX_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS: u64 =
    MAX_TCP_HEALTH_PROBE_INTERVAL_MS;
pub const MIN_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD: u32 =
    MIN_TCP_HEALTH_PROBE_FAILURE_THRESHOLD;
pub const MAX_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD: u32 =
    MAX_TCP_HEALTH_PROBE_FAILURE_THRESHOLD;
pub const DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS: u64 = 250;
pub const MIN_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS: u64 = 1;
pub const MAX_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES: u64 = 64 * 1024;
pub const MIN_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES: u64 = 1;
pub const MAX_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmConfig {
    pub backend: TransparentInterceptionMitmBackendConfig,
    pub client_trust: TransparentInterceptionMitmClientTrustConfig,
    pub plaintext_bridge: TransparentInterceptionMitmPlaintextBridgeConfig,
    pub policy_hook: TransparentInterceptionMitmPolicyHookConfig,
    pub ca_certificate_ref: Option<String>,
    pub ca_private_key_ref: Option<String>,
    pub leaf_certificate_chain_refs: Vec<String>,
    pub leaf_private_key_ref: Option<String>,
    pub upstream_trust_anchor_refs: Vec<String>,
}

impl TransparentInterceptionMitmConfig {
    pub fn is_configured(&self) -> bool {
        self.backend.is_configured()
            || self.client_trust.is_configured()
            || self.plaintext_bridge.is_configured()
            || self.policy_hook.is_configured()
            || self.ca_certificate_ref.is_some()
            || self.ca_private_key_ref.is_some()
            || !self.leaf_certificate_chain_refs.is_empty()
            || self.leaf_private_key_ref.is_some()
            || !self.upstream_trust_anchor_refs.is_empty()
    }

    pub fn has_ca_material_pair(&self) -> bool {
        self.ca_certificate_ref.is_some() && self.ca_private_key_ref.is_some()
    }

    pub fn has_leaf_material_pair(&self) -> bool {
        !self.leaf_certificate_chain_refs.is_empty() && self.leaf_private_key_ref.is_some()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmClientTrustConfig {
    pub mode: TransparentInterceptionMitmClientTrustModeConfig,
}

impl TransparentInterceptionMitmClientTrustConfig {
    pub fn is_configured(&self) -> bool {
        self.mode != TransparentInterceptionMitmClientTrustModeConfig::None
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionMitmClientTrustModeConfig {
    #[default]
    None,
    OperatorManaged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmBackendReadinessProbeConfig {
    pub target: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
}

impl TransparentInterceptionMitmBackendReadinessProbeConfig {
    pub fn is_configured(&self) -> bool {
        self.target.is_some()
            || self.interval_ms != DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS
            || self.timeout_ms != DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS
            || self.failure_threshold
                != DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD
    }
}

impl Default for TransparentInterceptionMitmBackendReadinessProbeConfig {
    fn default() -> Self {
        Self {
            target: None,
            interval_ms: DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS,
            timeout_ms: DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS,
            failure_threshold: DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransparentInterceptionMitmBackendConfig {
    #[default]
    Disabled,
    External {
        #[serde(default)]
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeConfig,
    },
    ManagedProcess {
        #[serde(default)]
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeConfig,
        #[serde(default)]
        process: TransparentInterceptionMitmManagedProcessConfig,
    },
    ProductProxy {
        #[serde(default)]
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeConfig,
        #[serde(default)]
        process: TransparentInterceptionMitmProductProxyConfig,
    },
}

impl TransparentInterceptionMitmBackendConfig {
    pub fn external(
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeConfig,
    ) -> Self {
        Self::External { readiness_probe }
    }

    pub fn managed_process(
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeConfig,
        process: TransparentInterceptionMitmManagedProcessConfig,
    ) -> Self {
        Self::ManagedProcess {
            readiness_probe,
            process,
        }
    }

    pub fn product_proxy(
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeConfig,
        process: TransparentInterceptionMitmProductProxyConfig,
    ) -> Self {
        Self::ProductProxy {
            readiness_probe,
            process,
        }
    }

    pub fn is_configured(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmManagedProcessConfig {
    pub program: Option<PathBuf>,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
}

impl TransparentInterceptionMitmManagedProcessConfig {
    pub fn is_configured(&self) -> bool {
        self.program.is_some() || !self.args.is_empty() || self.working_dir.is_some()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmProductProxyConfig {
    pub launcher: TransparentInterceptionMitmProductProxyLauncherConfig,
    pub application_protocols: Option<Vec<ApplicationProtocol>>,
    pub upstream_discovery: TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig,
    pub upstream_routes: Vec<TransparentInterceptionMitmProductProxyUpstreamRouteConfig>,
}

impl TransparentInterceptionMitmProductProxyConfig {
    pub fn is_configured(&self) -> bool {
        self.launcher.is_configured()
            || self.application_protocols.is_some()
            || self.upstream_discovery.is_configured()
            || !self.upstream_routes.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransparentInterceptionMitmProductProxyLauncherConfig {
    #[default]
    None,
    ExternalBinary {
        program: Option<PathBuf>,
        working_dir: Option<PathBuf>,
    },
    EmbeddedAgent {
        program: Option<PathBuf>,
        working_dir: Option<PathBuf>,
    },
}

impl TransparentInterceptionMitmProductProxyLauncherConfig {
    pub fn external_binary(program: PathBuf) -> Self {
        Self::ExternalBinary {
            program: Some(program),
            working_dir: None,
        }
    }

    pub fn embedded_agent(program: PathBuf) -> Self {
        Self::EmbeddedAgent {
            program: Some(program),
            working_dir: None,
        }
    }

    pub fn is_configured(&self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig {
    pub mode: TransparentInterceptionMitmProductProxyUpstreamDiscoveryModeConfig,
    pub default_port: Option<NonZeroU16>,
    pub allow_special_use_addresses: bool,
}

impl TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig {
    pub fn is_configured(&self) -> bool {
        self.mode != TransparentInterceptionMitmProductProxyUpstreamDiscoveryModeConfig::None
            || self.default_port.is_some()
            || self.allow_special_use_addresses
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionMitmProductProxyUpstreamDiscoveryModeConfig {
    #[default]
    None,
    Dns,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
    pub host: String,
    pub target: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmPlaintextBridgeConfig {
    pub mode: TransparentInterceptionMitmPlaintextBridgeModeConfig,
    pub path: Option<PathBuf>,
    pub follow: Option<bool>,
}

impl TransparentInterceptionMitmPlaintextBridgeConfig {
    pub fn is_configured(&self) -> bool {
        self.mode != TransparentInterceptionMitmPlaintextBridgeModeConfig::None
            || self.path.is_some()
            || self.follow.is_some()
    }

    pub fn follow_enabled(&self) -> bool {
        self.follow.unwrap_or(true)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionMitmPlaintextBridgeModeConfig {
    #[default]
    None,
    CaptureEventFeed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmPolicyHookConfig {
    pub mode: TransparentInterceptionMitmPolicyHookModeConfig,
    pub endpoint: Option<String>,
    pub timeout_ms: u64,
    pub max_response_bytes: u64,
}

impl TransparentInterceptionMitmPolicyHookConfig {
    pub fn is_configured(&self) -> bool {
        self.mode != TransparentInterceptionMitmPolicyHookModeConfig::None
            || self.endpoint.is_some()
            || self.timeout_ms != DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS
            || self.max_response_bytes != DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES
    }
}

impl Default for TransparentInterceptionMitmPolicyHookConfig {
    fn default() -> Self {
        Self {
            mode: TransparentInterceptionMitmPolicyHookModeConfig::None,
            endpoint: None,
            timeout_ms: DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS,
            max_response_bytes: DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionMitmPolicyHookModeConfig {
    #[default]
    None,
    HttpJson,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmBackendIntent {
    Disabled,
    External {
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeIntent,
    },
    ManagedProcess {
        process: TransparentInterceptionMitmManagedProcessIntent,
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeIntent,
    },
    ProductProxy {
        process: TransparentInterceptionMitmProductProxyIntent,
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeIntent,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionMitmManagedProcessIntent {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionMitmProductProxyIntent {
    pub launcher: TransparentInterceptionMitmProductProxyLauncherIntent,
    pub application_protocols: ApplicationProtocolPolicy,
    pub upstream_discovery: TransparentInterceptionMitmProductProxyUpstreamDiscoveryIntent,
    pub upstream_routes: Vec<TransparentInterceptionMitmProductProxyUpstreamRouteIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmProductProxyLauncherIntent {
    ExternalBinary {
        program: PathBuf,
        working_dir: Option<PathBuf>,
    },
    EmbeddedAgent {
        program: PathBuf,
        working_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentInterceptionMitmProductProxyUpstreamDiscoveryIntent {
    Disabled,
    Dns {
        default_port: Option<NonZeroU16>,
        allow_special_use_addresses: bool,
    },
}

pub type TransparentInterceptionMitmProductProxyUpstreamRouteIntent = UpstreamRoute;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmBackendReadinessProbeIntent {
    TcpConnect {
        target: SocketAddr,
        interval_ms: u64,
        timeout_ms: u64,
        failure_threshold: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmPlaintextBridgeIntent {
    Disabled,
    CaptureEventFeed { path: PathBuf, follow: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmClientTrustIntent {
    Disabled,
    OperatorManaged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmPolicyHookIntent {
    Disabled,
    HttpJson {
        endpoint: TransparentInterceptionMitmPolicyHookEndpointIntent,
        timeout_ms: u64,
        max_response_bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionMitmPolicyHookEndpointIntent {
    pub endpoint: String,
    pub address: SocketAddr,
    pub authority: String,
    pub path_and_query: String,
}

pub type TransparentInterceptionMitmIntentViolation = TransparentInterceptionIntentViolation;

impl EnforcementInterceptionConfig {
    pub fn mitm_backend_intent(
        &self,
    ) -> Result<
        TransparentInterceptionMitmBackendIntent,
        Vec<TransparentInterceptionMitmIntentViolation>,
    > {
        if !self.strategy.is_mitm() {
            return Ok(TransparentInterceptionMitmBackendIntent::Disabled);
        }

        let mut violations = Vec::new();
        let backend = match &self.mitm.backend {
            TransparentInterceptionMitmBackendConfig::Disabled => {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.backend.mode",
                    "MITM interception requires enforcement.interception.mitm.backend.mode = \"external\", \"managed_process\", or \"product_proxy\"",
                ));
                None
            }
            TransparentInterceptionMitmBackendConfig::External { readiness_probe } => {
                let readiness_probe = validate_mitm_backend_readiness_probe(
                    self.proxy.listen_port.and_then(NonZeroU16::new),
                    readiness_probe,
                    &mut violations,
                );
                readiness_probe.map(|readiness_probe| {
                    TransparentInterceptionMitmBackendIntent::External { readiness_probe }
                })
            }
            TransparentInterceptionMitmBackendConfig::ManagedProcess {
                process,
                readiness_probe,
            } => {
                let process = validate_mitm_managed_process(process, &mut violations);
                let readiness_probe = validate_mitm_backend_readiness_probe(
                    self.proxy.listen_port.and_then(NonZeroU16::new),
                    readiness_probe,
                    &mut violations,
                );
                match (process, readiness_probe) {
                    (Some(process), Some(readiness_probe)) => {
                        Some(TransparentInterceptionMitmBackendIntent::ManagedProcess {
                            process,
                            readiness_probe,
                        })
                    }
                    _ => None,
                }
            }
            TransparentInterceptionMitmBackendConfig::ProductProxy {
                process,
                readiness_probe,
            } => {
                let process = validate_mitm_product_proxy_process(process, &mut violations);
                let readiness_probe = validate_mitm_backend_readiness_probe(
                    self.proxy.listen_port.and_then(NonZeroU16::new),
                    readiness_probe,
                    &mut violations,
                );
                match (process, readiness_probe) {
                    (Some(process), Some(readiness_probe)) => {
                        validate_mitm_product_proxy_routes_do_not_target_listener(
                            &process.upstream_routes,
                            &readiness_probe,
                            &mut violations,
                        );
                        Some(TransparentInterceptionMitmBackendIntent::ProductProxy {
                            process,
                            readiness_probe,
                        })
                    }
                    _ => None,
                }
            }
        };

        if !violations.is_empty() {
            return Err(violations);
        }

        backend.ok_or_else(Vec::new)
    }

    pub fn mitm_plaintext_bridge_intent(
        &self,
    ) -> Result<
        TransparentInterceptionMitmPlaintextBridgeIntent,
        Vec<TransparentInterceptionMitmIntentViolation>,
    > {
        if !self.strategy.is_mitm() {
            return Ok(TransparentInterceptionMitmPlaintextBridgeIntent::Disabled);
        }

        let mut violations = Vec::new();
        let intent = validate_mitm_plaintext_bridge(&self.mitm.plaintext_bridge, &mut violations);
        if !violations.is_empty() {
            return Err(violations);
        }
        Ok(intent)
    }

    pub fn mitm_client_trust_intent(
        &self,
    ) -> Result<
        TransparentInterceptionMitmClientTrustIntent,
        Vec<TransparentInterceptionMitmIntentViolation>,
    > {
        if !self.strategy.is_mitm() {
            return Ok(TransparentInterceptionMitmClientTrustIntent::Disabled);
        }

        let mut violations = Vec::new();
        let intent = validate_mitm_client_trust(&self.mitm.client_trust, &mut violations);
        if !violations.is_empty() {
            return Err(violations);
        }
        Ok(intent)
    }

    pub fn mitm_policy_hook_intent(
        &self,
    ) -> Result<
        TransparentInterceptionMitmPolicyHookIntent,
        Vec<TransparentInterceptionMitmIntentViolation>,
    > {
        if !self.strategy.is_mitm() {
            return Ok(TransparentInterceptionMitmPolicyHookIntent::Disabled);
        }

        let mut violations = Vec::new();
        let intent = validate_mitm_policy_hook(&self.mitm.policy_hook, &mut violations);
        if !violations.is_empty() {
            return Err(violations);
        }
        Ok(intent)
    }
}

fn validate_mitm_client_trust(
    client_trust: &TransparentInterceptionMitmClientTrustConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> TransparentInterceptionMitmClientTrustIntent {
    match client_trust.mode {
        TransparentInterceptionMitmClientTrustModeConfig::None => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.client_trust.mode",
                "MITM interception requires client_trust.mode = \"operator_managed\" so client trust installation is explicit",
            ));
            TransparentInterceptionMitmClientTrustIntent::Disabled
        }
        TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged => {
            TransparentInterceptionMitmClientTrustIntent::OperatorManaged
        }
    }
}

fn validate_mitm_managed_process(
    process: &TransparentInterceptionMitmManagedProcessConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<TransparentInterceptionMitmManagedProcessIntent> {
    let program = validate_mitm_process_program(
        &process.program,
        "enforcement.interception.mitm.backend.process.program",
        "managed MITM backend",
        violations,
    )?;
    validate_mitm_process_working_dir(
        &process.working_dir,
        "enforcement.interception.mitm.backend.process.working_dir",
        "managed MITM backend",
        violations,
    );
    Some(TransparentInterceptionMitmManagedProcessIntent {
        program,
        args: process.args.clone(),
        working_dir: process.working_dir.clone(),
    })
}

fn validate_mitm_product_proxy_process(
    process: &TransparentInterceptionMitmProductProxyConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<TransparentInterceptionMitmProductProxyIntent> {
    let launcher = validate_mitm_product_proxy_launcher(&process.launcher, violations)?;
    let upstream_routes = validate_mitm_product_proxy_upstream_routes(
        &process.upstream_routes,
        "enforcement.interception.mitm.backend.process.upstream_routes",
        violations,
    );
    let application_protocols = validate_mitm_product_proxy_application_protocols(
        &process.application_protocols,
        "enforcement.interception.mitm.backend.process.application_protocols",
        violations,
    )?;
    let upstream_discovery =
        validate_mitm_product_proxy_upstream_discovery(&process.upstream_discovery, violations)?;
    Some(TransparentInterceptionMitmProductProxyIntent {
        launcher,
        application_protocols,
        upstream_discovery,
        upstream_routes,
    })
}

fn validate_mitm_product_proxy_launcher(
    launcher: &TransparentInterceptionMitmProductProxyLauncherConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<TransparentInterceptionMitmProductProxyLauncherIntent> {
    match launcher {
        TransparentInterceptionMitmProductProxyLauncherConfig::None => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend.process.launcher.mode",
                "product MITM proxy requires launcher.mode = \"external_binary\" or \"embedded_agent\"",
            ));
            None
        }
        TransparentInterceptionMitmProductProxyLauncherConfig::ExternalBinary {
            program,
            working_dir,
        } => {
            let program = validate_mitm_process_program(
                program,
                "enforcement.interception.mitm.backend.process.launcher.program",
                "product MITM proxy external binary launcher",
                violations,
            )?;
            validate_mitm_process_working_dir(
                working_dir,
                "enforcement.interception.mitm.backend.process.launcher.working_dir",
                "product MITM proxy external binary launcher",
                violations,
            );
            Some(
                TransparentInterceptionMitmProductProxyLauncherIntent::ExternalBinary {
                    program,
                    working_dir: working_dir.clone(),
                },
            )
        }
        TransparentInterceptionMitmProductProxyLauncherConfig::EmbeddedAgent {
            program,
            working_dir,
        } => {
            let program = validate_mitm_process_program(
                program,
                "enforcement.interception.mitm.backend.process.launcher.program",
                "product MITM proxy embedded agent launcher",
                violations,
            )?;
            validate_mitm_process_working_dir(
                working_dir,
                "enforcement.interception.mitm.backend.process.launcher.working_dir",
                "product MITM proxy embedded agent launcher",
                violations,
            );
            Some(
                TransparentInterceptionMitmProductProxyLauncherIntent::EmbeddedAgent {
                    program,
                    working_dir: working_dir.clone(),
                },
            )
        }
    }
}

fn validate_mitm_product_proxy_application_protocols(
    configured: &Option<Vec<ApplicationProtocol>>,
    field: &'static str,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<ApplicationProtocolPolicy> {
    match configured {
        None => Some(ApplicationProtocolPolicy::default()),
        Some(protocols) => match ApplicationProtocolPolicy::new(protocols.iter().copied()) {
            Ok(policy) => Some(policy),
            Err(error) => {
                violations.push(intent_violation(field, error.to_string()));
                None
            }
        },
    }
}

fn validate_mitm_product_proxy_upstream_discovery(
    discovery: &TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<TransparentInterceptionMitmProductProxyUpstreamDiscoveryIntent> {
    match discovery.mode {
        TransparentInterceptionMitmProductProxyUpstreamDiscoveryModeConfig::None => {
            if discovery.default_port.is_some() || discovery.allow_special_use_addresses {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.backend.process.upstream_discovery",
                    "product MITM proxy upstream DNS discovery fields require upstream_discovery.mode = \"dns\"",
                ));
                return None;
            }
            Some(TransparentInterceptionMitmProductProxyUpstreamDiscoveryIntent::Disabled)
        }
        TransparentInterceptionMitmProductProxyUpstreamDiscoveryModeConfig::Dns => Some(
            TransparentInterceptionMitmProductProxyUpstreamDiscoveryIntent::Dns {
                default_port: discovery.default_port,
                allow_special_use_addresses: discovery.allow_special_use_addresses,
            },
        ),
    }
}

fn validate_mitm_product_proxy_upstream_routes(
    routes: &[TransparentInterceptionMitmProductProxyUpstreamRouteConfig],
    field: &'static str,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Vec<TransparentInterceptionMitmProductProxyUpstreamRouteIntent> {
    let mut intents = Vec::new();
    let mut seen_hosts = HashSet::new();
    for (index, route) in routes.iter().enumerate() {
        let host = validate_product_proxy_upstream_route_host(route, field, index, violations);
        let target = validate_product_proxy_upstream_route_target(route, field, index, violations);
        let Some(host) = host else {
            continue;
        };
        if !seen_hosts.insert(host.clone()) {
            violations.push(intent_violation(
                field,
                format!("product MITM proxy upstream route host {host} is duplicated"),
            ));
        }
        if let Some(target) = target {
            match UpstreamRoute::from_parts(host, target) {
                Ok(route) => intents.push(route),
                Err(error) => violations.push(intent_violation(
                    field,
                    format!("product MITM proxy upstream route {index} {error}"),
                )),
            }
        }
    }
    intents
}

fn validate_mitm_product_proxy_routes_do_not_target_listener(
    routes: &[TransparentInterceptionMitmProductProxyUpstreamRouteIntent],
    readiness_probe: &TransparentInterceptionMitmBackendReadinessProbeIntent,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) {
    let TransparentInterceptionMitmBackendReadinessProbeIntent::TcpConnect { target, .. } =
        readiness_probe;
    for route in routes {
        if socket_addr_points_to_listener(route.target(), *target) {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend.process.upstream_routes",
                format!(
                    "product MITM proxy upstream route host {} target must not point back to the proxy listener",
                    route.host_pattern()
                ),
            ));
        }
    }
}

fn validate_product_proxy_upstream_route_host(
    route: &TransparentInterceptionMitmProductProxyUpstreamRouteConfig,
    field: &'static str,
    index: usize,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<UpstreamRouteHostPattern> {
    let host = route.host.trim();
    if host.is_empty() {
        violations.push(intent_violation(
            field,
            format!("product MITM proxy upstream route {index} host must not be empty"),
        ));
        return None;
    }
    match UpstreamRouteHostPattern::parse(host) {
        Ok(host) => Some(host),
        Err(error) => {
            violations.push(intent_violation(
                field,
                format!("product MITM proxy upstream route {index} {error}"),
            ));
            None
        }
    }
}

fn validate_product_proxy_upstream_route_target(
    route: &TransparentInterceptionMitmProductProxyUpstreamRouteConfig,
    field: &'static str,
    index: usize,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<SocketAddr> {
    match UpstreamRoute::parse_target(&route.target) {
        Ok(target) => Some(target),
        Err(error) => {
            violations.push(intent_violation(
                field,
                format!("product MITM proxy upstream route {index} {error}"),
            ));
            None
        }
    }
}

fn validate_mitm_process_program(
    program: &Option<PathBuf>,
    field: &'static str,
    label: &'static str,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<PathBuf> {
    let Some(program) = program else {
        violations.push(intent_violation(
            field,
            format!("{label} requires a program path"),
        ));
        return None;
    };
    if program.as_os_str().is_empty() {
        violations.push(intent_violation(
            field,
            format!("{label} program path must not be empty"),
        ));
        return None;
    }
    if !program.is_absolute() {
        violations.push(intent_violation(
            field,
            format!("{label} program path must be absolute"),
        ));
    }
    Some(program.clone())
}

fn validate_mitm_process_working_dir(
    working_dir: &Option<PathBuf>,
    field: &'static str,
    label: &'static str,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) {
    if let Some(working_dir) = working_dir {
        if working_dir.as_os_str().is_empty() {
            violations.push(intent_violation(
                field,
                format!("{label} working_dir must not be empty"),
            ));
        } else if !working_dir.is_absolute() {
            violations.push(intent_violation(
                field,
                format!("{label} working_dir must be absolute"),
            ));
        }
    }
}

fn validate_mitm_backend_readiness_probe(
    proxy_listen_port: Option<NonZeroU16>,
    probe: &TransparentInterceptionMitmBackendReadinessProbeConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<TransparentInterceptionMitmBackendReadinessProbeIntent> {
    let target = validate_mitm_backend_readiness_probe_target(proxy_listen_port, probe, violations);
    validate_mitm_backend_readiness_probe_ranges(probe, violations);
    target.map(
        |target| TransparentInterceptionMitmBackendReadinessProbeIntent::TcpConnect {
            target,
            interval_ms: probe.interval_ms,
            timeout_ms: probe.timeout_ms,
            failure_threshold: probe.failure_threshold,
        },
    )
}

fn validate_mitm_backend_readiness_probe_target(
    proxy_listen_port: Option<NonZeroU16>,
    probe: &TransparentInterceptionMitmBackendReadinessProbeConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<SocketAddr> {
    let Some(target) = &probe.target else {
        violations.push(intent_violation(
            "enforcement.interception.mitm.backend.readiness_probe.target",
            "MITM backend requires a TCP readiness probe target",
        ));
        return None;
    };

    let parsed_target = match target.parse::<SocketAddr>() {
        Ok(address) if address.port() == 0 => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend.readiness_probe.target",
                "MITM backend readiness probe target must use a non-zero port",
            ));
            None
        }
        Ok(address) if !is_loopback_address(address.ip()) => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend.readiness_probe.target",
                "MITM backend readiness probe target must use a loopback IP address",
            ));
            Some(address)
        }
        Ok(address) => Some(address),
        Err(_) => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend.readiness_probe.target",
                "MITM backend readiness probe target must be an IP socket address",
            ));
            None
        }
    };

    if let (Some(target), Some(listen_port)) = (parsed_target, proxy_listen_port)
        && target.port() != listen_port.get()
    {
        violations.push(intent_violation(
            "enforcement.interception.mitm.backend.readiness_probe.target",
            "MITM backend readiness probe target port must match proxy listen_port",
        ));
    }

    parsed_target
}

fn validate_mitm_backend_readiness_probe_ranges(
    probe: &TransparentInterceptionMitmBackendReadinessProbeConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) {
    validate_tcp_health_probe_timing(
        TcpHealthProbeTimingFields {
            interval_ms: "enforcement.interception.mitm.backend.readiness_probe.interval_ms",
            timeout_ms: "enforcement.interception.mitm.backend.readiness_probe.timeout_ms",
            failure_threshold: "enforcement.interception.mitm.backend.readiness_probe.failure_threshold",
        },
        "MITM backend readiness probe",
        probe.interval_ms,
        probe.timeout_ms,
        probe.failure_threshold,
        violations,
    );
}

fn validate_mitm_plaintext_bridge(
    bridge: &TransparentInterceptionMitmPlaintextBridgeConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> TransparentInterceptionMitmPlaintextBridgeIntent {
    match bridge.mode {
        TransparentInterceptionMitmPlaintextBridgeModeConfig::None => {
            if bridge.path.is_some() {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.plaintext_bridge.path",
                    "MITM plaintext bridge path requires plaintext_bridge.mode = \"capture_event_feed\"",
                ));
            }
            if bridge.follow.is_some() {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.plaintext_bridge.follow",
                    "MITM plaintext bridge follow mode requires plaintext_bridge.mode = \"capture_event_feed\"",
                ));
            }
            TransparentInterceptionMitmPlaintextBridgeIntent::Disabled
        }
        TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed => {
            let Some(path) = &bridge.path else {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.plaintext_bridge.path",
                    "capture-event MITM plaintext bridge requires a JSON-lines capture event path",
                ));
                return TransparentInterceptionMitmPlaintextBridgeIntent::Disabled;
            };
            if path.as_os_str().is_empty() {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.plaintext_bridge.path",
                    "capture-event MITM plaintext bridge path must not be empty",
                ));
            }
            TransparentInterceptionMitmPlaintextBridgeIntent::CaptureEventFeed {
                path: path.clone(),
                follow: bridge.follow_enabled(),
            }
        }
    }
}

fn validate_mitm_policy_hook(
    hook: &TransparentInterceptionMitmPolicyHookConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> TransparentInterceptionMitmPolicyHookIntent {
    match hook.mode {
        TransparentInterceptionMitmPolicyHookModeConfig::None => {
            if hook.endpoint.is_some() {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.policy_hook.endpoint",
                    "MITM policy hook endpoint requires policy_hook.mode = \"http_json\"",
                ));
            }
            if hook.timeout_ms != DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.policy_hook.timeout_ms",
                    "MITM policy hook timeout requires policy_hook.mode = \"http_json\"",
                ));
            }
            if hook.max_response_bytes != DEFAULT_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.policy_hook.max_response_bytes",
                    "MITM policy hook response limit requires policy_hook.mode = \"http_json\"",
                ));
            }
            TransparentInterceptionMitmPolicyHookIntent::Disabled
        }
        TransparentInterceptionMitmPolicyHookModeConfig::HttpJson => {
            validate_mitm_policy_hook_ranges(hook, violations);
            let Some(endpoint) = &hook.endpoint else {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.policy_hook.endpoint",
                    "HTTP JSON MITM policy hook requires a loopback endpoint",
                ));
                return TransparentInterceptionMitmPolicyHookIntent::Disabled;
            };
            let Some(endpoint) = validate_mitm_policy_hook_endpoint(endpoint, violations) else {
                return TransparentInterceptionMitmPolicyHookIntent::Disabled;
            };
            TransparentInterceptionMitmPolicyHookIntent::HttpJson {
                endpoint,
                timeout_ms: hook.timeout_ms,
                max_response_bytes: hook.max_response_bytes,
            }
        }
    }
}

fn validate_mitm_policy_hook_ranges(
    hook: &TransparentInterceptionMitmPolicyHookConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) {
    if !(MIN_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS..=MAX_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS)
        .contains(&hook.timeout_ms)
    {
        violations.push(intent_violation(
            "enforcement.interception.mitm.policy_hook.timeout_ms",
            format!(
                "MITM policy hook timeout_ms must be between {MIN_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS} and {MAX_TRANSPARENT_MITM_POLICY_HOOK_TIMEOUT_MS}"
            ),
        ));
    }
    if !(MIN_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES
        ..=MAX_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES)
        .contains(&hook.max_response_bytes)
    {
        violations.push(intent_violation(
            "enforcement.interception.mitm.policy_hook.max_response_bytes",
            format!(
                "MITM policy hook max_response_bytes must be between {MIN_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES} and {MAX_TRANSPARENT_MITM_POLICY_HOOK_MAX_RESPONSE_BYTES}"
            ),
        ));
    }
}

fn validate_mitm_policy_hook_endpoint(
    endpoint: &str,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<TransparentInterceptionMitmPolicyHookEndpointIntent> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        violations.push(intent_violation(
            "enforcement.interception.mitm.policy_hook.endpoint",
            "HTTP JSON MITM policy hook endpoint must not be empty",
        ));
        return None;
    }
    let parsed = match Url::parse(endpoint) {
        Ok(parsed) => parsed,
        Err(_) => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.policy_hook.endpoint",
                "HTTP JSON MITM policy hook endpoint must be a valid URL",
            ));
            return None;
        }
    };
    if parsed.scheme() != "http" {
        violations.push(intent_violation(
            "enforcement.interception.mitm.policy_hook.endpoint",
            "HTTP JSON MITM policy hook endpoint must use the http scheme",
        ));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        violations.push(intent_violation(
            "enforcement.interception.mitm.policy_hook.endpoint",
            "HTTP JSON MITM policy hook endpoint must not include credentials",
        ));
    }
    if parsed.fragment().is_some() {
        violations.push(intent_violation(
            "enforcement.interception.mitm.policy_hook.endpoint",
            "HTTP JSON MITM policy hook endpoint must not include a fragment",
        ));
    }
    let host = parsed
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok());
    let address = match host {
        Some(address) if is_loopback_address(address) => Some(normalized_ip_address(address)),
        Some(_) => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.policy_hook.endpoint",
                "HTTP JSON MITM policy hook endpoint host must be a loopback IP address",
            ));
            None
        }
        None => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.policy_hook.endpoint",
                "HTTP JSON MITM policy hook endpoint host must be an IP address",
            ));
            None
        }
    };
    match explicit_url_port(endpoint) {
        Some(0) => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.policy_hook.endpoint",
                "HTTP JSON MITM policy hook endpoint port must be non-zero",
            ));
            None
        }
        Some(port) => {
            address.map(|address| policy_hook_endpoint_intent(endpoint, address, port, &parsed))
        }
        None => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.policy_hook.endpoint",
                "HTTP JSON MITM policy hook endpoint must include an explicit port",
            ));
            None
        }
    }
}

fn explicit_url_port(endpoint: &str) -> Option<u16> {
    let endpoint_authority = endpoint
        .split_once("://")?
        .1
        .split(['/', '?', '#'])
        .next()?;
    let authority = endpoint_authority
        .rsplit_once('@')
        .map_or(endpoint_authority, |(_, host)| host);
    let port = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']')?.1.strip_prefix(':')?
    } else {
        authority.rsplit_once(':')?.1
    };
    port.parse::<u16>().ok()
}

fn policy_hook_endpoint_intent(
    endpoint: &str,
    address: IpAddr,
    port: u16,
    parsed: &Url,
) -> TransparentInterceptionMitmPolicyHookEndpointIntent {
    let address = SocketAddr::new(address, port);
    let mut path_and_query = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }
    TransparentInterceptionMitmPolicyHookEndpointIntent {
        endpoint: endpoint.to_string(),
        address,
        authority: address.to_string(),
        path_and_query,
    }
}

fn is_loopback_address(address: IpAddr) -> bool {
    match normalized_ip_address(address) {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address.is_loopback(),
    }
}

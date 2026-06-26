use std::{fmt, net::SocketAddr, num::NonZeroU16, path::PathBuf};

use probe_config::{
    AgentConfig, ConfigError, ConfigValidationError, ConfigViolation,
    ConnectionEnforcementBackendConfig, EnforcementInterceptionConfig, TlsMaterialKind,
    TransparentInterceptionDirectionConfig, TransparentInterceptionL7ModeConfig,
    TransparentInterceptionMitmBackendIntent,
    TransparentInterceptionMitmBackendReadinessProbeIntent,
    TransparentInterceptionMitmManagedProcessIntent,
    TransparentInterceptionMitmPlaintextBridgeIntent, TransparentInterceptionOutboundProxyIntent,
    TransparentInterceptionOutboundProxyModeIntent,
    TransparentInterceptionOutboundProxySelfBypassIntent,
    TransparentInterceptionProxyHealthProbeIntent, TransparentInterceptionProxyIntent,
    TransparentInterceptionProxyIntentViolation, TransparentInterceptionProxyModeConfig,
    TransparentInterceptionProxySelfBypassConfig, TransparentInterceptionStrategyConfig,
};
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState, EnforcementMode, RuntimeMode};
use serde::{Deserialize, Serialize};
use transparent_linux::{OutboundRedirectArtifactSpec, TransparentLinuxResources};

use super::{
    enforcement_policy_source::EnforcementPolicySourcePlan,
    interception_scope::TransparentInterceptionLocalSetupProjectionPlan,
    tls::{
        TlsMaterialPlan, mitm_tls_material_from_ref, mitm_tls_materials_by_id,
        mitm_tls_materials_from_refs,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPlan {
    pub mode: EnforcementMode,
    pub execution_surfaces: Vec<EnforcementExecutionSurface>,
    pub mode_capability: EnforcementCapabilityPlan,
    pub connection: EnforcementConnectionPlan,
    pub interception: EnforcementInterceptionPlan,
    pub config_selector_configured: bool,
    pub policy_source: EnforcementPolicySourcePlan,
}

impl EnforcementPlan {
    pub(super) fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        Self {
            mode: config.enforcement.mode,
            execution_surfaces: enabled_execution_surfaces(config),
            mode_capability: EnforcementCapabilityPlan::from_mode(
                config.enforcement.mode,
                capabilities,
            ),
            connection: EnforcementConnectionPlan::from_config(config, capabilities),
            interception: EnforcementInterceptionPlan::from_config(config, capabilities),
            config_selector_configured: config.enforcement.selector.is_some(),
            policy_source: EnforcementPolicySourcePlan::from_config(
                &config.enforcement.policy.source,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementExecutionSurface {
    Connection,
    TransparentInterception,
}

pub(super) fn enabled_execution_surfaces(config: &AgentConfig) -> Vec<EnforcementExecutionSurface> {
    if config.enforcement.mode != EnforcementMode::Enforce {
        return Vec::new();
    }

    let mut surfaces = Vec::new();
    if config.enforcement.backend != ConnectionEnforcementBackendConfig::None {
        surfaces.push(EnforcementExecutionSurface::Connection);
    }
    if config.enforcement.interception.strategy.is_enabled() {
        surfaces.push(EnforcementExecutionSurface::TransparentInterception);
    }
    surfaces
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementConnectionPlan {
    pub backend: ConnectionEnforcementBackendConfig,
    pub capability: EnforcementCapabilityPlan,
}

impl EnforcementConnectionPlan {
    fn from_config(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        let backend = config.enforcement.backend;
        Self {
            backend,
            capability: EnforcementCapabilityPlan::from_connection_backend(
                config.enforcement.mode,
                backend,
                capabilities,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementInterceptionPlan {
    pub strategy: TransparentInterceptionStrategyConfig,
    pub proxy: TransparentInterceptionProxyPlan,
    pub execution: TransparentInterceptionExecutionPlan,
    pub nftables: TransparentInterceptionNftablesPlan,
    pub mitm: TransparentInterceptionMitmPlan,
    pub local_setup_projection: TransparentInterceptionLocalSetupProjectionPlan,
    pub classification: TransparentInterceptionClassificationPlan,
    pub capabilities: Vec<RequiredCapabilityPlan>,
    pub selector_configured: bool,
}

impl EnforcementInterceptionPlan {
    fn from_config(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        let intent = config
            .enforcement
            .interception
            .transparent_proxy_intent()
            .expect("transparent interception config should be validated before planning");
        let strategy = intent.strategy();
        let nftables = TransparentInterceptionNftablesPlan::reserved();
        let execution =
            TransparentInterceptionExecutionPlan::from_intent_with_nftables(&intent, &nftables);
        Self {
            strategy,
            proxy: TransparentInterceptionProxyPlan::from_intent(&intent),
            execution,
            nftables,
            mitm: TransparentInterceptionMitmPlan::from_config(config),
            local_setup_projection:
                TransparentInterceptionLocalSetupProjectionPlan::from_strategy_and_selectors(
                    strategy,
                    config.enforcement.selector.as_ref(),
                    config.enforcement.interception.selector.as_ref(),
                ),
            classification: TransparentInterceptionClassificationPlan::from_capabilities(
                capabilities,
            ),
            capabilities: EnforcementCapabilityPlan::from_interception_config(
                &config.enforcement.interception,
                capabilities,
            ),
            selector_configured: config.enforcement.interception.selector.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionClassificationPlan {
    pub process_classifier: CapabilityState,
    pub flow_classifier: CapabilityState,
}

impl TransparentInterceptionClassificationPlan {
    fn from_capabilities(capabilities: &CapabilityMatrix) -> Self {
        Self {
            process_classifier: capabilities.state(CapabilityKind::TransparentProcessClassifier),
            flow_classifier: capabilities.state(CapabilityKind::TransparentFlowClassifier),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionProxyPlan {
    pub mode: TransparentInterceptionProxyModeConfig,
    pub self_bypass: TransparentInterceptionProxySelfBypassConfig,
    pub listen_port: Option<u16>,
    pub health_probe: TransparentInterceptionProxyHealthProbePlan,
}

impl TransparentInterceptionProxyPlan {
    pub fn try_from_config(
        config: &EnforcementInterceptionConfig,
    ) -> Result<Self, TransparentInterceptionProxyPlanError> {
        let intent = config
            .transparent_proxy_intent()
            .map_err(TransparentInterceptionProxyPlanError::new)?;
        Ok(Self::from_intent(&intent))
    }

    fn from_intent(intent: &TransparentInterceptionProxyIntent) -> Self {
        Self {
            mode: intent.mode(),
            self_bypass: intent.self_bypass(),
            listen_port: intent.listen_port().map(NonZeroU16::get),
            health_probe: TransparentInterceptionProxyHealthProbePlan::from_intent(
                intent.health_probe(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionProxyPlanError {
    violations: Vec<TransparentInterceptionProxyIntentViolation>,
}

impl TransparentInterceptionProxyPlanError {
    fn new(violations: Vec<TransparentInterceptionProxyIntentViolation>) -> Self {
        Self { violations }
    }

    pub fn violations(&self) -> &[TransparentInterceptionProxyIntentViolation] {
        &self.violations
    }
}

impl fmt::Display for TransparentInterceptionProxyPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transparent interception proxy config is invalid")?;
        for violation in &self.violations {
            write!(formatter, "; {}: {}", violation.field(), violation.reason())?;
        }
        Ok(())
    }
}

impl std::error::Error for TransparentInterceptionProxyPlanError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "direction")]
pub enum TransparentInterceptionExecutionPlan {
    Disabled,
    InboundTproxy(TransparentInterceptionInboundTproxyPlan),
    OutboundTransparentProxy(TransparentInterceptionOutboundProxyPlan),
}

impl TransparentInterceptionExecutionPlan {
    pub fn try_from_config(
        config: &EnforcementInterceptionConfig,
    ) -> Result<Self, TransparentInterceptionProxyPlanError> {
        let intent = config
            .transparent_proxy_intent()
            .map_err(TransparentInterceptionProxyPlanError::new)?;
        Ok(Self::from_intent(&intent))
    }

    fn from_intent(intent: &TransparentInterceptionProxyIntent) -> Self {
        Self::from_intent_with_nftables(intent, &TransparentInterceptionNftablesPlan::reserved())
    }

    fn from_intent_with_nftables(
        intent: &TransparentInterceptionProxyIntent,
        nftables: &TransparentInterceptionNftablesPlan,
    ) -> Self {
        match intent {
            TransparentInterceptionProxyIntent::Disabled(_) => Self::Disabled,
            TransparentInterceptionProxyIntent::InboundTproxy(proxy) => {
                Self::InboundTproxy(TransparentInterceptionInboundTproxyPlan {
                    l7_mode: proxy.l7_mode(),
                    proxy_mode: proxy.mode(),
                    listen_port: proxy.listen_port(),
                    health_probe: TransparentInterceptionProxyHealthProbePlan::from_intent(
                        proxy.health_probe().clone(),
                    ),
                })
            }
            TransparentInterceptionProxyIntent::OutboundTransparentProxy(proxy) => {
                Self::OutboundTransparentProxy(
                    TransparentInterceptionOutboundProxyPlan::from_proxy(proxy, nftables),
                )
            }
        }
    }

    pub fn strategy(&self) -> TransparentInterceptionStrategyConfig {
        match self {
            Self::Disabled => TransparentInterceptionStrategyConfig::None,
            Self::InboundTproxy(plan) => TransparentInterceptionStrategyConfig::from_parts(
                TransparentInterceptionDirectionConfig::InboundTproxy,
                plan.l7_mode,
            ),
            Self::OutboundTransparentProxy(plan) => {
                TransparentInterceptionStrategyConfig::from_parts(
                    TransparentInterceptionDirectionConfig::OutboundTransparentProxy,
                    plan.l7_mode,
                )
            }
        }
    }

    pub fn outbound_redirect_plan(&self) -> TransparentInterceptionOutboundRedirectPlan {
        match self {
            Self::OutboundTransparentProxy(plan) => plan.outbound_redirect_plan(),
            Self::Disabled | Self::InboundTproxy(_) => {
                TransparentInterceptionOutboundRedirectPlan::NotConfigured
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionMitmPlan {
    pub backend: TransparentInterceptionMitmBackendPlan,
    pub plaintext_bridge: TransparentInterceptionMitmPlaintextBridgePlan,
    pub ca_certificate: Option<TlsMaterialPlan>,
    pub ca_private_key: Option<TlsMaterialPlan>,
    pub leaf_certificate_chain: Vec<TlsMaterialPlan>,
    pub leaf_private_key: Option<TlsMaterialPlan>,
    pub upstream_trust_anchors: Vec<TlsMaterialPlan>,
}

impl TransparentInterceptionMitmPlan {
    pub fn try_from_config(config: &AgentConfig) -> Result<Self, ConfigValidationError> {
        config
            .validate_l7_mitm_contract()
            .map_err(config_validation_error)?;
        Ok(Self::from_validated_config(config))
    }

    fn from_config(config: &AgentConfig) -> Self {
        Self::from_validated_config(config)
    }

    fn from_validated_config(config: &AgentConfig) -> Self {
        let mitm = &config.enforcement.interception.mitm;
        let materials_by_id = mitm_tls_materials_by_id(&config.tls.materials);
        let backend_intent = config
            .enforcement
            .interception
            .mitm_backend_intent()
            .expect("MITM backend contract should be validated before planning");
        Self {
            backend: TransparentInterceptionMitmBackendPlan::from_intent(backend_intent),
            plaintext_bridge: TransparentInterceptionMitmPlaintextBridgePlan::from_intent(
                config
                    .enforcement
                    .interception
                    .mitm_plaintext_bridge_intent()
                    .expect("MITM plaintext bridge contract should be validated before planning"),
            ),
            ca_certificate: mitm.ca_certificate_ref.as_deref().and_then(|reference| {
                mitm_tls_material_from_ref(
                    reference,
                    TlsMaterialKind::MitmCaCertificate,
                    &materials_by_id,
                )
            }),
            ca_private_key: mitm.ca_private_key_ref.as_deref().and_then(|reference| {
                mitm_tls_material_from_ref(
                    reference,
                    TlsMaterialKind::MitmCaPrivateKey,
                    &materials_by_id,
                )
            }),
            leaf_certificate_chain: mitm_tls_materials_from_refs(
                &mitm.leaf_certificate_chain_refs,
                TlsMaterialKind::MitmLeafCertificate,
                &materials_by_id,
            ),
            leaf_private_key: mitm.leaf_private_key_ref.as_deref().and_then(|reference| {
                mitm_tls_material_from_ref(
                    reference,
                    TlsMaterialKind::MitmLeafPrivateKey,
                    &materials_by_id,
                )
            }),
            upstream_trust_anchors: mitm_tls_materials_from_refs(
                &mitm.upstream_trust_anchor_refs,
                TlsMaterialKind::MitmUpstreamTrustAnchor,
                &materials_by_id,
            ),
        }
    }
}

fn config_validation_error(error: ConfigError) -> ConfigValidationError {
    match error {
        ConfigError::Validation(error) => error,
        ConfigError::Toml(error) => ConfigValidationError::new(vec![ConfigViolation {
            field: "config".to_string(),
            reason: error.to_string(),
        }]),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum TransparentInterceptionMitmBackendPlan {
    Disabled,
    External {
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbePlan,
    },
    ManagedProcess {
        process: TransparentInterceptionMitmManagedProcessPlan,
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbePlan,
    },
}

impl TransparentInterceptionMitmBackendPlan {
    fn from_intent(intent: TransparentInterceptionMitmBackendIntent) -> Self {
        match intent {
            TransparentInterceptionMitmBackendIntent::Disabled => Self::Disabled,
            TransparentInterceptionMitmBackendIntent::External { readiness_probe } => {
                Self::External {
                    readiness_probe:
                        TransparentInterceptionMitmBackendReadinessProbePlan::from_intent(
                            readiness_probe,
                        ),
                }
            }
            TransparentInterceptionMitmBackendIntent::ManagedProcess {
                process,
                readiness_probe,
            } => Self::ManagedProcess {
                process: TransparentInterceptionMitmManagedProcessPlan::from_intent(process),
                readiness_probe: TransparentInterceptionMitmBackendReadinessProbePlan::from_intent(
                    readiness_probe,
                ),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionMitmManagedProcessPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
}

impl TransparentInterceptionMitmManagedProcessPlan {
    fn from_intent(intent: TransparentInterceptionMitmManagedProcessIntent) -> Self {
        Self {
            program: intent.program,
            args: intent.args,
            working_dir: intent.working_dir,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum TransparentInterceptionMitmBackendReadinessProbePlan {
    TcpConnect {
        target: SocketAddr,
        interval_ms: u64,
        timeout_ms: u64,
        failure_threshold: u32,
    },
}

impl TransparentInterceptionMitmBackendReadinessProbePlan {
    fn from_intent(intent: TransparentInterceptionMitmBackendReadinessProbeIntent) -> Self {
        match intent {
            TransparentInterceptionMitmBackendReadinessProbeIntent::TcpConnect {
                target,
                interval_ms,
                timeout_ms,
                failure_threshold,
            } => Self::TcpConnect {
                target,
                interval_ms,
                timeout_ms,
                failure_threshold,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum TransparentInterceptionMitmPlaintextBridgePlan {
    Disabled,
    CaptureEventFeed { path: PathBuf, follow: bool },
}

impl TransparentInterceptionMitmPlaintextBridgePlan {
    fn from_intent(intent: TransparentInterceptionMitmPlaintextBridgeIntent) -> Self {
        match intent {
            TransparentInterceptionMitmPlaintextBridgeIntent::Disabled => Self::Disabled,
            TransparentInterceptionMitmPlaintextBridgeIntent::CaptureEventFeed { path, follow } => {
                Self::CaptureEventFeed { path, follow }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionInboundTproxyPlan {
    l7_mode: TransparentInterceptionL7ModeConfig,
    proxy_mode: TransparentInterceptionProxyModeConfig,
    listen_port: NonZeroU16,
    health_probe: TransparentInterceptionProxyHealthProbePlan,
}

impl TransparentInterceptionInboundTproxyPlan {
    pub fn l7_mode(&self) -> TransparentInterceptionL7ModeConfig {
        self.l7_mode
    }

    pub fn proxy_mode(&self) -> TransparentInterceptionProxyModeConfig {
        self.proxy_mode
    }

    pub fn listen_port(&self) -> NonZeroU16 {
        self.listen_port
    }

    pub fn health_probe(&self) -> &TransparentInterceptionProxyHealthProbePlan {
        &self.health_probe
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionOutboundProxyPlan {
    l7_mode: TransparentInterceptionL7ModeConfig,
    lifecycle: TransparentInterceptionOutboundProxyLifecyclePlan,
    outbound_redirect_artifact: OutboundRedirectArtifactSpec,
}

impl TransparentInterceptionOutboundProxyPlan {
    fn from_proxy(
        proxy: &TransparentInterceptionOutboundProxyIntent,
        nftables: &TransparentInterceptionNftablesPlan,
    ) -> Self {
        Self {
            l7_mode: proxy.l7_mode(),
            lifecycle: TransparentInterceptionOutboundProxyLifecyclePlan::from_intent(
                *proxy.lifecycle(),
            ),
            outbound_redirect_artifact: OutboundRedirectArtifactSpec::outbound_transparent_proxy(
                nftables.clone(),
                proxy.listen_port().get(),
            ),
        }
    }

    pub fn l7_mode(&self) -> TransparentInterceptionL7ModeConfig {
        self.l7_mode
    }

    pub fn proxy_mode(&self) -> TransparentInterceptionProxyModeConfig {
        self.lifecycle.proxy_mode()
    }

    pub fn requires_managed_proxy(&self) -> bool {
        self.lifecycle.requires_managed_proxy()
    }

    pub fn self_bypass(&self) -> TransparentInterceptionProxySelfBypassConfig {
        self.lifecycle.self_bypass()
    }

    pub fn listen_port(&self) -> NonZeroU16 {
        NonZeroU16::new(self.outbound_redirect_artifact.proxy_port)
            .expect("outbound transparent proxy redirect artifact proxy port should be non-zero")
    }

    pub fn outbound_redirect_artifact(&self) -> &OutboundRedirectArtifactSpec {
        &self.outbound_redirect_artifact
    }

    pub fn outbound_redirect_plan(&self) -> TransparentInterceptionOutboundRedirectPlan {
        TransparentInterceptionOutboundRedirectPlan::Planned {
            artifact: self.outbound_redirect_artifact.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
enum TransparentInterceptionOutboundProxyLifecyclePlan {
    ManagedTcpRelay,
    External {
        self_bypass: TransparentInterceptionOutboundProxySelfBypassPlan,
    },
}

impl TransparentInterceptionOutboundProxyLifecyclePlan {
    fn from_intent(intent: TransparentInterceptionOutboundProxyModeIntent) -> Self {
        match intent {
            TransparentInterceptionOutboundProxyModeIntent::ManagedTcpRelay => {
                Self::ManagedTcpRelay
            }
            TransparentInterceptionOutboundProxyModeIntent::External { self_bypass } => {
                Self::External {
                    self_bypass: TransparentInterceptionOutboundProxySelfBypassPlan::from_intent(
                        self_bypass,
                    ),
                }
            }
        }
    }

    fn proxy_mode(self) -> TransparentInterceptionProxyModeConfig {
        match self {
            Self::ManagedTcpRelay => TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            Self::External { .. } => TransparentInterceptionProxyModeConfig::External,
        }
    }

    fn requires_managed_proxy(self) -> bool {
        matches!(self, Self::ManagedTcpRelay)
    }

    fn self_bypass(self) -> TransparentInterceptionProxySelfBypassConfig {
        match self {
            Self::ManagedTcpRelay => TransparentInterceptionProxySelfBypassConfig::None,
            Self::External { self_bypass } => self_bypass.config(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransparentInterceptionOutboundProxySelfBypassPlan {
    UsesReservedMark,
}

impl TransparentInterceptionOutboundProxySelfBypassPlan {
    fn from_intent(intent: TransparentInterceptionOutboundProxySelfBypassIntent) -> Self {
        match intent {
            TransparentInterceptionOutboundProxySelfBypassIntent::UsesReservedMark => {
                Self::UsesReservedMark
            }
        }
    }

    fn config(self) -> TransparentInterceptionProxySelfBypassConfig {
        match self {
            Self::UsesReservedMark => {
                TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum TransparentInterceptionProxyHealthProbePlan {
    Disabled,
    Enabled {
        target: SocketAddr,
        interval_ms: u64,
        timeout_ms: u64,
        failure_threshold: u32,
    },
}

impl TransparentInterceptionProxyHealthProbePlan {
    fn from_intent(intent: TransparentInterceptionProxyHealthProbeIntent) -> Self {
        match intent {
            TransparentInterceptionProxyHealthProbeIntent::Disabled => Self::Disabled,
            TransparentInterceptionProxyHealthProbeIntent::Enabled {
                target,
                interval_ms,
                timeout_ms,
                failure_threshold,
            } => Self::Enabled {
                target,
                interval_ms,
                timeout_ms,
                failure_threshold,
            },
        }
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }
}

pub type TransparentInterceptionNftablesPlan = TransparentLinuxResources;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransparentInterceptionOutboundRedirectPlan {
    NotConfigured,
    Planned {
        artifact: OutboundRedirectArtifactSpec,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementCapabilityPlan {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredCapabilityPlan {
    pub capability: CapabilityKind,
    pub mode: RuntimeMode,
}

impl RequiredCapabilityPlan {
    fn from_requirement(
        requirement: EnforcementCapabilityRequirement,
        capabilities: &CapabilityMatrix,
    ) -> Self {
        Self {
            capability: requirement.capability,
            mode: capabilities.mode(requirement.capability),
        }
    }
}

impl EnforcementCapabilityPlan {
    pub(super) fn requirement_for_mode(
        mode: EnforcementMode,
    ) -> Option<EnforcementCapabilityRequirement> {
        match mode {
            EnforcementMode::Disabled | EnforcementMode::AuditOnly => None,
            EnforcementMode::DryRun => Some(EnforcementCapabilityRequirement {
                capability: CapabilityKind::DryRunEnforcement,
                unavailable_reason: "dry-run enforcement provider is not available in this build/runtime",
            }),
            EnforcementMode::Enforce => None,
        }
    }

    pub(super) fn requirement_for_connection_backend(
        backend: ConnectionEnforcementBackendConfig,
    ) -> Option<EnforcementCapabilityRequirement> {
        match backend {
            ConnectionEnforcementBackendConfig::None => None,
            ConnectionEnforcementBackendConfig::LinuxSocketDestroy => {
                Some(EnforcementCapabilityRequirement {
                    capability: CapabilityKind::ConnectionEnforcement,
                    unavailable_reason: "connection-level enforcement backend is not available in this build/runtime",
                })
            }
        }
    }

    pub(super) fn requirements_for_interception_strategy(
        strategy: TransparentInterceptionStrategyConfig,
    ) -> Vec<EnforcementCapabilityRequirement> {
        let Some(descriptor) = strategy.descriptor() else {
            return Vec::new();
        };
        let mut requirements = vec![EnforcementCapabilityRequirement {
            capability: CapabilityKind::TransparentInterception,
            unavailable_reason: match descriptor.direction() {
                TransparentInterceptionDirectionConfig::InboundTproxy => {
                    "transparent interception backend is not available in this build/runtime"
                }
                TransparentInterceptionDirectionConfig::OutboundTransparentProxy => {
                    "outbound transparent proxy backend is not available in this build/runtime"
                }
            },
        }];
        if descriptor.l7_mode().is_mitm() {
            requirements.push(EnforcementCapabilityRequirement {
                capability: CapabilityKind::L7Mitm,
                unavailable_reason: "L7 MITM backend is not available in this build/runtime",
            });
        }
        requirements
    }

    pub(super) fn requirements_for_interception_config(
        config: &EnforcementInterceptionConfig,
    ) -> Vec<EnforcementCapabilityRequirement> {
        let mut requirements = Self::requirements_for_interception_strategy(config.strategy);
        if matches!(
            config.mitm_plaintext_bridge_intent(),
            Ok(TransparentInterceptionMitmPlaintextBridgeIntent::CaptureEventFeed { .. })
        ) {
            requirements.push(EnforcementCapabilityRequirement {
                capability: CapabilityKind::CaptureEventFeed,
                unavailable_reason: "MITM plaintext bridge requires the capture-event feed provider",
            });
        }
        requirements
    }

    fn from_mode(mode: EnforcementMode, capabilities: &CapabilityMatrix) -> Self {
        Self::requirement_for_mode(mode).map_or(Self::NotRequired, |requirement| {
            Self::required(
                requirement.capability,
                capabilities.mode(requirement.capability),
            )
        })
    }

    fn from_connection_backend(
        mode: EnforcementMode,
        backend: ConnectionEnforcementBackendConfig,
        capabilities: &CapabilityMatrix,
    ) -> Self {
        if mode != EnforcementMode::Enforce {
            return Self::NotRequired;
        }
        Self::requirement_for_connection_backend(backend).map_or(Self::NotRequired, |requirement| {
            Self::required(
                requirement.capability,
                capabilities.mode(requirement.capability),
            )
        })
    }

    fn from_interception_config(
        config: &EnforcementInterceptionConfig,
        capabilities: &CapabilityMatrix,
    ) -> Vec<RequiredCapabilityPlan> {
        Self::requirements_for_interception_config(config)
            .into_iter()
            .map(|requirement| RequiredCapabilityPlan::from_requirement(requirement, capabilities))
            .collect()
    }

    fn required(capability: CapabilityKind, mode: RuntimeMode) -> Self {
        Self::Required { capability, mode }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EnforcementCapabilityRequirement {
    pub(super) capability: CapabilityKind,
    pub(super) unavailable_reason: &'static str,
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use probe_config::{
        AgentConfig, ConnectionEnforcementBackendConfig, TlsMaterialConfig, TlsMaterialKind,
        TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmManagedProcessConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityMatrix, CapabilityState, Direction, ProcessSelector, Selector, TrafficSelector,
    };

    use super::*;

    #[test]
    fn dry_run_enforcement_is_a_supported_runtime_capability() {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::DryRun;
        let capabilities = CapabilityMatrix::new(test_platform_capabilities());

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.mode_capability,
            EnforcementCapabilityPlan::Required {
                capability: CapabilityKind::DryRunEnforcement,
                mode: RuntimeMode::Available,
            }
        );
    }

    #[test]
    fn enforce_enforcement_plan_records_connection_capability() {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;
        let capabilities = CapabilityMatrix::new(test_platform_capabilities_with_connection(
            RuntimeMode::Available,
        ));

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.connection.backend,
            ConnectionEnforcementBackendConfig::LinuxSocketDestroy
        );
        assert_eq!(
            plan.execution_surfaces,
            vec![EnforcementExecutionSurface::Connection]
        );
        assert_eq!(
            plan.connection.capability,
            EnforcementCapabilityPlan::Required {
                capability: CapabilityKind::ConnectionEnforcement,
                mode: RuntimeMode::Available,
            }
        );
    }

    #[test]
    fn enforcement_plan_preserves_transparent_interception_strategy() {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.proxy.health_probe.target =
            Some("127.0.0.1:18080".to_string());
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .interval_ms = 500;
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .timeout_ms = 100;
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .failure_threshold = 2;
        config.enforcement.interception.selector = Some(Selector::default());
        let capabilities = CapabilityMatrix::new(test_platform_capabilities_with_interception(
            RuntimeMode::Available,
        ));

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.interception.strategy,
            TransparentInterceptionStrategyConfig::InboundTproxy
        );
        assert_eq!(
            plan.execution_surfaces,
            vec![EnforcementExecutionSurface::TransparentInterception]
        );
        assert!(plan.interception.selector_configured);
        assert!(matches!(
            plan.interception.local_setup_projection,
            TransparentInterceptionLocalSetupProjectionPlan::Unsupported { .. }
        ));
        assert_eq!(
            plan.interception.proxy.mode,
            TransparentInterceptionProxyModeConfig::External
        );
        assert_eq!(
            plan.interception.proxy.self_bypass,
            TransparentInterceptionProxySelfBypassConfig::None
        );
        assert_eq!(plan.interception.proxy.listen_port, Some(15001));
        assert_eq!(
            plan.interception.proxy.health_probe,
            TransparentInterceptionProxyHealthProbePlan::Enabled {
                target: "127.0.0.1:18080"
                    .parse()
                    .expect("test socket address should parse"),
                interval_ms: 500,
                timeout_ms: 100,
                failure_threshold: 2,
            }
        );
        assert_eq!(plan.interception.nftables.table_name, "traffic_probe");
        assert_eq!(plan.interception.nftables.inbound_tproxy_mark, 0x5450_0101);
        assert_eq!(
            plan.interception.nftables.outbound_proxy_bypass_mark,
            NonZeroU32::new(0x5450_0102)
                .expect("test outbound proxy bypass mark should be non-zero")
        );
        assert_eq!(
            plan.interception.nftables.inbound_tproxy_route_table,
            45_100
        );
        assert_eq!(
            plan.interception.execution.outbound_redirect_plan(),
            TransparentInterceptionOutboundRedirectPlan::NotConfigured
        );
        assert_eq!(
            plan.interception.capabilities,
            vec![RequiredCapabilityPlan {
                capability: CapabilityKind::TransparentInterception,
                mode: RuntimeMode::Available,
            }]
        );
        assert_eq!(
            plan.interception.classification.process_classifier,
            CapabilityState::unavailable(CapabilityKind::TransparentProcessClassifier, "not built")
        );
        assert_eq!(
            plan.interception.classification.flow_classifier,
            CapabilityState::unavailable(CapabilityKind::TransparentFlowClassifier, "not built")
        );
    }

    #[test]
    fn enforcement_plan_reports_outbound_redirect_artifact() {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
        config.enforcement.interception.proxy.mode =
            TransparentInterceptionProxyModeConfig::ManagedTcpRelay;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let capabilities = CapabilityMatrix::new(test_platform_capabilities_with_interception(
            RuntimeMode::Unavailable,
        ));

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.interception.strategy,
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy
        );
        assert!(matches!(
            plan.interception.local_setup_projection,
            TransparentInterceptionLocalSetupProjectionPlan::HostRules { .. }
        ));
        assert_eq!(
            plan.interception.capabilities,
            vec![RequiredCapabilityPlan {
                capability: CapabilityKind::TransparentInterception,
                mode: RuntimeMode::Unavailable,
            }]
        );
        assert_eq!(
            plan.interception.execution.outbound_redirect_plan(),
            TransparentInterceptionOutboundRedirectPlan::Planned {
                artifact: OutboundRedirectArtifactSpec {
                    table_name: "traffic_probe".to_string(),
                    chain_name: "outbound_transparent_proxy".to_string(),
                    hook: "output".to_string(),
                    priority: "dstnat".to_string(),
                    proxy_port: 15001,
                    proxy_bypass_mark: NonZeroU32::new(0x5450_0102)
                        .expect("test outbound proxy bypass mark should be non-zero"),
                }
            }
        );
    }

    #[test]
    fn enforcement_plan_reports_outbound_mitm_capability_requirements()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm;
        config.enforcement.interception.proxy.self_bypass =
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        configure_external_mitm_backend(&mut config);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let capabilities = CapabilityMatrix::new([
            CapabilityState::available(CapabilityKind::TransparentInterception),
            CapabilityState::unavailable(CapabilityKind::L7Mitm, "not wired"),
        ]);

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.interception.strategy,
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm
        );
        assert_eq!(
            plan.interception.proxy.mode,
            TransparentInterceptionProxyModeConfig::External
        );
        assert_eq!(
            plan.interception.proxy.self_bypass,
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
        );
        assert_eq!(
            plan.interception.capabilities,
            vec![
                RequiredCapabilityPlan {
                    capability: CapabilityKind::TransparentInterception,
                    mode: RuntimeMode::Available,
                },
                RequiredCapabilityPlan {
                    capability: CapabilityKind::L7Mitm,
                    mode: RuntimeMode::Unavailable,
                },
            ]
        );
        assert_eq!(
            plan.interception.mitm.backend,
            TransparentInterceptionMitmBackendPlan::External {
                readiness_probe: TransparentInterceptionMitmBackendReadinessProbePlan::TcpConnect {
                    target: "127.0.0.1:15002".parse()?,
                    interval_ms: 1_000,
                    timeout_ms: 200,
                    failure_threshold: 3,
                },
            }
        );
        assert_eq!(
            plan.interception.mitm.plaintext_bridge,
            TransparentInterceptionMitmPlaintextBridgePlan::Disabled
        );
        assert_eq!(
            plan.interception
                .mitm
                .ca_certificate
                .as_ref()
                .map(|material| material.id.as_str()),
            Some("mitm-ca")
        );
        assert_eq!(
            plan.interception
                .mitm
                .ca_private_key
                .as_ref()
                .map(|material| material.id.as_str()),
            Some("mitm-ca-key")
        );
        assert!(matches!(
            plan.interception.execution.outbound_redirect_plan(),
            TransparentInterceptionOutboundRedirectPlan::Planned { .. }
        ));
        Ok(())
    }

    #[test]
    fn enforcement_plan_preserves_managed_process_mitm_backend()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        configure_managed_process_mitm_backend(&mut config);
        let capabilities = CapabilityMatrix::new([
            CapabilityState::available(CapabilityKind::TransparentInterception),
            CapabilityState::available(CapabilityKind::L7Mitm),
        ]);

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        let TransparentInterceptionMitmBackendPlan::ManagedProcess {
            process,
            readiness_probe,
        } = &plan.interception.mitm.backend
        else {
            panic!(
                "managed MITM backend plan should be preserved: {:?}",
                plan.interception.mitm.backend
            );
        };
        assert_eq!(
            readiness_probe,
            &TransparentInterceptionMitmBackendReadinessProbePlan::TcpConnect {
                target: "127.0.0.1:15002".parse()?,
                interval_ms: 1_000,
                timeout_ms: 200,
                failure_threshold: 3,
            }
        );
        assert_eq!(
            process.program,
            PathBuf::from("/usr/local/bin/traffic-probe-mitm-proxy")
        );
        assert_eq!(
            process.args,
            vec!["--listen".to_string(), "127.0.0.1:15002".to_string()]
        );
        assert_eq!(
            process.working_dir,
            Some(PathBuf::from("/run/traffic-probe"))
        );
        Ok(())
    }

    #[test]
    fn enforcement_plan_reports_external_mitm_plaintext_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        configure_external_mitm_backend(&mut config);
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path =
            Some("/run/traffic-probe/mitm-capture-events.jsonl".into());
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        let capabilities = CapabilityMatrix::new([
            CapabilityState::available(CapabilityKind::TransparentInterception),
            CapabilityState::available(CapabilityKind::L7Mitm),
            CapabilityState::available(CapabilityKind::CaptureEventFeed),
        ]);

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.interception.capabilities,
            vec![
                RequiredCapabilityPlan {
                    capability: CapabilityKind::TransparentInterception,
                    mode: RuntimeMode::Available,
                },
                RequiredCapabilityPlan {
                    capability: CapabilityKind::L7Mitm,
                    mode: RuntimeMode::Available,
                },
                RequiredCapabilityPlan {
                    capability: CapabilityKind::CaptureEventFeed,
                    mode: RuntimeMode::Available,
                },
            ]
        );
        assert_eq!(
            plan.interception.mitm.plaintext_bridge,
            TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed {
                path: "/run/traffic-probe/mitm-capture-events.jsonl".into(),
                follow: true,
            }
        );
        Ok(())
    }

    #[test]
    fn enforcement_plan_preserves_explicit_finite_mitm_plaintext_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        configure_external_mitm_backend(&mut config);
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path =
            Some("/run/traffic-probe/finite-mitm-capture-events.jsonl".into());
        config.enforcement.interception.mitm.plaintext_bridge.follow = Some(false);
        let capabilities = CapabilityMatrix::new([
            CapabilityState::available(CapabilityKind::TransparentInterception),
            CapabilityState::available(CapabilityKind::L7Mitm),
            CapabilityState::available(CapabilityKind::CaptureEventFeed),
        ]);

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.interception.mitm.plaintext_bridge,
            TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed {
                path: "/run/traffic-probe/finite-mitm-capture-events.jsonl".into(),
                follow: false,
            }
        );
        Ok(())
    }

    #[test]
    fn enforcement_plan_reports_external_outbound_proxy_self_bypass_contract() {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
        config.enforcement.interception.proxy.mode =
            TransparentInterceptionProxyModeConfig::External;
        config.enforcement.interception.proxy.self_bypass =
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let capabilities = CapabilityMatrix::new(test_platform_capabilities_with_interception(
            RuntimeMode::Available,
        ));

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.interception.proxy.self_bypass,
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
        );
        let TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound) =
            plan.interception.execution
        else {
            panic!("external outbound proxy should produce outbound execution plan");
        };
        assert_eq!(
            outbound.self_bypass(),
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
        );
        assert_eq!(
            outbound.proxy_mode(),
            TransparentInterceptionProxyModeConfig::External
        );
        assert_eq!(
            outbound.outbound_redirect_artifact().proxy_bypass_mark,
            NonZeroU32::new(0x5450_0102)
                .expect("test outbound proxy bypass mark should be non-zero")
        );
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        test_platform_capabilities_with_connection(RuntimeMode::Unavailable)
    }

    fn test_platform_capabilities_with_connection(mode: RuntimeMode) -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            match mode {
                RuntimeMode::Available => {
                    CapabilityState::available(CapabilityKind::ConnectionEnforcement)
                }
                RuntimeMode::Degraded => {
                    CapabilityState::degraded(CapabilityKind::ConnectionEnforcement, "degraded")
                }
                RuntimeMode::Unavailable => {
                    CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built")
                }
            },
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not built"),
            CapabilityState::unavailable(CapabilityKind::TransparentProcessClassifier, "not built"),
            CapabilityState::unavailable(CapabilityKind::TransparentFlowClassifier, "not built"),
            CapabilityState::unavailable(CapabilityKind::L7Mitm, "not built"),
        ]
    }

    fn test_platform_capabilities_with_interception(mode: RuntimeMode) -> Vec<CapabilityState> {
        test_platform_capabilities_with_connection(RuntimeMode::Unavailable)
            .into_iter()
            .map(|state| {
                if state.kind == CapabilityKind::TransparentInterception {
                    match mode {
                        RuntimeMode::Available => {
                            CapabilityState::available(CapabilityKind::TransparentInterception)
                        }
                        RuntimeMode::Degraded => CapabilityState::degraded(
                            CapabilityKind::TransparentInterception,
                            "degraded",
                        ),
                        RuntimeMode::Unavailable => CapabilityState::unavailable(
                            CapabilityKind::TransparentInterception,
                            "unavailable",
                        ),
                    }
                } else {
                    state
                }
            })
            .collect()
    }

    fn configure_external_mitm_backend(config: &mut AgentConfig) {
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some("127.0.0.1:15002".to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        configure_mitm_materials(config);
    }

    fn configure_mitm_materials(config: &mut AgentConfig) {
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
    }

    fn configure_managed_process_mitm_backend(config: &mut AgentConfig) {
        let readiness_probe = TransparentInterceptionMitmBackendReadinessProbeConfig {
            target: Some("127.0.0.1:15002".to_string()),
            ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
        };
        let process = TransparentInterceptionMitmManagedProcessConfig {
            program: Some("/usr/local/bin/traffic-probe-mitm-proxy".into()),
            args: vec!["--listen".to_string(), "127.0.0.1:15002".to_string()],
            working_dir: Some("/run/traffic-probe".into()),
        };
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::managed_process(readiness_probe, process);
        configure_mitm_materials(config);
    }
}

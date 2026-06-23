use std::{fmt, net::SocketAddr, num::NonZeroU16, path::PathBuf};

use probe_config::{
    AgentConfig, ConnectionEnforcementBackendConfig, EnforcementInterceptionConfig,
    EnforcementPolicySourceConfig, TransparentInterceptionProxyHealthProbeIntent,
    TransparentInterceptionProxyIntent, TransparentInterceptionProxyIntentViolation,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
};
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState, EnforcementMode, RuntimeMode};
use serde::{Deserialize, Serialize};

use super::interception_scope::TransparentInterceptionLocalSetupProjectionPlan;

const RESERVED_TRANSPARENT_INTERCEPTION_NFTABLES_TABLE: &str = "sssa_probe";
const RESERVED_TRANSPARENT_INTERCEPTION_NFTABLES_MARK: u32 = 0x5353_4101;
const RESERVED_TRANSPARENT_INTERCEPTION_ROUTE_TABLE: u32 = 53_534;
const RESERVED_TRANSPARENT_INTERCEPTION_OUTBOUND_CHAIN: &str = "outbound_mitm";
const TRANSPARENT_INTERCEPTION_OUTPUT_HOOK: &str = "output";
const TRANSPARENT_INTERCEPTION_DSTNAT_PRIORITY: &str = "dstnat";
const OUTBOUND_MITM_INSTALL_BLOCKED_REASON: &str = "outbound transparent MITM redirect install has an existing Linux original-destination resolver primitive, but requires proxy self-bypass socket marking, output redirect lifecycle, and MITM lifecycle";

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
    pub outbound_redirect: TransparentInterceptionOutboundRedirectPlan,
    pub local_setup_projection: TransparentInterceptionLocalSetupProjectionPlan,
    pub classification: TransparentInterceptionClassificationPlan,
    pub capability: EnforcementCapabilityPlan,
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
        Self {
            strategy,
            proxy: TransparentInterceptionProxyPlan::from_intent(&intent),
            execution: TransparentInterceptionExecutionPlan::from_intent(&intent),
            outbound_redirect: TransparentInterceptionOutboundRedirectPlan::from_intent(
                &intent, &nftables,
            ),
            nftables,
            local_setup_projection:
                TransparentInterceptionLocalSetupProjectionPlan::from_strategy_and_selectors(
                    strategy,
                    config.enforcement.selector.as_ref(),
                    config.enforcement.interception.selector.as_ref(),
                ),
            classification: TransparentInterceptionClassificationPlan::from_capabilities(
                capabilities,
            ),
            capability: EnforcementCapabilityPlan::from_interception_strategy(
                strategy,
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
            listen_port: intent.listen_port().map(NonZeroU16::get),
            health_probe: TransparentInterceptionProxyHealthProbePlan::from_intent(
                intent.health_probe().clone(),
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
#[serde(rename_all = "snake_case", tag = "strategy")]
pub enum TransparentInterceptionExecutionPlan {
    Disabled,
    InboundTproxy(TransparentInterceptionInboundTproxyPlan),
    OutboundMitm(TransparentInterceptionOutboundMitmPlan),
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
        match intent {
            TransparentInterceptionProxyIntent::Disabled(_) => Self::Disabled,
            TransparentInterceptionProxyIntent::InboundTproxy(proxy) => {
                Self::InboundTproxy(TransparentInterceptionInboundTproxyPlan {
                    proxy_mode: proxy.mode(),
                    listen_port: proxy.listen_port(),
                    health_probe: TransparentInterceptionProxyHealthProbePlan::from_intent(
                        proxy.health_probe().clone(),
                    ),
                })
            }
            TransparentInterceptionProxyIntent::OutboundMitm(proxy) => {
                Self::OutboundMitm(TransparentInterceptionOutboundMitmPlan {
                    listen_port: proxy.listen_port(),
                })
            }
        }
    }

    pub fn strategy(&self) -> TransparentInterceptionStrategyConfig {
        match self {
            Self::Disabled => TransparentInterceptionStrategyConfig::None,
            Self::InboundTproxy(_) => TransparentInterceptionStrategyConfig::InboundTproxy,
            Self::OutboundMitm(_) => TransparentInterceptionStrategyConfig::OutboundMitm,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionInboundTproxyPlan {
    proxy_mode: TransparentInterceptionProxyModeConfig,
    listen_port: NonZeroU16,
    health_probe: TransparentInterceptionProxyHealthProbePlan,
}

impl TransparentInterceptionInboundTproxyPlan {
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
pub struct TransparentInterceptionOutboundMitmPlan {
    listen_port: NonZeroU16,
}

impl TransparentInterceptionOutboundMitmPlan {
    pub fn listen_port(&self) -> NonZeroU16 {
        self.listen_port
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionNftablesPlan {
    pub table_name: String,
    pub mark: u32,
    pub route_table: u32,
}

impl TransparentInterceptionNftablesPlan {
    pub fn reserved() -> Self {
        Self {
            table_name: RESERVED_TRANSPARENT_INTERCEPTION_NFTABLES_TABLE.to_string(),
            mark: RESERVED_TRANSPARENT_INTERCEPTION_NFTABLES_MARK,
            route_table: RESERVED_TRANSPARENT_INTERCEPTION_ROUTE_TABLE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransparentInterceptionOutboundRedirectPlan {
    NotConfigured,
    Planned {
        table_name: String,
        chain_name: String,
        hook: String,
        priority: String,
        proxy_port: u16,
        proxy_bypass_mark: u32,
        install: TransparentInterceptionOutboundRedirectInstallPlan,
    },
}

impl TransparentInterceptionOutboundRedirectPlan {
    fn from_intent(
        intent: &TransparentInterceptionProxyIntent,
        nftables: &TransparentInterceptionNftablesPlan,
    ) -> Self {
        let TransparentInterceptionProxyIntent::OutboundMitm(proxy) = intent else {
            return Self::NotConfigured;
        };
        Self::Planned {
            table_name: nftables.table_name.clone(),
            chain_name: RESERVED_TRANSPARENT_INTERCEPTION_OUTBOUND_CHAIN.to_string(),
            hook: TRANSPARENT_INTERCEPTION_OUTPUT_HOOK.to_string(),
            priority: TRANSPARENT_INTERCEPTION_DSTNAT_PRIORITY.to_string(),
            proxy_port: proxy.listen_port().get(),
            proxy_bypass_mark: nftables.mark,
            install: TransparentInterceptionOutboundRedirectInstallPlan::Blocked {
                reason: OUTBOUND_MITM_INSTALL_BLOCKED_REASON.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransparentInterceptionOutboundRedirectInstallPlan {
    Blocked { reason: String },
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

    pub(super) fn requirement_for_interception_strategy(
        strategy: TransparentInterceptionStrategyConfig,
    ) -> Option<EnforcementCapabilityRequirement> {
        match strategy {
            TransparentInterceptionStrategyConfig::InboundTproxy => {
                Some(EnforcementCapabilityRequirement {
                    capability: CapabilityKind::TransparentInterception,
                    unavailable_reason: "transparent interception backend is not available in this build/runtime",
                })
            }
            TransparentInterceptionStrategyConfig::None
            | TransparentInterceptionStrategyConfig::OutboundMitm => None,
        }
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

    fn from_interception_strategy(
        strategy: TransparentInterceptionStrategyConfig,
        capabilities: &CapabilityMatrix,
    ) -> Self {
        Self::requirement_for_interception_strategy(strategy).map_or(
            Self::NotRequired,
            |requirement| {
                Self::required(
                    requirement.capability,
                    capabilities.mode(requirement.capability),
                )
            },
        )
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementPolicySourcePlan {
    None,
    LocalManifest {
        source_kind: EnforcementPolicySourceKind,
        path: PathBuf,
    },
    Remote {
        endpoint: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPolicySourceKind {
    File,
    Directory,
}

impl EnforcementPolicySourcePlan {
    fn from_config(source: &EnforcementPolicySourceConfig) -> Self {
        match source {
            EnforcementPolicySourceConfig::None => Self::None,
            EnforcementPolicySourceConfig::File { path } => Self::LocalManifest {
                source_kind: EnforcementPolicySourceKind::File,
                path: path.clone(),
            },
            EnforcementPolicySourceConfig::Directory { path } => Self::LocalManifest {
                source_kind: EnforcementPolicySourceKind::Directory,
                path: path.join("manifest.toml"),
            },
            EnforcementPolicySourceConfig::Remote { endpoint } => Self::Remote {
                endpoint: endpoint.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{
        AgentConfig, ConnectionEnforcementBackendConfig, TransparentInterceptionStrategyConfig,
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
    fn enforcement_plan_preserves_external_policy_source() {
        let mut config = AgentConfig::default();
        config.enforcement.selector = Some(Selector::default());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Directory {
            path: "/etc/sssa-probe/enforcement.d".into(),
        };
        let capabilities = CapabilityMatrix::new(test_platform_capabilities());

        let plan = EnforcementPlan::resolve(&config, &capabilities);

        assert_eq!(plan.mode, EnforcementMode::AuditOnly);
        assert!(plan.config_selector_configured);
        assert_eq!(
            plan.policy_source,
            EnforcementPolicySourcePlan::LocalManifest {
                source_kind: EnforcementPolicySourceKind::Directory,
                path: "/etc/sssa-probe/enforcement.d/manifest.toml".into(),
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
        assert_eq!(plan.interception.nftables.table_name, "sssa_probe");
        assert_eq!(plan.interception.nftables.mark, 0x5353_4101);
        assert_eq!(plan.interception.nftables.route_table, 53_534);
        assert_eq!(
            plan.interception.outbound_redirect,
            TransparentInterceptionOutboundRedirectPlan::NotConfigured
        );
        assert_eq!(
            plan.interception.capability,
            EnforcementCapabilityPlan::Required {
                capability: CapabilityKind::TransparentInterception,
                mode: RuntimeMode::Available,
            }
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
    fn enforcement_plan_reports_outbound_redirect_preview() {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundMitm;
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
            TransparentInterceptionStrategyConfig::OutboundMitm
        );
        assert!(matches!(
            plan.interception.local_setup_projection,
            TransparentInterceptionLocalSetupProjectionPlan::HostRules { .. }
        ));
        assert_eq!(
            plan.interception.capability,
            EnforcementCapabilityPlan::NotRequired
        );
        assert_eq!(
            plan.interception.outbound_redirect,
            TransparentInterceptionOutboundRedirectPlan::Planned {
                table_name: "sssa_probe".to_string(),
                chain_name: "outbound_mitm".to_string(),
                hook: "output".to_string(),
                priority: "dstnat".to_string(),
                proxy_port: 15001,
                proxy_bypass_mark: 0x5353_4101,
                install: TransparentInterceptionOutboundRedirectInstallPlan::Blocked {
                    reason: OUTBOUND_MITM_INSTALL_BLOCKED_REASON.to_string(),
                },
            }
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
}

use std::path::PathBuf;

use probe_config::{
    AgentConfig, ConnectionEnforcementBackendConfig, EnforcementPolicySourceConfig,
    TransparentInterceptionProxyConfig, TransparentInterceptionProxyHealthProbeConfig,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
};
use probe_core::{CapabilityKind, CapabilityMatrix, EnforcementMode, RuntimeMode};
use serde::{Deserialize, Serialize};

use super::interception_scope::TransparentInterceptionLocalSetupScopePlan;

const RESERVED_TRANSPARENT_INTERCEPTION_NFTABLES_TABLE: &str = "sssa_probe";
const RESERVED_TRANSPARENT_INTERCEPTION_NFTABLES_MARK: u32 = 0x5353_4101;
const RESERVED_TRANSPARENT_INTERCEPTION_ROUTE_TABLE: u32 = 53_534;

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
    pub fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
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
    pub nftables: TransparentInterceptionNftablesPlan,
    pub local_setup_scope: TransparentInterceptionLocalSetupScopePlan,
    pub capability: EnforcementCapabilityPlan,
    pub selector_configured: bool,
}

impl EnforcementInterceptionPlan {
    fn from_config(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        let strategy = config.enforcement.interception.strategy;
        Self {
            strategy,
            proxy: TransparentInterceptionProxyPlan::from_config(
                &config.enforcement.interception.proxy,
            ),
            nftables: TransparentInterceptionNftablesPlan::reserved(),
            local_setup_scope:
                TransparentInterceptionLocalSetupScopePlan::from_strategy_and_selectors(
                    strategy,
                    config.enforcement.selector.as_ref(),
                    config.enforcement.interception.selector.as_ref(),
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
pub struct TransparentInterceptionProxyPlan {
    pub mode: TransparentInterceptionProxyModeConfig,
    pub listen_port: Option<u16>,
    pub health_probe: TransparentInterceptionProxyHealthProbeConfig,
}

impl TransparentInterceptionProxyPlan {
    fn from_config(config: &TransparentInterceptionProxyConfig) -> Self {
        Self {
            mode: config.mode,
            listen_port: config.listen_port,
            health_probe: config.health_probe.clone(),
        }
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
        strategy.is_enabled().then_some(EnforcementCapabilityRequirement {
            capability: CapabilityKind::TransparentInterception,
            unavailable_reason: "transparent interception backend is not available in this build/runtime",
        })
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
    use probe_core::{CapabilityMatrix, CapabilityState, Selector};

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
            plan.interception.local_setup_scope,
            TransparentInterceptionLocalSetupScopePlan::Unsupported { .. }
        ));
        assert_eq!(
            plan.interception.proxy.mode,
            TransparentInterceptionProxyModeConfig::External
        );
        assert_eq!(plan.interception.proxy.listen_port, Some(15001));
        assert_eq!(
            plan.interception.proxy.health_probe.target.as_deref(),
            Some("127.0.0.1:18080")
        );
        assert_eq!(plan.interception.proxy.health_probe.interval_ms, 500);
        assert_eq!(plan.interception.proxy.health_probe.timeout_ms, 100);
        assert_eq!(plan.interception.proxy.health_probe.failure_threshold, 2);
        assert_eq!(plan.interception.nftables.table_name, "sssa_probe");
        assert_eq!(plan.interception.nftables.mark, 0x5353_4101);
        assert_eq!(plan.interception.nftables.route_table, 53_534);
        assert_eq!(
            plan.interception.capability,
            EnforcementCapabilityPlan::Required {
                capability: CapabilityKind::TransparentInterception,
                mode: RuntimeMode::Available,
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

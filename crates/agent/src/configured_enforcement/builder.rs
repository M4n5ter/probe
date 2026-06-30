use enforcement::{
    EnforcementBackend, EnforcementError, PlannerPolicy, ProxySideEnforcementSurface,
    ScopedEnforcementPlanner, SetupTimeEnforcementSurface,
};
use interception::{
    TransparentInterceptionHostRuleSet, TransparentInterceptionSetupSelectorSources,
    TransparentInterceptionSetupSelectors,
};
use probe_core::{EnforcementMode, ProtectiveActionProfile, Selector};
use runtime::{
    EnforcementExecutionSurface, EnforcementPolicySourcePlan, RuntimePlan,
    TransparentInterceptionExecutionPlan, TransparentInterceptionMitmPolicyHookPlan,
};
use thiserror::Error;

use crate::transparent_interception::{
    TransparentInterceptionError, TransparentInterceptionProcessClassifier,
};

use super::source::{
    EnforcementPolicySourceError, EnforcementPolicySourceLoadContext,
    LoadedEnforcementPolicySource, load_enforcement_policy_source_with_context,
};

#[derive(Debug, Error)]
pub enum ConfiguredEnforcementError {
    #[error("enforcement planner error: {0}")]
    Planner(#[from] EnforcementError),
    #[error("enforcement policy source error: {0}")]
    Source(#[source] Box<EnforcementPolicySourceError>),
    #[error("{0}")]
    TransparentInterception(#[from] TransparentInterceptionError),
    #[error("{0}")]
    L7MitmPolicyHook(#[from] crate::l7_mitm::L7MitmPolicyHookError),
    #[error("enforcement execution backend is not available in this build/runtime")]
    ExecutionBackendUnavailable,
    #[error("enforce mode requires an explicit enforcement policy source")]
    PolicySourceRequiredForEnforce,
}

impl From<EnforcementPolicySourceError> for ConfiguredEnforcementError {
    fn from(error: EnforcementPolicySourceError) -> Self {
        Self::Source(Box::new(error))
    }
}

#[derive(Clone)]
pub(crate) struct ActiveEnforcementPolicy {
    effective_selector: Option<Selector>,
    planner_policy: PlannerPolicy,
    policy_source: Option<LoadedEnforcementPolicySource>,
}

impl ActiveEnforcementPolicy {
    pub(crate) fn new(
        effective_selector: Option<Selector>,
        protective_actions: ProtectiveActionProfile,
        policy_source: Option<LoadedEnforcementPolicySource>,
    ) -> Result<Self, EnforcementError> {
        let planner_policy =
            PlannerPolicy::compile(effective_selector.as_ref(), protective_actions)?;
        Ok(Self {
            effective_selector,
            planner_policy,
            policy_source,
        })
    }

    pub(crate) fn effective_selector(&self) -> Option<&Selector> {
        self.effective_selector.as_ref()
    }

    pub(crate) fn effective_selector_configured(&self) -> bool {
        self.effective_selector.is_some()
    }

    pub(crate) fn manifest_selector_configured(&self) -> Option<bool> {
        self.policy_source
            .as_ref()
            .map(|source| source.manifest.selector.is_some())
    }

    pub(crate) fn planner_policy(&self) -> &PlannerPolicy {
        &self.planner_policy
    }

    pub(crate) fn policy_source(&self) -> Option<&LoadedEnforcementPolicySource> {
        self.policy_source.as_ref()
    }

    pub(crate) fn protective_actions(&self) -> &ProtectiveActionProfile {
        self.planner_policy.protective_action_profile()
    }
}

pub struct ConfiguredEnforcement {
    pub planner: ScopedEnforcementPlanner,
    pub mode: EnforcementMode,
    pub config_selector_configured: bool,
    pub active_policy: ActiveEnforcementPolicy,
    pub transparent_interception_setup_scope: Option<TransparentInterceptionHostRuleSet>,
}

pub struct ConfiguredEnforcementCheck {
    pub configured: ConfiguredEnforcement,
    pub setup_error: Option<TransparentInterceptionError>,
}

pub async fn build_configured_enforcement_with_backend(
    plan: &RuntimePlan,
    backend: Option<Box<dyn EnforcementBackend>>,
    policy_source_context: EnforcementPolicySourceLoadContext,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    let check =
        build_configured_enforcement_check_with_backend(plan, backend, policy_source_context)
            .await?;
    if let Some(error) = check.setup_error {
        return Err(error.into());
    }
    Ok(check.configured)
}

pub async fn build_configured_enforcement_check_with_backend(
    plan: &RuntimePlan,
    backend: Option<Box<dyn EnforcementBackend>>,
    policy_source_context: EnforcementPolicySourceLoadContext,
) -> Result<ConfiguredEnforcementCheck, ConfiguredEnforcementError> {
    let mut configured = build_configured_enforcement_from_parts(
        ConfiguredEnforcementParts {
            mode: plan.enforcement.mode,
            config_selector: plan.config.enforcement.selector.clone(),
            config_selector_configured: plan.enforcement.config_selector_configured,
            policy_source_plan: &plan.enforcement.policy_source,
            execution: ConfiguredEnforcementExecution::from_plan(plan, backend),
        },
        policy_source_context,
    )
    .await?;
    let setup_selectors = TransparentInterceptionSetupSelectors::from_sources(
        TransparentInterceptionSetupSelectorSources {
            local_enforcement_selector: plan.config.enforcement.selector.as_ref(),
            effective_enforcement_selector: configured.active_policy.effective_selector(),
            interception_selector: plan.config.enforcement.interception.selector.as_ref(),
        },
    );
    let mut process_classifier = TransparentInterceptionProcessClassifier::new();
    let transparent_interception_setup_scope =
        crate::transparent_interception::effective_setup_scope(
            &plan.enforcement.interception.execution,
            &plan.enforcement.interception.classification,
            &mut process_classifier,
            setup_selectors,
        );
    let setup_error = match transparent_interception_setup_scope {
        Ok(scope) => {
            configured.transparent_interception_setup_scope = scope;
            None
        }
        Err(error @ TransparentInterceptionError::Setup(_)) => Some(error),
        Err(error) => return Err(error.into()),
    };
    Ok(ConfiguredEnforcementCheck {
        configured,
        setup_error,
    })
}

struct ConfiguredEnforcementParts<'a> {
    mode: EnforcementMode,
    config_selector: Option<Selector>,
    config_selector_configured: bool,
    policy_source_plan: &'a EnforcementPolicySourcePlan,
    execution: ConfiguredEnforcementExecution<'a>,
}

async fn build_configured_enforcement_from_parts(
    parts: ConfiguredEnforcementParts<'_>,
    policy_source_context: EnforcementPolicySourceLoadContext,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    parts.execution.validate(parts.mode)?;
    validate_enforce_policy_source(parts.mode, parts.policy_source_plan)?;

    let policy_runtime = load_configured_enforcement_policy_runtime(
        parts.config_selector,
        parts.policy_source_plan,
        policy_source_context,
    )
    .await?;
    let planner = parts
        .execution
        .into_planner(parts.mode, policy_runtime.planner_policy().clone())?;
    Ok(ConfiguredEnforcement {
        planner,
        mode: parts.mode,
        config_selector_configured: parts.config_selector_configured,
        active_policy: policy_runtime,
        transparent_interception_setup_scope: None,
    })
}

fn validate_enforce_policy_source(
    mode: EnforcementMode,
    policy_source_plan: &EnforcementPolicySourcePlan,
) -> Result<(), ConfiguredEnforcementError> {
    if mode == EnforcementMode::Enforce
        && matches!(policy_source_plan, EnforcementPolicySourcePlan::None)
    {
        return Err(ConfiguredEnforcementError::PolicySourceRequiredForEnforce);
    }
    Ok(())
}

pub(crate) async fn load_configured_enforcement_policy_runtime(
    config_selector: Option<Selector>,
    policy_source_plan: &EnforcementPolicySourcePlan,
    policy_source_context: EnforcementPolicySourceLoadContext,
) -> Result<ActiveEnforcementPolicy, ConfiguredEnforcementError> {
    let policy_source =
        load_enforcement_policy_source_with_context(policy_source_plan, policy_source_context)
            .await?;
    let effective_selector = effective_selector(
        config_selector,
        policy_source
            .as_ref()
            .and_then(|source| source.manifest.selector.clone()),
    );
    let protective_actions = policy_source
        .as_ref()
        .map_or_else(ProtectiveActionProfile::default, |source| {
            source.manifest.protective_actions.clone()
        });
    ActiveEnforcementPolicy::new(effective_selector, protective_actions, policy_source)
        .map_err(ConfiguredEnforcementError::Planner)
}

fn mitm_policy_hook_connection_options_from_plan(
    plan: &RuntimePlan,
) -> crate::l7_mitm::L7MitmPolicyHookConnectionOptions {
    match &plan.enforcement.interception.execution {
        TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound) => {
            crate::l7_mitm::L7MitmPolicyHookConnectionOptions::default()
                .with_socket_mark(outbound.outbound_redirect_artifact().proxy_bypass_mark)
        }
        TransparentInterceptionExecutionPlan::Disabled
        | TransparentInterceptionExecutionPlan::InboundTproxy(_) => {
            crate::l7_mitm::L7MitmPolicyHookConnectionOptions::default()
        }
    }
}

enum ConfiguredEnforcementExecution<'a> {
    Unavailable,
    ConnectionBackend(Box<dyn EnforcementBackend>),
    TransparentInterceptionSetup,
    L7MitmProxyHook {
        policy_hook: &'a TransparentInterceptionMitmPolicyHookPlan,
        connection: crate::l7_mitm::L7MitmPolicyHookConnectionOptions,
    },
}

impl<'a> ConfiguredEnforcementExecution<'a> {
    fn from_plan(plan: &'a RuntimePlan, backend: Option<Box<dyn EnforcementBackend>>) -> Self {
        if let Some(backend) = backend {
            return Self::ConnectionBackend(backend);
        }
        match plan.enforcement.execution_surface {
            Some(EnforcementExecutionSurface::TransparentInterceptionSetup) => {
                Self::TransparentInterceptionSetup
            }
            Some(EnforcementExecutionSurface::L7MitmProxyHook) => Self::L7MitmProxyHook {
                policy_hook: &plan.enforcement.interception.mitm.policy_hook,
                connection: mitm_policy_hook_connection_options_from_plan(plan),
            },
            Some(EnforcementExecutionSurface::Connection) | None => Self::Unavailable,
        }
    }

    fn validate(&self, mode: EnforcementMode) -> Result<(), ConfiguredEnforcementError> {
        if mode != EnforcementMode::Enforce || !matches!(self, Self::Unavailable) {
            return Ok(());
        }
        Err(ConfiguredEnforcementError::ExecutionBackendUnavailable)
    }

    fn into_planner(
        self,
        mode: EnforcementMode,
        policy: PlannerPolicy,
    ) -> Result<ScopedEnforcementPlanner, ConfiguredEnforcementError> {
        if mode != EnforcementMode::Enforce {
            return ScopedEnforcementPlanner::with_planner_policy(mode, policy)
                .map_err(ConfiguredEnforcementError::Planner);
        }
        match self {
            Self::ConnectionBackend(backend) => {
                ScopedEnforcementPlanner::with_backend_policy(policy, backend)
                    .map_err(ConfiguredEnforcementError::Planner)
            }
            Self::TransparentInterceptionSetup => ScopedEnforcementPlanner::with_setup_time_policy(
                policy,
                SetupTimeEnforcementSurface::TransparentInterception,
            )
            .map_err(ConfiguredEnforcementError::Planner),
            Self::L7MitmProxyHook {
                policy_hook,
                connection,
            } => {
                let hook = crate::l7_mitm::policy_hook_from_plan(policy_hook, connection)?;
                ScopedEnforcementPlanner::with_proxy_side_policy_hook(
                    policy,
                    ProxySideEnforcementSurface::L7Mitm,
                    hook,
                )
                .map_err(ConfiguredEnforcementError::Planner)
            }
            Self::Unavailable => Err(ConfiguredEnforcementError::ExecutionBackendUnavailable),
        }
    }
}

fn effective_selector(
    config_selector: Option<Selector>,
    policy_selector: Option<Selector>,
) -> Option<Selector> {
    match (config_selector, policy_selector) {
        (Some(config), Some(policy)) => Some(Selector::All {
            selectors: vec![config, policy],
        }),
        (Some(selector), None) | (None, Some(selector)) => Some(selector),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{SocketAddr, TcpListener, TcpStream},
        path::{Path, PathBuf},
        thread::{self, JoinHandle},
    };

    use enforcement::{
        EnforcementBackend, EnforcementBackendDecision, EnforcementBackendRequest,
        EnforcementPlanRequest, EnforcementPlanner,
    };
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicyManifest,
        EnforcementPolicySourceConfig, TlsMaterialConfig, TlsMaterialKind,
        TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmPolicyHookConfig,
        TransparentInterceptionMitmPolicyHookModeConfig,
        TransparentInterceptionProxySelfBypassConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        Action, AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource,
        Direction, EnforcementExecutionEvidence, EnforcementMode, EnforcementOutcome,
        EventEnvelope, EventKind, FlowContext, FlowIdentity, OpaqueStream, ProcessContext,
        ProcessIdentity, ProcessSelector, ProxySideEnforcementSurface, Timestamp, TrafficSelector,
        TransportProtocol, Verdict, VerdictScope,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry,
        TransparentInterceptionExecutionPlan, TransparentInterceptionLocalSetupProjectionPlan,
        TransparentInterceptionMitmPolicyHookEndpointPlan,
        TransparentInterceptionMitmPolicyHookPlan,
    };

    use super::*;

    #[tokio::test]
    async fn enforce_without_backend_fails_before_loading_policy_source() {
        let policy_source_plan = EnforcementPolicySourcePlan::Remote {
            endpoint: "http://127.0.0.1:9/enforcement".to_string(),
            max_body_bytes: runtime::RemoteEnforcementPolicyBodyLimitBytes::from_config(None)
                .expect("default remote enforcement policy body limit must be valid"),
        };
        let error = match build_configured_enforcement_from_parts(
            ConfiguredEnforcementParts {
                mode: EnforcementMode::Enforce,
                config_selector: None,
                config_selector_configured: false,
                policy_source_plan: &policy_source_plan,
                execution: ConfiguredEnforcementExecution::Unavailable,
            },
            EnforcementPolicySourceLoadContext::default(),
        )
        .await
        {
            Ok(_) => panic!("enforce mode must not run without an execution backend"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConfiguredEnforcementError::ExecutionBackendUnavailable
        ));
    }

    #[tokio::test]
    async fn enforce_requires_policy_source() {
        let error = match build_configured_enforcement_from_parts(
            ConfiguredEnforcementParts {
                mode: EnforcementMode::Enforce,
                config_selector: None,
                config_selector_configured: false,
                policy_source_plan: &EnforcementPolicySourcePlan::None,
                execution: ConfiguredEnforcementExecution::ConnectionBackend(Box::new(
                    ApplyingBackend,
                )),
            },
            EnforcementPolicySourceLoadContext::default(),
        )
        .await
        {
            Ok(_) => panic!("enforce mode must require an explicit policy source"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConfiguredEnforcementError::PolicySourceRequiredForEnforce
        ));
    }

    #[tokio::test]
    async fn enforce_uses_injected_backend() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let policy_source_plan = test_enforcement_policy_source_plan(temp.path())?;
        let mut configured = build_configured_enforcement_from_parts(
            ConfiguredEnforcementParts {
                mode: EnforcementMode::Enforce,
                config_selector: None,
                config_selector_configured: false,
                policy_source_plan: &policy_source_plan,
                execution: ConfiguredEnforcementExecution::ConnectionBackend(Box::new(
                    ApplyingBackend,
                )),
            },
            EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let trigger = outbound_event();
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "managed policy".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = configured
            .planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict must produce an enforcement decision");

        assert_eq!(configured.planner.mode(), EnforcementMode::Enforce);
        assert_eq!(decision.outcome, EnforcementOutcome::Applied);
        assert_eq!(decision.effective_action, Action::Deny);
        assert_eq!(decision.reason, "backend applied Deny");
        Ok(())
    }

    #[tokio::test]
    async fn transparent_interception_enforce_records_per_flow_verdicts_as_setup_time_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let policy_source_plan = test_enforcement_policy_source_plan(temp.path())?;
        let mut configured = build_configured_enforcement_from_parts(
            ConfiguredEnforcementParts {
                mode: EnforcementMode::Enforce,
                config_selector: None,
                config_selector_configured: false,
                policy_source_plan: &policy_source_plan,
                execution: ConfiguredEnforcementExecution::TransparentInterceptionSetup,
            },
            EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let trigger = outbound_event();
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "managed policy".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = configured
            .planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict must produce an enforcement decision");

        assert_eq!(configured.planner.mode(), EnforcementMode::Enforce);
        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.reason.contains("setup-time enforcement surface"));
        Ok(())
    }

    #[tokio::test]
    async fn l7_mitm_proxy_hook_execution_surface_delegates_to_configured_hook()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let policy_source_plan = test_enforcement_policy_source_plan(temp.path())?;
        let hook_server = spawn_policy_hook(
            r#"{"outcome":"delegated","executed_action":"deny","reason":"proxy hook accepted"}"#,
        )?;
        let mitm_policy_hook = TransparentInterceptionMitmPolicyHookPlan::HttpJson {
            endpoint: policy_hook_endpoint_plan(&hook_server.endpoint, hook_server.address),
            timeout_ms: 1_000,
            max_response_bytes: 4_096,
        };
        let mut configured = build_configured_enforcement_from_parts(
            ConfiguredEnforcementParts {
                mode: EnforcementMode::Enforce,
                config_selector: None,
                config_selector_configured: false,
                policy_source_plan: &policy_source_plan,
                execution: ConfiguredEnforcementExecution::L7MitmProxyHook {
                    policy_hook: &mitm_policy_hook,
                    connection: crate::l7_mitm::L7MitmPolicyHookConnectionOptions::default(),
                },
            },
            EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let trigger = outbound_event();
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "managed policy".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = configured
            .planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict must produce an enforcement decision");

        assert_eq!(decision.outcome, EnforcementOutcome::Delegated);
        assert_eq!(decision.effective_action, Action::Deny);
        assert_eq!(
            decision.execution,
            Some(EnforcementExecutionEvidence::ProxySideHook {
                surface: ProxySideEnforcementSurface::L7Mitm,
                executed_action: Action::Deny,
                reason: "proxy hook accepted".to_string(),
            })
        );
        let body = hook_server
            .server
            .join()
            .expect("server thread should not panic")
            .map_err(std::io::Error::other)?;
        assert!(body.contains("\"requested_action\":\"deny\""));
        Ok(())
    }

    #[tokio::test]
    async fn l7_mitm_proxy_hook_composition_preserves_transparent_setup_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let hook_server = spawn_policy_hook(
            r#"{"outcome":"delegated","executed_action":"deny","reason":"proxy hook accepted"}"#,
        )?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        configure_test_enforcement_policy_source(&mut config, temp.path())?;
        configure_external_mitm_policy_hook(&mut config, &hook_server.endpoint);
        let plan = RuntimePlan::build(config, &transparent_interception_registry())?;
        assert_eq!(
            plan.enforcement.execution_surface,
            Some(EnforcementExecutionSurface::L7MitmProxyHook)
        );

        let mut check = build_configured_enforcement_check_with_backend(
            &plan,
            None,
            EnforcementPolicySourceLoadContext::default(),
        )
        .await?;

        assert!(check.setup_error.is_none());
        assert!(
            check
                .configured
                .transparent_interception_setup_scope
                .is_some()
        );
        let trigger = outbound_event();
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "managed policy".to_string(),
            confidence: 100,
            ttl_ms: None,
        };
        let decision = check
            .configured
            .planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict must produce an enforcement decision");

        assert_eq!(decision.outcome, EnforcementOutcome::Delegated);
        assert_eq!(decision.effective_action, Action::Deny);
        hook_server
            .server
            .join()
            .expect("server thread should not panic")
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    #[test]
    fn outbound_mitm_policy_hook_connection_uses_proxy_bypass_mark()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let plan = outbound_mitm_policy_hook_plan(temp.path())?;
        let TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound) =
            &plan.enforcement.interception.execution
        else {
            panic!("outbound MITM plan must use outbound transparent proxy execution");
        };

        let connection = mitm_policy_hook_connection_options_from_plan(&plan);

        assert_eq!(
            connection,
            crate::l7_mitm::L7MitmPolicyHookConnectionOptions::default()
                .with_socket_mark(outbound.outbound_redirect_artifact().proxy_bypass_mark)
        );
        Ok(())
    }

    #[tokio::test]
    async fn local_process_scoped_transparent_interception_fails_at_setup_composition()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        ));
        configure_test_enforcement_policy_source(&mut config, temp.path())?;

        let plan = RuntimePlan::build(config, &transparent_interception_registry())?;
        assert!(matches!(
            plan.enforcement.interception.local_setup_projection,
            TransparentInterceptionLocalSetupProjectionPlan::RequiresProcessClassifier { .. }
        ));
        let error = match build_configured_enforcement_with_backend(
            &plan,
            None,
            EnforcementPolicySourceLoadContext::default(),
        )
        .await
        {
            Ok(_) => panic!("process-scoped setup must require classifier support"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("process classifier"));
        Ok(())
    }

    #[tokio::test]
    async fn manifest_selector_can_narrow_but_not_make_setup_process_scoped()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let manifest_path = write_test_enforcement_manifest_with_selector(
            temp.path(),
            Some(Selector::term(
                ProcessSelector {
                    names: vec!["curl".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            )),
        )?;

        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path,
        };

        let plan = RuntimePlan::build(config, &transparent_interception_registry())?;
        assert!(matches!(
            plan.enforcement.interception.local_setup_projection,
            TransparentInterceptionLocalSetupProjectionPlan::HostRules { .. }
        ));
        let error = match build_configured_enforcement_with_backend(
            &plan,
            None,
            EnforcementPolicySourceLoadContext::default(),
        )
        .await
        {
            Ok(_) => panic!("manifest process selector must require classifier support"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("process classifier"));
        Ok(())
    }

    #[tokio::test]
    async fn manifest_selector_cannot_supply_the_only_setup_host_constraint()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let manifest_path = write_test_enforcement_manifest_with_selector(
            temp.path(),
            Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![8443],
                    directions: vec![Direction::Inbound],
                    ..TrafficSelector::default()
                },
            )),
        )?;

        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path,
        };

        let plan = RuntimePlan::build(config, &transparent_interception_registry())?;
        assert!(matches!(
            plan.enforcement.interception.local_setup_projection,
            TransparentInterceptionLocalSetupProjectionPlan::Unsupported { .. }
        ));
        let error = match build_configured_enforcement_with_backend(
            &plan,
            None,
            EnforcementPolicySourceLoadContext::default(),
        )
        .await
        {
            Ok(_) => panic!("manifest must not supply the only setup host constraint"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("at least one host-rule constraint")
        );
        Ok(())
    }

    fn test_enforcement_policy_source_plan(
        dir: &Path,
    ) -> Result<EnforcementPolicySourcePlan, Box<dyn std::error::Error>> {
        let path = write_test_enforcement_manifest(dir)?;
        Ok(EnforcementPolicySourcePlan::LocalManifest {
            source_kind: runtime::EnforcementPolicySourceKind::File,
            path,
        })
    }

    fn configure_test_enforcement_policy_source(
        config: &mut AgentConfig,
        dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: write_test_enforcement_manifest(dir)?,
        };
        Ok(())
    }

    fn write_test_enforcement_manifest(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        write_test_enforcement_manifest_with_selector(dir, None)
    }

    fn write_test_enforcement_manifest_with_selector(
        dir: &Path,
        selector: Option<Selector>,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = dir.join("manifest.toml");
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selector,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        std::fs::write(&path, toml::to_string(&manifest)?)?;
        Ok(path)
    }

    struct ApplyingBackend;

    impl EnforcementBackend for ApplyingBackend {
        fn apply(
            &mut self,
            request: EnforcementBackendRequest<'_>,
        ) -> Result<EnforcementBackendDecision, enforcement::EnforcementError> {
            Ok(EnforcementBackendDecision::applied(format!(
                "backend applied {:?}",
                request.verdict.action
            )))
        }
    }

    struct SpawnedPolicyHook {
        endpoint: String,
        address: SocketAddr,
        server: JoinHandle<Result<String, String>>,
    }

    fn spawn_policy_hook(response_body: &'static str) -> Result<SpawnedPolicyHook, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let endpoint = format!("http://{address}/enforce");
        let server = thread::spawn(move || -> Result<String, String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let request_body = read_request_body(&stream)?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .map_err(|error| error.to_string())?;
            Ok(request_body)
        });
        Ok(SpawnedPolicyHook {
            endpoint,
            address,
            server,
        })
    }

    fn policy_hook_endpoint_plan(
        endpoint: &str,
        address: SocketAddr,
    ) -> TransparentInterceptionMitmPolicyHookEndpointPlan {
        TransparentInterceptionMitmPolicyHookEndpointPlan {
            endpoint: endpoint.to_string(),
            address,
            authority: address.to_string(),
            path_and_query: "/enforce".to_string(),
        }
    }

    fn outbound_mitm_policy_hook_plan(
        policy_source_dir: &Path,
    ) -> Result<RuntimePlan, Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        config.enforcement.interception.proxy.self_bypass =
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark;
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        configure_test_enforcement_policy_source(&mut config, policy_source_dir)?;
        configure_external_mitm_policy_hook(&mut config, "http://127.0.0.1:16000/enforce");
        Ok(RuntimePlan::build(
            config,
            &transparent_interception_registry(),
        )?)
    }

    fn configure_external_mitm_policy_hook(config: &mut AgentConfig, endpoint: &str) {
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some("127.0.0.1:15002".to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        config.enforcement.interception.mitm.policy_hook =
            TransparentInterceptionMitmPolicyHookConfig {
                mode: TransparentInterceptionMitmPolicyHookModeConfig::HttpJson,
                endpoint: Some(endpoint.to_string()),
                ..TransparentInterceptionMitmPolicyHookConfig::default()
            };
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.enforcement.interception.mitm.client_trust.mode =
            probe_config::TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
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

    fn read_request_body(stream: &TcpStream) -> Result<String, String> {
        let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);
        let mut content_length = None;
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|error| error.to_string())?;
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix("Content-Length:") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|error| error.to_string())?,
                );
            }
        }
        let mut body = vec![0_u8; content_length.ok_or("missing content length")?];
        reader
            .read_exact(&mut body)
            .map_err(|error| error.to_string())?;
        String::from_utf8(body).map_err(|error| error.to_string())
    }

    fn outbound_event() -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1_700_000_000,
            },
            flow_context(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test-config",
            EventKind::OpaqueStream(OpaqueStream {
                direction: Direction::Outbound,
                fingerprint: vec![1, 2, 3],
                reason: "test payload".to_string(),
            }),
        )
    }

    fn transparent_interception_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            )],
            vec![
                CapabilityState::available(CapabilityKind::Http1),
                CapabilityState::available(CapabilityKind::Sse),
                CapabilityState::available(CapabilityKind::WebSocketHandoff),
                CapabilityState::available(CapabilityKind::WebSocketFrame),
                CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
                CapabilityState::available(CapabilityKind::DryRunEnforcement),
                CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
                CapabilityState::available(CapabilityKind::TransparentInterception),
                CapabilityState::available(CapabilityKind::L7Mitm),
            ],
        )
    }

    fn flow_context() -> FlowContext {
        FlowContext {
            id: FlowIdentity("flow-1".to_string()),
            process: ProcessContext {
                identity: ProcessIdentity {
                    pid: 42,
                    tgid: 42,
                    start_time_ticks: 7,
                    boot_id: "boot".to_string(),
                    exe_path: "/usr/bin/app".to_string(),
                    cmdline_hash: "hash".to_string(),
                    uid: 1000,
                    gid: 1000,
                    cgroup: None,
                    systemd_service: Some("app.service".to_string()),
                    container_id: None,
                    runtime_hint: None,
                },
                name: "app".to_string(),
                cmdline: vec!["app".to_string()],
            },
            local: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 41000,
            },
            remote: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 8080,
            },
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

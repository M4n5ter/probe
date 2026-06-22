use enforcement::{
    EnforcementBackend, EnforcementError, PlannerPolicy, ScopedEnforcementPlanner,
    SetupTimeEnforcementSurface,
};
use interception::{
    TransparentInterceptionHostRuleScope, TransparentInterceptionSetupSelectorSources,
    TransparentInterceptionSetupSelectors,
};
use probe_core::{EnforcementMode, ProtectiveActionProfile, Selector};
use runtime::{EnforcementExecutionSurface, EnforcementPolicySourcePlan, RuntimePlan};
use thiserror::Error;

use crate::transparent_interception::TransparentInterceptionError;

use super::source::{
    EnforcementPolicySourceError, LoadedEnforcementPolicySource, load_enforcement_policy_source,
};

#[derive(Debug, Error)]
pub enum ConfiguredEnforcementError {
    #[error("enforcement planner error: {0}")]
    Planner(#[from] EnforcementError),
    #[error("enforcement policy source error: {0}")]
    Source(#[from] EnforcementPolicySourceError),
    #[error("{0}")]
    TransparentInterception(#[from] TransparentInterceptionError),
    #[error("enforcement execution backend is not available in this build/runtime")]
    ExecutionBackendUnavailable,
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
    pub transparent_interception_setup_scope: Option<TransparentInterceptionHostRuleScope>,
}

pub async fn build_configured_enforcement_with_backend(
    plan: &RuntimePlan,
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    let mut configured = build_configured_enforcement_from_parts(
        plan.enforcement.mode,
        plan.config.enforcement.selector.clone(),
        plan.enforcement.config_selector_configured,
        &plan.enforcement.policy_source,
        &plan.enforcement.execution_surfaces,
        backend,
    )
    .await?;
    let setup_selectors = TransparentInterceptionSetupSelectors::from_sources(
        TransparentInterceptionSetupSelectorSources {
            local_enforcement_selector: plan.config.enforcement.selector.as_ref(),
            effective_enforcement_selector: configured.active_policy.effective_selector(),
            interception_selector: plan.config.enforcement.interception.selector.as_ref(),
        },
    );
    let transparent_interception_setup_scope =
        crate::transparent_interception::effective_setup_scope(
            &plan.enforcement.interception.execution,
            setup_selectors,
        )?;
    configured.transparent_interception_setup_scope = transparent_interception_setup_scope;
    Ok(configured)
}

async fn build_configured_enforcement_from_parts(
    mode: EnforcementMode,
    config_selector: Option<Selector>,
    config_selector_configured: bool,
    policy_source_plan: &EnforcementPolicySourcePlan,
    execution_surfaces: &[EnforcementExecutionSurface],
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    validate_enforcement_execution(mode, execution_surfaces, backend.is_some())?;

    let policy_runtime =
        load_configured_enforcement_policy_runtime(config_selector, policy_source_plan).await?;
    let planner = scoped_enforcement_planner(
        mode,
        policy_runtime.planner_policy().clone(),
        execution_surfaces,
        backend,
    )?;
    Ok(ConfiguredEnforcement {
        planner,
        mode,
        config_selector_configured,
        active_policy: policy_runtime,
        transparent_interception_setup_scope: None,
    })
}

pub(crate) async fn load_configured_enforcement_policy_runtime(
    config_selector: Option<Selector>,
    policy_source_plan: &EnforcementPolicySourcePlan,
) -> Result<ActiveEnforcementPolicy, ConfiguredEnforcementError> {
    let policy_source = load_enforcement_policy_source(policy_source_plan).await?;
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

fn scoped_enforcement_planner(
    mode: EnforcementMode,
    policy: PlannerPolicy,
    execution_surfaces: &[EnforcementExecutionSurface],
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<ScopedEnforcementPlanner, ConfiguredEnforcementError> {
    if mode != EnforcementMode::Enforce {
        return ScopedEnforcementPlanner::with_planner_policy(mode, policy)
            .map_err(ConfiguredEnforcementError::Planner);
    }

    if let Some(backend) = backend {
        return ScopedEnforcementPlanner::with_backend_policy(policy, backend)
            .map_err(ConfiguredEnforcementError::Planner);
    }

    if execution_surfaces == [EnforcementExecutionSurface::TransparentInterception] {
        return ScopedEnforcementPlanner::with_setup_time_policy(
            policy,
            SetupTimeEnforcementSurface::TransparentInterception,
        )
        .map_err(ConfiguredEnforcementError::Planner);
    }

    Err(ConfiguredEnforcementError::ExecutionBackendUnavailable)
}

fn validate_enforcement_execution(
    mode: EnforcementMode,
    execution_surfaces: &[EnforcementExecutionSurface],
    backend_present: bool,
) -> Result<(), ConfiguredEnforcementError> {
    if mode != EnforcementMode::Enforce || backend_present {
        return Ok(());
    }
    if execution_surfaces == [EnforcementExecutionSurface::TransparentInterception] {
        return Ok(());
    }
    Err(ConfiguredEnforcementError::ExecutionBackendUnavailable)
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
    use enforcement::{
        EnforcementBackend, EnforcementBackendDecision, EnforcementBackendRequest,
        EnforcementPlanRequest, EnforcementPlanner,
    };
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicyManifest,
        EnforcementPolicySourceConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        Action, AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource,
        Direction, EnforcementMode, EnforcementOutcome, EventEnvelope, EventKind, FlowContext,
        FlowIdentity, OpaqueStream, ProcessContext, ProcessIdentity, ProcessSelector, Timestamp,
        TrafficSelector, TransportProtocol, Verdict, VerdictScope,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry,
        TransparentInterceptionLocalSetupScopePlan,
    };

    use super::*;

    #[tokio::test]
    async fn enforce_without_backend_fails_before_loading_policy_source() {
        let error = match build_configured_enforcement_from_parts(
            EnforcementMode::Enforce,
            None,
            false,
            &EnforcementPolicySourcePlan::Remote {
                endpoint: "http://127.0.0.1:9/enforcement".to_string(),
            },
            &[EnforcementExecutionSurface::Connection],
            None,
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
    async fn enforce_uses_injected_backend() -> Result<(), Box<dyn std::error::Error>> {
        let mut configured = build_configured_enforcement_from_parts(
            EnforcementMode::Enforce,
            None,
            false,
            &EnforcementPolicySourcePlan::None,
            &[EnforcementExecutionSurface::Connection],
            Some(Box::new(ApplyingBackend)),
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
        let mut configured = build_configured_enforcement_from_parts(
            EnforcementMode::Enforce,
            None,
            false,
            &EnforcementPolicySourcePlan::None,
            &[EnforcementExecutionSurface::TransparentInterception],
            None,
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
    async fn local_process_scoped_transparent_interception_fails_at_setup_composition()
    -> Result<(), Box<dyn std::error::Error>> {
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

        let plan = RuntimePlan::build(config, &transparent_interception_registry())?;
        assert!(matches!(
            plan.enforcement.interception.local_setup_scope,
            TransparentInterceptionLocalSetupScopePlan::RequiresProcessClassifier { .. }
        ));
        let error = match build_configured_enforcement_with_backend(&plan, None).await {
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
        let manifest_path = temp.path().join("manifest.toml");
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selector: Some(Selector::term(
                ProcessSelector {
                    names: vec!["curl".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            )),
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        std::fs::write(&manifest_path, toml::to_string(&manifest)?)?;

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
        assert_eq!(
            plan.enforcement.interception.local_setup_scope,
            TransparentInterceptionLocalSetupScopePlan::HostRules
        );
        let error = match build_configured_enforcement_with_backend(&plan, None).await {
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
        let manifest_path = temp.path().join("manifest.toml");
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selector: Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![8443],
                    directions: vec![Direction::Inbound],
                    ..TrafficSelector::default()
                },
            )),
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        std::fs::write(&manifest_path, toml::to_string(&manifest)?)?;

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
            plan.enforcement.interception.local_setup_scope,
            TransparentInterceptionLocalSetupScopePlan::Unsupported { .. }
        ));
        let error = match build_configured_enforcement_with_backend(&plan, None).await {
            Ok(_) => panic!("manifest must not supply the only setup host constraint"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("at least one port or remote address")
        );
        Ok(())
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

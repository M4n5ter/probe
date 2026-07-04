use std::sync::Arc;

use probe_core::EnforcementMode;
use runtime::{EnforcementPolicySourcePlan, RuntimePlan};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::configured_enforcement::{
    ActiveEnforcementPolicy, ConfiguredEnforcementError, EnforcementRuntimeState,
    load_configured_enforcement_policy_runtime,
};
use crate::control_plane_http::enforcement_policy_source_load_context_from_plan;

#[derive(Clone, Default)]
pub(crate) struct EnforcementReloadGate {
    inner: Arc<Mutex<()>>,
}

pub(crate) struct EnforcementReloadSummary {
    pub active_policy: ActiveEnforcementPolicy,
}

pub(crate) struct PreparedEnforcementPolicyReload {
    active_policy: ActiveEnforcementPolicy,
}

impl PreparedEnforcementPolicyReload {
    pub(crate) async fn commit(
        self,
        runtime_state: &EnforcementRuntimeState,
        gate: &EnforcementReloadGate,
    ) -> EnforcementReloadSummary {
        let _reload_guard = gate.inner.lock().await;
        self.commit_with_gate_held(runtime_state)
    }

    fn commit_with_gate_held(
        self,
        runtime_state: &EnforcementRuntimeState,
    ) -> EnforcementReloadSummary {
        runtime_state.replace(self.active_policy.clone());
        EnforcementReloadSummary {
            active_policy: self.active_policy,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum EnforcementReloadError {
    #[error("enforcement runtime state is not available")]
    RuntimeStateUnavailable,
    #[error(
        "online enforcement policy reload with transparent interception requires a stable explicit interception selector"
    )]
    SetupTimeInterception,
    #[error("enforce mode requires an explicit enforcement policy source")]
    PolicySourceRequiredForEnforce,
    #[error(transparent)]
    Configured(#[from] Box<ConfiguredEnforcementError>),
    #[error("failed to reconfigure active enforcement planner: {0}")]
    Planner(#[from] enforcement::EnforcementError),
}

impl From<ConfiguredEnforcementError> for EnforcementReloadError {
    fn from(error: ConfiguredEnforcementError) -> Self {
        Self::Configured(Box::new(error))
    }
}

pub(crate) fn validate_enforcement_policy_reload_plan(
    plan: &RuntimePlan,
) -> Result<(), EnforcementReloadError> {
    reject_setup_time_interception_reload(plan)?;
    reject_enforce_without_policy_source(plan)
}

pub(crate) async fn reload_enforcement_policy(
    plan: &RuntimePlan,
    runtime_state: Option<&EnforcementRuntimeState>,
    gate: &EnforcementReloadGate,
) -> Result<EnforcementReloadSummary, EnforcementReloadError> {
    let runtime_state = runtime_state.ok_or(EnforcementReloadError::RuntimeStateUnavailable)?;
    let _reload_guard = gate.inner.lock().await;
    let prepared = prepare_enforcement_policy_reload(plan).await?;
    Ok(prepared.commit_with_gate_held(runtime_state))
}

pub(crate) async fn prepare_enforcement_policy_reload(
    plan: &RuntimePlan,
) -> Result<PreparedEnforcementPolicyReload, EnforcementReloadError> {
    validate_enforcement_policy_reload_plan(plan)?;
    let active_policy = load_configured_enforcement_policy_runtime(
        plan.config.enforcement.selector.clone(),
        &plan.config.selectors,
        &plan.enforcement.policy_source,
        enforcement_policy_source_load_context_from_plan(plan),
    )
    .await?;
    Ok(PreparedEnforcementPolicyReload { active_policy })
}

fn reject_setup_time_interception_reload(plan: &RuntimePlan) -> Result<(), EnforcementReloadError> {
    if plan
        .enforcement
        .interception
        .setup_scope_is_independent_from_enforcement_policy()
    {
        return Ok(());
    }
    Err(EnforcementReloadError::SetupTimeInterception)
}

fn reject_enforce_without_policy_source(plan: &RuntimePlan) -> Result<(), EnforcementReloadError> {
    if plan.enforcement.mode == EnforcementMode::Enforce
        && matches!(
            plan.enforcement.policy_source,
            EnforcementPolicySourcePlan::None
        )
    {
        return Err(EnforcementReloadError::PolicySourceRequiredForEnforce);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use enforcement::{EnforcementPlanRequest, EnforcementPlanner, ScopedEnforcementPlanner};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicyManifest,
        EnforcementPolicySourceConfig, TlsMaterialConfig, TlsMaterialKind,
        TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmPolicyHookConfig,
        TransparentInterceptionMitmPolicyHookModeConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        Action, AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource,
        Direction, EnforcementDecision, EnforcementMode, EnforcementOutcome, EventEnvelope,
        EventKind, FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity,
        ProcessSelector, ProtectiveActionProfile, Selector, Timestamp, TrafficSelector,
        TransportProtocol, Verdict, VerdictScope,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, EnforcementExecutionSurface,
        ProviderRegistry, RuntimePlan,
    };

    use crate::configured_enforcement::RuntimeEnforcementPlanner;

    use super::*;

    #[tokio::test]
    async fn invalid_reload_keeps_active_enforcement_planner()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let manifest_path = temp.path().join("enforcement.toml");
        write_enforcement_manifest(&manifest_path, "initial", 80, Action::Deny)?;
        let mut config = config_with_storage_path(temp.path().join("spool"));
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path.clone(),
        };
        let plan = RuntimePlan::build(config, &replay_registry())?;
        let configured = crate::configured_enforcement::build_configured_enforcement_with_backend(
            &plan,
            None,
            crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let (mut planner_view, runtime_state) =
            EnforcementRuntimeState::from_planner(configured.planner, configured.active_policy);
        assert_eq!(
            enforcement_decision(&mut planner_view, Action::Deny, 80)?.outcome,
            EnforcementOutcome::DryRun
        );
        std::fs::write(&manifest_path, b"id = ")?;

        let error = match reload_enforcement_policy(
            &plan,
            Some(&runtime_state),
            &EnforcementReloadGate::default(),
        )
        .await
        {
            Ok(_) => panic!("invalid manifest must fail reload"),
            Err(error) => error,
        };

        assert!(matches!(error, EnforcementReloadError::Configured(_)));
        let decision = enforcement_decision(&mut planner_view, Action::Deny, 80)?;
        assert_eq!(decision.outcome, EnforcementOutcome::DryRun);
        assert!(decision.selector_matched);
        Ok(())
    }

    #[tokio::test]
    async fn standalone_reload_reads_manifest_after_reload_gate_opens()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let manifest_path = temp.path().join("enforcement.toml");
        write_enforcement_manifest(&manifest_path, "old", 80, Action::Deny)?;
        let mut config = config_with_storage_path(temp.path().join("spool"));
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path.clone(),
        };
        let plan = RuntimePlan::build(config, &replay_registry())?;
        let configured = crate::configured_enforcement::build_configured_enforcement_with_backend(
            &plan,
            None,
            crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let (_, runtime_state) =
            EnforcementRuntimeState::from_planner(configured.planner, configured.active_policy);
        let gate = EnforcementReloadGate::default();
        let gate_guard = gate.inner.lock().await;

        let reload = reload_enforcement_policy(&plan, Some(&runtime_state), &gate);
        tokio::pin!(reload);
        tokio::select! {
            _ = &mut reload => panic!("reload should wait for the reload gate"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }
        write_enforcement_manifest(&manifest_path, "new", 443, Action::Deny)?;
        drop(gate_guard);

        let summary = reload.await?;

        assert_eq!(
            summary
                .active_policy
                .policy_source()
                .expect("reloaded policy should keep source details")
                .manifest
                .version,
            "new"
        );
        Ok(())
    }

    #[tokio::test]
    async fn transparent_interception_with_explicit_selector_allows_online_reload()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let manifest_path = temp.path().join("enforcement.toml");
        write_enforcement_manifest(&manifest_path, "reloaded", 443, Action::Deny)?;
        let plan = transparent_interception_plan(&manifest_path, InterceptionSetupScope::Explicit)?;
        assert!(plan.enforcement.interception.selector_configured);
        let (mut planner_view, runtime_state) = runtime_state_for_reload_test().await?;

        let summary = reload_enforcement_policy(
            &plan,
            Some(&runtime_state),
            &EnforcementReloadGate::default(),
        )
        .await?;

        assert!(summary.active_policy.effective_selector_configured());
        let decision = enforcement_decision(&mut planner_view, Action::Deny, 443)?;
        assert_eq!(decision.outcome, EnforcementOutcome::AuditOnly);
        assert!(decision.selector_matched);
        Ok(())
    }

    #[tokio::test]
    async fn setup_time_interception_without_explicit_selector_rejects_online_reload()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = transparent_interception_plan(
            std::path::Path::new("/tmp/traffic-probe-enforcement.toml"),
            InterceptionSetupScope::Inherited,
        )?;
        assert!(!plan.enforcement.interception.selector_configured);
        let (_, runtime_state) = runtime_state_for_reload_test().await?;

        let error = match reload_enforcement_policy(
            &plan,
            Some(&runtime_state),
            &EnforcementReloadGate::default(),
        )
        .await
        {
            Ok(_) => {
                panic!("inherited interception setup scope cannot be reloaded by planner swap")
            }
            Err(error) => error,
        };

        assert!(matches!(
            error,
            EnforcementReloadError::SetupTimeInterception
        ));
        Ok(())
    }

    #[test]
    fn mitm_policy_hook_plan_with_explicit_selector_allows_online_reload_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = mitm_policy_hook_interception_plan()?;
        assert_eq!(
            plan.enforcement.execution_surface,
            Some(EnforcementExecutionSurface::L7MitmProxyHook)
        );
        assert!(plan.enforcement.interception.selector_configured);

        validate_enforcement_policy_reload_plan(&plan)?;
        Ok(())
    }

    async fn runtime_state_for_reload_test()
    -> Result<(RuntimeEnforcementPlanner, EnforcementRuntimeState), Box<dyn std::error::Error>>
    {
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::AuditOnly, None)?;
        let selector_registry = probe_core::SelectorRegistry::default();
        let active_policy =
            crate::configured_enforcement::load_configured_enforcement_policy_runtime(
                None,
                &selector_registry,
                &runtime::EnforcementPolicySourcePlan::None,
                crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
            )
            .await?;
        Ok(EnforcementRuntimeState::from_planner(
            planner,
            active_policy,
        ))
    }

    fn config_with_storage_path(storage_path: std::path::PathBuf) -> AgentConfig {
        AgentConfig {
            capture: probe_config::CaptureConfig {
                selection: CaptureSelection::Replay,
                ..Default::default()
            },
            storage: probe_config::StorageConfig {
                path: storage_path,
                ..Default::default()
            },
            ..AgentConfig::default()
        }
    }

    fn transparent_interception_plan(
        policy_source_path: &std::path::Path,
        setup_scope: InterceptionSetupScope,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        let setup_selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        );
        match setup_scope {
            InterceptionSetupScope::Explicit => {
                config.enforcement.interception.selector = Some(setup_selector);
            }
            InterceptionSetupScope::Inherited => {
                config.enforcement.selector = Some(setup_selector);
            }
        }
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: policy_source_path.into(),
        };
        RuntimePlan::build(config, &transparent_interception_registry())
    }

    enum InterceptionSetupScope {
        Explicit,
        Inherited,
    }

    fn mitm_policy_hook_interception_plan() -> Result<RuntimePlan, runtime::RuntimeError> {
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
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: "/tmp/traffic-probe-enforcement.toml".into(),
        };
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
                endpoint: Some("http://127.0.0.1:15002/enforce".to_string()),
                ..TransparentInterceptionMitmPolicyHookConfig::default()
            };
        config.enforcement.interception.mitm.client_trust.mode =
            probe_config::TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
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
        RuntimePlan::build(config, &transparent_interception_registry())
    }

    fn replay_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            platform_capabilities(),
        )
    }

    fn transparent_interception_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            )],
            platform_capabilities()
                .into_iter()
                .map(|state| {
                    if state.kind == CapabilityKind::TransparentInterception {
                        CapabilityState::available(CapabilityKind::TransparentInterception)
                    } else {
                        state
                    }
                })
                .collect(),
        )
    }

    fn platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::L7Mitm),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not built"),
        ]
    }

    fn write_enforcement_manifest(
        path: &std::path::Path,
        version: &str,
        remote_port: u16,
        action: Action,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: version.to_string(),
            selectors: Default::default(),
            selector: Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![remote_port],
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            )),
            protective_actions: ProtectiveActionProfile::new([action])?,
        };
        std::fs::write(path, toml::to_string(&manifest)?)?;
        Ok(())
    }

    fn enforcement_decision(
        planner: &mut impl EnforcementPlanner,
        action: Action,
        remote_port: u16,
    ) -> Result<EnforcementDecision, Box<dyn std::error::Error>> {
        let trigger = request_event(remote_port);
        let verdict = Verdict {
            action,
            scope: VerdictScope::Flow,
            reason: "managed policy".to_string(),
            confidence: 100,
            ttl_ms: None,
        };
        Ok(planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce enforcement audit"))
    }

    fn request_event(remote_port: u16) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(remote_port),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn demo_flow(remote_port: u16) -> FlowContext {
        let process = ProcessIdentity {
            pid: 100,
            tgid: 100,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: remote_port,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

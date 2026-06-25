use std::sync::Arc;

use runtime::{EnforcementExecutionSurface, RuntimePlan};
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

pub(super) struct EnforcementReloadSummary {
    pub active_policy: ActiveEnforcementPolicy,
}

#[derive(Debug, Error)]
pub(super) enum EnforcementReloadError {
    #[error("enforcement runtime state is not available")]
    RuntimeStateUnavailable,
    #[error(
        "online enforcement policy reload is not supported while transparent interception owns setup-time host rules"
    )]
    SetupTimeInterception,
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

pub(super) async fn reload_enforcement_policy(
    plan: &RuntimePlan,
    runtime_state: Option<&EnforcementRuntimeState>,
    gate: &EnforcementReloadGate,
) -> Result<EnforcementReloadSummary, EnforcementReloadError> {
    reject_setup_time_interception_reload(plan)?;
    let runtime_state = runtime_state.ok_or(EnforcementReloadError::RuntimeStateUnavailable)?;
    let _reload_guard = gate.inner.lock().await;
    let loaded = load_configured_enforcement_policy_runtime(
        plan.config.enforcement.selector.clone(),
        &plan.enforcement.policy_source,
        enforcement_policy_source_load_context_from_plan(plan),
    )
    .await?;
    runtime_state.replace(loaded.clone());
    Ok(EnforcementReloadSummary {
        active_policy: loaded,
    })
}

fn reject_setup_time_interception_reload(plan: &RuntimePlan) -> Result<(), EnforcementReloadError> {
    if plan
        .enforcement
        .execution_surfaces
        .contains(&EnforcementExecutionSurface::TransparentInterception)
    {
        return Err(EnforcementReloadError::SetupTimeInterception);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use enforcement::{EnforcementPlanRequest, EnforcementPlanner, ScopedEnforcementPlanner};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicyManifest,
        EnforcementPolicySourceConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        Action, AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource,
        Direction, EnforcementDecision, EnforcementMode, EnforcementOutcome, EventEnvelope,
        EventKind, FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity,
        ProcessSelector, ProtectiveActionProfile, Selector, Timestamp, TrafficSelector,
        TransportProtocol, Verdict, VerdictScope,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };

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
    async fn setup_time_interception_plan_rejects_online_reload()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = transparent_interception_plan()?;
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::AuditOnly, None)?;
        let active_policy =
            crate::configured_enforcement::load_configured_enforcement_policy_runtime(
                None,
                &runtime::EnforcementPolicySourcePlan::None,
                crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
            )
            .await?;
        let (_, runtime_state) = EnforcementRuntimeState::from_planner(planner, active_policy);

        let error = match reload_enforcement_policy(
            &plan,
            Some(&runtime_state),
            &EnforcementReloadGate::default(),
        )
        .await
        {
            Ok(_) => panic!("setup-time host rules cannot be reloaded by planner swap"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            EnforcementReloadError::SetupTimeInterception
        ));
        Ok(())
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

    fn transparent_interception_plan() -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
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

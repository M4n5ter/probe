use std::{convert::Infallible, sync::Arc, time::Duration};

use runtime::{EnforcementPolicySourcePlan, RuntimePlan};
use tracing::{info, warn};

use crate::{
    configured_enforcement::EnforcementRuntimeState,
    enforcement_reload::{
        EnforcementReloadError, EnforcementReloadGate, reload_enforcement_policy,
        validate_enforcement_policy_reload_plan,
    },
    periodic_worker::{PeriodicWorkerHandle, spawn_delayed_async_periodic_worker},
};

pub(crate) type EnforcementReloadPollerHandle = PeriodicWorkerHandle;

pub(crate) fn spawn_poller(
    plan: Arc<RuntimePlan>,
    runtime_state: EnforcementRuntimeState,
    gate: EnforcementReloadGate,
) -> Result<Option<EnforcementReloadPollerHandle>, EnforcementReloadError> {
    if !plan.config.enforcement.policy.reload.poll_remote_manifest
        || !matches!(
            plan.enforcement.policy_source,
            EnforcementPolicySourcePlan::Remote { .. }
        )
    {
        return Ok(None);
    }
    validate_enforcement_policy_reload_plan(&plan)?;
    let interval = Duration::from_millis(
        plan.config
            .enforcement
            .policy
            .reload
            .remote_poll_interval_ms,
    );
    let inner = spawn_delayed_async_periodic_worker(
        "remote enforcement policy reload",
        interval,
        move || {
            let plan = Arc::clone(&plan);
            let runtime_state = runtime_state.clone();
            let gate = gate.clone();
            async move {
                reload_remote_enforcement_policy_once(&plan, &runtime_state, &gate).await;
                Ok::<(), Infallible>(())
            }
        },
    );
    Ok(Some(inner))
}

async fn reload_remote_enforcement_policy_once(
    plan: &RuntimePlan,
    runtime_state: &EnforcementRuntimeState,
    gate: &EnforcementReloadGate,
) {
    match reload_enforcement_policy(plan, Some(runtime_state), gate).await {
        Ok(summary) => {
            info!(
                manifest_selector_configured = summary.active_policy.manifest_selector_configured(),
                effective_selector_configured =
                    summary.active_policy.effective_selector_configured(),
                "reloaded enforcement policy after remote poll"
            );
        }
        Err(error) => {
            warn!("failed to reload enforcement policy after remote poll: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use enforcement::{EnforcementPlanRequest, EnforcementPlanner, ScopedEnforcementPlanner};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicySourceConfig,
        MIN_ENFORCEMENT_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        Action, AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource,
        Direction, EnforcementMode, EnforcementOutcome, EventEnvelope, EventKind, FlowContext,
        FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity, ProcessSelector, Selector,
        Timestamp, TrafficSelector, TransportProtocol, Verdict, VerdictScope,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, EnforcementPolicySourcePlan,
        ProviderRegistry,
    };
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate,
        matchers::{method, path},
    };

    use crate::{
        configured_enforcement::EnforcementRuntimeState,
        configured_enforcement::{
            EnforcementPolicySourceLoadContext, build_configured_enforcement_with_backend,
        },
    };

    use super::*;

    #[tokio::test]
    async fn poller_reloads_remote_enforcement_manifest_after_interval()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        let remote_manifest = Arc::new(Mutex::new(enforcement_manifest("old", Action::Deny)));
        let response_manifest = Arc::clone(&remote_manifest);
        Mock::given(method("GET"))
            .and(path("/enforcement"))
            .respond_with(move |_: &Request| {
                ResponseTemplate::new(200).set_body_string(
                    response_manifest
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone(),
                )
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: format!("{}/enforcement", server.uri()),
            max_body_bytes: None,
        };
        config.enforcement.policy.reload.poll_remote_manifest = true;
        config.enforcement.policy.reload.remote_poll_interval_ms =
            MIN_ENFORCEMENT_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS;
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let configured = build_configured_enforcement_with_backend(
            &plan,
            None,
            EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let (mut planner, runtime_state) =
            EnforcementRuntimeState::from_planner(configured.planner, configured.active_policy);
        assert_eq!(
            evaluate_protective(&mut planner, Action::Deny)?.outcome,
            EnforcementOutcome::DryRun
        );
        assert_eq!(
            evaluate_protective(&mut planner, Action::Reset)?.outcome,
            EnforcementOutcome::Unsupported
        );

        *remote_manifest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            enforcement_manifest("new", Action::Reset);
        let poller = spawn_poller(
            Arc::clone(&plan),
            runtime_state,
            EnforcementReloadGate::default(),
        )?
        .expect("remote enforcement policy poller should start");

        wait_until_enforcement_action(&mut planner, Action::Reset).await?;

        poller.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn poller_rejects_setup_time_interception_plan() -> Result<(), Box<dyn std::error::Error>>
    {
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
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: "https://control.example/enforcement.toml".to_string(),
            max_body_bytes: None,
        };
        config.enforcement.policy.reload.poll_remote_manifest = true;
        let plan = Arc::new(runtime_plan_from_config_with_registry(
            config,
            transparent_interception_registry(),
        )?);
        let runtime_state = empty_runtime_state().await?;

        let Err(error) = spawn_poller(plan, runtime_state, EnforcementReloadGate::default()) else {
            panic!("setup-time interception plan must reject remote poller reload");
        };

        assert!(matches!(
            error,
            crate::enforcement_reload::EnforcementReloadError::SetupTimeInterception
        ));
        Ok(())
    }

    async fn wait_until_enforcement_action(
        planner: &mut impl EnforcementPlanner,
        expected: Action,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if evaluate_protective(planner, expected)?.outcome == EnforcementOutcome::DryRun {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for remote enforcement policy reload poller".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn evaluate_protective(
        planner: &mut impl EnforcementPlanner,
        action: Action,
    ) -> Result<probe_core::EnforcementDecision, Box<dyn std::error::Error>> {
        planner
            .evaluate(EnforcementPlanRequest {
                verdict: &Verdict {
                    action,
                    scope: VerdictScope::Flow,
                    reason: "test".to_string(),
                    confidence: 100,
                    ttl_ms: None,
                },
                trigger: &trigger_event(),
            })
            .ok_or_else(|| "protective verdict should be evaluated".into())
    }

    fn trigger_event() -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
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

    fn runtime_plan_from_config(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        runtime_plan_from_config_with_registry(config, replay_registry())
    }

    fn runtime_plan_from_config_with_registry(
        config: AgentConfig,
        registry: ProviderRegistry,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(config, &registry)
    }

    fn replay_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            vec![CapabilityState::available(
                CapabilityKind::DryRunEnforcement,
            )],
        )
    }

    fn transparent_interception_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            )],
            vec![
                CapabilityState::available(CapabilityKind::DryRunEnforcement),
                CapabilityState::available(CapabilityKind::TransparentInterception),
            ],
        )
    }

    async fn empty_runtime_state() -> Result<EnforcementRuntimeState, Box<dyn std::error::Error>> {
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::AuditOnly, None)?;
        let active_policy =
            crate::configured_enforcement::load_configured_enforcement_policy_runtime(
                None,
                &EnforcementPolicySourcePlan::None,
                EnforcementPolicySourceLoadContext::default(),
            )
            .await?;
        let (_, runtime_state) = EnforcementRuntimeState::from_planner(planner, active_policy);
        Ok(runtime_state)
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "replay".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
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
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "replay".to_string(),
                cmdline: vec!["replay".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 0,
        }
    }

    fn enforcement_manifest(version: &str, action: Action) -> String {
        format!(
            r#"
id = "guard"
version = "{version}"
protective_actions = ["{action}"]
"#,
            action = action_name(action)
        )
    }

    fn action_name(action: Action) -> &'static str {
        match action {
            Action::Deny => "deny",
            Action::Reset => "reset",
            Action::Quarantine => "quarantine",
            Action::Allow | Action::Observe | Action::Alert => {
                panic!("test enforcement manifest requires protective action")
            }
        }
    }
}

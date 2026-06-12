use enforcement::{EnforcementBackend, EnforcementError, ScopedEnforcementPlanner};
use probe_core::{EnforcementMode, ProtectiveActionProfile, Selector};
use runtime::{EnforcementPolicySourcePlan, RuntimePlan};
use thiserror::Error;

use super::source::{
    EnforcementPolicySourceError, LoadedEnforcementPolicySource, load_enforcement_policy_source,
};

#[derive(Debug, Error)]
pub enum ConfiguredEnforcementError {
    #[error("enforcement planner error: {0}")]
    Planner(#[from] EnforcementError),
    #[error("enforcement policy source error: {0}")]
    Source(#[from] EnforcementPolicySourceError),
    #[error("connection-level enforcement backend is not available in this build/runtime")]
    BackendUnavailable,
}

pub struct ConfiguredEnforcement {
    pub planner: ScopedEnforcementPlanner,
    pub mode: EnforcementMode,
    pub effective_selector_configured: bool,
    pub config_selector_configured: bool,
    pub manifest_selector_configured: Option<bool>,
    pub policy_source: Option<LoadedEnforcementPolicySource>,
}

pub async fn build_configured_enforcement(
    plan: &RuntimePlan,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    build_configured_enforcement_from_parts(
        plan.enforcement.mode,
        plan.config.enforcement.selector.clone(),
        plan.enforcement.config_selector_configured,
        &plan.enforcement.policy_source,
        None,
    )
    .await
}

async fn build_configured_enforcement_from_parts(
    mode: EnforcementMode,
    config_selector: Option<Selector>,
    config_selector_configured: bool,
    policy_source_plan: &EnforcementPolicySourcePlan,
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    if mode == EnforcementMode::Enforce && backend.is_none() {
        return Err(ConfiguredEnforcementError::BackendUnavailable);
    }

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
    let planner = scoped_enforcement_planner(
        mode,
        effective_selector.as_ref(),
        protective_actions,
        backend,
    )?;
    Ok(ConfiguredEnforcement {
        planner,
        mode,
        effective_selector_configured: effective_selector.is_some(),
        config_selector_configured,
        manifest_selector_configured: policy_source
            .as_ref()
            .map(|source| source.manifest.selector.is_some()),
        policy_source,
    })
}

fn scoped_enforcement_planner(
    mode: EnforcementMode,
    selector: Option<&Selector>,
    protective_actions: ProtectiveActionProfile,
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<ScopedEnforcementPlanner, ConfiguredEnforcementError> {
    if mode == EnforcementMode::Enforce {
        let backend = backend.ok_or(ConfiguredEnforcementError::BackendUnavailable)?;
        return ScopedEnforcementPlanner::with_backend(selector, protective_actions, backend)
            .map_err(ConfiguredEnforcementError::Planner);
    }

    ScopedEnforcementPlanner::with_protective_action_profile(mode, selector, protective_actions)
        .map_err(ConfiguredEnforcementError::Planner)
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
    use probe_core::{
        Action, AddressPort, CaptureSource, Direction, EnforcementMode, EnforcementOutcome,
        EventEnvelope, EventKind, FlowContext, FlowIdentity, OpaqueStream, ProcessContext,
        ProcessIdentity, Timestamp, TransportProtocol, Verdict, VerdictScope,
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
            None,
        )
        .await
        {
            Ok(_) => panic!("enforce mode must not run without an execution backend"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConfiguredEnforcementError::BackendUnavailable
        ));
    }

    #[tokio::test]
    async fn enforce_uses_injected_backend() -> Result<(), Box<dyn std::error::Error>> {
        let mut configured = build_configured_enforcement_from_parts(
            EnforcementMode::Enforce,
            None,
            false,
            &EnforcementPolicySourcePlan::None,
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
            })?
            .expect("protective verdict must produce an enforcement decision");

        assert_eq!(configured.planner.mode(), EnforcementMode::Enforce);
        assert_eq!(decision.outcome, EnforcementOutcome::Applied);
        assert_eq!(decision.effective_action, Action::Deny);
        assert_eq!(decision.reason, "backend applied Deny");
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
        EventEnvelope::new(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1_700_000_000,
            },
            flow_context(),
            CaptureSource::Replay,
            "test-config",
            EventKind::OpaqueStream(OpaqueStream {
                direction: Direction::Outbound,
                fingerprint: vec![1, 2, 3],
                reason: "test payload".to_string(),
            }),
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

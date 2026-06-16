use enforcement::{
    EnforcementBackend, EnforcementError, ScopedEnforcementPlanner, SetupTimeEnforcementSurface,
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

pub struct ConfiguredEnforcement {
    pub planner: ScopedEnforcementPlanner,
    pub mode: EnforcementMode,
    pub effective_selector_configured: bool,
    pub config_selector_configured: bool,
    pub manifest_selector_configured: Option<bool>,
    pub effective_selector: Option<Selector>,
    pub policy_source: Option<LoadedEnforcementPolicySource>,
}

pub async fn build_configured_enforcement_with_backend(
    plan: &RuntimePlan,
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    let configured = build_configured_enforcement_from_parts(
        plan.enforcement.mode,
        plan.config.enforcement.selector.clone(),
        plan.enforcement.config_selector_configured,
        &plan.enforcement.policy_source,
        &plan.enforcement.execution_surfaces,
        backend,
    )
    .await?;
    crate::transparent_interception::validate_setup_scope(
        &plan.config.enforcement.interception,
        configured.effective_selector.as_ref(),
    )?;
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
        execution_surfaces,
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
        effective_selector,
        policy_source,
    })
}

fn scoped_enforcement_planner(
    mode: EnforcementMode,
    selector: Option<&Selector>,
    protective_actions: ProtectiveActionProfile,
    execution_surfaces: &[EnforcementExecutionSurface],
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<ScopedEnforcementPlanner, ConfiguredEnforcementError> {
    if mode != EnforcementMode::Enforce {
        return ScopedEnforcementPlanner::with_protective_action_profile(
            mode,
            selector,
            protective_actions,
        )
        .map_err(ConfiguredEnforcementError::Planner);
    }

    if let Some(backend) = backend {
        return ScopedEnforcementPlanner::with_backend(selector, protective_actions, backend)
            .map_err(ConfiguredEnforcementError::Planner);
    }

    if execution_surfaces == [EnforcementExecutionSurface::TransparentInterception] {
        return ScopedEnforcementPlanner::with_setup_time_execution(
            selector,
            protective_actions,
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

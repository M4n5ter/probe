use probe_core::{
    Action, EnforcementDecision, EnforcementMode, EnforcementOutcome, EventEnvelope,
    ProcessContext, ProtectiveActionError, ProtectiveActionProfile, Selector, SelectorError,
    Verdict,
};
use thiserror::Error;

use crate::{EnforcementBackend, EnforcementBackendRequest, ProxySideEnforcementHook, TargetScope};

#[derive(Debug, Error)]
pub enum EnforcementError {
    #[error("invalid enforcement selector: {0}")]
    Selector(#[from] SelectorError),
    #[error("invalid enforcement protective action profile: {0}")]
    ProtectiveActionProfile(#[from] ProtectiveActionError),
    #[error("connection-level enforcement backend is not available in this build/runtime")]
    BackendUnavailable,
    #[error("enforcement backend error: {0}")]
    Backend(String),
}

#[derive(Clone, Copy)]
pub struct EnforcementPlanRequest<'a> {
    pub verdict: &'a Verdict,
    pub trigger: &'a EventEnvelope,
}

pub trait EnforcementPlanner {
    fn evaluate(&mut self, request: EnforcementPlanRequest<'_>) -> Option<EnforcementDecision>;
}

#[derive(Clone)]
pub struct PlannerPolicy {
    scope: TargetScope,
    protective_actions: ProtectiveActionProfile,
}

impl PlannerPolicy {
    pub fn compile(
        selector: Option<&Selector>,
        protective_actions: ProtectiveActionProfile,
    ) -> Result<Self, EnforcementError> {
        Ok(Self {
            scope: TargetScope::compile(selector)?,
            protective_actions,
        })
    }

    pub fn protective_actions(&self) -> &[Action] {
        self.protective_actions.actions()
    }

    pub fn protective_action_profile(&self) -> &ProtectiveActionProfile {
        &self.protective_actions
    }

    pub fn target_scope(&self) -> &TargetScope {
        &self.scope
    }

    fn contains_action(&self, action: Action) -> bool {
        self.protective_actions.contains(action)
    }
}

pub struct ScopedEnforcementPlanner {
    execution: EnforcementExecution,
    policy: PlannerPolicy,
}

impl ScopedEnforcementPlanner {
    pub fn new(
        mode: EnforcementMode,
        selector: Option<&Selector>,
    ) -> Result<Self, EnforcementError> {
        Self::with_protective_action_profile(mode, selector, ProtectiveActionProfile::default())
    }

    pub fn with_protective_actions(
        mode: EnforcementMode,
        selector: Option<&Selector>,
        protective_actions: impl IntoIterator<Item = Action>,
    ) -> Result<Self, EnforcementError> {
        Self::with_protective_action_profile(
            mode,
            selector,
            ProtectiveActionProfile::new(protective_actions)?,
        )
    }

    pub fn with_protective_action_profile(
        mode: EnforcementMode,
        selector: Option<&Selector>,
        protective_actions: ProtectiveActionProfile,
    ) -> Result<Self, EnforcementError> {
        let policy = PlannerPolicy::compile(selector, protective_actions)?;
        Self::with_planner_policy(mode, policy)
    }

    pub fn with_planner_policy(
        mode: EnforcementMode,
        policy: PlannerPolicy,
    ) -> Result<Self, EnforcementError> {
        Ok(Self {
            execution: EnforcementExecution::without_backend(mode)?,
            policy,
        })
    }

    pub fn with_backend(
        selector: Option<&Selector>,
        protective_actions: ProtectiveActionProfile,
        backend: impl EnforcementBackend + 'static,
    ) -> Result<Self, EnforcementError> {
        let policy = PlannerPolicy::compile(selector, protective_actions)?;
        Self::with_backend_policy(policy, backend)
    }

    pub fn with_backend_policy(
        policy: PlannerPolicy,
        backend: impl EnforcementBackend + 'static,
    ) -> Result<Self, EnforcementError> {
        Ok(Self {
            execution: EnforcementExecution::Enforce(Box::new(backend)),
            policy,
        })
    }

    pub fn with_setup_time_execution(
        selector: Option<&Selector>,
        protective_actions: ProtectiveActionProfile,
        surface: SetupTimeEnforcementSurface,
    ) -> Result<Self, EnforcementError> {
        let policy = PlannerPolicy::compile(selector, protective_actions)?;
        Self::with_setup_time_policy(policy, surface)
    }

    pub fn with_setup_time_policy(
        policy: PlannerPolicy,
        surface: SetupTimeEnforcementSurface,
    ) -> Result<Self, EnforcementError> {
        Ok(Self {
            execution: EnforcementExecution::SetupTimeOnly(surface),
            policy,
        })
    }

    pub fn with_proxy_side_policy_hook(
        policy: PlannerPolicy,
        surface: ProxySideEnforcementSurface,
        hook: impl ProxySideEnforcementHook + 'static,
    ) -> Result<Self, EnforcementError> {
        Ok(Self {
            execution: EnforcementExecution::ProxySideHook {
                surface,
                hook: Box::new(hook),
            },
            policy,
        })
    }

    pub fn mode(&self) -> EnforcementMode {
        self.execution.mode()
    }

    pub fn protective_actions(&self) -> &[Action] {
        self.policy.protective_actions()
    }

    pub fn replace_policy(&mut self, policy: PlannerPolicy) {
        self.policy = policy;
    }

    pub fn target_scope(&self) -> &TargetScope {
        self.policy.target_scope()
    }

    pub fn may_include_process(&self, process: &ProcessContext) -> bool {
        self.policy.target_scope().may_include_process(process)
    }
}

impl EnforcementPlanner for ScopedEnforcementPlanner {
    fn evaluate(&mut self, request: EnforcementPlanRequest<'_>) -> Option<EnforcementDecision> {
        if !requires_enforcement(request.verdict.action) {
            return None;
        }

        if request.trigger.flow().is_none() {
            return Some(EnforcementDecision {
                mode: self.mode(),
                outcome: EnforcementOutcome::Unsupported,
                requested_action: request.verdict.action,
                effective_action: Action::Observe,
                scope: request.verdict.scope.clone(),
                selector_matched: false,
                reason: format!(
                    "policy requested {:?}, but trigger event is not flow-scoped and cannot drive connection-level enforcement: {}",
                    request.verdict.action, request.verdict.reason
                ),
            });
        }

        let selector_matched = self.policy.target_scope().matches_trigger(request.trigger);
        let (outcome, effective_action, reason) = if !selector_matched {
            (
                EnforcementOutcome::SelectorMiss,
                Action::Observe,
                format!(
                    "policy requested {:?}, but enforcement selector did not match: {}",
                    request.verdict.action, request.verdict.reason
                ),
            )
        } else if !self.policy.contains_action(request.verdict.action) {
            (
                EnforcementOutcome::Unsupported,
                Action::Observe,
                format!(
                    "policy requested {:?}, but the configured enforcement profile does not allow that protective action: {}",
                    request.verdict.action, request.verdict.reason
                ),
            )
        } else {
            self.decision_for_mode(request)
        };

        Some(EnforcementDecision {
            mode: self.mode(),
            outcome,
            requested_action: request.verdict.action,
            effective_action,
            scope: request.verdict.scope.clone(),
            selector_matched,
            reason,
        })
    }
}

impl ScopedEnforcementPlanner {
    fn decision_for_mode(
        &mut self,
        request: EnforcementPlanRequest<'_>,
    ) -> (EnforcementOutcome, Action, String) {
        let verdict = request.verdict;
        if self.execution.requires_complete_enforcement_evidence()
            && let Some(reason) = destructive_enforcement_evidence_rejection_reason(request.trigger)
        {
            return (
                EnforcementOutcome::Unsupported,
                Action::Observe,
                format!(
                    "policy requested {:?}, but trigger evidence cannot safely drive destructive enforcement: {reason}: {}",
                    verdict.action, verdict.reason
                ),
            );
        }

        match &mut self.execution {
            EnforcementExecution::Disabled => (
                EnforcementOutcome::Disabled,
                Action::Observe,
                format!(
                    "policy requested {:?}, but enforcement is disabled: {}",
                    verdict.action, verdict.reason
                ),
            ),
            EnforcementExecution::AuditOnly => (
                EnforcementOutcome::AuditOnly,
                Action::Observe,
                format!(
                    "policy requested {:?}; audit-only mode recorded the requested action: {}",
                    verdict.action, verdict.reason
                ),
            ),
            EnforcementExecution::DryRun => (
                EnforcementOutcome::DryRun,
                Action::Observe,
                format!(
                    "policy requested {:?}; dry-run mode did not execute the action: {}",
                    verdict.action, verdict.reason
                ),
            ),
            EnforcementExecution::Enforce(backend) => {
                match backend.apply(EnforcementBackendRequest {
                    verdict,
                    trigger: request.trigger,
                }) {
                    Ok(decision) => decision.into_enforcement_parts(verdict.action),
                    Err(error) => failed_decision_parts(verdict, &error),
                }
            }
            EnforcementExecution::SetupTimeOnly(surface) => (
                EnforcementOutcome::Unsupported,
                Action::Observe,
                format!(
                    "policy requested {:?}, but {} is a setup-time enforcement surface and no per-flow connection backend is configured: {}",
                    verdict.action,
                    surface.description(),
                    verdict.reason
                ),
            ),
            EnforcementExecution::ProxySideHook { surface, hook } => {
                match hook.delegate(EnforcementBackendRequest {
                    verdict,
                    trigger: request.trigger,
                }) {
                    Ok(decision) => {
                        decision.into_enforcement_parts(verdict.action, surface.description())
                    }
                    Err(error) => failed_decision_parts(verdict, &error),
                }
            }
        }
    }
}

enum EnforcementExecution {
    Disabled,
    AuditOnly,
    DryRun,
    Enforce(Box<dyn EnforcementBackend>),
    SetupTimeOnly(SetupTimeEnforcementSurface),
    ProxySideHook {
        surface: ProxySideEnforcementSurface,
        hook: Box<dyn ProxySideEnforcementHook>,
    },
}

impl EnforcementExecution {
    fn without_backend(mode: EnforcementMode) -> Result<Self, EnforcementError> {
        Ok(match mode {
            EnforcementMode::Disabled => Self::Disabled,
            EnforcementMode::AuditOnly => Self::AuditOnly,
            EnforcementMode::DryRun => Self::DryRun,
            EnforcementMode::Enforce => return Err(EnforcementError::BackendUnavailable),
        })
    }

    fn mode(&self) -> EnforcementMode {
        match self {
            Self::Disabled => EnforcementMode::Disabled,
            Self::AuditOnly => EnforcementMode::AuditOnly,
            Self::DryRun => EnforcementMode::DryRun,
            Self::Enforce(_) | Self::SetupTimeOnly(_) | Self::ProxySideHook { .. } => {
                EnforcementMode::Enforce
            }
        }
    }

    fn requires_complete_enforcement_evidence(&self) -> bool {
        matches!(self, Self::Enforce(_) | Self::ProxySideHook { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupTimeEnforcementSurface {
    TransparentInterception,
}

impl SetupTimeEnforcementSurface {
    fn description(self) -> &'static str {
        match self {
            Self::TransparentInterception => "transparent interception",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxySideEnforcementSurface {
    L7Mitm,
}

impl ProxySideEnforcementSurface {
    fn description(self) -> &'static str {
        match self {
            Self::L7Mitm => "L7 MITM proxy-side policy hook",
        }
    }
}

fn requires_enforcement(action: Action) -> bool {
    action.is_protective()
}

fn failed_decision_parts(
    verdict: &Verdict,
    error: &EnforcementError,
) -> (EnforcementOutcome, Action, String) {
    (
        EnforcementOutcome::Failed,
        Action::Observe,
        format!(
            "policy requested {:?}, but enforcement failed: {error}: {}",
            verdict.action, verdict.reason
        ),
    )
}

fn destructive_enforcement_evidence_rejection_reason(
    trigger: &EventEnvelope,
) -> Option<&'static str> {
    trigger
        .enforcement_evidence()
        .destructive_enforcement_rejection_reason()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use probe_core::{
        AddressPort, CaptureLoss, CaptureOrigin, CaptureSource, Direction, EnforcementEvidence,
        EventKind, FlowContext, FlowIdentity, HttpHeaders, ObservationOnlyReason, ProcessContext,
        ProcessIdentity, ProcessSelector, Selector, Timestamp, TrafficSelector, TransportProtocol,
        VerdictScope,
    };

    use crate::{EnforcementBackendDecision, ProxySideEnforcementHookDecision};

    use super::*;

    #[test]
    fn dry_run_records_matching_protective_verdict_without_applying_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, None)?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Request,
            reason: "blocked path".to_string(),
            confidence: 90,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("deny verdict should produce enforcement audit");

        assert_eq!(decision.outcome, EnforcementOutcome::DryRun);
        assert_eq!(decision.requested_action, Action::Deny);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.selector_matched);
        Ok(())
    }

    #[test]
    fn selector_miss_records_that_requested_action_was_not_in_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["other".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        );
        let mut planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, Some(&selector))?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict {
            action: Action::Reset,
            scope: VerdictScope::Flow,
            reason: "reset flow".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce enforcement audit");

        assert_eq!(decision.outcome, EnforcementOutcome::SelectorMiss);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(!decision.selector_matched);
        Ok(())
    }

    #[test]
    fn non_flow_trigger_records_unsupported_without_matching_selector()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, None)?;
        let trigger = EventEnvelope::from_provider(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "test",
            EventKind::CaptureLoss(CaptureLoss {
                lost_events: 1,
                reason: "lost".to_string(),
            }),
        );
        let verdict = Verdict {
            action: Action::Reset,
            scope: VerdictScope::Flow,
            reason: "reset flow".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce enforcement audit");

        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(!decision.selector_matched);
        assert!(decision.reason.contains("not flow-scoped"));
        Ok(())
    }

    #[test]
    fn direction_scoped_selector_misses_directionless_trigger()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        );
        let mut planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, Some(&selector))?;
        let trigger = directionless_event();
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "close verdict".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce enforcement audit");

        assert_eq!(decision.outcome, EnforcementOutcome::SelectorMiss);
        assert!(!decision.selector_matched);
        Ok(())
    }

    #[test]
    fn disabled_mode_records_that_requested_action_was_not_applied()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut planner = ScopedEnforcementPlanner::new(EnforcementMode::Disabled, None)?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict {
            action: Action::Quarantine,
            scope: VerdictScope::Flow,
            reason: "quarantine flow".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce disabled audit");

        assert_eq!(decision.outcome, EnforcementOutcome::Disabled);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.selector_matched);
        Ok(())
    }

    #[test]
    fn non_protective_verdicts_are_left_to_policy_events() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut planner = ScopedEnforcementPlanner::new(EnforcementMode::AuditOnly, None)?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict::alert("alert only");

        let decision = planner.evaluate(EnforcementPlanRequest {
            verdict: &verdict,
            trigger: &trigger,
        });

        assert!(decision.is_none());
        Ok(())
    }

    #[test]
    fn configured_profile_limits_protective_actions() -> Result<(), Box<dyn std::error::Error>> {
        let mut planner = ScopedEnforcementPlanner::with_protective_actions(
            EnforcementMode::DryRun,
            None,
            [Action::Deny, Action::Deny],
        )?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict {
            action: Action::Reset,
            scope: VerdictScope::Flow,
            reason: "reset flow".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        assert_eq!(planner.protective_actions(), &[Action::Deny]);
        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce enforcement audit");

        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.requested_action, Action::Reset);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.selector_matched);
        Ok(())
    }

    #[test]
    fn scoped_planner_policy_replacement_changes_scope_and_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut planner = ScopedEnforcementPlanner::with_protective_actions(
            EnforcementMode::DryRun,
            Some(&remote_port_selector(80)),
            [Action::Deny],
        )?;

        let decision = evaluate_plan(&mut planner, Action::Deny, 80)?;
        assert_eq!(decision.outcome, EnforcementOutcome::DryRun);
        assert!(decision.selector_matched);

        let policy = PlannerPolicy::compile(
            Some(&remote_port_selector(443)),
            ProtectiveActionProfile::new([Action::Reset])?,
        )?;
        planner.replace_policy(policy);

        let old_scope_decision = evaluate_plan(&mut planner, Action::Deny, 80)?;
        assert_eq!(old_scope_decision.outcome, EnforcementOutcome::SelectorMiss);
        assert!(!old_scope_decision.selector_matched);

        let new_profile_decision = evaluate_plan(&mut planner, Action::Reset, 443)?;
        assert_eq!(new_profile_decision.outcome, EnforcementOutcome::DryRun);
        assert!(new_profile_decision.selector_matched);

        let rejected_action = evaluate_plan(&mut planner, Action::Deny, 443)?;
        assert_eq!(rejected_action.outcome, EnforcementOutcome::Unsupported);
        assert!(rejected_action.selector_matched);
        Ok(())
    }

    #[test]
    fn enforce_mode_delegates_to_backend() -> Result<(), Box<dyn std::error::Error>> {
        let mut planner = ScopedEnforcementPlanner::with_backend(
            None,
            ProtectiveActionProfile::default(),
            ApplyingBackend,
        )?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict {
            action: Action::Reset,
            scope: VerdictScope::Flow,
            reason: "reset flow".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should be delegated to backend");

        assert_eq!(decision.outcome, EnforcementOutcome::Applied);
        assert_eq!(decision.requested_action, Action::Reset);
        assert_eq!(decision.effective_action, Action::Reset);
        assert_eq!(decision.reason, "backend applied Reset");
        assert!(decision.selector_matched);
        Ok(())
    }

    #[test]
    fn enforce_mode_rejects_observation_only_evidence_before_backend()
    -> Result<(), Box<dyn std::error::Error>> {
        let backend = CountingBackend::default();
        let mut planner = ScopedEnforcementPlanner::with_backend(
            None,
            ProtectiveActionProfile::default(),
            backend.clone(),
        )?;
        let trigger = request_event(Direction::Outbound)
            .with_degraded(true)
            .with_enforcement_evidence(EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                "test eBPF syscall payload snapshot",
            ));
        let verdict = Verdict {
            action: Action::Reset,
            scope: VerdictScope::Flow,
            reason: "reset flow".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce unsupported audit");

        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.requested_action, Action::Reset);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(
            decision
                .reason
                .contains("cannot prove complete socket payload")
        );
        assert!(
            decision
                .reason
                .contains("eBPF syscall payload snapshot cannot prove")
        );
        assert!(
            !decision
                .reason
                .contains("test eBPF syscall payload snapshot")
        );
        assert_eq!(backend.calls(), 0);
        Ok(())
    }

    #[test]
    fn enforce_mode_can_record_setup_time_only_surface() -> Result<(), Box<dyn std::error::Error>> {
        let mut planner = ScopedEnforcementPlanner::with_setup_time_execution(
            None,
            ProtectiveActionProfile::default(),
            SetupTimeEnforcementSurface::TransparentInterception,
        )?;
        let trigger = request_event(Direction::Inbound);
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "host rule already redirected matching traffic".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce setup-time enforcement audit");

        assert_eq!(decision.mode, EnforcementMode::Enforce);
        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.reason.contains("setup-time enforcement surface"));
        Ok(())
    }

    #[test]
    fn proxy_side_hook_delegates_allowed_actions_to_l7_mitm_surface()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = PlannerPolicy::compile(None, ProtectiveActionProfile::new([Action::Deny])?)?;
        let mut planner = ScopedEnforcementPlanner::with_proxy_side_policy_hook(
            policy,
            ProxySideEnforcementSurface::L7Mitm,
            DelegatingProxyHook,
        )?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "block inside MITM policy hook".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should be delegated to the proxy surface");

        assert_eq!(decision.mode, EnforcementMode::Enforce);
        assert_eq!(decision.outcome, EnforcementOutcome::Delegated);
        assert_eq!(decision.requested_action, Action::Deny);
        assert_eq!(decision.effective_action, Action::Deny);
        assert!(decision.selector_matched);
        assert!(decision.reason.contains("accepted delegated enforcement"));
        Ok(())
    }

    #[test]
    fn proxy_side_hook_still_obeys_scope_and_action_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = PlannerPolicy::compile(
            Some(&remote_port_selector(443)),
            ProtectiveActionProfile::new([Action::Deny])?,
        )?;
        let mut planner = ScopedEnforcementPlanner::with_proxy_side_policy_hook(
            policy,
            ProxySideEnforcementSurface::L7Mitm,
            DelegatingProxyHook,
        )?;

        let out_of_scope = evaluate_plan(&mut planner, Action::Deny, 80)?;
        assert_eq!(out_of_scope.outcome, EnforcementOutcome::SelectorMiss);
        assert_eq!(out_of_scope.effective_action, Action::Observe);
        assert!(!out_of_scope.selector_matched);

        let unsupported_action = evaluate_plan(&mut planner, Action::Reset, 443)?;
        assert_eq!(unsupported_action.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(unsupported_action.effective_action, Action::Observe);
        assert!(unsupported_action.selector_matched);
        Ok(())
    }

    #[test]
    fn proxy_side_hook_rejects_observation_only_evidence_before_hook()
    -> Result<(), Box<dyn std::error::Error>> {
        let hook = CountingProxyHook::default();
        let policy = PlannerPolicy::compile(None, ProtectiveActionProfile::new([Action::Deny])?)?;
        let mut planner = ScopedEnforcementPlanner::with_proxy_side_policy_hook(
            policy,
            ProxySideEnforcementSurface::L7Mitm,
            hook.clone(),
        )?;
        let trigger = request_event(Direction::Outbound)
            .with_degraded(true)
            .with_enforcement_evidence(EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                "test eBPF syscall payload snapshot",
            ));
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "block inside MITM policy hook".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce unsupported audit");

        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(
            decision
                .reason
                .contains("cannot prove complete socket payload")
        );
        assert_eq!(hook.calls(), 0);
        Ok(())
    }

    #[test]
    fn proxy_side_hook_can_decline_delegation_without_failing()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = PlannerPolicy::compile(None, ProtectiveActionProfile::new([Action::Deny])?)?;
        let mut planner = ScopedEnforcementPlanner::with_proxy_side_policy_hook(
            policy,
            ProxySideEnforcementSurface::L7Mitm,
            UnsupportedProxyHook,
        )?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "block inside MITM policy hook".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce unsupported audit");

        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.selector_matched);
        assert!(
            decision
                .reason
                .contains("cannot delegate enforcement action")
        );
        assert!(
            decision
                .reason
                .contains("hook has no matching in-flight request")
        );
        Ok(())
    }

    #[test]
    fn enforce_mode_records_backend_error_as_failed_decision()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut planner = ScopedEnforcementPlanner::with_backend(
            None,
            ProtectiveActionProfile::default(),
            FailingBackend,
        )?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict {
            action: Action::Reset,
            scope: VerdictScope::Flow,
            reason: "reset flow".to_string(),
            confidence: 100,
            ttl_ms: None,
        };

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce failure audit");

        assert_eq!(decision.outcome, EnforcementOutcome::Failed);
        assert_eq!(decision.requested_action, Action::Reset);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.reason.contains("planned backend failure"));
        assert!(decision.selector_matched);
        Ok(())
    }

    #[test]
    fn enforce_mode_without_backend_is_rejected() {
        let result = ScopedEnforcementPlanner::new(EnforcementMode::Enforce, None);

        assert!(matches!(result, Err(EnforcementError::BackendUnavailable)));
    }

    #[test]
    fn configured_profile_rejects_non_protective_actions() {
        let result = ScopedEnforcementPlanner::with_protective_actions(
            EnforcementMode::DryRun,
            None,
            [Action::Alert],
        );
        let Err(error) = result else {
            panic!("alert is not an enforcement protective action");
        };

        assert!(matches!(
            error,
            EnforcementError::ProtectiveActionProfile(ProtectiveActionError::Unsupported {
                action: Action::Alert
            })
        ));
    }

    fn evaluate_plan(
        planner: &mut impl EnforcementPlanner,
        action: Action,
        remote_port: u16,
    ) -> Result<EnforcementDecision, Box<dyn std::error::Error>> {
        let trigger = request_event_with_remote_port(Direction::Outbound, remote_port);
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

    fn remote_port_selector(remote_port: u16) -> Selector {
        Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![remote_port],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
    }

    struct ApplyingBackend;

    impl EnforcementBackend for ApplyingBackend {
        fn apply(
            &mut self,
            request: EnforcementBackendRequest<'_>,
        ) -> Result<EnforcementBackendDecision, EnforcementError> {
            Ok(EnforcementBackendDecision::applied(format!(
                "backend applied {:?}",
                request.verdict.action
            )))
        }
    }

    #[derive(Clone, Default)]
    struct CountingBackend {
        calls: Arc<Mutex<usize>>,
    }

    impl CountingBackend {
        fn calls(&self) -> usize {
            *self.calls.lock().expect("fake backend state poisoned")
        }
    }

    impl EnforcementBackend for CountingBackend {
        fn apply(
            &mut self,
            request: EnforcementBackendRequest<'_>,
        ) -> Result<EnforcementBackendDecision, EnforcementError> {
            *self.calls.lock().expect("fake backend state poisoned") += 1;
            Ok(EnforcementBackendDecision::applied(format!(
                "backend applied {:?}",
                request.verdict.action
            )))
        }
    }

    struct FailingBackend;

    impl EnforcementBackend for FailingBackend {
        fn apply(
            &mut self,
            _request: EnforcementBackendRequest<'_>,
        ) -> Result<EnforcementBackendDecision, EnforcementError> {
            Err(EnforcementError::Backend(
                "planned backend failure".to_string(),
            ))
        }
    }

    struct DelegatingProxyHook;

    impl ProxySideEnforcementHook for DelegatingProxyHook {
        fn delegate(
            &mut self,
            request: EnforcementBackendRequest<'_>,
        ) -> Result<ProxySideEnforcementHookDecision, EnforcementError> {
            Ok(ProxySideEnforcementHookDecision::delegated(format!(
                "hook accepted {:?}",
                request.verdict.action
            )))
        }
    }

    #[derive(Clone, Default)]
    struct CountingProxyHook {
        calls: Arc<Mutex<usize>>,
    }

    impl CountingProxyHook {
        fn calls(&self) -> usize {
            *self.calls.lock().expect("fake proxy hook state poisoned")
        }
    }

    impl ProxySideEnforcementHook for CountingProxyHook {
        fn delegate(
            &mut self,
            _request: EnforcementBackendRequest<'_>,
        ) -> Result<ProxySideEnforcementHookDecision, EnforcementError> {
            *self.calls.lock().expect("fake proxy hook state poisoned") += 1;
            Ok(ProxySideEnforcementHookDecision::delegated(
                "hook accepted request",
            ))
        }
    }

    struct UnsupportedProxyHook;

    impl ProxySideEnforcementHook for UnsupportedProxyHook {
        fn delegate(
            &mut self,
            _request: EnforcementBackendRequest<'_>,
        ) -> Result<ProxySideEnforcementHookDecision, EnforcementError> {
            Ok(ProxySideEnforcementHookDecision::unsupported(
                "hook has no matching in-flight request",
            ))
        }
    }

    fn request_event(direction: Direction) -> EventEnvelope {
        request_event_with_remote_port(direction, 80)
    }

    fn request_event_with_remote_port(direction: Direction, remote_port: u16) -> EventEnvelope {
        request_event_from_source(direction, CaptureSource::Replay, remote_port)
    }

    fn request_event_from_source(
        direction: Direction,
        source: CaptureSource,
        remote_port: u16,
    ) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(remote_port),
            CaptureOrigin::from_source(source),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction,
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

    fn directionless_event() -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(80),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::ConnectionClosed,
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

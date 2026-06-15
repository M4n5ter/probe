use probe_core::{
    Action, EnforcementDecision, EnforcementMode, EnforcementOutcome, EventEnvelope,
    ProcessContext, ProtectiveActionError, ProtectiveActionProfile, Selector, SelectorError,
    Verdict,
};
use thiserror::Error;

use crate::{EnforcementBackend, EnforcementBackendRequest, TargetScope};

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
    fn evaluate(
        &mut self,
        request: EnforcementPlanRequest<'_>,
    ) -> Result<Option<EnforcementDecision>, EnforcementError>;
}

pub struct ScopedEnforcementPlanner {
    mode: EnforcementMode,
    scope: TargetScope,
    protective_actions: ProtectiveActionProfile,
    backend: Option<Box<dyn EnforcementBackend>>,
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
        if mode == EnforcementMode::Enforce {
            return Err(EnforcementError::BackendUnavailable);
        }
        Ok(Self {
            mode,
            scope: TargetScope::compile(selector)?,
            protective_actions,
            backend: None,
        })
    }

    pub fn with_backend(
        selector: Option<&Selector>,
        protective_actions: ProtectiveActionProfile,
        backend: impl EnforcementBackend + 'static,
    ) -> Result<Self, EnforcementError> {
        Ok(Self {
            mode: EnforcementMode::Enforce,
            scope: TargetScope::compile(selector)?,
            protective_actions,
            backend: Some(Box::new(backend)),
        })
    }

    pub fn mode(&self) -> EnforcementMode {
        self.mode
    }

    pub fn protective_actions(&self) -> &[Action] {
        self.protective_actions.actions()
    }

    pub fn target_scope(&self) -> &TargetScope {
        &self.scope
    }

    pub fn may_include_process(&self, process: &ProcessContext) -> bool {
        self.scope.may_include_process(process)
    }
}

impl EnforcementPlanner for ScopedEnforcementPlanner {
    fn evaluate(
        &mut self,
        request: EnforcementPlanRequest<'_>,
    ) -> Result<Option<EnforcementDecision>, EnforcementError> {
        if !requires_enforcement(request.verdict.action) {
            return Ok(None);
        }

        let selector_matched = self.scope.matches_trigger(request.trigger);
        let (outcome, effective_action, reason) = if !selector_matched {
            (
                EnforcementOutcome::SelectorMiss,
                Action::Observe,
                format!(
                    "policy requested {:?}, but enforcement selector did not match: {}",
                    request.verdict.action, request.verdict.reason
                ),
            )
        } else if !self.protective_actions.contains(request.verdict.action) {
            (
                EnforcementOutcome::Unsupported,
                Action::Observe,
                format!(
                    "policy requested {:?}, but the configured enforcement profile does not allow that protective action: {}",
                    request.verdict.action, request.verdict.reason
                ),
            )
        } else {
            self.decision_for_mode(request)?
        };

        Ok(Some(EnforcementDecision {
            mode: self.mode,
            outcome,
            requested_action: request.verdict.action,
            effective_action,
            scope: request.verdict.scope.clone(),
            selector_matched,
            reason,
        }))
    }
}

impl ScopedEnforcementPlanner {
    fn decision_for_mode(
        &mut self,
        request: EnforcementPlanRequest<'_>,
    ) -> Result<(EnforcementOutcome, Action, String), EnforcementError> {
        let verdict = request.verdict;
        let decision = match self.mode {
            EnforcementMode::Disabled => (
                EnforcementOutcome::Disabled,
                Action::Observe,
                format!(
                    "policy requested {:?}, but enforcement is disabled: {}",
                    verdict.action, verdict.reason
                ),
            ),
            EnforcementMode::AuditOnly => (
                EnforcementOutcome::AuditOnly,
                Action::Observe,
                format!(
                    "policy requested {:?}; audit-only mode recorded the requested action: {}",
                    verdict.action, verdict.reason
                ),
            ),
            EnforcementMode::DryRun => (
                EnforcementOutcome::DryRun,
                Action::Observe,
                format!(
                    "policy requested {:?}; dry-run mode did not execute the action: {}",
                    verdict.action, verdict.reason
                ),
            ),
            EnforcementMode::Enforce => {
                let backend = self
                    .backend
                    .as_deref_mut()
                    .ok_or(EnforcementError::BackendUnavailable)?;
                let decision = backend.apply(EnforcementBackendRequest {
                    verdict,
                    trigger: request.trigger,
                })?;
                decision.into_enforcement_parts(verdict.action)
            }
        };
        Ok(decision)
    }
}

fn requires_enforcement(action: Action) -> bool {
    action.is_protective()
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureSource, Direction, EventKind, FlowContext, FlowIdentity, HttpHeaders,
        ProcessContext, ProcessIdentity, ProcessSelector, Selector, Timestamp, TrafficSelector,
        TransportProtocol, VerdictScope,
    };

    use crate::EnforcementBackendDecision;

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
            })?
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
            })?
            .expect("protective verdict should produce enforcement audit");

        assert_eq!(decision.outcome, EnforcementOutcome::SelectorMiss);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(!decision.selector_matched);
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
            })?
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
            })?
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
        })?;

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
            })?
            .expect("protective verdict should produce enforcement audit");

        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.requested_action, Action::Reset);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.selector_matched);
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
            })?
            .expect("protective verdict should be delegated to backend");

        assert_eq!(decision.outcome, EnforcementOutcome::Applied);
        assert_eq!(decision.requested_action, Action::Reset);
        assert_eq!(decision.effective_action, Action::Reset);
        assert_eq!(decision.reason, "backend applied Reset");
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

    fn request_event(direction: Direction) -> EventEnvelope {
        EventEnvelope::new(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            CaptureSource::Replay,
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
        EventEnvelope::new(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            CaptureSource::Replay,
            "test",
            EventKind::ConnectionClosed,
        )
    }

    fn demo_flow() -> FlowContext {
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
            port: 80,
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

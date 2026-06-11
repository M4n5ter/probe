use probe_core::{
    Action, CompiledSelector, Direction, EnforcementDecision, EnforcementMode, EnforcementOutcome,
    EventEnvelope, EventKind, Selector, SelectorError, Verdict,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnforcementError {
    #[error("invalid enforcement selector: {0}")]
    Selector(#[from] SelectorError),
}

pub struct EnforcementPlanRequest<'a> {
    pub verdict: &'a Verdict,
    pub trigger: &'a EventEnvelope,
}

pub trait EnforcementPlanner {
    fn evaluate(
        &self,
        request: EnforcementPlanRequest<'_>,
    ) -> Result<Option<EnforcementDecision>, EnforcementError>;
}

pub struct ScopedEnforcementPlanner {
    mode: EnforcementMode,
    selector: Option<CompiledSelector>,
}

impl ScopedEnforcementPlanner {
    pub fn new(
        mode: EnforcementMode,
        selector: Option<&Selector>,
    ) -> Result<Self, EnforcementError> {
        Ok(Self {
            mode,
            selector: selector.map(Selector::compile).transpose()?,
        })
    }

    pub fn mode(&self) -> EnforcementMode {
        self.mode
    }

    fn selector_matches(&self, trigger: &EventEnvelope) -> bool {
        let Some(selector) = &self.selector else {
            return true;
        };

        event_direction(&trigger.kind).map_or_else(
            || selector.matches_flow_without_direction(&trigger.flow),
            |direction| selector.matches_flow(&trigger.flow, direction),
        )
    }
}

impl EnforcementPlanner for ScopedEnforcementPlanner {
    fn evaluate(
        &self,
        request: EnforcementPlanRequest<'_>,
    ) -> Result<Option<EnforcementDecision>, EnforcementError> {
        if !requires_enforcement(request.verdict.action) {
            return Ok(None);
        }

        let selector_matched = self.selector_matches(request.trigger);
        let (outcome, effective_action, reason) = if !selector_matched {
            (
                EnforcementOutcome::SelectorMiss,
                Action::Observe,
                format!(
                    "policy requested {:?}, but enforcement selector did not match: {}",
                    request.verdict.action, request.verdict.reason
                ),
            )
        } else {
            decision_for_mode(self.mode, request.verdict)
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

fn decision_for_mode(
    mode: EnforcementMode,
    verdict: &Verdict,
) -> (EnforcementOutcome, Action, String) {
    match mode {
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
        EnforcementMode::Enforce => (
            EnforcementOutcome::Unsupported,
            Action::Observe,
            format!(
                "policy requested {:?}, but real enforcement is not implemented: {}",
                verdict.action, verdict.reason
            ),
        ),
    }
}

fn requires_enforcement(action: Action) -> bool {
    matches!(action, Action::Deny | Action::Reset | Action::Quarantine)
}

fn event_direction(kind: &EventKind) -> Option<Direction> {
    match kind {
        EventKind::HttpRequestHeaders(headers) | EventKind::HttpResponseHeaders(headers) => {
            Some(headers.direction)
        }
        EventKind::HttpBodyChunk(chunk) => Some(chunk.direction),
        EventKind::SseEvent(event) => Some(event.direction),
        EventKind::Gap(gap) => Some(gap.direction),
        EventKind::ProtocolError(error) => Some(error.direction),
        EventKind::OpaqueStream(stream) => Some(stream.direction),
        EventKind::ConnectionOpened
        | EventKind::ConnectionClosed
        | EventKind::PolicyAlert(_)
        | EventKind::PolicyVerdict(_)
        | EventKind::EnforcementDecision(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureSource, FlowContext, FlowIdentity, HttpHeaders, ProcessContext,
        ProcessIdentity, ProcessSelector, Selector, Timestamp, TrafficSelector, TransportProtocol,
        VerdictScope,
    };

    use super::*;

    #[test]
    fn dry_run_records_matching_protective_verdict_without_applying_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, None)?;
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
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, Some(&selector))?;
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
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, Some(&selector))?;
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
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::Disabled, None)?;
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
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::AuditOnly, None)?;
        let trigger = request_event(Direction::Outbound);
        let verdict = Verdict::alert("alert only");

        let decision = planner.evaluate(EnforcementPlanRequest {
            verdict: &verdict,
            trigger: &trigger,
        })?;

        assert!(decision.is_none());
        Ok(())
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

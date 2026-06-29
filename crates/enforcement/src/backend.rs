use probe_core::{
    Action, EnforcementExecutionEvidence, EnforcementOutcome, EventEnvelope,
    ProxySideEnforcementSurface, Verdict,
};

use crate::{EnforcementError, decision::EnforcementDecisionParts};

pub struct EnforcementBackendRequest<'a> {
    pub verdict: &'a Verdict,
    pub trigger: &'a EventEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementBackendDecision {
    result: EnforcementBackendResult,
    reason: String,
}

impl EnforcementBackendDecision {
    pub fn applied(reason: impl Into<String>) -> Self {
        Self {
            result: EnforcementBackendResult::Applied,
            reason: reason.into(),
        }
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            result: EnforcementBackendResult::Unsupported,
            reason: reason.into(),
        }
    }

    pub(crate) fn into_enforcement_parts(
        self,
        requested_action: Action,
    ) -> EnforcementDecisionParts {
        match self.result {
            EnforcementBackendResult::Applied => EnforcementDecisionParts::new(
                EnforcementOutcome::Applied,
                requested_action,
                self.reason,
            ),
            EnforcementBackendResult::Unsupported => EnforcementDecisionParts::new(
                EnforcementOutcome::Unsupported,
                Action::Observe,
                self.reason,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnforcementBackendResult {
    Applied,
    Unsupported,
}

pub trait EnforcementBackend: Send {
    fn apply(
        &mut self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<EnforcementBackendDecision, EnforcementError>;
}

impl<T> EnforcementBackend for Box<T>
where
    T: EnforcementBackend + ?Sized,
{
    fn apply(
        &mut self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<EnforcementBackendDecision, EnforcementError> {
        self.as_mut().apply(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySideEnforcementHookDecision {
    result: ProxySideEnforcementHookResult,
    reason: String,
}

impl ProxySideEnforcementHookDecision {
    pub fn delegated(executed_action: Action, reason: impl Into<String>) -> Self {
        Self {
            result: ProxySideEnforcementHookResult::Delegated { executed_action },
            reason: reason.into(),
        }
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            result: ProxySideEnforcementHookResult::Unsupported,
            reason: reason.into(),
        }
    }

    pub(crate) fn into_enforcement_parts(
        self,
        requested_action: Action,
        surface: ProxySideEnforcementSurface,
    ) -> Result<EnforcementDecisionParts, EnforcementError> {
        match self.result {
            ProxySideEnforcementHookResult::Delegated { executed_action } => {
                if executed_action != requested_action {
                    return Err(EnforcementError::Backend(format!(
                        "{} returned executed action {executed_action:?} for requested action {requested_action:?}",
                        surface.description()
                    )));
                }
                let reason = format!(
                    "{} accepted delegated enforcement action: {}",
                    surface.description(),
                    self.reason
                );
                Ok(EnforcementDecisionParts::with_execution(
                    EnforcementOutcome::Delegated,
                    executed_action,
                    reason,
                    EnforcementExecutionEvidence::ProxySideHook {
                        surface,
                        executed_action,
                        reason: self.reason,
                    },
                ))
            }
            ProxySideEnforcementHookResult::Unsupported => Ok(EnforcementDecisionParts::new(
                EnforcementOutcome::Unsupported,
                Action::Observe,
                format!(
                    "{} cannot delegate enforcement action: {}",
                    surface.description(),
                    self.reason
                ),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxySideEnforcementHookResult {
    Delegated { executed_action: Action },
    Unsupported,
}

pub trait ProxySideEnforcementHook: Send {
    fn delegate(
        &mut self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<ProxySideEnforcementHookDecision, EnforcementError>;
}

impl<T> ProxySideEnforcementHook for Box<T>
where
    T: ProxySideEnforcementHook + ?Sized,
{
    fn delegate(
        &mut self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<ProxySideEnforcementHookDecision, EnforcementError> {
        self.as_mut().delegate(request)
    }
}

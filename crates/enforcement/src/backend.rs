use probe_core::{Action, EnforcementOutcome, EventEnvelope, Verdict};

use crate::EnforcementError;

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
    ) -> (EnforcementOutcome, Action, String) {
        match self.result {
            EnforcementBackendResult::Applied => {
                (EnforcementOutcome::Applied, requested_action, self.reason)
            }
            EnforcementBackendResult::Unsupported => (
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
    pub fn delegated(reason: impl Into<String>) -> Self {
        Self {
            result: ProxySideEnforcementHookResult::Delegated,
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
        surface: &str,
    ) -> (EnforcementOutcome, Action, String) {
        match self.result {
            ProxySideEnforcementHookResult::Delegated => (
                EnforcementOutcome::Delegated,
                requested_action,
                format!(
                    "{surface} accepted delegated enforcement action: {}",
                    self.reason
                ),
            ),
            ProxySideEnforcementHookResult::Unsupported => (
                EnforcementOutcome::Unsupported,
                Action::Observe,
                format!(
                    "{surface} cannot delegate enforcement action: {}",
                    self.reason
                ),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxySideEnforcementHookResult {
    Delegated,
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

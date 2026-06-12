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

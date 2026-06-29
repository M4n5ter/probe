use probe_core::{Action, EnforcementExecutionEvidence, EnforcementOutcome};

pub(crate) struct EnforcementDecisionParts {
    pub(crate) outcome: EnforcementOutcome,
    pub(crate) effective_action: Action,
    pub(crate) reason: String,
    pub(crate) execution: Option<EnforcementExecutionEvidence>,
}

impl EnforcementDecisionParts {
    pub(crate) fn new(
        outcome: EnforcementOutcome,
        effective_action: Action,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            outcome,
            effective_action,
            reason: reason.into(),
            execution: None,
        }
    }

    pub(crate) fn with_execution(
        outcome: EnforcementOutcome,
        effective_action: Action,
        reason: impl Into<String>,
        execution: EnforcementExecutionEvidence,
    ) -> Self {
        Self {
            outcome,
            effective_action,
            reason: reason.into(),
            execution: Some(execution),
        }
    }
}

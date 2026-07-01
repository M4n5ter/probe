use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PipelinePolicyRuntimeSnapshot {
    pub id: String,
    pub version: String,
    pub policy_version: String,
    pub selector_configured: bool,
    pub runtime_errors: PipelinePolicyRuntimeErrorSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PipelinePolicyRuntimeErrorSnapshot {
    pub disable_threshold: u64,
    pub consecutive_errors: u64,
    pub disabled_reason: Option<String>,
}

#[derive(Debug)]
pub(super) struct PolicyRuntimeErrorState {
    disable_threshold: u64,
    consecutive_errors: u64,
    disabled_reason: Option<String>,
}

impl PolicyRuntimeErrorState {
    pub(super) fn new(disable_threshold: u64) -> Self {
        Self {
            disable_threshold,
            consecutive_errors: 0,
            disabled_reason: None,
        }
    }

    pub(super) fn is_disabled(&self) -> bool {
        self.disabled_reason.is_some()
    }

    pub(super) fn planned_persisted_error(&self, reason: &str) -> PersistedRuntimeErrorPlan {
        let consecutive_errors = self.consecutive_errors.saturating_add(1);
        let disabled_reason =
            (self.disable_threshold > 0 && consecutive_errors >= self.disable_threshold).then(
                || disabled_after_error_reason(reason, consecutive_errors, self.disable_threshold),
            );
        PersistedRuntimeErrorPlan {
            event_reason: disabled_reason
                .clone()
                .unwrap_or_else(|| reason.to_string()),
            consecutive_errors,
            disabled_reason,
        }
    }

    pub(super) fn commit_persisted_error(&mut self, plan: PersistedRuntimeErrorPlan) {
        if self.disabled_reason.is_some() {
            return;
        }
        self.consecutive_errors = plan.consecutive_errors;
        self.disabled_reason = plan.disabled_reason;
    }

    pub(super) fn record_success(&mut self) {
        if self.disabled_reason.is_none() {
            self.consecutive_errors = 0;
        }
    }

    pub(super) fn snapshot(&self) -> PipelinePolicyRuntimeErrorSnapshot {
        PipelinePolicyRuntimeErrorSnapshot {
            disable_threshold: self.disable_threshold,
            consecutive_errors: self.consecutive_errors,
            disabled_reason: self.disabled_reason.clone(),
        }
    }
}

#[derive(Debug)]
pub(super) struct PersistedRuntimeErrorPlan {
    pub(super) event_reason: String,
    consecutive_errors: u64,
    disabled_reason: Option<String>,
}

fn disabled_after_error_reason(reason: &str, count: u64, threshold: u64) -> String {
    format!(
        "{reason}; policy disabled after {count} consecutive runtime errors (threshold {threshold})"
    )
}

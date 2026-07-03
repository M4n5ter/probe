use std::path::Path;

use serde_json::Value;
use thiserror::Error;

use crate::{
    admin::{AdminClientError, AdminRequest, send_admin_json_request},
    runtime_reload::config_reload::{
        ConfigReloadApplyAction, ConfigReloadApplyActionOutcome, ConfigReloadApplySnapshot,
        ConfigReloadDecision, ConfigReloadPlanSnapshot, ConfigReloadRuntimeAction,
        ConfigReloadRuntimeGenerationActionOutcome, ConfigReloadSection,
    },
};

pub(crate) async fn request_config_reload_apply(
    socket_path: &Path,
    candidate_path: &Path,
) -> Result<ConfigReloadApplySummary, ConfigReloadPlanClientError> {
    let response = send_admin_json_request(
        socket_path,
        AdminRequest::ApplyConfigReload {
            path: candidate_path.to_path_buf(),
        },
    )
    .await
    .map_err(ConfigReloadPlanClientError::AdminClient)?;
    parse_config_reload_apply_response(&response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigReloadPlanSummary {
    decision: ConfigReloadPlanDecision,
    changed_sections: Vec<String>,
}

impl ConfigReloadPlanSummary {
    pub(crate) fn no_runtime_change(&self) -> bool {
        self.decision == ConfigReloadPlanDecision::NoChange
    }

    fn can_apply_online(&self) -> bool {
        matches!(self.decision, ConfigReloadPlanDecision::ApplyOnline { .. })
    }

    fn requires_runtime_rebuild(&self) -> bool {
        matches!(
            self.decision,
            ConfigReloadPlanDecision::RestartRequired { .. }
        )
    }

    fn invalid_candidate(&self) -> bool {
        matches!(
            self.decision,
            ConfigReloadPlanDecision::InvalidCandidate { .. }
        )
    }

    pub(crate) fn status_text(&self) -> String {
        match &self.decision {
            ConfigReloadPlanDecision::NoChange => {
                "running agent already matches saved config".to_string()
            }
            ConfigReloadPlanDecision::ApplyOnline { reason } => {
                let sections = self.changed_sections_text();
                format!("runtime can apply saved config online for {sections}: {reason}")
            }
            ConfigReloadPlanDecision::QueueRuntimeGeneration { reason } => {
                let sections = self.changed_sections_text();
                format!("runtime can queue live generation for {sections}: {reason}")
            }
            ConfigReloadPlanDecision::RestartRequired { reason } => {
                let sections = self.changed_sections_text();
                format!("runtime rebuild required for {sections}: {reason}")
            }
            ConfigReloadPlanDecision::InvalidCandidate { stage, reason } => {
                format!("saved config is not runtime-loadable at {stage}: {reason}")
            }
        }
    }

    fn changed_sections_text(&self) -> String {
        if self.changed_sections.is_empty() {
            "unknown sections".to_string()
        } else {
            self.changed_sections.join(", ")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigReloadPlanDecision {
    NoChange,
    ApplyOnline { reason: String },
    QueueRuntimeGeneration { reason: String },
    RestartRequired { reason: String },
    InvalidCandidate { stage: String, reason: String },
}

impl ConfigReloadPlanDecision {
    fn from_snapshot(decision: ConfigReloadDecision) -> Self {
        match decision {
            ConfigReloadDecision::NoChange => Self::NoChange,
            ConfigReloadDecision::ApplyOnline { reason } => Self::ApplyOnline { reason },
            ConfigReloadDecision::QueueRuntimeGeneration { reason } => {
                Self::QueueRuntimeGeneration { reason }
            }
            ConfigReloadDecision::RestartRequired { reason } => Self::RestartRequired { reason },
            ConfigReloadDecision::InvalidCandidate { stage, reason } => {
                Self::InvalidCandidate { stage, reason }
            }
        }
    }
}

impl ConfigReloadPlanSummary {
    fn from_snapshot(snapshot: ConfigReloadPlanSnapshot) -> Self {
        Self {
            decision: ConfigReloadPlanDecision::from_snapshot(snapshot.decision),
            changed_sections: snapshot
                .changed_sections
                .into_iter()
                .map(|change| section_label(change.section).to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigReloadApplySummary {
    plan: ConfigReloadPlanSummary,
    actions: Vec<ConfigReloadApplyActionSummary>,
    active_plan_updated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigReloadApplyDisposition {
    NoChange,
    AppliedOnline,
    QueuedGeneration { request_id: u64 },
    NeedsRestart,
    Rejected,
    OnlineApplyFailed,
    RuntimeGenerationQueueFailed,
    Failed,
}

impl ConfigReloadApplySummary {
    pub(crate) fn disposition(&self) -> ConfigReloadApplyDisposition {
        if self.plan.requires_runtime_rebuild() {
            return ConfigReloadApplyDisposition::NeedsRestart;
        }
        if self.plan.invalid_candidate() {
            return ConfigReloadApplyDisposition::Rejected;
        }
        if self
            .actions
            .iter()
            .any(ConfigReloadApplyActionSummary::failed)
        {
            if self.has_failed_runtime_generation_request() {
                return ConfigReloadApplyDisposition::RuntimeGenerationQueueFailed;
            }
            if self.plan.can_apply_online() {
                return ConfigReloadApplyDisposition::OnlineApplyFailed;
            }
            return ConfigReloadApplyDisposition::Failed;
        }
        if let Some(request_id) = self.queued_runtime_generation_request_id() {
            return ConfigReloadApplyDisposition::QueuedGeneration { request_id };
        }
        if self.plan.no_runtime_change() {
            return ConfigReloadApplyDisposition::NoChange;
        }
        if self.plan.can_apply_online() && self.active_plan_updated {
            return ConfigReloadApplyDisposition::AppliedOnline;
        }
        ConfigReloadApplyDisposition::Failed
    }

    pub(crate) fn status_text(&self) -> String {
        let queued = self
            .actions
            .iter()
            .filter_map(ConfigReloadApplyActionSummary::queued_text)
            .collect::<Vec<_>>();
        if !queued.is_empty() {
            return format!("runtime generation reload queued: {}", queued.join("; "));
        }
        let failed = self
            .actions
            .iter()
            .filter_map(ConfigReloadApplyActionSummary::failure_text)
            .collect::<Vec<_>>();
        if !failed.is_empty() {
            let prefix = match self.disposition() {
                ConfigReloadApplyDisposition::OnlineApplyFailed => "runtime online apply failed",
                ConfigReloadApplyDisposition::RuntimeGenerationQueueFailed => {
                    "runtime generation reload request failed"
                }
                _ => "runtime config reload failed",
            };
            return format!("{prefix}: {}", failed.join("; "));
        }
        if self.plan.no_runtime_change() {
            return self.plan.status_text();
        }
        if !self.plan.can_apply_online() {
            return self.plan.status_text();
        }
        let applied = self
            .actions
            .iter()
            .filter_map(ConfigReloadApplyActionSummary::success_text)
            .collect::<Vec<_>>();
        if applied.is_empty() {
            return "runtime accepted saved config online".to_string();
        }
        format!(
            "runtime applied saved config online: {}",
            applied.join("; ")
        )
    }

    fn queued_runtime_generation_request_id(&self) -> Option<u64> {
        self.actions.iter().find_map(|action| {
            (action.action == ConfigReloadRuntimeAction::RequestRuntimeGeneration)
                .then(|| action.queued_request_id())
                .flatten()
        })
    }

    fn has_failed_runtime_generation_request(&self) -> bool {
        self.actions.iter().any(|action| {
            action.action == ConfigReloadRuntimeAction::RequestRuntimeGeneration && action.failed()
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigReloadApplyActionSummary {
    action: ConfigReloadRuntimeAction,
    outcome: ConfigReloadApplyActionOutcomeSummary,
}

impl ConfigReloadApplyActionSummary {
    fn failed(&self) -> bool {
        matches!(
            self.outcome,
            ConfigReloadApplyActionOutcomeSummary::Failed { .. }
        )
    }

    fn queued_request_id(&self) -> Option<u64> {
        match self.outcome {
            ConfigReloadApplyActionOutcomeSummary::QueuedGeneration { request_id, .. } => {
                Some(request_id)
            }
            ConfigReloadApplyActionOutcomeSummary::Succeeded { .. }
            | ConfigReloadApplyActionOutcomeSummary::Failed { .. } => None,
        }
    }

    fn success_text(&self) -> Option<String> {
        match &self.outcome {
            ConfigReloadApplyActionOutcomeSummary::Succeeded { detail } => {
                Some(format!("{}: {detail}", runtime_action_label(self.action)))
            }
            ConfigReloadApplyActionOutcomeSummary::Failed { .. }
            | ConfigReloadApplyActionOutcomeSummary::QueuedGeneration { .. } => None,
        }
    }

    fn failure_text(&self) -> Option<String> {
        match &self.outcome {
            ConfigReloadApplyActionOutcomeSummary::Failed { message } => {
                Some(format!("{}: {message}", runtime_action_label(self.action)))
            }
            ConfigReloadApplyActionOutcomeSummary::QueuedGeneration { .. } => None,
            ConfigReloadApplyActionOutcomeSummary::Succeeded { .. } => None,
        }
    }

    fn queued_text(&self) -> Option<String> {
        match &self.outcome {
            ConfigReloadApplyActionOutcomeSummary::QueuedGeneration { detail, .. } => {
                Some(format!("{}: {detail}", runtime_action_label(self.action)))
            }
            ConfigReloadApplyActionOutcomeSummary::Succeeded { .. }
            | ConfigReloadApplyActionOutcomeSummary::Failed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigReloadApplyActionOutcomeSummary {
    Succeeded { detail: String },
    QueuedGeneration { detail: String, request_id: u64 },
    Failed { message: String },
}

impl ConfigReloadApplyActionSummary {
    fn from_snapshot(snapshot: ConfigReloadApplyAction) -> Self {
        match snapshot {
            ConfigReloadApplyAction::ReloadPolicies(outcome) => Self {
                action: ConfigReloadRuntimeAction::ReloadPolicies,
                outcome: ConfigReloadApplyActionOutcomeSummary::from_action_outcome(outcome),
            },
            ConfigReloadApplyAction::ReloadEnforcementPolicy(outcome) => Self {
                action: ConfigReloadRuntimeAction::ReloadEnforcementPolicy,
                outcome: ConfigReloadApplyActionOutcomeSummary::from_action_outcome(outcome),
            },
            ConfigReloadApplyAction::RequestRuntimeGeneration(outcome) => Self {
                action: ConfigReloadRuntimeAction::RequestRuntimeGeneration,
                outcome: ConfigReloadApplyActionOutcomeSummary::from_runtime_generation_outcome(
                    outcome,
                ),
            },
        }
    }
}

impl ConfigReloadApplyActionOutcomeSummary {
    fn from_action_outcome(snapshot: ConfigReloadApplyActionOutcome) -> Self {
        match snapshot {
            ConfigReloadApplyActionOutcome::Succeeded { detail } => Self::Succeeded { detail },
            ConfigReloadApplyActionOutcome::Failed { message } => Self::Failed { message },
        }
    }

    fn from_runtime_generation_outcome(
        snapshot: ConfigReloadRuntimeGenerationActionOutcome,
    ) -> Self {
        match snapshot {
            ConfigReloadRuntimeGenerationActionOutcome::Queued { detail, request_id } => {
                Self::QueuedGeneration { detail, request_id }
            }
            ConfigReloadRuntimeGenerationActionOutcome::Busy { message } => {
                Self::Failed { message }
            }
            ConfigReloadRuntimeGenerationActionOutcome::Failed { message } => {
                Self::Failed { message }
            }
        }
    }
}

#[cfg(test)]
fn parse_config_reload_plan_response(
    response: &Value,
) -> Result<ConfigReloadPlanSummary, ConfigReloadPlanClientError> {
    match response.get("kind").and_then(Value::as_str) {
        Some("config_reload_plan") => {
            let plan = response
                .get("plan")
                .cloned()
                .ok_or(ConfigReloadPlanClientError::MissingPlan)?;
            let plan = serde_json::from_value::<ConfigReloadPlanSnapshot>(plan)
                .map_err(ConfigReloadPlanClientError::Json)?;
            Ok(ConfigReloadPlanSummary::from_snapshot(plan))
        }
        Some("error") => Err(ConfigReloadPlanClientError::Admin(
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("admin plan_config_reload returned an error")
                .to_string(),
        )),
        other => Err(ConfigReloadPlanClientError::UnexpectedResponse {
            kind: other.unwrap_or("<missing>").to_string(),
        }),
    }
}

fn parse_config_reload_apply_response(
    response: &Value,
) -> Result<ConfigReloadApplySummary, ConfigReloadPlanClientError> {
    match response.get("kind").and_then(Value::as_str) {
        Some("config_reload_apply") => {
            let apply = response
                .get("apply")
                .cloned()
                .ok_or(ConfigReloadPlanClientError::MissingApply)?;
            let apply = serde_json::from_value::<ConfigReloadApplySnapshot>(apply)
                .map_err(ConfigReloadPlanClientError::Json)?;
            Ok(ConfigReloadApplySummary {
                plan: ConfigReloadPlanSummary::from_snapshot(apply.plan),
                actions: apply
                    .actions
                    .into_iter()
                    .map(ConfigReloadApplyActionSummary::from_snapshot)
                    .collect(),
                active_plan_updated: apply.active_plan_updated,
            })
        }
        Some("error") => Err(ConfigReloadPlanClientError::Admin(
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("admin apply_config_reload returned an error")
                .to_string(),
        )),
        other => Err(ConfigReloadPlanClientError::UnexpectedResponse {
            kind: other.unwrap_or("<missing>").to_string(),
        }),
    }
}

fn section_label(section: ConfigReloadSection) -> &'static str {
    match section {
        ConfigReloadSection::AgentIdentity => "agent_identity",
        ConfigReloadSection::Capture => "capture",
        ConfigReloadSection::Observations => "observations",
        ConfigReloadSection::Storage => "storage",
        ConfigReloadSection::Export => "export",
        ConfigReloadSection::RuntimeReload => "runtime_reload",
        ConfigReloadSection::PolicyReload => "policy_reload",
        ConfigReloadSection::Policies => "policies",
        ConfigReloadSection::Selectors => "selectors",
        ConfigReloadSection::Tls => "tls",
        ConfigReloadSection::Enforcement => "enforcement",
        ConfigReloadSection::Admin => "admin",
    }
}

fn runtime_action_label(action: ConfigReloadRuntimeAction) -> &'static str {
    match action {
        ConfigReloadRuntimeAction::ReloadPolicies => "reload_policies",
        ConfigReloadRuntimeAction::ReloadEnforcementPolicy => "reload_enforcement_policy",
        ConfigReloadRuntimeAction::RequestRuntimeGeneration => "request_runtime_generation",
    }
}

#[derive(Debug, Error)]
pub(crate) enum ConfigReloadPlanClientError {
    #[error("admin client error: {0}")]
    AdminClient(AdminClientError),
    #[cfg(test)]
    #[error("admin config reload response is missing plan")]
    MissingPlan,
    #[error("admin config reload response is missing apply result")]
    MissingApply,
    #[error("admin plan_config_reload failed: {0}")]
    Admin(String),
    #[error("unexpected admin response kind: {kind}")]
    UnexpectedResponse { kind: String },
    #[error("failed to parse admin config reload response: {0}")]
    Json(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn config_reload_plan_summary_reports_no_change() {
        let response = json!({
            "kind": "config_reload_plan",
            "plan": config_reload_plan(json!({ "kind": "no_change" }), json!([]))
        });

        let summary =
            parse_config_reload_plan_response(&response).expect("no-change response should parse");

        assert!(summary.no_runtime_change());
        assert_eq!(
            summary.status_text(),
            "running agent already matches saved config"
        );
    }

    #[test]
    fn config_reload_plan_summary_reports_restart_sections() {
        let response = json!({
            "kind": "config_reload_plan",
            "plan": config_reload_plan(
                json!({
                    "kind": "restart_required",
                    "reason": "capture provider ownership is fixed"
                }),
                json!([
                    { "section": "observations", "reload_mode": "process_restart", "reason": "process observation profiles changed" },
                    { "section": "capture", "reload_mode": "process_restart", "reason": "capture provider changed" }
                ])
            )
        });

        let summary =
            parse_config_reload_plan_response(&response).expect("restart response should parse");

        assert!(!summary.no_runtime_change());
        assert_eq!(summary.changed_sections, ["observations", "capture"]);
        assert_eq!(
            summary.status_text(),
            "runtime rebuild required for observations, capture: capture provider ownership is fixed"
        );
    }

    #[test]
    fn config_reload_plan_summary_reports_online_apply_sections() {
        let response = json!({
            "kind": "config_reload_plan",
            "plan": config_reload_plan(
                json!({
                    "kind": "apply_online",
                    "reason": "changed sections are owned by runtime reload gates"
                }),
                json!([
                    { "section": "policies", "reload_mode": "apply_online", "reason": "pipeline policy set is reloadable" }
                ])
            )
        });

        let summary =
            parse_config_reload_plan_response(&response).expect("online response should parse");

        assert!(!summary.no_runtime_change());
        assert!(summary.can_apply_online());
        assert_eq!(
            summary.status_text(),
            "runtime can apply saved config online for policies: changed sections are owned by runtime reload gates"
        );
    }

    #[test]
    fn config_reload_apply_summary_reports_online_success() {
        let response = json!({
            "kind": "config_reload_apply",
            "apply": {
                "plan": config_reload_plan(
                    json!({
                        "kind": "apply_online",
                        "reason": "changed sections are owned by runtime reload gates"
                    }),
                    json!([
                        { "section": "policies", "reload_mode": "apply_online", "reason": "pipeline policy set is reloadable" }
                    ])
                ),
                "active_plan_updated": true,
                "actions": [
                    {
                        "action": "reload_policies",
                        "outcome": {
                            "result": "succeeded",
                            "detail": "loaded 1 policy bundle(s), active set updated: true"
                        }
                    }
                ]
            }
        });

        let summary =
            parse_config_reload_apply_response(&response).expect("apply response should parse");

        assert_eq!(
            summary.disposition(),
            ConfigReloadApplyDisposition::AppliedOnline
        );
        assert_eq!(
            summary.status_text(),
            "runtime applied saved config online: reload_policies: loaded 1 policy bundle(s), active set updated: true"
        );
    }

    #[test]
    fn config_reload_apply_summary_reports_enforcement_success() {
        let response = json!({
            "kind": "config_reload_apply",
            "apply": {
                "plan": config_reload_plan(
                    json!({
                        "kind": "apply_online",
                        "reason": "changed sections are owned by runtime reload gates"
                    }),
                    json!([
                        { "section": "enforcement", "reload_mode": "apply_online", "reason": "enforcement policy source and enforcement.selector are owned by an online reload gate" }
                    ])
                ),
                "active_plan_updated": true,
                "actions": [
                    {
                        "action": "reload_enforcement_policy",
                        "outcome": {
                            "result": "succeeded",
                            "detail": "active enforcement policy reloaded"
                        }
                    }
                ]
            }
        });

        let summary =
            parse_config_reload_apply_response(&response).expect("apply response should parse");

        assert_eq!(
            summary.disposition(),
            ConfigReloadApplyDisposition::AppliedOnline
        );
        assert_eq!(
            summary.status_text(),
            "runtime applied saved config online: reload_enforcement_policy: active enforcement policy reloaded"
        );
    }

    #[test]
    fn config_reload_apply_summary_reports_online_failure() {
        let response = json!({
            "kind": "config_reload_apply",
            "apply": {
                "plan": config_reload_plan(
                    json!({
                        "kind": "apply_online",
                        "reason": "changed sections are owned by runtime reload gates"
                    }),
                    json!([
                        { "section": "policies", "reload_mode": "apply_online", "reason": "pipeline policy set is reloadable" }
                    ])
                ),
                "active_plan_updated": false,
                "actions": [
                    {
                        "action": "reload_policies",
                        "outcome": {
                            "result": "failed",
                            "message": "failed to compile policy"
                        }
                    }
                ]
            }
        });

        let summary =
            parse_config_reload_apply_response(&response).expect("apply response should parse");

        assert_eq!(
            summary.disposition(),
            ConfigReloadApplyDisposition::OnlineApplyFailed
        );
        assert_eq!(
            summary.status_text(),
            "runtime online apply failed: reload_policies: failed to compile policy"
        );
    }

    #[test]
    fn config_reload_apply_summary_reports_queued_runtime_generation() {
        let response = json!({
            "kind": "config_reload_apply",
            "apply": {
                "plan": config_reload_plan(
                    json!({
                        "kind": "queue_runtime_generation",
                        "reason": "changed sections are owned by capture provider generation swaps"
                    }),
                    json!([
                        { "section": "capture", "reload_mode": "runtime_generation", "reason": "capture provider changed" }
                    ])
                ),
                "active_plan_updated": false,
                "actions": [
                    {
                        "action": "request_runtime_generation",
                        "outcome": {
                            "result": "queued",
                            "request_id": 1,
                            "detail": "runtime generation reload request 1 queued for live"
                        }
                    }
                ]
            }
        });

        let summary =
            parse_config_reload_apply_response(&response).expect("queued response should parse");

        assert_eq!(
            summary.disposition(),
            ConfigReloadApplyDisposition::QueuedGeneration { request_id: 1 }
        );
        assert_eq!(
            summary.status_text(),
            "runtime generation reload queued: request_runtime_generation: runtime generation reload request 1 queued for live"
        );
    }

    #[test]
    fn config_reload_apply_summary_reports_runtime_generation_queue_failure() {
        let response = json!({
            "kind": "config_reload_apply",
            "apply": {
                "plan": config_reload_plan(
                    json!({
                        "kind": "queue_runtime_generation",
                        "reason": "changed sections are owned by capture provider generation swaps"
                    }),
                    json!([
                        { "section": "capture", "reload_mode": "runtime_generation", "reason": "capture provider changed" }
                    ])
                ),
                "active_plan_updated": false,
                "actions": [
                    {
                        "action": "request_runtime_generation",
                        "outcome": {
                            "result": "busy",
                            "message": "runtime generation reload is busy: applying request 1"
                        }
                    }
                ]
            }
        });

        let summary = parse_config_reload_apply_response(&response)
            .expect("queue failure response should parse");

        assert_eq!(
            summary.disposition(),
            ConfigReloadApplyDisposition::RuntimeGenerationQueueFailed
        );
        assert_eq!(
            summary.status_text(),
            "runtime generation reload request failed: request_runtime_generation: runtime generation reload is busy: applying request 1"
        );
    }

    #[test]
    fn config_reload_plan_summary_rejects_admin_error() {
        let response = json!({
            "kind": "error",
            "message": "admin disabled"
        });

        let error = parse_config_reload_plan_response(&response)
            .expect_err("admin errors should not parse as summaries");

        assert!(
            matches!(error, ConfigReloadPlanClientError::Admin(message) if message == "admin disabled")
        );
    }

    fn config_reload_plan(
        decision: serde_json::Value,
        changed_sections: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "candidate_path": "/tmp/probe-candidate.toml",
            "current_config_version": "current",
            "candidate_config_version": "candidate",
            "decision": decision,
            "changed_sections": changed_sections,
            "reloadable_runtime_actions": [
                "reload_policies",
                "reload_enforcement_policy",
                "request_runtime_generation"
            ]
        })
    }
}

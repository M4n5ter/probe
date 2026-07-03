use std::path::Path;

use serde_json::Value;
use thiserror::Error;

use crate::{
    admin::{AdminClientError, AdminRequest, send_admin_json_request},
    runtime_reload::config_reload::{
        ConfigReloadApplyAction, ConfigReloadApplyActionOutcome, ConfigReloadApplySnapshot,
        ConfigReloadDecision, ConfigReloadPlanSnapshot, ConfigReloadRuntimeAction,
        ConfigReloadSection,
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

    fn can_queue_runtime_generation(&self) -> bool {
        matches!(
            self.decision,
            ConfigReloadPlanDecision::QueueRuntimeGeneration { .. }
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

impl ConfigReloadApplySummary {
    pub(crate) fn no_runtime_rebuild_required(&self) -> bool {
        self.plan.no_runtime_change()
            || (self.plan.can_apply_online()
                && self.active_plan_updated
                && self
                    .actions
                    .iter()
                    .all(ConfigReloadApplyActionSummary::succeeded))
            || (self.plan.can_queue_runtime_generation()
                && !self.actions.is_empty()
                && self
                    .actions
                    .iter()
                    .all(ConfigReloadApplyActionSummary::accepted_without_restart)
                && self
                    .actions
                    .iter()
                    .any(ConfigReloadApplyActionSummary::queued))
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
            let prefix = if self.plan.can_apply_online() {
                "runtime online apply failed"
            } else {
                "runtime config reload failed"
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigReloadApplyActionSummary {
    action: String,
    outcome: ConfigReloadApplyActionOutcomeSummary,
}

impl ConfigReloadApplyActionSummary {
    fn succeeded(&self) -> bool {
        matches!(
            self.outcome,
            ConfigReloadApplyActionOutcomeSummary::Succeeded { .. }
        )
    }

    fn queued(&self) -> bool {
        matches!(
            self.outcome,
            ConfigReloadApplyActionOutcomeSummary::Queued { .. }
        )
    }

    fn accepted_without_restart(&self) -> bool {
        self.succeeded() || self.queued()
    }

    fn success_text(&self) -> Option<String> {
        match &self.outcome {
            ConfigReloadApplyActionOutcomeSummary::Succeeded { detail } => {
                Some(format!("{}: {detail}", self.action))
            }
            ConfigReloadApplyActionOutcomeSummary::Failed { .. }
            | ConfigReloadApplyActionOutcomeSummary::Queued { .. } => None,
        }
    }

    fn failure_text(&self) -> Option<String> {
        match &self.outcome {
            ConfigReloadApplyActionOutcomeSummary::Failed { message } => {
                Some(format!("{}: {message}", self.action))
            }
            ConfigReloadApplyActionOutcomeSummary::Queued { .. } => None,
            ConfigReloadApplyActionOutcomeSummary::Succeeded { .. } => None,
        }
    }

    fn queued_text(&self) -> Option<String> {
        match &self.outcome {
            ConfigReloadApplyActionOutcomeSummary::Queued { detail } => {
                Some(format!("{}: {detail}", self.action))
            }
            ConfigReloadApplyActionOutcomeSummary::Succeeded { .. }
            | ConfigReloadApplyActionOutcomeSummary::Failed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigReloadApplyActionOutcomeSummary {
    Succeeded { detail: String },
    Queued { detail: String },
    Failed { message: String },
}

impl ConfigReloadApplyActionSummary {
    fn from_snapshot(snapshot: ConfigReloadApplyAction) -> Self {
        Self {
            action: runtime_action_label(snapshot.action).to_string(),
            outcome: ConfigReloadApplyActionOutcomeSummary::from_snapshot(snapshot.outcome),
        }
    }
}

impl ConfigReloadApplyActionOutcomeSummary {
    fn from_snapshot(snapshot: ConfigReloadApplyActionOutcome) -> Self {
        match snapshot {
            ConfigReloadApplyActionOutcome::Succeeded { detail } => Self::Succeeded { detail },
            ConfigReloadApplyActionOutcome::Queued { detail } => Self::Queued { detail },
            ConfigReloadApplyActionOutcome::Failed { message } => Self::Failed { message },
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
                    { "section": "observations", "restart_required": true, "reason": "process observation profiles changed" },
                    { "section": "capture", "restart_required": true, "reason": "capture provider changed" }
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
                    { "section": "policies", "restart_required": false, "reason": "pipeline policy set is reloadable" }
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
                        { "section": "policies", "restart_required": false, "reason": "pipeline policy set is reloadable" }
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

        assert!(summary.no_runtime_rebuild_required());
        assert_eq!(
            summary.status_text(),
            "runtime applied saved config online: reload_policies: loaded 1 policy bundle(s), active set updated: true"
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
                        { "section": "policies", "restart_required": false, "reason": "pipeline policy set is reloadable" }
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

        assert!(!summary.no_runtime_rebuild_required());
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
                        { "section": "capture", "restart_required": true, "reason": "capture provider changed" }
                    ])
                ),
                "active_plan_updated": false,
                "actions": [
                    {
                        "action": "request_runtime_generation",
                        "outcome": {
                            "result": "queued",
                            "detail": "runtime generation reload request 1 queued for live"
                        }
                    }
                ]
            }
        });

        let summary =
            parse_config_reload_apply_response(&response).expect("queued response should parse");

        assert!(summary.no_runtime_rebuild_required());
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
                        { "section": "capture", "restart_required": true, "reason": "capture provider changed" }
                    ])
                ),
                "active_plan_updated": false,
                "actions": [
                    {
                        "action": "request_runtime_generation",
                        "outcome": {
                            "result": "failed",
                            "message": "runtime generation reload is busy: pending request 1"
                        }
                    }
                ]
            }
        });

        let summary = parse_config_reload_apply_response(&response)
            .expect("queue failure response should parse");

        assert!(!summary.no_runtime_rebuild_required());
        assert_eq!(
            summary.status_text(),
            "runtime config reload failed: request_runtime_generation: runtime generation reload is busy: pending request 1"
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

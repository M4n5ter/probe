use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::admin::{AdminClientError, AdminRequest, send_admin_json_request};

pub(crate) async fn request_runtime_actions_reload(
    socket_path: &Path,
) -> Result<RuntimeActionsReloadSummary, RuntimeActionsClientError> {
    let response = send_admin_json_request(socket_path, AdminRequest::ReloadRuntimeActions)
        .await
        .map_err(RuntimeActionsClientError::from_admin_client)?;
    parse_runtime_actions_reload_response(&response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeActionsReloadSummary {
    succeeded: usize,
    failures: Vec<RuntimeActionFailure>,
}

impl RuntimeActionsReloadSummary {
    pub(crate) fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    pub(crate) fn status_text(&self) -> String {
        if self.failures.is_empty() {
            return format!("Reloaded {} runtime actions", self.succeeded);
        }
        let failures = self
            .failures
            .iter()
            .map(|failure| format!("{}: {}", failure.action, failure.message))
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "Reloaded {} runtime actions; {} failed ({failures})",
            self.succeeded,
            self.failures.len()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeActionFailure {
    action: String,
    message: String,
}

fn parse_runtime_actions_reload_response(
    response: &Value,
) -> Result<RuntimeActionsReloadSummary, RuntimeActionsClientError> {
    match response.get("kind").and_then(Value::as_str) {
        Some("runtime_actions_reload") => {
            let actions = response
                .get("actions")
                .cloned()
                .ok_or(RuntimeActionsClientError::MissingActions)?;
            let actions = serde_json::from_value::<Vec<RuntimeActionEnvelope>>(actions)
                .map_err(RuntimeActionsClientError::Json)?;
            Ok(summarize_actions(actions))
        }
        Some("error") => Err(RuntimeActionsClientError::Admin(
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("admin reload_runtime_actions returned an error")
                .to_string(),
        )),
        other => Err(RuntimeActionsClientError::UnexpectedResponse {
            kind: other.unwrap_or("<missing>").to_string(),
        }),
    }
}

fn summarize_actions(actions: Vec<RuntimeActionEnvelope>) -> RuntimeActionsReloadSummary {
    let mut succeeded = 0;
    let mut failures = Vec::new();
    for action in actions {
        match action.outcome.result.as_str() {
            "succeeded" => succeeded += 1,
            "failed" => failures.push(RuntimeActionFailure {
                action: action.action,
                message: action
                    .outcome
                    .message
                    .unwrap_or_else(|| "failed without message".to_string()),
            }),
            result => failures.push(RuntimeActionFailure {
                action: action.action,
                message: format!("unexpected result {result}"),
            }),
        }
    }
    RuntimeActionsReloadSummary {
        succeeded,
        failures,
    }
}

#[derive(Debug, Deserialize)]
struct RuntimeActionEnvelope {
    action: String,
    outcome: RuntimeActionOutcome,
}

#[derive(Debug, Deserialize)]
struct RuntimeActionOutcome {
    result: String,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Error)]
pub(crate) enum RuntimeActionsClientError {
    #[error("admin client error: {0}")]
    AdminClient(AdminClientError),
    #[error("admin runtime actions response is missing actions")]
    MissingActions,
    #[error("admin reload_runtime_actions failed: {0}")]
    Admin(String),
    #[error("unexpected admin response kind: {kind}")]
    UnexpectedResponse { kind: String },
    #[error(
        "admin reload_runtime_actions timed out; the agent may still be applying runtime changes"
    )]
    AmbiguousTimeout,
    #[error("failed to parse admin runtime actions response: {0}")]
    Json(serde_json::Error),
}

impl RuntimeActionsClientError {
    fn from_admin_client(error: AdminClientError) -> Self {
        match error {
            AdminClientError::Timeout => Self::AmbiguousTimeout,
            other => Self::AdminClient(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn runtime_actions_response_summarizes_successes() {
        let response = json!({
            "kind": "runtime_actions_reload",
            "actions": [
                {
                    "action": "reload_policies",
                    "outcome": {
                        "result": "succeeded",
                        "loaded_count": 1,
                        "policies": [],
                        "active_set_updated": true
                    }
                },
                {
                    "action": "reload_enforcement_policy",
                    "outcome": {
                        "result": "succeeded",
                        "source": { "mode": "not_configured" },
                        "effective_selector_configured": false,
                        "manifest_selector_configured": null,
                        "protective_actions": { "drop": false, "redact": false }
                    }
                }
            ]
        });

        let summary = parse_runtime_actions_reload_response(&response)
            .expect("success response should parse");

        assert!(!summary.has_failures());
        assert_eq!(summary.status_text(), "Reloaded 2 runtime actions");
    }

    #[test]
    fn runtime_actions_response_keeps_failed_action_messages() {
        let response = json!({
            "kind": "runtime_actions_reload",
            "actions": [
                {
                    "action": "reload_policies",
                    "outcome": { "result": "succeeded", "loaded_count": 0, "policies": [], "active_set_updated": false }
                },
                {
                    "action": "reload_enforcement_policy",
                    "outcome": { "result": "failed", "message": "missing runtime enforcement state" }
                }
            ]
        });

        let summary =
            parse_runtime_actions_reload_response(&response).expect("mixed response should parse");

        assert!(summary.has_failures());
        assert_eq!(
            summary.status_text(),
            "Reloaded 1 runtime actions; 1 failed (reload_enforcement_policy: missing runtime enforcement state)"
        );
    }

    #[test]
    fn runtime_actions_response_rejects_admin_error() {
        let response = json!({
            "kind": "error",
            "message": "admin disabled"
        });

        let error = parse_runtime_actions_reload_response(&response)
            .expect_err("admin error should not be summarized");

        assert!(
            matches!(error, RuntimeActionsClientError::Admin(message) if message == "admin disabled")
        );
    }
}

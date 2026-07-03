use std::path::{Path, PathBuf};

use clap::Subcommand;
use probe_core::{EventType, ProcessSelector, Selector, SelectorTerm, TrafficSelector};
use serde_json::Value;

use crate::{
    admin::{AdminRequest, send_admin_json_request},
    error::AgentError,
};

#[derive(Debug, Clone, Subcommand)]
pub(super) enum AdminCliCommand {
    Status,
    Metrics,
    PrometheusMetrics,
    DebugDump,
    TailEvents {
        #[arg(long, default_value_t = 0)]
        after_sequence: u64,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        process_exe_glob: Option<String>,
        #[arg(long)]
        http: bool,
        #[arg(long = "event-type")]
        event_types: Vec<EventType>,
    },
    EventDetail {
        #[arg(long)]
        sequence: u64,
    },
    PlanConfigReload {
        #[arg(long)]
        config: PathBuf,
    },
    ReloadRuntimeActions,
    ReloadPolicies,
    ReloadEnforcementPolicy,
}

pub(super) async fn run_admin_command(
    socket: &Path,
    command: AdminCliCommand,
) -> Result<(), AgentError> {
    let print_prometheus = matches!(command, AdminCliCommand::PrometheusMetrics);
    let response = send_admin_json_request(socket, admin_request(command)).await?;
    if response.get("kind").and_then(|kind| kind.as_str()) == Some("error") {
        let message = response
            .get("message")
            .and_then(|message| message.as_str())
            .unwrap_or("admin command returned an error");
        return Err(AgentError::AdminCommand(message.to_string()));
    }
    let runtime_action_error = runtime_actions_error_message(&response);
    if print_prometheus
        && let Some(metrics) = response.get("metrics").and_then(|metrics| metrics.as_str())
    {
        print!("{metrics}");
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    if let Some(message) = runtime_action_error {
        return Err(AgentError::AdminCommand(message));
    }
    Ok(())
}

fn admin_request(command: AdminCliCommand) -> AdminRequest {
    match command {
        AdminCliCommand::Status => AdminRequest::Status,
        AdminCliCommand::Metrics => AdminRequest::Metrics,
        AdminCliCommand::PrometheusMetrics => AdminRequest::PrometheusMetrics,
        AdminCliCommand::DebugDump => AdminRequest::DebugDump,
        AdminCliCommand::TailEvents {
            after_sequence,
            limit,
            process_exe_glob,
            http,
            event_types,
        } => AdminRequest::TailEvents {
            after_sequence,
            limit,
            selector: process_exe_glob.map(process_exe_selector),
            event_types: tail_event_types(http, event_types),
        },
        AdminCliCommand::EventDetail { sequence } => AdminRequest::EventDetail { sequence },
        AdminCliCommand::PlanConfigReload { config } => {
            AdminRequest::PlanConfigReload { path: config }
        }
        AdminCliCommand::ReloadRuntimeActions => AdminRequest::ReloadRuntimeActions,
        AdminCliCommand::ReloadPolicies => AdminRequest::ReloadPolicies,
        AdminCliCommand::ReloadEnforcementPolicy => AdminRequest::ReloadEnforcementPolicy,
    }
}

fn tail_event_types(http: bool, mut event_types: Vec<EventType>) -> Vec<EventType> {
    if http {
        event_types.extend(http_event_types());
    }
    event_types.sort_by_key(|event_type| event_type.as_str());
    event_types.dedup();
    event_types
}

fn http_event_types() -> [EventType; 3] {
    [
        EventType::HttpRequestHeaders,
        EventType::HttpResponseHeaders,
        EventType::HttpBodyChunk,
    ]
}

fn process_exe_selector(exe_path_glob: String) -> Selector {
    Selector::Match {
        term: Box::new(SelectorTerm {
            process: ProcessSelector {
                exe_path_globs: vec![exe_path_glob],
                ..ProcessSelector::default()
            },
            traffic: TrafficSelector::default(),
        }),
    }
}

fn runtime_actions_error_message(response: &Value) -> Option<String> {
    if response.get("kind").and_then(Value::as_str) != Some("runtime_actions_reload") {
        return None;
    }
    let failures = response
        .get("actions")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(runtime_action_failure)
        .collect::<Vec<_>>();
    (!failures.is_empty()).then(|| format!("runtime reload action failed: {}", failures.join("; ")))
}

fn runtime_action_failure(action: &Value) -> Option<String> {
    let outcome = action.get("outcome")?;
    if outcome.get("result").and_then(Value::as_str) != Some("failed") {
        return None;
    }
    let action_name = action
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("unknown_action");
    let message = outcome
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("failed");
    Some(format!("{action_name}: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_cli_commands_map_to_admin_request_variants() {
        assert_eq!(admin_request(AdminCliCommand::Status), AdminRequest::Status);
        assert_eq!(
            admin_request(AdminCliCommand::Metrics),
            AdminRequest::Metrics
        );
        assert_eq!(
            admin_request(AdminCliCommand::PrometheusMetrics),
            AdminRequest::PrometheusMetrics
        );
        assert_eq!(
            admin_request(AdminCliCommand::DebugDump),
            AdminRequest::DebugDump
        );
        assert_eq!(
            admin_request(AdminCliCommand::TailEvents {
                after_sequence: 7,
                limit: 10,
                process_exe_glob: Some("/usr/bin/curl".to_string()),
                http: true,
                event_types: vec![EventType::Gap, EventType::HttpRequestHeaders],
            }),
            AdminRequest::TailEvents {
                after_sequence: 7,
                limit: 10,
                selector: Some(process_exe_selector("/usr/bin/curl".to_string())),
                event_types: vec![
                    EventType::Gap,
                    EventType::HttpBodyChunk,
                    EventType::HttpRequestHeaders,
                    EventType::HttpResponseHeaders,
                ],
            }
        );
        assert_eq!(
            admin_request(AdminCliCommand::EventDetail { sequence: 7 }),
            AdminRequest::EventDetail { sequence: 7 }
        );
        assert_eq!(
            admin_request(AdminCliCommand::PlanConfigReload {
                config: PathBuf::from("/tmp/agent.toml"),
            }),
            AdminRequest::PlanConfigReload {
                path: PathBuf::from("/tmp/agent.toml"),
            }
        );
        assert_eq!(
            admin_request(AdminCliCommand::ReloadRuntimeActions),
            AdminRequest::ReloadRuntimeActions
        );
        assert_eq!(
            admin_request(AdminCliCommand::ReloadPolicies),
            AdminRequest::ReloadPolicies
        );
        assert_eq!(
            admin_request(AdminCliCommand::ReloadEnforcementPolicy),
            AdminRequest::ReloadEnforcementPolicy
        );
    }

    #[test]
    fn runtime_actions_error_message_reports_failed_actions() {
        let response = serde_json::json!({
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
                        "result": "failed",
                        "message": "failed to reload enforcement policy: invalid manifest"
                    }
                }
            ]
        });

        assert_eq!(
            runtime_actions_error_message(&response).as_deref(),
            Some(
                "runtime reload action failed: reload_enforcement_policy: failed to reload enforcement policy: invalid manifest"
            )
        );
    }

    #[test]
    fn runtime_actions_error_message_ignores_successful_actions() {
        let response = serde_json::json!({
            "kind": "runtime_actions_reload",
            "actions": [
                {
                    "action": "reload_policies",
                    "outcome": {
                        "result": "succeeded",
                        "loaded_count": 1,
                        "policies": [],
                        "active_set_updated": false
                    }
                }
            ]
        });

        assert_eq!(runtime_actions_error_message(&response), None);
    }
}

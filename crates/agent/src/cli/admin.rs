use std::path::{Path, PathBuf};

use clap::Subcommand;
use probe_core::{EventType, ProcessSelector, Selector, SelectorTerm, TrafficSelector};
use serde_json::Value;

use crate::{
    admin::{AdminRequest, EventTailAttributionMode, send_admin_json_request},
    error::AgentError,
    event_type_groups,
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
        #[arg(long)]
        latest: bool,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        process_exe_glob: Option<String>,
        #[arg(long)]
        include_unknown_process: bool,
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
    ApplyConfigReload {
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
    let action_error = admin_action_error_message(&response);
    if print_prometheus
        && let Some(metrics) = response.get("metrics").and_then(|metrics| metrics.as_str())
    {
        print!("{metrics}");
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    if let Some(message) = action_error {
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
            latest,
            limit,
            process_exe_glob,
            include_unknown_process,
            http,
            event_types,
        } => AdminRequest::TailEvents {
            after_sequence,
            latest,
            limit,
            selector: process_exe_glob.map(process_exe_selector),
            attribution_mode: tail_attribution_mode(include_unknown_process),
            event_types: tail_event_types(http, event_types),
        },
        AdminCliCommand::EventDetail { sequence } => AdminRequest::EventDetail { sequence },
        AdminCliCommand::PlanConfigReload { config } => {
            AdminRequest::PlanConfigReload { path: config }
        }
        AdminCliCommand::ApplyConfigReload { config } => {
            AdminRequest::ApplyConfigReload { path: config }
        }
        AdminCliCommand::ReloadRuntimeActions => AdminRequest::ReloadRuntimeActions,
        AdminCliCommand::ReloadPolicies => AdminRequest::ReloadPolicies,
        AdminCliCommand::ReloadEnforcementPolicy => AdminRequest::ReloadEnforcementPolicy,
    }
}

fn tail_attribution_mode(include_unknown_process: bool) -> EventTailAttributionMode {
    if include_unknown_process {
        EventTailAttributionMode::IncludeUnknownProcess
    } else {
        EventTailAttributionMode::Strict
    }
}

fn tail_event_types(http: bool, mut event_types: Vec<EventType>) -> Vec<EventType> {
    if http {
        event_types.extend(event_type_groups::http());
    }
    event_types.sort_by_key(|event_type| event_type.as_str());
    event_types.dedup();
    event_types
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

fn admin_action_error_message(response: &Value) -> Option<String> {
    let (label, actions) = match response.get("kind").and_then(Value::as_str) {
        Some("runtime_actions_reload") => ("runtime reload action", response.get("actions")),
        Some("config_reload_apply") => (
            "config reload action",
            response.get("apply").and_then(|apply| apply.get("actions")),
        ),
        _ => return None,
    };
    let failures = actions
        .and_then(Value::as_array)?
        .iter()
        .filter_map(runtime_action_failure)
        .collect::<Vec<_>>();
    (!failures.is_empty()).then(|| format!("{label} failed: {}", failures.join("; ")))
}

fn runtime_action_failure(action: &Value) -> Option<String> {
    let outcome = action.get("outcome")?;
    let result = outcome.get("result").and_then(Value::as_str)?;
    let default_message = match result {
        "busy" => "busy",
        "failed" => "failed",
        _ => return None,
    };
    let action_name = action
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("unknown_action");
    let message = outcome
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or(default_message);
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
                latest: false,
                limit: 10,
                process_exe_glob: Some("/usr/bin/curl".to_string()),
                include_unknown_process: true,
                http: true,
                event_types: vec![EventType::Gap, EventType::HttpRequestHeaders],
            }),
            AdminRequest::TailEvents {
                after_sequence: 7,
                latest: false,
                limit: 10,
                selector: Some(process_exe_selector("/usr/bin/curl".to_string())),
                attribution_mode: EventTailAttributionMode::IncludeUnknownProcess,
                event_types: vec![
                    EventType::Gap,
                    EventType::HttpBodyChunk,
                    EventType::HttpRequestHeaders,
                    EventType::HttpResponseHeaders,
                    EventType::SseEvent,
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
            admin_request(AdminCliCommand::ApplyConfigReload {
                config: PathBuf::from("/tmp/agent.toml"),
            }),
            AdminRequest::ApplyConfigReload {
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
    fn admin_action_error_message_reports_failed_runtime_actions() {
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
            admin_action_error_message(&response).as_deref(),
            Some(
                "runtime reload action failed: reload_enforcement_policy: failed to reload enforcement policy: invalid manifest"
            )
        );
    }

    #[test]
    fn admin_action_error_message_reports_failed_config_reload_apply_actions() {
        let response = serde_json::json!({
            "kind": "config_reload_apply",
            "apply": {
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

        assert_eq!(
            admin_action_error_message(&response).as_deref(),
            Some(
                "config reload action failed: request_runtime_generation: runtime generation reload is busy: applying request 1"
            )
        );
    }

    #[test]
    fn admin_action_error_message_ignores_successful_actions() {
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

        assert_eq!(admin_action_error_message(&response), None);
    }
}

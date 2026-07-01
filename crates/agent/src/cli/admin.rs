use std::path::{Path, PathBuf};

use clap::Subcommand;

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
    PlanConfigReload {
        #[arg(long)]
        config: PathBuf,
    },
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
    if print_prometheus
        && let Some(metrics) = response.get("metrics").and_then(|metrics| metrics.as_str())
    {
        print!("{metrics}");
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn admin_request(command: AdminCliCommand) -> AdminRequest {
    match command {
        AdminCliCommand::Status => AdminRequest::Status,
        AdminCliCommand::Metrics => AdminRequest::Metrics,
        AdminCliCommand::PrometheusMetrics => AdminRequest::PrometheusMetrics,
        AdminCliCommand::DebugDump => AdminRequest::DebugDump,
        AdminCliCommand::PlanConfigReload { config } => {
            AdminRequest::PlanConfigReload { path: config }
        }
        AdminCliCommand::ReloadPolicies => AdminRequest::ReloadPolicies,
        AdminCliCommand::ReloadEnforcementPolicy => AdminRequest::ReloadEnforcementPolicy,
    }
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
            admin_request(AdminCliCommand::PlanConfigReload {
                config: PathBuf::from("/tmp/agent.toml"),
            }),
            AdminRequest::PlanConfigReload {
                path: PathBuf::from("/tmp/agent.toml"),
            }
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
}

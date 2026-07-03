mod admin;
mod artifacts;
mod capture_event_feed;
mod capture_provider;
mod capture_registry;
mod check;
mod cli;
mod configured_enforcement;
mod configured_policy;
mod connection_enforcement;
mod control_plane_http;
mod enforcement_reload;
mod enforcement_reload_poller;
mod enforcement_reload_watcher;
mod error;
mod event_type_groups;
mod export;
mod json_lines;
mod l7_mitm;
mod live_agent;
mod periodic_worker;
mod plaintext_feed;
mod policy_reload;
mod policy_reload_poller;
mod policy_reload_watcher;
mod reload_watcher;
mod remote_source;
mod runtime_composition;
mod runtime_config_watcher;
mod runtime_generation;
mod runtime_plan;
mod runtime_reload;
mod shutdown;
mod status;
mod storage_retention;
mod tcp_health;
mod telemetry;
mod tls_material;
mod tls_plaintext;
mod transparent_interception;
mod tui;

#[tokio::main]
async fn main() {
    telemetry::init_for_current_invocation();
    if let Err(error) = cli::run_from_env().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

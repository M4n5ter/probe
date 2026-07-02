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
mod shutdown;
mod status;
mod storage_retention;
mod tcp_health;
mod tls_material;
mod tls_plaintext;
mod transparent_interception;
mod tui;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    if let Err(error) = cli::run_from_env().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

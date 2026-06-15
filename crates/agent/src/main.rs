mod admin;
mod capture_provider;
mod capture_registry;
mod check;
mod cli;
mod configured_enforcement;
mod configured_policy;
mod connection_enforcement;
mod error;
mod export;
mod periodic_worker;
mod plaintext_feed;
mod runtime_composition;
mod status;
mod storage_retention;
mod tls_material;
mod tls_plaintext;
mod transparent_interception;

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

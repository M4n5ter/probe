mod admin;
mod capture_provider;
mod capture_registry;
mod check;
mod cli;
mod configured_enforcement;
mod configured_policy;
mod error;
mod export;
mod plaintext_feed;
#[cfg(test)]
mod single_response_http_server;
mod status;
mod tls_material;

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

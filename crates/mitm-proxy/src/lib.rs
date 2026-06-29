mod cli;
mod error;
mod feed;
mod flow;
mod http;
mod proxy;

pub use cli::Cli;
pub use error::MitmProxyError;
pub use proxy::{MitmProxyConfig, MitmProxyGuard, TargetRecovery};

pub fn run_cli() -> Result<(), MitmProxyError> {
    proxy::run_forever(cli::parse()?)
}

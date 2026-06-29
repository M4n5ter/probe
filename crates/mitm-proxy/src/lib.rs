mod cli;
mod error;
mod feed;
mod flow;
mod http;
mod proxy;
mod tls;

pub use cli::Cli;
pub use error::MitmProxyError;
pub use proxy::{MitmProxyConfig, MitmProxyGuard, TargetRecovery};
pub use tls::TlsTerminationConfig;

pub fn run_cli() -> Result<(), MitmProxyError> {
    proxy::run_forever(cli::parse()?)
}

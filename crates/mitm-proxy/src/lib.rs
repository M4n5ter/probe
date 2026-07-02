use std::ffi::OsString;

mod authority;
mod cli;
mod error;
mod feed;
mod flow;
mod http;
mod proxy;
mod tls;

pub use cli::Cli;
pub use error::MitmProxyError;
pub use proxy::{
    MitmProxyConfig, MitmProxyGuard, TargetRecovery, UpstreamTargetRoute, UpstreamTargetRoutes,
    UpstreamTlsMode,
};
pub use tls::{TlsTerminationConfig, UpstreamTlsConfig};

pub fn run_cli() -> Result<(), MitmProxyError> {
    proxy::run_forever(cli::parse()?)
}

pub fn config_from_cli_args<I, T>(args: I) -> Result<MitmProxyConfig, MitmProxyError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    cli::parse_from(args)
}

pub fn run_cli_from<I, T>(args: I) -> Result<(), MitmProxyError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    proxy::run_forever(config_from_cli_args(args)?)
}

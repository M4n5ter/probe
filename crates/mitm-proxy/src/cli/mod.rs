use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;
use probe_core::Direction;

use crate::{
    MitmProxyError,
    proxy::{MitmProxyConfig, TargetRecovery},
};

#[derive(Debug, Parser)]
#[command(name = "traffic-probe-mitm-proxy")]
#[command(about = "Selector-scoped L7 MITM proxy data plane for traffic-probe")]
pub struct Cli {
    #[arg(long)]
    pub listen: SocketAddr,
    #[arg(long)]
    pub feed: PathBuf,
    #[arg(long)]
    pub pid_file: Option<PathBuf>,
    #[arg(long)]
    pub upstream: Option<SocketAddr>,
    #[arg(long, default_value_t = TargetRecovery::AcceptedLocal)]
    pub target_recovery: TargetRecovery,
    #[arg(long, default_value_t = RequestDirection::Outbound)]
    pub request_direction: RequestDirection,
    #[arg(long)]
    pub policy_hook_listen: Option<SocketAddr>,
    #[arg(long, default_value = "/mitm-policy-hook")]
    pub policy_hook_path: String,
    #[arg(long, default_value_t = 65_536)]
    pub max_request_bytes: usize,
    #[arg(long, default_value_t = 5_000)]
    pub io_timeout_ms: u64,
    #[arg(long, default_value_t = 5_000)]
    pub action_timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum RequestDirection {
    Inbound,
    Outbound,
}

impl std::fmt::Display for RequestDirection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inbound => formatter.write_str("inbound"),
            Self::Outbound => formatter.write_str("outbound"),
        }
    }
}

impl From<RequestDirection> for Direction {
    fn from(value: RequestDirection) -> Self {
        match value {
            RequestDirection::Inbound => Self::Inbound,
            RequestDirection::Outbound => Self::Outbound,
        }
    }
}

pub(crate) fn parse() -> Result<MitmProxyConfig, MitmProxyError> {
    Cli::parse().try_into()
}

impl TryFrom<Cli> for MitmProxyConfig {
    type Error = MitmProxyError;

    fn try_from(value: Cli) -> Result<Self, Self::Error> {
        if value.max_request_bytes == 0 {
            return Err(MitmProxyError::InvalidConfig(
                "max_request_bytes must be greater than zero".to_string(),
            ));
        }
        if value.policy_hook_path.is_empty() || !value.policy_hook_path.starts_with('/') {
            return Err(MitmProxyError::InvalidConfig(
                "policy_hook_path must be an absolute path".to_string(),
            ));
        }
        Ok(MitmProxyConfig {
            listen: value.listen,
            feed_path: value.feed,
            pid_file: value.pid_file,
            upstream: value.upstream,
            target_recovery: value.target_recovery,
            request_direction: value.request_direction.into(),
            policy_hook_listen: value.policy_hook_listen,
            policy_hook_path: value.policy_hook_path,
            max_request_bytes: value.max_request_bytes,
            io_timeout: Duration::from_millis(value.io_timeout_ms),
            action_timeout: Duration::from_millis(value.action_timeout_ms),
        })
    }
}

use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, time::Duration};

use clap::Parser;
use probe_core::Direction;

use crate::{
    MitmProxyError,
    proxy::{MitmProxyConfig, TargetRecovery},
    tls::{TlsTerminationConfig, UpstreamTlsConfig},
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
    #[arg(long)]
    pub upstream_tls: bool,
    #[arg(long)]
    pub upstream_trust_anchor: Vec<PathBuf>,
    #[arg(long)]
    pub upstream_server_name: Option<String>,
    #[arg(long, value_parser = parse_socket_mark)]
    pub upstream_socket_mark: Option<NonZeroU32>,
    #[arg(long)]
    pub tls_certificate_chain: Option<PathBuf>,
    #[arg(long)]
    pub tls_private_key: Option<PathBuf>,
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
        let tls = match (value.tls_certificate_chain, value.tls_private_key) {
            (Some(certificate_chain), Some(private_key)) => {
                Some(TlsTerminationConfig::new(certificate_chain, private_key))
            }
            (None, None) => None,
            _ => {
                return Err(MitmProxyError::InvalidConfig(
                    "tls_certificate_chain and tls_private_key must be configured together"
                        .to_string(),
                ));
            }
        };
        if !value.upstream_tls
            && (!value.upstream_trust_anchor.is_empty() || value.upstream_server_name.is_some())
        {
            return Err(MitmProxyError::InvalidConfig(
                "upstream TLS trust anchors and server name require upstream_tls = true"
                    .to_string(),
            ));
        }
        let upstream_tls = value.upstream_tls.then(|| {
            UpstreamTlsConfig::new(value.upstream_trust_anchor, value.upstream_server_name)
        });
        Ok(MitmProxyConfig {
            listen: value.listen,
            feed_path: value.feed,
            pid_file: value.pid_file,
            upstream: value.upstream,
            upstream_tls,
            upstream_socket_mark: value.upstream_socket_mark,
            tls,
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

fn parse_socket_mark(value: &str) -> Result<NonZeroU32, String> {
    let mark = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse::<u32>(), |hex| u32::from_str_radix(hex, 16))
        .map_err(|error| format!("invalid socket mark {value:?}: {error}"))?;
    NonZeroU32::new(mark).ok_or_else(|| "socket mark must be non-zero".to_string())
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, path::Path};

    use super::*;

    #[test]
    fn tls_certificate_chain_and_private_key_must_be_configured_together() {
        let error = MitmProxyConfig::try_from(Cli {
            tls_certificate_chain: Some(Path::new("/tmp/server.pem").to_path_buf()),
            tls_private_key: None,
            ..minimal_cli()
        })
        .expect_err("partial TLS termination config must be rejected");

        assert!(
            matches!(error, MitmProxyError::InvalidConfig(reason) if reason.contains("must be configured together"))
        );
    }

    #[test]
    fn tls_certificate_chain_and_private_key_build_tls_config() {
        let config = MitmProxyConfig::try_from(Cli {
            tls_certificate_chain: Some(Path::new("/tmp/server.pem").to_path_buf()),
            tls_private_key: Some(Path::new("/tmp/server.key").to_path_buf()),
            ..minimal_cli()
        })
        .expect("complete TLS termination config should parse");

        let tls = config
            .tls
            .expect("complete TLS termination config should be preserved");
        assert_eq!(tls.certificate_chain, Path::new("/tmp/server.pem"));
        assert_eq!(tls.private_key, Path::new("/tmp/server.key"));
    }

    #[test]
    fn upstream_tls_builds_connector_config() {
        let config = MitmProxyConfig::try_from(Cli {
            upstream_tls: true,
            upstream_trust_anchor: vec![Path::new("/tmp/upstream-ca.pem").to_path_buf()],
            upstream_server_name: Some("upstream.test".to_string()),
            ..minimal_cli()
        })
        .expect("upstream TLS config should parse");

        let upstream_tls = config
            .upstream_tls
            .expect("upstream TLS config should be preserved");
        assert_eq!(
            upstream_tls.trust_anchors,
            vec![Path::new("/tmp/upstream-ca.pem").to_path_buf()]
        );
        assert_eq!(upstream_tls.server_name.as_deref(), Some("upstream.test"));
    }

    #[test]
    fn upstream_tls_details_require_upstream_tls_mode() {
        let error = MitmProxyConfig::try_from(Cli {
            upstream_trust_anchor: vec![Path::new("/tmp/upstream-ca.pem").to_path_buf()],
            ..minimal_cli()
        })
        .expect_err("trust anchors without upstream TLS mode should be rejected");

        assert!(
            matches!(error, MitmProxyError::InvalidConfig(reason) if reason.contains("require upstream_tls"))
        );
    }

    #[test]
    fn upstream_socket_mark_accepts_hex_value() {
        let mark = parse_socket_mark("0x54500102").expect("hex socket mark should parse");

        assert_eq!(mark.get(), 0x5450_0102);
    }

    fn minimal_cli() -> Cli {
        Cli {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 15_001)),
            feed: Path::new("/tmp/mitm-feed.jsonl").to_path_buf(),
            pid_file: None,
            upstream: None,
            upstream_tls: false,
            upstream_trust_anchor: Vec::new(),
            upstream_server_name: None,
            upstream_socket_mark: None,
            tls_certificate_chain: None,
            tls_private_key: None,
            target_recovery: TargetRecovery::AcceptedLocal,
            request_direction: RequestDirection::Outbound,
            policy_hook_listen: None,
            policy_hook_path: "/mitm-policy-hook".to_string(),
            max_request_bytes: 65_536,
            io_timeout_ms: 5_000,
            action_timeout_ms: 5_000,
        }
    }
}

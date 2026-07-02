use std::{
    ffi::OsString,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU32},
    path::PathBuf,
    time::Duration,
};

use clap::Parser;
use probe_core::{ApplicationProtocol, ApplicationProtocolPolicy, Direction};
use probe_io::AllowedFileRoots;

use crate::{
    MitmProxyError,
    proxy::{
        MitmProxyConfig, TargetRecovery, UpstreamDiscovery, UpstreamTargetRoute,
        UpstreamTargetRoutes,
    },
    tls::{TlsTerminationConfig, UpstreamTlsConfig},
};

#[derive(Debug, Parser)]
#[command(name = "traffic-probe-mitm-proxy")]
#[command(version)]
#[command(about = "Selector-scoped L7 MITM proxy data plane for traffic-probe")]
pub struct Cli {
    #[arg(long)]
    pub listen: SocketAddr,
    #[arg(long)]
    pub transparent_listen: bool,
    #[arg(long)]
    pub feed: PathBuf,
    #[arg(long)]
    pub pid_file: Option<PathBuf>,
    #[arg(long)]
    pub upstream: Option<SocketAddr>,
    #[arg(long = "upstream-route", value_parser = parse_upstream_route)]
    pub upstream_routes: Vec<UpstreamTargetRoute>,
    #[arg(long)]
    pub upstream_dns_discovery: bool,
    #[arg(long, value_parser = parse_nonzero_u16)]
    pub upstream_dns_default_port: Option<NonZeroU16>,
    #[arg(long)]
    pub upstream_dns_allow_special_use_addresses: bool,
    #[arg(long)]
    pub upstream_tls: bool,
    #[arg(long)]
    pub upstream_trust_anchor: Vec<PathBuf>,
    #[arg(long)]
    pub upstream_server_name: Option<String>,
    #[arg(long, value_parser = parse_socket_mark)]
    pub upstream_socket_mark: Option<NonZeroU32>,
    #[arg(long = "alpn", value_parser = parse_application_protocol)]
    pub alpn: Vec<ApplicationProtocol>,
    #[arg(long)]
    pub tls_certificate_chain: Option<PathBuf>,
    #[arg(long)]
    pub tls_private_key: Option<PathBuf>,
    #[arg(long)]
    pub tls_ca_certificate: Option<PathBuf>,
    #[arg(long)]
    pub tls_ca_private_key: Option<PathBuf>,
    #[arg(long = "tls-material-root")]
    pub tls_material_roots: Vec<PathBuf>,
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

pub(crate) fn parse_from<I, T>(args: I) -> Result<MitmProxyConfig, MitmProxyError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Cli::try_parse_from(args)
        .map_err(|error| MitmProxyError::InvalidConfig(error.to_string()))?
        .try_into()
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
        let tls_material_roots = AllowedFileRoots::new(value.tls_material_roots.clone())
            .map_err(|error| MitmProxyError::InvalidConfig(error.to_string()))?;
        let tls = tls_termination_config(
            value.tls_certificate_chain,
            value.tls_private_key,
            value.tls_ca_certificate,
            value.tls_ca_private_key,
        )?
        .map(|tls| tls.with_material_roots(tls_material_roots.clone()));
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
                .with_material_roots(tls_material_roots)
        });
        if !value.upstream_dns_discovery
            && (value.upstream_dns_default_port.is_some()
                || value.upstream_dns_allow_special_use_addresses)
        {
            return Err(MitmProxyError::InvalidConfig(
                "upstream DNS discovery fields require upstream_dns_discovery = true".to_string(),
            ));
        }
        if value.upstream.is_some()
            && (!value.upstream_routes.is_empty() || value.upstream_dns_discovery)
        {
            return Err(MitmProxyError::InvalidConfig(
                "upstream cannot be combined with upstream routes or DNS discovery".to_string(),
            ));
        }
        let upstream_discovery = if value.upstream_dns_discovery {
            UpstreamDiscovery::Dns {
                default_port: value.upstream_dns_default_port,
                allow_special_use_addresses: value.upstream_dns_allow_special_use_addresses,
            }
        } else {
            UpstreamDiscovery::Disabled
        };
        let upstream_routes = UpstreamTargetRoutes::from_routes(value.upstream_routes)?;
        let application_protocols = if value.alpn.is_empty() {
            ApplicationProtocolPolicy::default()
        } else {
            ApplicationProtocolPolicy::new(value.alpn)
                .map_err(|error| MitmProxyError::InvalidConfig(error.to_string()))?
        };
        Ok(MitmProxyConfig {
            listen: value.listen,
            transparent_listen: value.transparent_listen,
            feed_path: value.feed,
            pid_file: value.pid_file,
            upstream: value.upstream,
            upstream_routes,
            upstream_discovery,
            upstream_tls,
            upstream_socket_mark: value.upstream_socket_mark,
            tls,
            application_protocols,
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

fn tls_termination_config(
    certificate_chain: Option<PathBuf>,
    private_key: Option<PathBuf>,
    ca_certificate: Option<PathBuf>,
    ca_private_key: Option<PathBuf>,
) -> Result<Option<TlsTerminationConfig>, MitmProxyError> {
    let has_static_pair = certificate_chain.is_some() && private_key.is_some();
    let has_ca_pair = ca_certificate.is_some() && ca_private_key.is_some();
    if has_static_pair && has_ca_pair {
        return Err(MitmProxyError::InvalidConfig(
            "configure either tls_certificate_chain/tls_private_key or tls_ca_certificate/tls_ca_private_key, not both".to_string(),
        ));
    }
    match (
        certificate_chain,
        private_key,
        ca_certificate,
        ca_private_key,
    ) {
        (Some(certificate_chain), Some(private_key), None, None) => Ok(Some(
            TlsTerminationConfig::new(certificate_chain, private_key),
        )),
        (None, None, Some(ca_certificate), Some(ca_private_key)) => Ok(Some(
            TlsTerminationConfig::from_ca(ca_certificate, ca_private_key),
        )),
        (None, None, None, None) => Ok(None),
        (Some(_), None, _, _) | (None, Some(_), _, _) => Err(MitmProxyError::InvalidConfig(
            "tls_certificate_chain and tls_private_key must be configured together".to_string(),
        )),
        (_, _, Some(_), None) | (_, _, None, Some(_)) => Err(MitmProxyError::InvalidConfig(
            "tls_ca_certificate and tls_ca_private_key must be configured together".to_string(),
        )),
        _ => Err(MitmProxyError::InvalidConfig(
            "invalid TLS termination configuration".to_string(),
        )),
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

fn parse_nonzero_u16(value: &str) -> Result<NonZeroU16, String> {
    value
        .parse::<u16>()
        .map_err(|error| format!("invalid non-zero u16 value {value:?}: {error}"))
        .and_then(|port| NonZeroU16::new(port).ok_or_else(|| "value must be non-zero".to_string()))
}

fn parse_application_protocol(value: &str) -> Result<ApplicationProtocol, String> {
    ApplicationProtocol::from_wire_name(value).map_err(|error| error.to_string())
}

fn parse_upstream_route(value: &str) -> Result<UpstreamTargetRoute, String> {
    UpstreamTargetRoute::parse_cli_value(value).map_err(|error| error.to_string())
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
        assert_eq!(
            tls,
            TlsTerminationConfig::new(
                Path::new("/tmp/server.pem").to_path_buf(),
                Path::new("/tmp/server.key").to_path_buf()
            )
        );
    }

    #[test]
    fn tls_ca_certificate_and_private_key_build_dynamic_tls_config() {
        let config = MitmProxyConfig::try_from(Cli {
            tls_ca_certificate: Some(Path::new("/tmp/mitm-ca.pem").to_path_buf()),
            tls_ca_private_key: Some(Path::new("/tmp/mitm-ca.key").to_path_buf()),
            ..minimal_cli()
        })
        .expect("complete dynamic TLS termination config should parse");

        let tls = config
            .tls
            .expect("complete dynamic TLS termination config should be preserved");
        assert_eq!(
            tls,
            TlsTerminationConfig::from_ca(
                Path::new("/tmp/mitm-ca.pem").to_path_buf(),
                Path::new("/tmp/mitm-ca.key").to_path_buf()
            )
        );
    }

    #[test]
    fn tls_ca_certificate_and_private_key_must_be_configured_together() {
        let error = MitmProxyConfig::try_from(Cli {
            tls_ca_certificate: Some(Path::new("/tmp/mitm-ca.pem").to_path_buf()),
            tls_ca_private_key: None,
            ..minimal_cli()
        })
        .expect_err("partial dynamic TLS termination config must be rejected");

        assert!(
            matches!(error, MitmProxyError::InvalidConfig(reason) if reason.contains("tls_ca_certificate"))
        );
    }

    #[test]
    fn tls_static_and_ca_modes_are_mutually_exclusive() {
        let error = MitmProxyConfig::try_from(Cli {
            tls_certificate_chain: Some(Path::new("/tmp/server.pem").to_path_buf()),
            tls_private_key: Some(Path::new("/tmp/server.key").to_path_buf()),
            tls_ca_certificate: Some(Path::new("/tmp/mitm-ca.pem").to_path_buf()),
            tls_ca_private_key: Some(Path::new("/tmp/mitm-ca.key").to_path_buf()),
            ..minimal_cli()
        })
        .expect_err("ambiguous TLS termination config must be rejected");

        assert!(
            matches!(error, MitmProxyError::InvalidConfig(reason) if reason.contains("not both"))
        );
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
    fn tls_material_roots_are_attached_to_tls_configs() {
        let roots = vec![
            Path::new("/etc/probe/certs").to_path_buf(),
            Path::new("/var/lib/traffic-probe/tls").to_path_buf(),
        ];
        let config = MitmProxyConfig::try_from(Cli {
            upstream_tls: true,
            upstream_trust_anchor: vec![Path::new("/etc/probe/certs/upstream.pem").to_path_buf()],
            tls_certificate_chain: Some(Path::new("/etc/probe/certs/leaf.pem").to_path_buf()),
            tls_private_key: Some(Path::new("/etc/probe/certs/leaf.key").to_path_buf()),
            tls_material_roots: roots.clone(),
            ..minimal_cli()
        })
        .expect("TLS material roots should parse");

        let TlsTerminationConfig::Static(tls) = config
            .tls
            .expect("TLS termination config should be present")
        else {
            panic!("static TLS termination should be preserved");
        };
        assert_eq!(tls.material_roots.as_slice(), roots.as_slice());
        assert_eq!(
            config
                .upstream_tls
                .expect("upstream TLS config should be present")
                .material_roots
                .as_slice(),
            tls.material_roots.as_slice()
        );
    }

    #[test]
    fn tls_material_roots_must_be_safe_absolute_roots() {
        for root in [
            Path::new("relative").to_path_buf(),
            Path::new("/").to_path_buf(),
            Path::new("/etc/probe/../tls").to_path_buf(),
        ] {
            let error = MitmProxyConfig::try_from(Cli {
                tls_material_roots: vec![root],
                ..minimal_cli()
            })
            .expect_err("invalid TLS material root must be rejected");

            assert!(matches!(error, MitmProxyError::InvalidConfig(_)));
        }

        let error = MitmProxyConfig::try_from(Cli {
            tls_material_roots: vec![
                Path::new("/etc/probe/tls").to_path_buf(),
                Path::new("/etc/probe/tls").to_path_buf(),
            ],
            ..minimal_cli()
        })
        .expect_err("duplicate TLS material roots must be rejected");

        assert!(matches!(error, MitmProxyError::InvalidConfig(_)));
    }

    #[test]
    fn application_protocol_policy_defaults_to_http1() {
        let config = MitmProxyConfig::try_from(minimal_cli()).expect("minimal config should parse");

        assert_eq!(
            config.application_protocols.protocols(),
            [ApplicationProtocol::Http1]
        );
    }

    #[test]
    fn application_protocol_policy_preserves_explicit_http1() {
        let config = MitmProxyConfig::try_from(Cli {
            alpn: vec![parse_application_protocol("http/1.1").expect("http1 ALPN should parse")],
            ..minimal_cli()
        })
        .expect("explicit http1 ALPN should parse");

        assert_eq!(
            config.application_protocols.protocols(),
            [ApplicationProtocol::Http1]
        );
    }

    #[test]
    fn parse_from_accepts_agent_forwarded_product_proxy_args()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = parse_from([
            "traffic-probe-mitm-proxy",
            "--listen",
            "127.0.0.1:15002",
            "--feed",
            "/tmp/probe/mitm/feed.jsonl",
            "--target-recovery",
            "linux-original-destination",
            "--request-direction",
            "outbound",
            "--upstream-tls",
            "--tls-material-root",
            "/tmp/probe/tls",
            "--tls-ca-certificate",
            "/tmp/probe/tls/mitm-ca.pem",
            "--tls-ca-private-key",
            "/tmp/probe/tls/mitm-ca.key",
        ])?;

        assert_eq!(config.listen, "127.0.0.1:15002".parse()?);
        assert_eq!(
            config.target_recovery,
            TargetRecovery::LinuxOriginalDestination
        );
        assert_eq!(config.request_direction, Direction::Outbound);
        assert!(config.upstream_tls.is_some());
        assert!(matches!(
            config.tls,
            Some(TlsTerminationConfig::DynamicCa(_))
        ));
        Ok(())
    }

    #[test]
    fn application_protocol_policy_rejects_unsupported_protocols() {
        let error = parse_application_protocol("h2")
            .expect_err("unsupported application protocol should be rejected");

        assert!(error.contains("unsupported application protocol"));
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
    fn upstream_dns_discovery_builds_resolver_config() {
        let config = MitmProxyConfig::try_from(Cli {
            upstream_dns_discovery: true,
            upstream_dns_default_port: Some(NonZeroU16::new(443).expect("non-zero port")),
            ..minimal_cli()
        })
        .expect("DNS discovery config should parse");

        assert_eq!(
            config.upstream_discovery,
            UpstreamDiscovery::Dns {
                default_port: NonZeroU16::new(443),
                allow_special_use_addresses: false
            }
        );
    }

    #[test]
    fn upstream_dns_special_use_policy_is_explicit() {
        let config = MitmProxyConfig::try_from(Cli {
            upstream_dns_discovery: true,
            upstream_dns_allow_special_use_addresses: true,
            ..minimal_cli()
        })
        .expect("DNS discovery config should parse");

        assert_eq!(
            config.upstream_discovery,
            UpstreamDiscovery::Dns {
                default_port: None,
                allow_special_use_addresses: true
            }
        );
    }

    #[test]
    fn upstream_dns_default_port_requires_discovery_mode() {
        for cli in [
            Cli {
                upstream_dns_default_port: Some(NonZeroU16::new(443).expect("non-zero port")),
                ..minimal_cli()
            },
            Cli {
                upstream_dns_allow_special_use_addresses: true,
                ..minimal_cli()
            },
        ] {
            let error = MitmProxyConfig::try_from(cli)
                .expect_err("dangling DNS discovery fields should be rejected");
            assert!(
                matches!(error, MitmProxyError::InvalidConfig(reason) if reason.contains("upstream_dns_discovery"))
            );
        }
    }

    #[test]
    fn upstream_dns_default_port_rejects_zero() {
        let error = parse_nonzero_u16("0").expect_err("zero DNS default port should be rejected");

        assert!(error.contains("non-zero"));
    }

    #[test]
    fn fixed_upstream_rejects_route_and_dns_discovery_combinations() {
        let route = parse_upstream_route("Example.Test=127.0.0.1:8443")
            .expect("route argument should parse");
        for cli in [
            Cli {
                upstream: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 8443))),
                upstream_routes: vec![route],
                ..minimal_cli()
            },
            Cli {
                upstream: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 8443))),
                upstream_dns_discovery: true,
                ..minimal_cli()
            },
        ] {
            let error =
                MitmProxyConfig::try_from(cli).expect_err("ambiguous upstream config must fail");
            assert!(
                matches!(error, MitmProxyError::InvalidConfig(reason) if reason.contains("cannot be combined"))
            );
        }
    }

    #[test]
    fn upstream_routes_build_route_table() {
        let route = parse_upstream_route("Example.Test=127.0.0.1:8443")
            .expect("route argument should parse");
        let wildcard_route = parse_upstream_route("*.Route.Example=127.0.0.1:9443")
            .expect("wildcard route argument should parse");
        let config = MitmProxyConfig::try_from(Cli {
            upstream_routes: vec![route, wildcard_route],
            ..minimal_cli()
        })
        .expect("route table should build");

        assert_eq!(
            config
                .upstream_routes
                .target_for_observed_authority(crate::authority::ObservedAuthority::from_parts(
                    None,
                    Some("example.test")
                ))
                .expect("route lookup should succeed"),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)))
        );
        assert_eq!(
            config
                .upstream_routes
                .target_for_observed_authority(crate::authority::ObservedAuthority::from_parts(
                    None,
                    Some("api.route.example")
                ))
                .expect("wildcard route lookup should succeed"),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9443)))
        );
    }

    #[test]
    fn upstream_routes_reject_invalid_arguments() {
        for value in [
            "missing-separator",
            "bad_host=127.0.0.1:8443",
            "ok=bad",
            "ok.example=127.0.0.1:0",
        ] {
            assert!(
                parse_upstream_route(value).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn upstream_routes_reject_duplicate_hosts() {
        let route =
            parse_upstream_route("example.test=127.0.0.1:8443").expect("first route should parse");
        let duplicate = parse_upstream_route("EXAMPLE.TEST=127.0.0.1:8444")
            .expect("duplicate route argument should parse before table validation");
        let error = MitmProxyConfig::try_from(Cli {
            upstream_routes: vec![route, duplicate],
            ..minimal_cli()
        })
        .expect_err("duplicate route hosts must be rejected");

        assert!(
            matches!(error, MitmProxyError::InvalidConfig(reason) if reason.contains("duplicate upstream route host"))
        );
    }

    #[test]
    fn upstream_socket_mark_accepts_hex_value() {
        let mark = parse_socket_mark("0x54500102").expect("hex socket mark should parse");

        assert_eq!(mark.get(), 0x5450_0102);
    }

    #[test]
    fn transparent_listen_flag_is_preserved() {
        let config = MitmProxyConfig::try_from(Cli {
            transparent_listen: true,
            ..minimal_cli()
        })
        .expect("transparent listen should parse");

        assert!(config.transparent_listen);
    }

    fn minimal_cli() -> Cli {
        Cli {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 15_001)),
            transparent_listen: false,
            feed: Path::new("/tmp/mitm-feed.jsonl").to_path_buf(),
            pid_file: None,
            upstream: None,
            upstream_routes: Vec::new(),
            upstream_dns_discovery: false,
            upstream_dns_default_port: None,
            upstream_dns_allow_special_use_addresses: false,
            upstream_tls: false,
            upstream_trust_anchor: Vec::new(),
            upstream_server_name: None,
            upstream_socket_mark: None,
            alpn: Vec::new(),
            tls_certificate_chain: None,
            tls_private_key: None,
            tls_ca_certificate: None,
            tls_ca_private_key: None,
            tls_material_roots: Vec::new(),
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

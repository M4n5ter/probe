use std::{
    fmt,
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::{AddressPort, FlowContext, TransportProtocol};

impl From<TcpEndpoint> for AddressPort {
    fn from(endpoint: TcpEndpoint) -> Self {
        Self {
            address: endpoint.address.to_string(),
            port: endpoint.port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TcpEndpoint {
    pub address: IpAddr,
    pub port: u16,
}

impl TcpEndpoint {
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self { address, port }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpConnection {
    pub local: TcpEndpoint,
    pub remote: TcpEndpoint,
}

impl TcpConnection {
    pub fn new(local: TcpEndpoint, remote: TcpEndpoint) -> Self {
        Self { local, remote }
    }

    pub fn from_flow_context(flow: &FlowContext) -> Result<Self, TcpConnectionFromFlowError> {
        if flow.protocol != TransportProtocol::Tcp {
            return Err(TcpConnectionFromFlowError::UnsupportedTransport {
                protocol: flow.protocol,
            });
        }
        Ok(Self::new(
            tcp_endpoint_from_address_port(&flow.local, "local")?,
            tcp_endpoint_from_address_port(&flow.remote, "remote")?,
        ))
    }
}

#[derive(Debug, Error)]
pub enum TcpConnectionFromFlowError {
    #[error("tcp connection requires TCP flow, got {protocol:?}")]
    UnsupportedTransport { protocol: TransportProtocol },

    #[error("cannot parse {label} address {value}: {source}")]
    InvalidEndpointAddress {
        label: &'static str,
        value: String,
        source: AddrParseError,
    },
}

fn tcp_endpoint_from_address_port(
    endpoint: &AddressPort,
    label: &'static str,
) -> Result<TcpEndpoint, TcpConnectionFromFlowError> {
    let address = endpoint.address.parse::<IpAddr>().map_err(|source| {
        TcpConnectionFromFlowError::InvalidEndpointAddress {
            label,
            value: endpoint.address.clone(),
            source,
        }
    })?;
    Ok(TcpEndpoint::new(address, endpoint.port))
}

pub fn socket_addr_points_to_listener(target: SocketAddr, listener: SocketAddr) -> bool {
    if target.port() != listener.port() {
        return false;
    }
    let target_ip = normalized_ip_address(target.ip());
    let listener_ip = normalized_ip_address(listener.ip());
    target_ip == listener_ip
        || is_unspecified(target_ip)
        || is_loopback(target_ip) && is_loopback(listener_ip)
        || is_unspecified(listener_ip) && is_local_listener_address(target_ip)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UpstreamRouteHost(String);

impl UpstreamRouteHost {
    pub fn parse(host: impl AsRef<str>) -> Result<Self, UpstreamRouteError> {
        let host = host.as_ref().trim();
        if host.is_empty() {
            return Err(UpstreamRouteError::EmptyHost);
        }
        validate_dns_route_host(host)?;
        Ok(Self(host.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UpstreamRouteHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for UpstreamRouteHost {
    type Err = UpstreamRouteError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UpstreamRouteHostPattern {
    Exact(UpstreamRouteHost),
    WildcardSuffix(UpstreamRouteHost),
}

impl UpstreamRouteHostPattern {
    pub fn parse(pattern: impl AsRef<str>) -> Result<Self, UpstreamRouteError> {
        let pattern = pattern.as_ref().trim();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return Ok(Self::WildcardSuffix(UpstreamRouteHost::parse(suffix)?));
        }
        if pattern.starts_with('*') {
            return Err(invalid_route_host(
                pattern,
                "wildcard host patterns must use '*.suffix'",
            ));
        }
        Ok(Self::Exact(UpstreamRouteHost::parse(pattern)?))
    }

    pub fn matches(&self, host: &UpstreamRouteHost) -> bool {
        match self {
            Self::Exact(pattern) => pattern == host,
            Self::WildcardSuffix(suffix) => host_matches_wildcard_suffix(host, suffix),
        }
    }
}

impl fmt::Display for UpstreamRouteHostPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(host) => write!(formatter, "{host}"),
            Self::WildcardSuffix(suffix) => write!(formatter, "*.{suffix}"),
        }
    }
}

impl FromStr for UpstreamRouteHostPattern {
    type Err = UpstreamRouteError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRoute {
    host: UpstreamRouteHostPattern,
    target: SocketAddr,
}

impl UpstreamRoute {
    pub fn new(host: impl AsRef<str>, target: SocketAddr) -> Result<Self, UpstreamRouteError> {
        Self::from_parts(UpstreamRouteHostPattern::parse(host)?, target)
    }

    pub fn from_parts(
        host: UpstreamRouteHostPattern,
        target: SocketAddr,
    ) -> Result<Self, UpstreamRouteError> {
        if target.port() == 0 {
            return Err(UpstreamRouteError::ZeroTargetPort);
        }
        Ok(Self { host, target })
    }

    pub fn parse_cli_value(value: &str) -> Result<Self, UpstreamRouteError> {
        let (host, target) = value
            .split_once('=')
            .ok_or(UpstreamRouteError::InvalidRouteValue)?;
        Self::new(host, Self::parse_target(target)?)
    }

    pub fn parse_target(value: &str) -> Result<SocketAddr, UpstreamRouteError> {
        let target = value
            .parse::<SocketAddr>()
            .map_err(|_| UpstreamRouteError::InvalidTarget)?;
        if target.port() == 0 {
            return Err(UpstreamRouteError::ZeroTargetPort);
        }
        Ok(target)
    }

    pub fn host_pattern(&self) -> &UpstreamRouteHostPattern {
        &self.host
    }

    pub fn target(&self) -> SocketAddr {
        self.target
    }

    pub fn cli_value(&self) -> String {
        format!("{}={}", self.host, self.target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpstreamRouteError {
    #[error("upstream route host must not be empty")]
    EmptyHost,
    #[error("invalid upstream route host {host:?}: {reason}")]
    InvalidHost { host: String, reason: &'static str },
    #[error("upstream route value must use host=ip:port")]
    InvalidRouteValue,
    #[error("upstream route target must be an IP socket address")]
    InvalidTarget,
    #[error("upstream route target port must be non-zero")]
    ZeroTargetPort,
}

fn validate_dns_route_host(host: &str) -> Result<(), UpstreamRouteError> {
    if host.len() > 253 {
        return Err(invalid_route_host(
            host,
            "host name must not exceed 253 bytes",
        ));
    }
    for label in host.split('.') {
        validate_dns_route_label(host, label)?;
    }
    Ok(())
}

fn validate_dns_route_label(host: &str, label: &str) -> Result<(), UpstreamRouteError> {
    if label.is_empty() {
        return Err(invalid_route_host(host, "host labels must not be empty"));
    }
    if label.len() > 63 {
        return Err(invalid_route_host(
            host,
            "host labels must not exceed 63 bytes",
        ));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(invalid_route_host(
            host,
            "host labels must not start or end with '-'",
        ));
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(invalid_route_host(
            host,
            "host labels may only contain ASCII letters, digits, or '-'",
        ));
    }
    Ok(())
}

fn invalid_route_host(host: &str, reason: &'static str) -> UpstreamRouteError {
    UpstreamRouteError::InvalidHost {
        host: host.to_string(),
        reason,
    }
}

fn host_matches_wildcard_suffix(host: &UpstreamRouteHost, suffix: &UpstreamRouteHost) -> bool {
    let host = host.as_str();
    let suffix = suffix.as_str();
    host.len() > suffix.len()
        && host.ends_with(suffix)
        && host
            .as_bytes()
            .get(host.len() - suffix.len() - 1)
            .is_some_and(|byte| *byte == b'.')
}

fn normalized_ip_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
    }
}

fn is_local_listener_address(address: IpAddr) -> bool {
    is_loopback(address) || is_unspecified(address)
}

fn is_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address.is_loopback(),
    }
}

fn is_unspecified(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_unspecified(),
        IpAddr::V6(address) => address.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AddressPort, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, TransportProtocol,
    };

    #[test]
    fn upstream_route_host_normalization_is_case_insensitive_and_strict() {
        assert_eq!(
            UpstreamRouteHost::parse("Example-1.Test")
                .expect("valid route host should normalize")
                .as_str(),
            "example-1.test"
        );

        for host in ["", "-bad.test", "bad-.test", "bad..test", "bad_test"] {
            assert!(
                UpstreamRouteHost::parse(host).is_err(),
                "{host:?} should be rejected"
            );
        }
    }

    #[test]
    fn upstream_route_host_pattern_supports_wildcard_suffixes() {
        let pattern = UpstreamRouteHostPattern::parse("*.Example.Test")
            .expect("wildcard route pattern should parse");
        let child = UpstreamRouteHost::parse("api.example.test").expect("child host");
        let nested = UpstreamRouteHost::parse("v1.api.example.test").expect("nested host");
        let apex = UpstreamRouteHost::parse("example.test").expect("apex host");

        assert_eq!(pattern.to_string(), "*.example.test");
        assert!(pattern.matches(&child));
        assert!(pattern.matches(&nested));
        assert!(!pattern.matches(&apex));
    }

    #[test]
    fn upstream_route_host_pattern_rejects_bare_wildcard() {
        let error = UpstreamRouteHostPattern::parse("*")
            .expect_err("bare wildcard route pattern must be rejected");

        assert!(error.to_string().contains("*.suffix"));
    }

    #[test]
    fn upstream_route_rejects_zero_target_port() {
        let error = UpstreamRoute::parse_cli_value("example.test=127.0.0.1:0")
            .expect_err("zero target port must be rejected");

        assert_eq!(error, UpstreamRouteError::ZeroTargetPort);
    }

    #[test]
    fn socket_target_detects_listener_self_references() {
        for (target, listener) in [
            ("127.0.0.1:15002", "127.0.0.1:15002"),
            ("127.0.0.2:15002", "127.0.0.1:15002"),
            ("0.0.0.0:15002", "127.0.0.1:15002"),
            ("[::]:15002", "[::1]:15002"),
            ("127.0.0.1:15002", "0.0.0.0:15002"),
            ("[::1]:15002", "[::]:15002"),
        ] {
            assert!(
                socket_addr_points_to_listener(
                    target.parse().expect("target"),
                    listener.parse().expect("listener")
                ),
                "{target} should point at {listener}"
            );
        }

        assert!(!socket_addr_points_to_listener(
            "127.0.0.1:15003".parse().expect("target"),
            "127.0.0.1:15002".parse().expect("listener")
        ));
    }

    #[test]
    fn tcp_connection_from_flow_context_parses_tcp_ip_endpoints() {
        let flow = tcp_flow("192.0.2.10", 41000, "198.51.100.20", 443);

        assert_eq!(
            TcpConnection::from_flow_context(&flow).expect("TCP flow should parse"),
            TcpConnection::new(
                TcpEndpoint::new("192.0.2.10".parse().expect("local IP"), 41000),
                TcpEndpoint::new("198.51.100.20".parse().expect("remote IP"), 443),
            )
        );
    }

    #[test]
    fn tcp_connection_from_flow_context_rejects_non_tcp_flow() {
        let mut flow = tcp_flow("192.0.2.10", 41000, "198.51.100.20", 443);
        flow.protocol = TransportProtocol::Udp;

        assert!(matches!(
            TcpConnection::from_flow_context(&flow),
            Err(TcpConnectionFromFlowError::UnsupportedTransport {
                protocol: TransportProtocol::Udp
            })
        ));
    }

    #[test]
    fn tcp_connection_from_flow_context_rejects_invalid_endpoint_address() {
        let flow = tcp_flow("not-an-ip", 41000, "198.51.100.20", 443);

        assert!(matches!(
            TcpConnection::from_flow_context(&flow),
            Err(TcpConnectionFromFlowError::InvalidEndpointAddress {
                label: "local",
                value,
                ..
            }) if value == "not-an-ip"
        ));
    }

    fn tcp_flow(
        local_address: &str,
        local_port: u16,
        remote_address: &str,
        remote_port: u16,
    ) -> FlowContext {
        FlowContext {
            id: FlowIdentity("flow-1".to_string()),
            process: ProcessContext {
                identity: ProcessIdentity {
                    pid: 42,
                    tgid: 42,
                    start_time_ticks: 1,
                    boot_id: "boot".to_string(),
                    exe_path: "/usr/bin/app".to_string(),
                    cmdline_hash: "hash".to_string(),
                    uid: 1000,
                    gid: 1000,
                    cgroup: None,
                    systemd_service: None,
                    container_id: None,
                    runtime_hint: None,
                },
                name: "app".to_string(),
                cmdline: vec!["app".to_string()],
            },
            local: AddressPort {
                address: local_address.to_string(),
                port: local_port,
            },
            remote: AddressPort {
                address: remote_address.to_string(),
                port: remote_port,
            },
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

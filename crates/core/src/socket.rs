use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::AddressPort;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRoute {
    host: UpstreamRouteHost,
    target: SocketAddr,
}

impl UpstreamRoute {
    pub fn new(host: impl AsRef<str>, target: SocketAddr) -> Result<Self, UpstreamRouteError> {
        if target.port() == 0 {
            return Err(UpstreamRouteError::ZeroTargetPort);
        }
        Ok(Self {
            host: UpstreamRouteHost::parse(host)?,
            target,
        })
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

    pub fn host(&self) -> &UpstreamRouteHost {
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
}

use std::{
    collections::BTreeMap,
    net::{SocketAddr, ToSocketAddrs},
    num::NonZeroU16,
};

use probe_core::{UpstreamRoute, UpstreamRouteHost, UpstreamRouteHostPattern};

use crate::{MitmProxyError, authority::ObservedAuthority, error::io_error};

pub type UpstreamTargetRoute = UpstreamRoute;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UpstreamDiscovery {
    #[default]
    Disabled,
    Dns {
        default_port: Option<NonZeroU16>,
        allow_special_use_addresses: bool,
    },
}

impl UpstreamDiscovery {
    pub(crate) fn is_enabled(self) -> bool {
        matches!(self, Self::Dns { .. })
    }

    pub(crate) fn default_port(self) -> Option<NonZeroU16> {
        match self {
            Self::Disabled => None,
            Self::Dns { default_port, .. } => default_port,
        }
    }

    pub(crate) fn allow_special_use_addresses(self) -> bool {
        match self {
            Self::Disabled => false,
            Self::Dns {
                allow_special_use_addresses,
                ..
            } => allow_special_use_addresses,
        }
    }
}

const MAX_DNS_UPSTREAM_CANDIDATES: usize = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpstreamTargetRoutes {
    routes: BTreeMap<UpstreamRouteHostPattern, SocketAddr>,
}

impl UpstreamTargetRoutes {
    pub fn from_routes(
        routes: impl IntoIterator<Item = UpstreamTargetRoute>,
    ) -> Result<Self, MitmProxyError> {
        let mut normalized = BTreeMap::new();
        for route in routes {
            let host = route.host_pattern().clone();
            let target = route.target();
            if normalized.insert(host.clone(), target).is_some() {
                return Err(MitmProxyError::InvalidConfig(format!(
                    "duplicate upstream route host {host}"
                )));
            }
        }
        Ok(Self { routes: normalized })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&UpstreamRouteHostPattern, SocketAddr)> {
        self.routes.iter().map(|(host, target)| (host, *target))
    }

    pub(crate) fn target_for_observed_authority(
        &self,
        authority: ObservedAuthority<'_>,
    ) -> Result<Option<SocketAddr>, MitmProxyError> {
        let Some(host) = authority.candidates().resolve_observed()? else {
            return Ok(None);
        };
        let Ok(host) = UpstreamRouteHost::parse(host) else {
            return Ok(None);
        };
        if let Some(target) = self
            .routes
            .get(&UpstreamRouteHostPattern::Exact(host.clone()))
        {
            return Ok(Some(*target));
        }
        Ok(self
            .routes
            .iter()
            .filter_map(|(pattern, target)| {
                let UpstreamRouteHostPattern::WildcardSuffix(suffix) = pattern else {
                    return None;
                };
                pattern
                    .matches(&host)
                    .then_some((suffix.as_str().len(), *target))
            })
            .max_by_key(|(suffix_len, _)| *suffix_len)
            .map(|(_, target)| target))
    }
}

pub(crate) fn upstream_targets_for_request(
    recovered_target: SocketAddr,
    authority: ObservedAuthority<'_>,
    routes: &UpstreamTargetRoutes,
    discovery: UpstreamDiscovery,
) -> Result<Vec<SocketAddr>, MitmProxyError> {
    if let Some(target) = routes.target_for_observed_authority(authority)? {
        return Ok(vec![target]);
    }
    if let Some(targets) = dns_upstream_targets_for_request(recovered_target, authority, discovery)?
    {
        return Ok(targets);
    }
    Ok(vec![recovered_target])
}

fn dns_upstream_targets_for_request(
    recovered_target: SocketAddr,
    authority: ObservedAuthority<'_>,
    discovery: UpstreamDiscovery,
) -> Result<Option<Vec<SocketAddr>>, MitmProxyError> {
    if !discovery.is_enabled() {
        return Ok(None);
    }
    let Some(host) = authority.candidates().resolve_observed()? else {
        return Ok(None);
    };
    let port = discovery
        .default_port()
        .map_or_else(|| recovered_target.port(), |port| port.get());
    if port == 0 {
        return Ok(None);
    }
    let mut targets = Vec::new();
    for target in (host, port)
        .to_socket_addrs()
        .map_err(io_error("resolve MITM proxy upstream DNS target"))?
    {
        if !discovery.allow_special_use_addresses() && is_special_use_address(target) {
            continue;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
        if targets.len() >= MAX_DNS_UPSTREAM_CANDIDATES {
            break;
        }
    }
    if targets.is_empty() {
        return Err(MitmProxyError::Http(format!(
            "upstream DNS discovery returned no allowed addresses for {host}:{port}"
        )));
    }
    Ok(Some(targets))
}

fn is_special_use_address(target: SocketAddr) -> bool {
    match target.ip() {
        std::net::IpAddr::V4(address) => {
            let address = u32::from_be_bytes(address.octets());
            IPV4_SPECIAL_USE_PREFIXES
                .iter()
                .any(|(prefix, prefix_len)| matches_ipv4_prefix(address, *prefix, *prefix_len))
        }
        std::net::IpAddr::V6(address) => {
            let address = u128::from_be_bytes(address.octets());
            IPV6_SPECIAL_USE_PREFIXES
                .iter()
                .any(|(prefix, prefix_len)| matches_ipv6_prefix(address, *prefix, *prefix_len))
        }
    }
}

const IPV4_SPECIAL_USE_PREFIXES: &[(u32, u8)] = &[
    (ipv4_prefix([0, 0, 0, 0]), 8),
    (ipv4_prefix([10, 0, 0, 0]), 8),
    (ipv4_prefix([100, 64, 0, 0]), 10),
    (ipv4_prefix([127, 0, 0, 0]), 8),
    (ipv4_prefix([169, 254, 0, 0]), 16),
    (ipv4_prefix([172, 16, 0, 0]), 12),
    (ipv4_prefix([192, 0, 0, 0]), 24),
    (ipv4_prefix([192, 0, 2, 0]), 24),
    (ipv4_prefix([192, 31, 196, 0]), 24),
    (ipv4_prefix([192, 52, 193, 0]), 24),
    (ipv4_prefix([192, 88, 99, 0]), 24),
    (ipv4_prefix([192, 168, 0, 0]), 16),
    (ipv4_prefix([192, 175, 48, 0]), 24),
    (ipv4_prefix([198, 18, 0, 0]), 15),
    (ipv4_prefix([198, 51, 100, 0]), 24),
    (ipv4_prefix([203, 0, 113, 0]), 24),
    (ipv4_prefix([224, 0, 0, 0]), 4),
    (ipv4_prefix([240, 0, 0, 0]), 4),
];

const IPV6_SPECIAL_USE_PREFIXES: &[(u128, u8)] = &[
    (ipv6_prefix([0, 0, 0, 0, 0, 0, 0, 0]), 128),
    (ipv6_prefix([0, 0, 0, 0, 0, 0, 0, 1]), 128),
    (ipv6_prefix([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96),
    (ipv6_prefix([0x0064, 0xff9b, 0, 0, 0, 0, 0, 0]), 96),
    (ipv6_prefix([0x0064, 0xff9b, 0x0001, 0, 0, 0, 0, 0]), 48),
    (ipv6_prefix([0x0100, 0, 0, 0, 0, 0, 0, 0]), 64),
    (ipv6_prefix([0x0100, 0, 0, 0x0001, 0, 0, 0, 0]), 64),
    (ipv6_prefix([0x2001, 0, 0, 0, 0, 0, 0, 0]), 23),
    (ipv6_prefix([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0]), 32),
    (ipv6_prefix([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16),
    (ipv6_prefix([0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0]), 48),
    (ipv6_prefix([0x3fff, 0, 0, 0, 0, 0, 0, 0]), 20),
    (ipv6_prefix([0x5f00, 0, 0, 0, 0, 0, 0, 0]), 16),
    (ipv6_prefix([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7),
    (ipv6_prefix([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10),
    (ipv6_prefix([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8),
];

const fn ipv4_prefix(octets: [u8; 4]) -> u32 {
    u32::from_be_bytes(octets)
}

const fn ipv6_prefix(segments: [u16; 8]) -> u128 {
    ((segments[0] as u128) << 112)
        | ((segments[1] as u128) << 96)
        | ((segments[2] as u128) << 80)
        | ((segments[3] as u128) << 64)
        | ((segments[4] as u128) << 48)
        | ((segments[5] as u128) << 32)
        | ((segments[6] as u128) << 16)
        | segments[7] as u128
}

fn matches_ipv4_prefix(address: u32, prefix: u32, prefix_len: u8) -> bool {
    let mask = u32::MAX << (32 - prefix_len);
    (address & mask) == (prefix & mask)
}

fn matches_ipv6_prefix(address: u128, prefix: u128, prefix_len: u8) -> bool {
    let mask = u128::MAX << (128 - prefix_len);
    (address & mask) == (prefix & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_match_observed_http_host_case_insensitively() -> Result<(), Box<dyn std::error::Error>>
    {
        let target = "127.0.0.1:8443".parse()?;
        let routes =
            UpstreamTargetRoutes::from_routes([UpstreamTargetRoute::new("Example.Test", target)?])?;

        assert_eq!(
            routes.target_for_observed_authority(observed_authority(None, Some("example.test")))?,
            Some(target)
        );
        Ok(())
    }

    #[test]
    fn routes_treat_unsupported_observed_authority_as_miss()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = "127.0.0.1:8443".parse()?;
        let routes =
            UpstreamTargetRoutes::from_routes([UpstreamTargetRoute::new("Example.Test", target)?])?;

        assert_eq!(
            routes.target_for_observed_authority(observed_authority(None, Some("::1")))?,
            None
        );
        Ok(())
    }

    #[test]
    fn routes_match_wildcard_suffix_hosts() -> Result<(), Box<dyn std::error::Error>> {
        let target = "127.0.0.1:8443".parse()?;
        let routes = UpstreamTargetRoutes::from_routes([UpstreamTargetRoute::new(
            "*.Example.Test",
            target,
        )?])?;

        assert_eq!(
            routes.target_for_observed_authority(observed_authority(
                None,
                Some("api.example.test")
            ))?,
            Some(target)
        );
        assert_eq!(
            routes.target_for_observed_authority(observed_authority(None, Some("example.test")))?,
            None
        );
        Ok(())
    }

    #[test]
    fn exact_routes_override_wildcard_suffix_routes() -> Result<(), Box<dyn std::error::Error>> {
        let wildcard_target = "127.0.0.1:8443".parse()?;
        let exact_target = "127.0.0.1:9443".parse()?;
        let routes = UpstreamTargetRoutes::from_routes([
            UpstreamTargetRoute::new("*.Example.Test", wildcard_target)?,
            UpstreamTargetRoute::new("Api.Example.Test", exact_target)?,
        ])?;

        assert_eq!(
            routes.target_for_observed_authority(observed_authority(
                None,
                Some("api.example.test")
            ))?,
            Some(exact_target)
        );
        Ok(())
    }

    #[test]
    fn longest_wildcard_suffix_wins() -> Result<(), Box<dyn std::error::Error>> {
        let broad_target = "127.0.0.1:8443".parse()?;
        let narrow_target = "127.0.0.1:9443".parse()?;
        let routes = UpstreamTargetRoutes::from_routes([
            UpstreamTargetRoute::new("*.Example.Test", broad_target)?,
            UpstreamTargetRoute::new("*.Api.Example.Test", narrow_target)?,
        ])?;

        assert_eq!(
            routes.target_for_observed_authority(observed_authority(
                None,
                Some("v1.api.example.test")
            ))?,
            Some(narrow_target)
        );
        Ok(())
    }

    #[test]
    fn routes_reject_duplicate_normalized_hosts() -> Result<(), Box<dyn std::error::Error>> {
        let target = "127.0.0.1:8443".parse()?;
        let error = UpstreamTargetRoutes::from_routes([
            UpstreamTargetRoute::new("example.test", target)?,
            UpstreamTargetRoute::new("EXAMPLE.TEST", target)?,
        ])
        .expect_err("duplicate route hosts must be rejected");

        assert!(error.to_string().contains("duplicate upstream route host"));
        Ok(())
    }

    #[test]
    fn target_selection_falls_back_to_recovered_target_on_route_miss()
    -> Result<(), Box<dyn std::error::Error>> {
        let route_target = "127.0.0.1:8443".parse()?;
        let recovered_target = "127.0.0.1:9443".parse()?;
        let routes = UpstreamTargetRoutes::from_routes([UpstreamTargetRoute::new(
            "Route.Example",
            route_target,
        )?])?;

        assert_eq!(
            upstream_targets_for_request(
                recovered_target,
                observed_authority(None, Some("::1")),
                &routes,
                UpstreamDiscovery::Disabled
            )?,
            vec![recovered_target]
        );
        Ok(())
    }

    #[test]
    fn dns_discovery_rejects_special_use_addresses_by_default()
    -> Result<(), Box<dyn std::error::Error>> {
        let error = upstream_targets_for_request(
            "203.0.113.10:443".parse()?,
            observed_authority(None, Some("127.0.0.1")),
            &UpstreamTargetRoutes::default(),
            UpstreamDiscovery::Dns {
                default_port: std::num::NonZeroU16::new(443),
                allow_special_use_addresses: false,
            },
        )
        .expect_err("loopback target should be rejected by default");

        assert!(error.to_string().contains("no allowed addresses"));
        Ok(())
    }

    #[test]
    fn special_use_address_policy_covers_sensitive_ranges() -> Result<(), Box<dyn std::error::Error>>
    {
        for target in [
            "0.0.0.0:443",
            "10.0.0.1:443",
            "100.64.0.1:443",
            "127.0.0.1:443",
            "169.254.1.1:443",
            "172.16.0.1:443",
            "192.0.0.1:443",
            "192.0.2.1:443",
            "192.168.0.1:443",
            "198.18.0.1:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
            "[::]:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "[::ffff:93.184.216.34]:443",
            "[64:ff9b::a00:1]:443",
            "[64:ff9b:1::a00:1]:443",
            "[100::1]:443",
            "[100:0:0:1::1]:443",
            "[2001::1]:443",
            "[2001:2::1]:443",
            "[2001:db8::1]:443",
            "[2002::a00:1]:443",
            "[2620:4f:8000::1]:443",
            "[3fff::1]:443",
            "[5f00::1]:443",
            "[fc00::1]:443",
            "[fe80::1]:443",
            "[ff02::1]:443",
        ] {
            assert!(
                is_special_use_address(target.parse()?),
                "{target} should be blocked"
            );
        }

        for target in [
            "93.184.216.34:443",
            "[2606:2800:220:1:248:1893:25c8:1946]:443",
        ] {
            assert!(
                !is_special_use_address(target.parse()?),
                "{target} should be allowed"
            );
        }
        Ok(())
    }

    fn observed_authority<'a>(
        downstream_tls_server_name: Option<&'a str>,
        http_host: Option<&'a str>,
    ) -> ObservedAuthority<'a> {
        ObservedAuthority::from_parts(downstream_tls_server_name, http_host)
    }
}

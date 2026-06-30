use std::{collections::BTreeMap, net::SocketAddr};

use probe_core::{UpstreamRoute, UpstreamRouteHost, UpstreamRouteHostPattern};

use crate::{MitmProxyError, authority::ObservedAuthority};

pub type UpstreamTargetRoute = UpstreamRoute;

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

    fn observed_authority<'a>(
        downstream_tls_server_name: Option<&'a str>,
        http_host: Option<&'a str>,
    ) -> ObservedAuthority<'a> {
        ObservedAuthority::from_parts(downstream_tls_server_name, http_host)
    }
}

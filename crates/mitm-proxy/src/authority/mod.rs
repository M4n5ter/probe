use crate::{MitmProxyError, http::HttpMessage};

#[derive(Clone, Copy, Debug)]
pub(crate) struct ObservedAuthority<'a> {
    downstream_tls_server_name: Option<&'a str>,
    http_host: Option<&'a str>,
}

impl<'a> ObservedAuthority<'a> {
    pub(crate) fn from_parts(
        downstream_tls_server_name: Option<&'a str>,
        http_host: Option<&'a str>,
    ) -> Self {
        Self {
            downstream_tls_server_name,
            http_host,
        }
    }

    pub(crate) fn from_request(
        downstream_tls_server_name: Option<&'a str>,
        request: &'a HttpMessage,
        include_http_host: bool,
    ) -> Result<Self, MitmProxyError> {
        let http_host = if include_http_host {
            request.authority()?
        } else {
            None
        };
        Ok(Self::from_parts(downstream_tls_server_name, http_host))
    }

    pub(crate) fn candidates(self) -> UpstreamAuthorityCandidates<'a> {
        UpstreamAuthorityCandidates::observed(self.downstream_tls_server_name, self.http_host)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UpstreamAuthorityCandidates<'a> {
    configured_server_name: Option<&'a str>,
    downstream_tls_server_name: Option<&'a str>,
    http_host: Option<&'a str>,
}

impl<'a> UpstreamAuthorityCandidates<'a> {
    pub(crate) fn observed(
        downstream_tls_server_name: Option<&'a str>,
        http_host: Option<&'a str>,
    ) -> Self {
        Self {
            downstream_tls_server_name,
            http_host,
            ..Self::default()
        }
    }

    pub(crate) fn with_configured_server_name(
        mut self,
        configured_server_name: Option<&'a str>,
    ) -> Self {
        self.configured_server_name = configured_server_name;
        self
    }

    pub(crate) fn resolve_required(self) -> Result<&'a str, MitmProxyError> {
        self.resolve()?.ok_or_else(|| {
            MitmProxyError::Tls(
                "upstream TLS requires a configured server name, downstream TLS SNI, or a single valid HTTP Host header".to_string(),
            )
        })
    }

    pub(crate) fn resolve_observed(self) -> Result<Option<&'a str>, MitmProxyError> {
        Self {
            configured_server_name: None,
            ..self
        }
        .resolve()
    }

    fn resolve(self) -> Result<Option<&'a str>, MitmProxyError> {
        self.ordered_candidates()
            .into_iter()
            .flatten()
            .try_fold(None, |selected, candidate| {
                selected_name_or_error(selected, candidate).map(Some)
            })
            .map(|selected| selected.map(|candidate| candidate.name))
    }

    fn ordered_candidates(self) -> [Option<UpstreamAuthorityCandidate<'a>>; 3] {
        [
            self.configured_server_name
                .map(|name| UpstreamAuthorityCandidate {
                    label: "configured upstream TLS server name",
                    name,
                }),
            self.downstream_tls_server_name
                .map(|name| UpstreamAuthorityCandidate {
                    label: "downstream TLS SNI",
                    name,
                }),
            self.http_host.map(|name| UpstreamAuthorityCandidate {
                label: "HTTP Host",
                name,
            }),
        ]
    }
}

#[derive(Clone, Copy)]
struct UpstreamAuthorityCandidate<'a> {
    label: &'static str,
    name: &'a str,
}

fn selected_name_or_error<'a>(
    selected: Option<UpstreamAuthorityCandidate<'a>>,
    candidate: UpstreamAuthorityCandidate<'a>,
) -> Result<UpstreamAuthorityCandidate<'a>, MitmProxyError> {
    let Some(selected) = selected else {
        return Ok(candidate);
    };
    if selected.name.eq_ignore_ascii_case(candidate.name) {
        return Ok(selected);
    }
    Err(MitmProxyError::Tls(format!(
        "{} {:?} does not match {} {:?}",
        candidate.label, candidate.name, selected.label, selected.name
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_authority_accepts_matching_sni_and_host() {
        let selected =
            UpstreamAuthorityCandidates::observed(Some("Example.Test"), Some("example.test"))
                .resolve_observed()
                .expect("matching names should resolve");

        assert_eq!(selected, Some("Example.Test"));
    }

    #[test]
    fn observed_authority_rejects_mismatched_sni_and_host() {
        let error = UpstreamAuthorityCandidates::observed(Some("sni.test"), Some("host.test"))
            .resolve_observed()
            .expect_err("mismatched observed names must fail closed");

        assert!(error.to_string().contains("does not match"));
    }
}

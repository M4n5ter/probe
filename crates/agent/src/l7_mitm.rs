use std::{
    io,
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use probe_config::{
    AgentConfig, TransparentInterceptionMitmBackendIntent,
    TransparentInterceptionMitmBackendReadinessProbeIntent,
};
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

pub(crate) struct L7MitmRuntime {
    capability: CapabilityState,
}

impl L7MitmRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }
}

pub(crate) fn resolve(config: &AgentConfig) -> L7MitmRuntime {
    resolve_with_probe(config, connect_tcp)
}

fn resolve_with_probe(
    config: &AgentConfig,
    tcp_probe: impl FnOnce(SocketAddr, Duration) -> io::Result<()>,
) -> L7MitmRuntime {
    let interception = &config.enforcement.interception;
    if !interception.strategy.is_mitm() {
        return unavailable(
            "L7 MITM backend is not configured; select a MITM interception strategy to require it",
        );
    }
    if let Err(error) = config.validate_l7_mitm_contract() {
        return unavailable(format!("L7 MITM backend contract is invalid: {error}"));
    }
    if let Err(error) = probe_external_backend(config, tcp_probe) {
        return unavailable(error);
    }

    L7MitmRuntime {
        capability: CapabilityState {
            kind: CapabilityKind::L7Mitm,
            mode: RuntimeMode::Available,
            reason: Some(
                "external selector-scoped L7 MITM backend contract is configured and its configured readiness endpoint is reachable; agent redirects matching flows to the configured listener port but does not manage the L7 proxy process or prove per-family transparent listener behavior yet"
                    .to_string(),
            ),
        },
    }
}

fn connect_tcp(target: SocketAddr, timeout: Duration) -> io::Result<()> {
    TcpStream::connect_timeout(&target, timeout).map(|_| ())
}

fn probe_external_backend(
    config: &AgentConfig,
    tcp_probe: impl FnOnce(SocketAddr, Duration) -> io::Result<()>,
) -> Result<(), String> {
    let readiness_probe = config
        .enforcement
        .interception
        .mitm_backend_intent()
        .map_err(|violations| {
            violations
                .into_iter()
                .map(|violation| format!("{}: {}", violation.field(), violation.reason()))
                .collect::<Vec<_>>()
                .join("; ")
        })?;
    let TransparentInterceptionMitmBackendIntent::External { readiness_probe } = readiness_probe
    else {
        return Err("external L7 MITM backend contract is missing".to_string());
    };
    let TransparentInterceptionMitmBackendReadinessProbeIntent::TcpConnect { target, timeout_ms } =
        readiness_probe;
    tcp_probe(target, Duration::from_millis(timeout_ms)).map_err(|error| {
        format!("external L7 MITM backend readiness probe failed for {target}: {error}")
    })?;
    Ok(())
}

fn unavailable(reason: impl Into<String>) -> L7MitmRuntime {
    L7MitmRuntime {
        capability: CapabilityState::unavailable(CapabilityKind::L7Mitm, reason),
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use probe_config::{
        AgentConfig, TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::RuntimeMode;

    use super::*;

    #[test]
    fn failed_readiness_probe_reports_l7_mitm_unavailable() {
        let config = external_mitm_config("127.0.0.1:15002");

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            Err(io::Error::new(ErrorKind::ConnectionRefused, "closed"))
        });

        let capability = runtime.capability();
        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        assert!(
            capability
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("readiness probe failed")),
            "{capability:?}"
        );
    }

    fn external_mitm_config(target: &str) -> AgentConfig {
        let mut config = AgentConfig::default();
        let target: SocketAddr = target
            .parse()
            .expect("test MITM readiness target should parse");
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(target.port());
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::External;
        config
            .enforcement
            .interception
            .mitm
            .backend_readiness_probe
            .target = Some(target.to_string());
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/sssa/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/sssa/mitm-ca.key".into(),
            },
        ];
        config
    }
}

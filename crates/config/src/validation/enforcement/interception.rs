use std::net::{IpAddr, SocketAddr};

use crate::{
    ConfigViolation, EnforcementInterceptionConfig,
    MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
    MAX_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
    MIN_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
    MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, MIN_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
};

pub(super) fn validate(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if interception.proxy.mode == TransparentInterceptionProxyModeConfig::ManagedTcpRelay
        && interception.strategy != TransparentInterceptionStrategyConfig::InboundTproxy
    {
        violations.push(ConfigViolation {
            field: "enforcement.interception.proxy.mode".to_string(),
            reason: "managed TCP relay proxy mode is only valid for inbound TPROXY interception"
                .to_string(),
        });
    }

    validate_health_probe(interception, violations);

    if !interception.strategy.is_enabled() {
        return;
    }

    match interception.proxy.listen_port {
        Some(0) | None => violations.push(ConfigViolation {
            field: "enforcement.interception.proxy.listen_port".to_string(),
            reason: "transparent interception requires a non-zero proxy listen port".to_string(),
        }),
        Some(_) => {}
    }
}

fn validate_health_probe(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    let health_probe = &interception.proxy.health_probe;
    let Some(target) = &health_probe.target else {
        return;
    };
    if interception.strategy == TransparentInterceptionStrategyConfig::None {
        violations.push(ConfigViolation {
            field: "enforcement.interception.proxy.health_probe.target".to_string(),
            reason: "transparent proxy health probe requires an enabled interception strategy"
                .to_string(),
        });
    }
    if interception.strategy == TransparentInterceptionStrategyConfig::OutboundMitm {
        violations.push(ConfigViolation {
            field: "enforcement.interception.proxy.health_probe.target".to_string(),
            reason:
                "transparent proxy health probe is currently executable for inbound TPROXY only"
                    .to_string(),
        });
    }
    let parsed_target = match target.parse::<SocketAddr>() {
        Ok(address) if address.port() == 0 => {
            violations.push(ConfigViolation {
                field: "enforcement.interception.proxy.health_probe.target".to_string(),
                reason: "transparent proxy health probe target must use a non-zero port"
                    .to_string(),
            });
            None
        }
        Ok(address) => Some(address),
        Err(_) => {
            violations.push(ConfigViolation {
                field: "enforcement.interception.proxy.health_probe.target".to_string(),
                reason: "transparent proxy health probe target must be an IP socket address"
                    .to_string(),
            });
            None
        }
    };
    if let (
        Some(target),
        TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
        Some(listen_port),
    ) = (
        parsed_target,
        interception.proxy.mode,
        interception.proxy.listen_port,
    ) && health_probe_target_matches_managed_relay_listener(target, listen_port)
    {
        violations.push(ConfigViolation {
            field: "enforcement.interception.proxy.health_probe.target".to_string(),
            reason:
                "managed TCP relay health probe target must not point at the local relay listener"
                    .to_string(),
        });
    }
    validate_health_probe_range(
        "enforcement.interception.proxy.health_probe.interval_ms",
        health_probe.interval_ms,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS,
        "transparent proxy health probe interval",
        violations,
    );
    validate_health_probe_range(
        "enforcement.interception.proxy.health_probe.timeout_ms",
        health_probe.timeout_ms,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        "transparent proxy health probe timeout",
        violations,
    );
    validate_health_probe_range(
        "enforcement.interception.proxy.health_probe.failure_threshold",
        u64::from(health_probe.failure_threshold),
        u64::from(MIN_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD),
        u64::from(MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD),
        "transparent proxy health probe failure threshold",
        violations,
    );
    if health_probe.timeout_ms > health_probe.interval_ms {
        violations.push(ConfigViolation {
            field: "enforcement.interception.proxy.health_probe.timeout_ms".to_string(),
            reason: "transparent proxy health probe timeout must not exceed interval".to_string(),
        });
    }
}

fn validate_health_probe_range(
    field: &str,
    value: u64,
    min: u64,
    max: u64,
    label: &str,
    violations: &mut Vec<ConfigViolation>,
) {
    if !(min..=max).contains(&value) {
        violations.push(ConfigViolation {
            field: field.to_string(),
            reason: format!("{label} must be between {min} and {max}"),
        });
    }
}

fn health_probe_target_matches_managed_relay_listener(
    target: SocketAddr,
    listen_port: u16,
) -> bool {
    target.port() == listen_port && is_local_listener_address(target.ip())
}

fn is_local_listener_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_unspecified(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyHealthProbeConfig, TransparentInterceptionStrategyConfig,
    };

    use super::*;

    #[test]
    fn enabled_strategy_requires_proxy_port() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                selector: None,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(0),
                    ..TransparentInterceptionProxyConfig::default()
                },
            },
            &mut violations,
        );

        assert_eq!(violations.len(), 1);
        assert!(
            violations
                .iter()
                .any(|violation| violation.field == "enforcement.interception.proxy.listen_port")
        );
    }

    #[test]
    fn disabled_strategy_does_not_require_proxy_config() {
        let mut violations = Vec::new();
        validate(&EnforcementInterceptionConfig::default(), &mut violations);

        assert!(violations.is_empty());
    }

    #[test]
    fn managed_tcp_relay_is_not_valid_when_interception_is_disabled() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                proxy: TransparentInterceptionProxyConfig {
                    mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field, "enforcement.interception.proxy.mode");
    }

    #[test]
    fn managed_tcp_relay_requires_inbound_tproxy_strategy() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::OutboundMitm,
                selector: None,
                proxy: TransparentInterceptionProxyConfig {
                    mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                    listen_port: Some(15001),
                    ..TransparentInterceptionProxyConfig::default()
                },
            },
            &mut violations,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field, "enforcement.interception.proxy.mode");
    }

    #[test]
    fn health_probe_requires_enabled_strategy_and_valid_target() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                proxy: TransparentInterceptionProxyConfig {
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("localhost:15001".to_string()),
                        interval_ms: 0,
                        timeout_ms: 0,
                        failure_threshold: 0,
                    },
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.target"
            && violation.reason.contains("enabled interception strategy")));
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.target"
            && violation.reason.contains("IP socket address")));
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.interval_ms"));
        assert!(
            violations.iter().any(|violation| violation.field
                == "enforcement.interception.proxy.health_probe.timeout_ms")
        );
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.failure_threshold"));
    }

    #[test]
    fn managed_health_probe_cannot_target_relay_listen_port() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                proxy: TransparentInterceptionProxyConfig {
                    mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("127.0.0.1:15001".to_string()),
                        interval_ms: 500,
                        timeout_ms: 100,
                        failure_threshold: 1,
                    },
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.target"
            && violation.reason.contains("local relay listener")));
    }

    #[test]
    fn managed_health_probe_allows_remote_target_on_relay_port() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                proxy: TransparentInterceptionProxyConfig {
                    mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("203.0.113.10:15001".to_string()),
                        interval_ms: 500,
                        timeout_ms: 100,
                        failure_threshold: 1,
                    },
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.is_empty());
    }

    #[test]
    fn health_probe_is_currently_inbound_tproxy_only() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::OutboundMitm,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("127.0.0.1:18080".to_string()),
                        interval_ms: 500,
                        timeout_ms: 100,
                        failure_threshold: 1,
                    },
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.target"
            && violation.reason.contains("inbound TPROXY only")));
    }

    #[test]
    fn health_probe_timing_uses_bounded_runtime_values() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("127.0.0.1:18080".to_string()),
                        interval_ms: MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS - 1,
                        timeout_ms: MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS + 1,
                        failure_threshold: MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD + 1,
                    },
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.interval_ms"));
        assert!(
            violations.iter().any(|violation| violation.field
                == "enforcement.interception.proxy.health_probe.timeout_ms")
        );
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.failure_threshold"));
    }
}

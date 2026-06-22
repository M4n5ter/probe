use crate::{ConfigViolation, EnforcementInterceptionConfig};

pub(super) fn validate(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Err(intent_violations) = interception.transparent_proxy_intent() {
        violations.extend(
            intent_violations
                .into_iter()
                .map(|violation| ConfigViolation {
                    field: violation.field().to_string(),
                    reason: violation.reason().to_string(),
                }),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        EnforcementInterceptionConfig, MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyHealthProbeConfig, TransparentInterceptionProxyModeConfig,
        TransparentInterceptionStrategyConfig,
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

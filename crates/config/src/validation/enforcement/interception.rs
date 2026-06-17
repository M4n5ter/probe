use crate::{
    ConfigViolation, EnforcementInterceptionConfig, TransparentInterceptionProxyModeConfig,
    TransparentInterceptionStrategyConfig,
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

#[cfg(test)]
mod tests {
    use crate::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
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
                },
            },
            &mut violations,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field, "enforcement.interception.proxy.mode");
    }
}

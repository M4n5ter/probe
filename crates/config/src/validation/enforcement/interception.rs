use crate::{ConfigViolation, EnforcementInterceptionConfig};

pub(super) fn validate(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
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
}

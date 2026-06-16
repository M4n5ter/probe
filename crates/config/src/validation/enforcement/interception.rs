use crate::{
    ConfigViolation, DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_MARK,
    DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_TABLE, DEFAULT_TRANSPARENT_INTERCEPTION_ROUTE_TABLE,
    EnforcementInterceptionConfig, TransparentInterceptionNftablesConfig,
};

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

    if !TransparentInterceptionNftablesConfig::is_owned_mark(interception.nftables.mark) {
        violations.push(ConfigViolation {
            field: "enforcement.interception.nftables.mark".to_string(),
            reason: format!(
                "transparent interception nftables mark must be the reserved sssa_probe mark 0x{DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_MARK:x}"
            ),
        });
    }

    if !TransparentInterceptionNftablesConfig::is_owned_route_table(
        interception.nftables.route_table,
    ) {
        violations.push(ConfigViolation {
            field: "enforcement.interception.nftables.route_table".to_string(),
            reason: format!(
                "transparent interception policy route table must be the reserved sssa_probe table {DEFAULT_TRANSPARENT_INTERCEPTION_ROUTE_TABLE}"
            ),
        });
    }

    if !TransparentInterceptionNftablesConfig::is_owned_table_name(
        &interception.nftables.table_name,
    ) {
        violations.push(ConfigViolation {
            field: "enforcement.interception.nftables.table_name".to_string(),
            reason: format!(
                "transparent interception nftables table name must be the reserved {DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_TABLE} table"
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        EnforcementInterceptionConfig, TransparentInterceptionNftablesConfig,
        TransparentInterceptionProxyConfig, TransparentInterceptionStrategyConfig,
    };

    use super::*;

    #[test]
    fn enabled_strategy_requires_proxy_port_mark_and_safe_table_name() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                selector: None,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(0),
                },
                nftables: TransparentInterceptionNftablesConfig {
                    table_name: "bad-name".to_string(),
                    mark: 0,
                    route_table: 0,
                },
            },
            &mut violations,
        );

        assert_eq!(violations.len(), 4);
        assert!(
            violations
                .iter()
                .any(|violation| violation.field == "enforcement.interception.proxy.listen_port")
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.field == "enforcement.interception.nftables.mark")
        );
        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.nftables.table_name"
        }));
        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.nftables.route_table"
        }));
    }

    #[test]
    fn enabled_strategy_rejects_non_owned_host_resources() {
        let mut violations = Vec::new();
        validate(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                selector: None,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(15001),
                },
                nftables: TransparentInterceptionNftablesConfig {
                    table_name: "filter".to_string(),
                    mark: 0x5353_4102,
                    route_table: 53_535,
                },
            },
            &mut violations,
        );

        assert_eq!(violations.len(), 3);
        assert!(
            violations
                .iter()
                .any(|violation| violation.field == "enforcement.interception.nftables.mark")
        );
        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.nftables.table_name"
        }));
        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.nftables.route_table"
        }));
    }

    #[test]
    fn disabled_strategy_does_not_require_proxy_config() {
        let mut violations = Vec::new();
        validate(&EnforcementInterceptionConfig::default(), &mut violations);

        assert!(violations.is_empty());
    }
}

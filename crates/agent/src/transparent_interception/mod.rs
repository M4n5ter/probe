mod error;
mod ip_family;
mod nftables;
mod proxy;
mod runtime;

use interception::{TransparentInterceptionHostRuleScope, TransparentInterceptionSetupSelectors};
use probe_config::{EnforcementInterceptionConfig, TransparentInterceptionStrategyConfig};

pub(crate) use error::TransparentInterceptionError;
pub(crate) use ip_family::TransparentInterceptionIpFamily;
pub(crate) use proxy::{ManagedTransparentProxyGuard, start_managed_proxy};
pub(crate) use runtime::{TransparentInterceptionGuard, TransparentInterceptionRuntime};

const OUTBOUND_MITM_UNAVAILABLE: &str = "outbound transparent MITM requires proxy self-bypass and MITM lifecycle before rules can be installed";
const MISSING_LOCAL_SETUP_SELECTOR: &str =
    "transparent interception requires an explicit local selector for setup-time rules";

pub(crate) fn resolve(config: &EnforcementInterceptionConfig) -> TransparentInterceptionRuntime {
    match config.strategy {
        TransparentInterceptionStrategyConfig::None => TransparentInterceptionRuntime::unavailable(
            "transparent interception backend is not configured",
        ),
        TransparentInterceptionStrategyConfig::InboundTproxy => nftables::resolve(config),
        TransparentInterceptionStrategyConfig::OutboundMitm => {
            TransparentInterceptionRuntime::unavailable(OUTBOUND_MITM_UNAVAILABLE)
        }
    }
}

pub(crate) fn effective_setup_scope(
    config: &EnforcementInterceptionConfig,
    selectors: TransparentInterceptionSetupSelectors,
) -> Result<Option<TransparentInterceptionHostRuleScope>, TransparentInterceptionError> {
    if !config.strategy.is_enabled() {
        return Ok(None);
    }
    if config.strategy == TransparentInterceptionStrategyConfig::OutboundMitm {
        return Err(TransparentInterceptionError::Nftables(
            OUTBOUND_MITM_UNAVAILABLE.to_string(),
        ));
    }
    if selectors.local_config_scope().is_none() {
        return Err(TransparentInterceptionError::Nftables(
            MISSING_LOCAL_SETUP_SELECTOR.to_string(),
        ));
    }
    selectors
        .local_host_rule_scope()
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    let scope = selectors
        .final_host_rule_scope()
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    nftables::validate_effective_setup_scope(config, &scope)?;
    Ok(Some(scope))
}

#[cfg(test)]
mod tests {
    use interception::TransparentInterceptionSetupSelectorSources;
    use probe_config::{TransparentInterceptionProxyConfig, TransparentInterceptionStrategyConfig};
    use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

    use super::*;

    #[test]
    fn manifest_only_setup_scope_fails_closed() {
        let config = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
        };
        let manifest_selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        );

        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: None,
                effective_enforcement_selector: Some(&manifest_selector),
                interception_selector: config.selector.as_ref(),
            },
        );
        let error = effective_setup_scope(&config, selectors)
            .expect_err("remote manifest must not be the only transparent setup scope");

        assert!(error.to_string().contains("explicit local selector"));
    }
}

mod error;
mod ip_family;
mod nftables;
mod proxy;
mod runtime;

use ::runtime::TransparentInterceptionExecutionPlan;
use interception::{
    TransparentInterceptionHostRuleScope, TransparentInterceptionSetupPlan,
    TransparentInterceptionSetupProjectionError, TransparentInterceptionSetupSelectors,
};
use probe_config::TransparentInterceptionStrategyConfig;

pub(crate) use error::TransparentInterceptionError;
pub(crate) use ip_family::TransparentInterceptionIpFamily;
use proxy::TransparentProxyRuntime;
pub(crate) use proxy::{
    TransparentProxyHealthProbeMode, TransparentProxyRuntimeHandle, TransparentProxyRuntimeMode,
    TransparentProxyRuntimeSnapshot,
};
pub(crate) use runtime::{TransparentInterceptionGuard, TransparentInterceptionRuntime};

const OUTBOUND_MITM_UNAVAILABLE: &str = "outbound transparent MITM requires proxy self-bypass and MITM lifecycle before rules can be installed";
const MISSING_LOCAL_SETUP_SELECTOR: &str =
    "transparent interception requires an explicit local selector for setup-time rules";

pub(crate) fn unavailable_for_config_error(
    error: impl Into<String>,
) -> TransparentInterceptionRuntime {
    TransparentInterceptionRuntime::unavailable(error.into(), TransparentProxyRuntime::disabled())
}

pub(crate) fn resolve(
    execution_plan: TransparentInterceptionExecutionPlan,
) -> TransparentInterceptionRuntime {
    let proxy_runtime = TransparentProxyRuntime::for_execution_plan(&execution_plan);
    match execution_plan {
        TransparentInterceptionExecutionPlan::Disabled => {
            TransparentInterceptionRuntime::unavailable(
                "transparent interception backend is not configured",
                proxy_runtime,
            )
        }
        TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) => {
            nftables::resolve(inbound_plan, proxy_runtime)
        }
        TransparentInterceptionExecutionPlan::OutboundMitm(_) => {
            TransparentInterceptionRuntime::unavailable(OUTBOUND_MITM_UNAVAILABLE, proxy_runtime)
        }
    }
}

pub(crate) fn effective_setup_scope(
    execution_plan: &TransparentInterceptionExecutionPlan,
    selectors: TransparentInterceptionSetupSelectors,
) -> Result<Option<TransparentInterceptionHostRuleScope>, TransparentInterceptionError> {
    if execution_plan.strategy() == TransparentInterceptionStrategyConfig::None {
        return Ok(None);
    }
    let TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) = execution_plan else {
        return Err(TransparentInterceptionError::Setup(
            OUTBOUND_MITM_UNAVAILABLE.to_string(),
        ));
    };
    if selectors.local_config_scope().is_none() {
        return Err(TransparentInterceptionError::Setup(
            MISSING_LOCAL_SETUP_SELECTOR.to_string(),
        ));
    }
    executable_host_rule_scope(selectors.local_setup_plan())?;
    let scope = executable_host_rule_scope(selectors.final_setup_plan())?;
    nftables::validate_effective_setup_scope(inbound_plan, &scope)?;
    Ok(Some(scope))
}

fn executable_host_rule_scope(
    plan: Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError>,
) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionError> {
    match plan {
        Ok(TransparentInterceptionSetupPlan::HostRules(scope)) => Ok(scope),
        Ok(TransparentInterceptionSetupPlan::RequiresProcessClassifier { reason, .. }) => {
            Err(TransparentInterceptionError::Setup(reason))
        }
        Ok(TransparentInterceptionSetupPlan::RequiresFlowClassifier { reason, .. }) => {
            Err(TransparentInterceptionError::Setup(reason))
        }
        Err(error) => Err(TransparentInterceptionError::Setup(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use interception::TransparentInterceptionSetupSelectorSources;
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionStrategyConfig,
    };
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
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");
        let error = effective_setup_scope(&execution_plan, selectors)
            .expect_err("remote manifest must not be the only transparent setup scope");

        assert!(error.to_string().contains("explicit local selector"));
    }
}

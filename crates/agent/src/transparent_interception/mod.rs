mod error;
mod nftables;
mod runtime;

use probe_config::{EnforcementInterceptionConfig, TransparentInterceptionStrategyConfig};
use probe_core::Selector;

pub(crate) use error::TransparentInterceptionError;
pub(crate) use runtime::{TransparentInterceptionGuard, TransparentInterceptionRuntime};

const OUTBOUND_MITM_UNAVAILABLE: &str = "outbound transparent MITM requires proxy self-bypass and MITM lifecycle before rules can be installed";

pub(crate) fn resolve(
    config: &EnforcementInterceptionConfig,
    enforcement_selector: Option<&Selector>,
) -> TransparentInterceptionRuntime {
    match config.strategy {
        TransparentInterceptionStrategyConfig::None => TransparentInterceptionRuntime::unavailable(
            "transparent interception backend is not configured",
        ),
        TransparentInterceptionStrategyConfig::InboundTproxy => nftables::resolve(
            config,
            effective_setup_selector(enforcement_selector, config.selector.as_ref()).as_ref(),
        ),
        TransparentInterceptionStrategyConfig::OutboundMitm => {
            TransparentInterceptionRuntime::unavailable(OUTBOUND_MITM_UNAVAILABLE)
        }
    }
}

pub(crate) fn validate_setup_scope(
    config: &EnforcementInterceptionConfig,
    effective_enforcement_selector: Option<&Selector>,
) -> Result<(), TransparentInterceptionError> {
    if !config.strategy.is_enabled() {
        return Ok(());
    }
    if config.strategy == TransparentInterceptionStrategyConfig::OutboundMitm {
        return Err(TransparentInterceptionError::Nftables(
            OUTBOUND_MITM_UNAVAILABLE.to_string(),
        ));
    }
    nftables::validate_setup_scope(
        config,
        effective_setup_selector(effective_enforcement_selector, config.selector.as_ref()).as_ref(),
    )
}

fn effective_setup_selector(
    enforcement_selector: Option<&Selector>,
    interception_selector: Option<&Selector>,
) -> Option<Selector> {
    match (enforcement_selector, interception_selector) {
        (Some(enforcement), Some(interception)) => Some(Selector::All {
            selectors: vec![enforcement.clone(), interception.clone()],
        }),
        (Some(selector), None) | (None, Some(selector)) => Some(selector.clone()),
        (None, None) => None,
    }
}

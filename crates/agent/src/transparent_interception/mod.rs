mod runtime;

use probe_config::{EnforcementInterceptionConfig, TransparentInterceptionStrategyConfig};

pub(crate) use runtime::TransparentInterceptionRuntime;

pub(crate) fn resolve(config: &EnforcementInterceptionConfig) -> TransparentInterceptionRuntime {
    match config.strategy {
        TransparentInterceptionStrategyConfig::None => TransparentInterceptionRuntime::unavailable(
            "transparent interception backend is not configured",
        ),
        TransparentInterceptionStrategyConfig::InboundTproxy => {
            TransparentInterceptionRuntime::unavailable(
                "inbound TPROXY transparent interception backend is modeled but no executable backend is configured",
            )
        }
        TransparentInterceptionStrategyConfig::OutboundMitm => {
            TransparentInterceptionRuntime::unavailable(
                "outbound MITM transparent interception backend is modeled but no executable backend is configured",
            )
        }
    }
}

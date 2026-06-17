mod inbound;
mod projection;
mod route;

use probe_config::{EnforcementInterceptionConfig, TransparentInterceptionStrategyConfig};
use thiserror::Error;

pub(super) use inbound::InboundTproxyLifecyclePlan;

const INBOUND_TPROXY_OWNER_LOCK: &str = "inbound_tproxy";

#[derive(Debug, Error)]
pub(super) enum NftablesPlanError {
    #[error("transparent interception requires a proxy listen port")]
    MissingProxyPort,
    #[error(
        "transparent interception executable nftables lifecycle currently supports inbound TPROXY only; strategy {strategy:?} requires proxy self-bypass and MITM lifecycle"
    )]
    UnsupportedExecutableStrategy {
        strategy: TransparentInterceptionStrategyConfig,
    },
}

fn proxy_port_from_config(
    config: &EnforcementInterceptionConfig,
) -> Result<u16, NftablesPlanError> {
    let Some(proxy_port @ 1..) = config.proxy.listen_port else {
        return Err(NftablesPlanError::MissingProxyPort);
    };
    Ok(proxy_port)
}

fn hex_mark(mark: u32) -> String {
    format!("0x{mark:x}")
}

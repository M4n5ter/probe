mod command;
mod lifecycle;
mod owner_lock;
mod plan;
mod probe;

use probe_config::EnforcementInterceptionConfig;
use probe_core::Selector;

use self::{
    command::{SystemIp, SystemNft},
    plan::NftablesInterceptionPlan,
    probe::{NftablesInterceptionProbe, NftablesInterceptionProbeResult},
};
use super::TransparentInterceptionRuntime;

pub(super) use lifecycle::{NftablesTransparentInterception, NftablesTransparentInterceptionGuard};

pub(super) fn resolve(
    config: &EnforcementInterceptionConfig,
    setup_selector: Option<&Selector>,
) -> TransparentInterceptionRuntime {
    match NftablesInterceptionPlan::from_config_and_scope(config, setup_selector) {
        Ok(_) => {}
        Err(error) => return TransparentInterceptionRuntime::unavailable(error.to_string()),
    }

    match NftablesInterceptionProbe::default().resolve() {
        NftablesInterceptionProbeResult::Available { nft, ip } => {
            TransparentInterceptionRuntime::available(
                NftablesTransparentInterception::new(
                    config.clone(),
                    SystemNft::new(nft),
                    ip.map(SystemIp::new),
                ),
                "transparent interception nftables lifecycle entrypoints are available; run will check the final selector-projected rules before acquiring the owner lock and installing them",
            )
        }
        NftablesInterceptionProbeResult::Unavailable(capability) => {
            TransparentInterceptionRuntime::unavailable(
                capability
                    .reason
                    .unwrap_or_else(|| "transparent interception is unavailable".to_string()),
            )
        }
    }
}

pub(super) fn validate_setup_scope(
    config: &EnforcementInterceptionConfig,
    setup_selector: Option<&Selector>,
) -> Result<(), super::TransparentInterceptionError> {
    NftablesInterceptionPlan::from_config_and_scope(config, setup_selector)
        .map(|_| ())
        .map_err(|error| super::TransparentInterceptionError::Nftables(error.to_string()))
}

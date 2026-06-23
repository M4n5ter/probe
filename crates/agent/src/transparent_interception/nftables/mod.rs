mod command;
mod lifecycle;
mod local_addresses;
mod owner_lock;
mod plan;
mod probe;

use ::runtime::{
    TransparentInterceptionInboundTproxyPlan, TransparentInterceptionOutboundRedirectPlan,
};
use interception::TransparentInterceptionHostRuleScope;

use self::{
    command::{SystemIp, SystemNft},
    plan::{InboundTproxyLifecyclePlan, OutboundRedirectLifecyclePlan},
    probe::{NftablesInterceptionProbe, NftablesInterceptionProbeResult},
};
use super::{TransparentInterceptionRuntime, proxy::TransparentProxyRuntime};

pub(super) use lifecycle::{NftablesTransparentInterception, NftablesTransparentInterceptionGuard};

pub(super) fn resolve(
    inbound_plan: TransparentInterceptionInboundTproxyPlan,
    proxy_runtime: TransparentProxyRuntime,
) -> TransparentInterceptionRuntime {
    match NftablesInterceptionProbe::default().resolve() {
        NftablesInterceptionProbeResult::Available { nft, ip } => {
            TransparentInterceptionRuntime::available(
                NftablesTransparentInterception::new(
                    inbound_plan,
                    SystemNft::new(nft),
                    ip.map(SystemIp::new),
                    proxy_runtime.clone(),
                ),
                proxy_runtime,
                "transparent interception nftables lifecycle entrypoints are available; run will check the final selector-projected rules before acquiring the owner lock and installing them",
            )
        }
        NftablesInterceptionProbeResult::Unavailable(capability) => {
            TransparentInterceptionRuntime::unavailable(
                capability
                    .reason
                    .unwrap_or_else(|| "transparent interception is unavailable".to_string()),
                proxy_runtime,
            )
        }
    }
}

pub(super) fn validate_inbound_tproxy_setup_scope(
    inbound_plan: &TransparentInterceptionInboundTproxyPlan,
    setup_scope: &TransparentInterceptionHostRuleScope,
) -> Result<(), super::TransparentInterceptionError> {
    InboundTproxyLifecyclePlan::from_inbound_plan_and_scope(inbound_plan, setup_scope.clone())
        .map(|_| ())
        .map_err(|error| super::TransparentInterceptionError::Setup(error.to_string()))
}

pub(super) fn validate_outbound_redirect_setup_scope(
    outbound_redirect: &TransparentInterceptionOutboundRedirectPlan,
    setup_scope: &TransparentInterceptionHostRuleScope,
) -> Result<(), super::TransparentInterceptionError> {
    OutboundRedirectLifecyclePlan::from_redirect_plan_and_scope(
        outbound_redirect,
        setup_scope.clone(),
    )
    .map(|plan| plan.setup_nft_script())
    .map_err(|error| super::TransparentInterceptionError::Setup(error.to_string()))
    .map(|_| ())
}

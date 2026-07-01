mod activation;
mod command;
mod host_routing;
mod lifecycle;
mod outbound;
mod owner_lock;
mod probe;

use ::runtime::{
    TransparentInterceptionInboundTproxyPlan, TransparentInterceptionOutboundProxyPlan,
};
use interception::TransparentInterceptionHostRuleSet;

use self::{
    command::SystemNft,
    host_routing::RtnetlinkHostRouting,
    probe::{NftablesInterceptionProbe, NftablesInterceptionProbeResult},
};
use super::{TransparentInterceptionRuntime, proxy::TransparentProxyRuntime};
use transparent_linux::{
    InboundTproxyArtifactSpec, InboundTproxyLifecyclePlan, OutboundRedirectLifecyclePlan,
    TransparentLinuxResources,
};

pub(super) use lifecycle::{NftablesTransparentInterception, NftablesTransparentInterceptionGuard};
pub(super) use outbound::{
    NftablesOutboundTransparentProxy, NftablesOutboundTransparentProxyGuard,
};

pub(super) fn resolve(
    inbound_plan: TransparentInterceptionInboundTproxyPlan,
    proxy_runtime: TransparentProxyRuntime,
) -> TransparentInterceptionRuntime {
    match NftablesInterceptionProbe::default().resolve() {
        NftablesInterceptionProbeResult::Available { nft } => {
            let host_routing = match RtnetlinkHostRouting::new() {
                Ok(host_routing) => host_routing,
                Err(error) => {
                    return TransparentInterceptionRuntime::unavailable(
                        format!(
                            "transparent interception requires RTNETLINK host routing access: {error}"
                        ),
                        proxy_runtime,
                    );
                }
            };
            TransparentInterceptionRuntime::available(
                NftablesTransparentInterception::new(
                    inbound_plan,
                    SystemNft::new(nft),
                    host_routing,
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

pub(super) fn resolve_outbound(
    outbound_plan: TransparentInterceptionOutboundProxyPlan,
    proxy_runtime: TransparentProxyRuntime,
) -> TransparentInterceptionRuntime {
    match NftablesInterceptionProbe::default().resolve() {
        NftablesInterceptionProbeResult::Available { nft } => {
            let host_routing = match RtnetlinkHostRouting::new() {
                Ok(host_routing) => host_routing,
                Err(error) => {
                    return TransparentInterceptionRuntime::unavailable(
                        format!(
                            "outbound transparent proxy requires RTNETLINK host routing access: {error}"
                        ),
                        proxy_runtime,
                    );
                }
            };
            TransparentInterceptionRuntime::available(
                NftablesOutboundTransparentProxy::new(
                    outbound_plan,
                    SystemNft::new(nft),
                    host_routing,
                    proxy_runtime.clone(),
                ),
                proxy_runtime,
                "outbound transparent proxy nftables lifecycle entrypoints are available; run will check final selector-projected OUTPUT redirect rules before acquiring the owner lock and installing them",
            )
        }
        NftablesInterceptionProbeResult::Unavailable(capability) => {
            TransparentInterceptionRuntime::unavailable(
                capability
                    .reason
                    .unwrap_or_else(|| "outbound transparent proxy is unavailable".to_string()),
                proxy_runtime,
            )
        }
    }
}

pub(super) fn validate_inbound_tproxy_setup_scope(
    inbound_plan: &TransparentInterceptionInboundTproxyPlan,
    setup_scope: &TransparentInterceptionHostRuleSet,
) -> Result<(), super::TransparentInterceptionError> {
    InboundTproxyLifecyclePlan::from_spec_and_rule_set(
        InboundTproxyArtifactSpec::new(
            TransparentLinuxResources::reserved(),
            inbound_plan.listen_port().get(),
        ),
        setup_scope.clone(),
    )
    .map(|_| ())
    .map_err(|error| super::TransparentInterceptionError::Setup(error.to_string()))
}

pub(super) fn validate_outbound_redirect_setup_scope(
    outbound_plan: &TransparentInterceptionOutboundProxyPlan,
    setup_scope: &TransparentInterceptionHostRuleSet,
) -> Result<(), super::TransparentInterceptionError> {
    OutboundRedirectLifecyclePlan::from_spec_and_rule_set(
        outbound_plan.outbound_redirect_artifact().clone(),
        setup_scope.clone(),
    )
    .map(|plan| plan.setup_nft_script())
    .map_err(|error| super::TransparentInterceptionError::Setup(error.to_string()))
    .map(|_| ())
}

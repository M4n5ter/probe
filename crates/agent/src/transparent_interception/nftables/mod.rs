mod command;
mod lifecycle;
mod local_addresses;
mod owner_lock;
mod probe;

use ::runtime::{
    TransparentInterceptionInboundTproxyPlan, TransparentInterceptionOutboundRedirectPlan,
};
use interception::TransparentInterceptionHostRuleScope;

use self::{
    command::{SystemIp, SystemNft},
    probe::{NftablesInterceptionProbe, NftablesInterceptionProbeResult},
};
use super::{TransparentInterceptionRuntime, proxy::TransparentProxyRuntime};
use transparent_linux::{
    InboundTproxyArtifactSpec, InboundTproxyLifecyclePlan, OutboundRedirectArtifactSpec,
    OutboundRedirectLifecyclePlan, TransparentLinuxResources,
};

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
    InboundTproxyLifecyclePlan::from_spec_and_scope(
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
    outbound_redirect: &TransparentInterceptionOutboundRedirectPlan,
    setup_scope: &TransparentInterceptionHostRuleScope,
) -> Result<(), super::TransparentInterceptionError> {
    let spec = outbound_redirect_spec(outbound_redirect)?;
    OutboundRedirectLifecyclePlan::from_spec_and_scope(spec, setup_scope.clone())
        .map(|plan| plan.setup_nft_script())
        .map_err(|error| super::TransparentInterceptionError::Setup(error.to_string()))
        .map(|_| ())
}

fn outbound_redirect_spec(
    outbound_redirect: &TransparentInterceptionOutboundRedirectPlan,
) -> Result<OutboundRedirectArtifactSpec, super::TransparentInterceptionError> {
    match outbound_redirect {
        TransparentInterceptionOutboundRedirectPlan::Planned { artifact, .. } => {
            Ok(artifact.clone())
        }
        TransparentInterceptionOutboundRedirectPlan::NotConfigured => {
            Err(super::TransparentInterceptionError::Setup(
                "outbound MITM redirect preview is not planned".to_string(),
            ))
        }
    }
}

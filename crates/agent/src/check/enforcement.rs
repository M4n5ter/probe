use ::enforcement::EnforcementBackend;
use probe_config::{ConnectionEnforcementBackendConfig, TransparentInterceptionStrategyConfig};
use probe_core::EnforcementMode;
use runtime::{
    EnforcementCapabilityPlan, RequiredCapabilityPlan, RuntimePlan,
    TransparentInterceptionClassificationPlan, TransparentInterceptionLocalSetupProjectionPlan,
    TransparentInterceptionMitmPlan, TransparentInterceptionNftablesPlan,
    TransparentInterceptionOutboundRedirectPlan, TransparentInterceptionProxyPlan,
};
use serde::Serialize;

use crate::configured_enforcement::{
    LoadedEnforcementPolicySourceSnapshot, build_configured_enforcement_check_with_backend,
};
use crate::control_plane_http::enforcement_policy_source_load_context_from_plan;

use super::report::CheckError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementCheckSnapshot {
    pub mode: EnforcementMode,
    pub composition: EnforcementCompositionCheckSnapshot,
    pub connection: EnforcementConnectionCheckSnapshot,
    pub interception: EnforcementInterceptionCheckSnapshot,
    pub effective_selector_configured: bool,
    pub config_selector_configured: bool,
    pub manifest_selector_configured: Option<bool>,
    pub policy: EnforcementPolicyCheckSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementCompositionCheckSnapshot {
    Ready,
    Blocked { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementConnectionCheckSnapshot {
    pub backend: ConnectionEnforcementBackendConfig,
    pub capability: EnforcementCapabilityPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementInterceptionCheckSnapshot {
    pub strategy: TransparentInterceptionStrategyConfig,
    pub proxy: TransparentInterceptionProxyPlan,
    pub nftables: TransparentInterceptionNftablesPlan,
    pub mitm: TransparentInterceptionMitmPlan,
    pub outbound_redirect: TransparentInterceptionOutboundRedirectPlan,
    pub local_setup_projection: TransparentInterceptionLocalSetupProjectionPlan,
    pub classification: TransparentInterceptionClassificationPlan,
    pub selector_configured: bool,
    pub capabilities: Vec<RequiredCapabilityPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementPolicyCheckSnapshot {
    pub mode: EnforcementPolicyCheckMode,
    pub active: Option<LoadedEnforcementPolicySnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPolicyCheckMode {
    NotConfigured,
    Loaded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadedEnforcementPolicySnapshot {
    pub id: String,
    pub version: String,
    pub source: LoadedEnforcementPolicySourceSnapshot,
    pub selector_configured: bool,
    pub protective_actions: probe_core::ProtectiveActionProfile,
}

pub(super) async fn check_enforcement(
    plan: &RuntimePlan,
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<EnforcementCheckSnapshot, CheckError> {
    let check = build_configured_enforcement_check_with_backend(
        plan,
        backend,
        enforcement_policy_source_load_context_from_plan(plan),
    )
    .await?;
    let composition =
        check
            .setup_error
            .map_or(EnforcementCompositionCheckSnapshot::Ready, |error| {
                EnforcementCompositionCheckSnapshot::Blocked {
                    reason: error.to_string(),
                }
            });
    let enforcement = check.configured;
    let active_policy = &enforcement.active_policy;
    let policy = active_policy.policy_source().map_or(
        EnforcementPolicyCheckSnapshot {
            mode: EnforcementPolicyCheckMode::NotConfigured,
            active: None,
        },
        |source| EnforcementPolicyCheckSnapshot {
            mode: EnforcementPolicyCheckMode::Loaded,
            active: Some(LoadedEnforcementPolicySnapshot {
                id: source.manifest.id.clone(),
                version: source.manifest.version.clone(),
                source: source.snapshot(),
                selector_configured: source.manifest.selector.is_some(),
                protective_actions: source.manifest.protective_actions.clone(),
            }),
        },
    );
    Ok(EnforcementCheckSnapshot {
        mode: enforcement.mode,
        composition,
        connection: EnforcementConnectionCheckSnapshot {
            backend: plan.enforcement.connection.backend,
            capability: plan.enforcement.connection.capability.clone(),
        },
        interception: EnforcementInterceptionCheckSnapshot {
            strategy: plan.enforcement.interception.strategy,
            proxy: plan.enforcement.interception.proxy.clone(),
            nftables: plan.enforcement.interception.nftables.clone(),
            mitm: plan.enforcement.interception.mitm.clone(),
            outbound_redirect: plan
                .enforcement
                .interception
                .execution
                .outbound_redirect_plan(),
            local_setup_projection: plan.enforcement.interception.local_setup_projection.clone(),
            classification: plan.enforcement.interception.classification.clone(),
            selector_configured: plan.enforcement.interception.selector_configured,
            capabilities: plan.enforcement.interception.capabilities.clone(),
        },
        effective_selector_configured: active_policy.effective_selector_configured(),
        config_selector_configured: enforcement.config_selector_configured,
        manifest_selector_configured: active_policy.manifest_selector_configured(),
        policy,
    })
}

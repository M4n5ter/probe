use enforcement::{EnforcementError, ScopedEnforcementPlanner};
use probe_config::AgentConfig;
use probe_core::{EnforcementMode, ProtectiveActionProfile, Selector};
use runtime::{EnforcementPlan, EnforcementPolicySourcePlan, RuntimePlan};
use thiserror::Error;

use super::source::{
    EnforcementPolicySourceError, LoadedEnforcementPolicySource, load_enforcement_policy_source,
    load_enforcement_policy_source_metadata,
};

#[derive(Debug, Error)]
pub enum ConfiguredEnforcementError {
    #[error("enforcement planner error: {0}")]
    Planner(#[from] EnforcementError),
    #[error("enforcement policy source error: {0}")]
    Source(#[from] EnforcementPolicySourceError),
}

pub struct ConfiguredEnforcement {
    pub planner: ScopedEnforcementPlanner,
    pub mode: EnforcementMode,
    pub effective_selector_configured: bool,
    pub config_selector_configured: bool,
    pub manifest_selector_configured: Option<bool>,
    pub policy_source: Option<LoadedEnforcementPolicySource>,
}

pub async fn build_configured_enforcement(
    plan: &RuntimePlan,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    build_configured_enforcement_from_parts(
        plan.enforcement.mode,
        plan.config.enforcement.selector.clone(),
        plan.enforcement.config_selector_configured,
        &plan.enforcement.policy_source,
    )
    .await
}

pub fn validate_configured_enforcement_metadata(
    config: &AgentConfig,
) -> Result<(), ConfiguredEnforcementError> {
    let enforcement = EnforcementPlan::resolve(config);
    let manifest = load_enforcement_policy_source_metadata(&enforcement.policy_source)?;
    let effective_selector = effective_selector(
        config.enforcement.selector.clone(),
        manifest
            .as_ref()
            .and_then(|manifest| manifest.selector.clone()),
    );
    let protective_actions = manifest.map_or_else(ProtectiveActionProfile::default, |manifest| {
        manifest.protective_actions
    });
    ScopedEnforcementPlanner::with_protective_action_profile(
        enforcement.mode,
        effective_selector.as_ref(),
        protective_actions,
    )?;
    Ok(())
}

async fn build_configured_enforcement_from_parts(
    mode: EnforcementMode,
    config_selector: Option<Selector>,
    config_selector_configured: bool,
    policy_source_plan: &EnforcementPolicySourcePlan,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    let policy_source = load_enforcement_policy_source(policy_source_plan).await?;
    let effective_selector = effective_selector(
        config_selector,
        policy_source
            .as_ref()
            .and_then(|source| source.manifest.selector.clone()),
    );
    let protective_actions = policy_source
        .as_ref()
        .map_or_else(ProtectiveActionProfile::default, |source| {
            source.manifest.protective_actions.clone()
        });
    let planner = ScopedEnforcementPlanner::with_protective_action_profile(
        mode,
        effective_selector.as_ref(),
        protective_actions,
    )?;
    Ok(ConfiguredEnforcement {
        planner,
        mode,
        effective_selector_configured: effective_selector.is_some(),
        config_selector_configured,
        manifest_selector_configured: policy_source
            .as_ref()
            .map(|source| source.manifest.selector.is_some()),
        policy_source,
    })
}

fn effective_selector(
    config_selector: Option<Selector>,
    policy_selector: Option<Selector>,
) -> Option<Selector> {
    match (config_selector, policy_selector) {
        (Some(config), Some(policy)) => Some(Selector::All {
            selectors: vec![config, policy],
        }),
        (Some(selector), None) | (None, Some(selector)) => Some(selector),
        (None, None) => None,
    }
}

mod source;

pub use source::{LoadedEnforcementPolicySource, inspect_enforcement_policy_source};

use enforcement::{EnforcementError, ScopedEnforcementPlanner};
use probe_core::{EnforcementMode, ProtectiveActionProfile, Selector};
use runtime::RuntimePlan;
use thiserror::Error;

use self::source::{EnforcementPolicySourceError, load_enforcement_policy_source};

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

pub fn build_configured_enforcement(
    plan: &RuntimePlan,
) -> Result<ConfiguredEnforcement, ConfiguredEnforcementError> {
    let policy_source = load_enforcement_policy_source(&plan.enforcement.policy_source)?;
    let effective_selector = effective_selector(
        plan.config.enforcement.selector.clone(),
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
        plan.enforcement.mode,
        effective_selector.as_ref(),
        protective_actions,
    )?;
    Ok(ConfiguredEnforcement {
        planner,
        mode: plan.enforcement.mode,
        effective_selector_configured: effective_selector.is_some(),
        config_selector_configured: plan.enforcement.config_selector_configured,
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

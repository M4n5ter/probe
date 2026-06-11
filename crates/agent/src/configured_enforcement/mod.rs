use enforcement::{EnforcementError, ScopedEnforcementPlanner};
use probe_config::AgentConfig;
use probe_core::EnforcementMode;

pub struct ConfiguredEnforcement {
    pub planner: ScopedEnforcementPlanner,
    pub mode: EnforcementMode,
    pub selector_configured: bool,
}

pub fn build_configured_enforcement(
    config: &AgentConfig,
) -> Result<ConfiguredEnforcement, EnforcementError> {
    let planner = ScopedEnforcementPlanner::new(
        config.enforcement.mode,
        config.enforcement.selector.as_ref(),
    )?;
    Ok(ConfiguredEnforcement {
        planner,
        mode: config.enforcement.mode,
        selector_configured: config.enforcement.selector.is_some(),
    })
}

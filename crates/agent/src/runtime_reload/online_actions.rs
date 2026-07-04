use pipeline::PipelinePolicySet;
use probe_config::AgentConfig;
use runtime::RuntimePlan;

use crate::configured_enforcement::EnforcementRuntimeState;
use crate::control_plane_http::policy_source_load_context_from_plan;
use crate::enforcement_reload::{
    EnforcementReloadError, EnforcementReloadGate, PreparedEnforcementPolicyReload,
    prepare_enforcement_policy_reload,
};
use crate::policy_reload::{PolicyReloadGate, PreparedPolicyReload, prepare_policies_from_config};

use super::config_reload::{
    ConfigReloadApplyAction, ConfigReloadApplyActionOutcome, ConfigReloadPlanSnapshot,
    ConfigReloadSection,
};

pub(super) struct PreparedOnlineReloadActions<'a> {
    actions: Vec<PreparedOnlineReloadAction<'a>>,
}

enum PreparedOnlineReloadAction<'a> {
    Policies(PreparedPolicyReload),
    Enforcement {
        prepared: Box<PreparedEnforcementPolicyReload>,
        runtime_state: &'a EnforcementRuntimeState,
    },
}

pub(super) async fn prepare_online_reload_actions<'a>(
    plan: &ConfigReloadPlanSnapshot,
    candidate: &AgentConfig,
    current_plan: &RuntimePlan,
    applied_plan: &RuntimePlan,
    enforcement_runtime_state: Option<&'a EnforcementRuntimeState>,
) -> Result<PreparedOnlineReloadActions<'a>, ConfigReloadApplyAction> {
    let mut actions = Vec::new();
    if plan.includes_section(ConfigReloadSection::Policies) {
        actions.push(PreparedOnlineReloadAction::Policies(
            prepare_policies_from_config(
                candidate,
                policy_source_load_context_from_plan(current_plan),
            )
            .await
            .map_err(|error| {
                ConfigReloadApplyAction::ReloadPolicies(ConfigReloadApplyActionOutcome::Failed {
                    message: error.to_string(),
                })
            })?,
        ));
    }
    if plan.includes_section(ConfigReloadSection::Enforcement) {
        let runtime_state = enforcement_runtime_state.ok_or_else(|| {
            ConfigReloadApplyAction::ReloadEnforcementPolicy(
                ConfigReloadApplyActionOutcome::Failed {
                    message: EnforcementReloadError::RuntimeStateUnavailable.to_string(),
                },
            )
        })?;
        actions.push(PreparedOnlineReloadAction::Enforcement {
            prepared: Box::new(
                prepare_enforcement_policy_reload(applied_plan)
                    .await
                    .map_err(|error| {
                        ConfigReloadApplyAction::ReloadEnforcementPolicy(
                            ConfigReloadApplyActionOutcome::Failed {
                                message: error.to_string(),
                            },
                        )
                    })?,
            ),
            runtime_state,
        });
    }
    Ok(PreparedOnlineReloadActions { actions })
}

pub(super) async fn commit_online_reload_actions(
    prepared: PreparedOnlineReloadActions<'_>,
    policy_set: &PipelinePolicySet,
    policy_reload_gate: &PolicyReloadGate,
    enforcement_reload_gate: &EnforcementReloadGate,
) -> Vec<ConfigReloadApplyAction> {
    let mut outcomes = Vec::new();
    for action in prepared.actions {
        outcomes.push(match action {
            PreparedOnlineReloadAction::Policies(prepared) => {
                let summary = prepared.commit(policy_set, policy_reload_gate).await;
                ConfigReloadApplyAction::ReloadPolicies(
                    ConfigReloadApplyActionOutcome::Succeeded {
                        detail: format!(
                            "loaded {} policy bundle(s), active set updated: {}",
                            summary.loaded_count, summary.active_set_updated
                        ),
                    },
                )
            }
            PreparedOnlineReloadAction::Enforcement {
                prepared,
                runtime_state,
            } => {
                let summary = prepared
                    .commit(runtime_state, enforcement_reload_gate)
                    .await;
                ConfigReloadApplyAction::ReloadEnforcementPolicy(
                    ConfigReloadApplyActionOutcome::Succeeded {
                        detail: format!(
                            "active enforcement policy reloaded, effective selector configured: {}, protective actions: {:?}",
                            summary.active_policy.effective_selector_configured(),
                            summary.active_policy.protective_actions()
                        ),
                    },
                )
            }
        });
    }
    outcomes
}

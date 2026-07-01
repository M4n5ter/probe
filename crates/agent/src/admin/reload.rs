use runtime::RuntimePlan;

use super::{
    protocol::{
        AdminResponse, EnforcementPolicyReloadSuccess, PolicyReloadSuccess,
        RuntimeReloadActionResult, RuntimeReloadEnforcementOutcome, RuntimeReloadPolicyOutcome,
        enforcement_policy_reload_source,
    },
    server::AdminRuntimeState,
};
use crate::{enforcement_reload::reload_enforcement_policy, policy_reload::reload_policies};

const RUNTIME_RELOAD_ACTIONS: [RuntimeReloadAction; 2] = [
    RuntimeReloadAction::ReloadPolicies,
    RuntimeReloadAction::ReloadEnforcementPolicy,
];

#[derive(Debug, Clone, Copy)]
pub(super) enum RuntimeReloadAction {
    ReloadPolicies,
    ReloadEnforcementPolicy,
}

impl RuntimeReloadAction {
    async fn run(
        self,
        plan: &RuntimePlan,
        runtime_state: &AdminRuntimeState,
    ) -> RuntimeReloadActionResult {
        match self {
            Self::ReloadPolicies => RuntimeReloadActionResult::ReloadPolicies(
                reload_policies_outcome(plan, runtime_state).await,
            ),
            Self::ReloadEnforcementPolicy => RuntimeReloadActionResult::ReloadEnforcementPolicy(
                reload_enforcement_policy_outcome(plan, runtime_state).await,
            ),
        }
    }
}

pub(super) async fn reload_action_response(
    action: RuntimeReloadAction,
    plan: &RuntimePlan,
    runtime_state: &AdminRuntimeState,
) -> AdminResponse {
    match action.run(plan, runtime_state).await {
        RuntimeReloadActionResult::ReloadPolicies(RuntimeReloadPolicyOutcome::Succeeded(
            success,
        )) => AdminResponse::PolicyReload(success),
        RuntimeReloadActionResult::ReloadPolicies(RuntimeReloadPolicyOutcome::Failed {
            message,
        })
        | RuntimeReloadActionResult::ReloadEnforcementPolicy(
            RuntimeReloadEnforcementOutcome::Failed { message },
        ) => AdminResponse::Error { message },
        RuntimeReloadActionResult::ReloadEnforcementPolicy(
            RuntimeReloadEnforcementOutcome::Succeeded(success),
        ) => AdminResponse::EnforcementPolicyReload(success),
    }
}

pub(super) async fn reload_runtime_actions_response(
    plan: &RuntimePlan,
    runtime_state: &AdminRuntimeState,
) -> AdminResponse {
    let [policy_action, enforcement_action] = RUNTIME_RELOAD_ACTIONS;
    let (policy_result, enforcement_result) = tokio::join!(
        policy_action.run(plan, runtime_state),
        enforcement_action.run(plan, runtime_state)
    );
    AdminResponse::RuntimeActionsReload {
        actions: vec![policy_result, enforcement_result],
    }
}

async fn reload_policies_outcome(
    plan: &RuntimePlan,
    runtime_state: &AdminRuntimeState,
) -> RuntimeReloadPolicyOutcome {
    match reload_policies(
        plan,
        &runtime_state.policy_set,
        &runtime_state.policy_reload_gate,
    )
    .await
    {
        Ok(summary) => RuntimeReloadPolicyOutcome::Succeeded(PolicyReloadSuccess {
            loaded_count: summary.loaded_count,
            policies: summary.policies,
            active_set_updated: summary.active_set_updated,
        }),
        Err(source) => RuntimeReloadPolicyOutcome::Failed {
            message: format!("failed to reload policies: {source}"),
        },
    }
}

async fn reload_enforcement_policy_outcome(
    plan: &RuntimePlan,
    runtime_state: &AdminRuntimeState,
) -> RuntimeReloadEnforcementOutcome {
    match reload_enforcement_policy(
        plan,
        runtime_state.enforcement.as_ref(),
        &runtime_state.enforcement_reload_gate,
    )
    .await
    {
        Ok(summary) => RuntimeReloadEnforcementOutcome::Succeeded(EnforcementPolicyReloadSuccess {
            source: enforcement_policy_reload_source(&summary.active_policy),
            effective_selector_configured: summary.active_policy.effective_selector_configured(),
            manifest_selector_configured: summary.active_policy.manifest_selector_configured(),
            protective_actions: summary.active_policy.protective_actions().clone(),
        }),
        Err(source) => RuntimeReloadEnforcementOutcome::Failed {
            message: format!("failed to reload enforcement policy: {source}"),
        },
    }
}

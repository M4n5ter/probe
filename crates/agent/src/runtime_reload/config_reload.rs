use std::path::{Path, PathBuf};

use pipeline::PipelinePolicySet;
use probe_config::{
    AgentConfig, ConfigError, EnforcementConfig, EnforcementPolicyConfig,
    EnforcementPolicyReloadConfig, TlsConfig, TlsMaterialConfig, TlsMaterialKind,
};
use runtime::{
    OnlineEnforcementPolicyConfigUpdate, OnlineExportConfigUpdate, OnlineReloadConfigUpdate,
    RuntimePlan, validate_static_runtime_config,
};
use serde::{Deserialize, Serialize};

use crate::artifacts::normalize_embedded_artifact_paths_for_comparison;
use crate::configured_enforcement::EnforcementRuntimeState;
use crate::control_plane_http::policy_source_load_context_from_plan;
use crate::enforcement_reload::{EnforcementReloadGate, reload_enforcement_policy};
use crate::policy_reload::{PolicyReloadGate, reload_policies_from_config};
use crate::runtime_generation::{RuntimeGenerationReloadRequestInput, RuntimeGenerationState};
use crate::runtime_plan::RuntimePlanHandle;

use super::RuntimeReloadGate;

const MAX_CANDIDATE_CONFIG_BYTES: u64 = 1024 * 1024;

const CONFIG_RELOAD_SECTIONS: [ConfigReloadSectionSpec; 12] = [
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::AgentIdentity,
        reason: "agent identity and event config_version are bound into status, audit, and durable event metadata",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Capture,
        reason: "capture provider generations are rebuilt and swapped at live capture safe points",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Observations,
        reason: "process observation profiles project into capture provider selection and deep observation selectors, so they are applied through capture provider generation swaps",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Storage,
        reason: "durable spool path is owned by the running process; retention changes can apply online only when the path is unchanged",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Export,
        reason: "export worker lifecycle reconciles the active export plan online",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::RuntimeReload,
        reason: "runtime config reload watcher topology is created from the startup plan",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::PolicyReload,
        reason: "policy reload watcher and poller topology is created from the startup plan",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Policies,
        reason: "pipeline policy slots are scoped by the startup plan; reload_policies only refreshes configured sources",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Selectors,
        reason: "selectors feed capture, policy, enforcement, and interception planning boundaries",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Tls,
        reason: "TLS materials and plaintext instrumentation are resolved before provider construction",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Enforcement,
        reason: "enforcement backend, transparent rules, and MITM lifecycle ownership are setup-time resources",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Admin,
        reason: "admin socket and Prometheus listener are bound by the running admin server",
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct ConfigReloadPlanSnapshot {
    pub candidate_path: PathBuf,
    pub current_config_version: String,
    pub candidate_config_version: Option<String>,
    pub decision: ConfigReloadDecision,
    pub changed_sections: Vec<ConfigReloadSectionChange>,
    pub reloadable_runtime_actions: Vec<ConfigReloadRuntimeAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum ConfigReloadDecision {
    NoChange,
    ApplyOnline { reason: String },
    QueueRuntimeGeneration { reason: String },
    RestartRequired { reason: String },
    InvalidCandidate { stage: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct ConfigReloadSectionChange {
    pub section: ConfigReloadSection,
    pub reload_mode: ConfigReloadSectionReloadMode,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigReloadSection {
    AgentIdentity,
    Capture,
    Observations,
    Storage,
    Export,
    RuntimeReload,
    PolicyReload,
    Policies,
    Selectors,
    Tls,
    Enforcement,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigReloadSectionReloadMode {
    ApplyOnline,
    RuntimeGeneration,
    ProcessRestart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigReloadRuntimeAction {
    ReloadPolicies,
    ReloadEnforcementPolicy,
    RequestRuntimeGeneration,
}

#[derive(Debug)]
pub(crate) struct ConfigReloadApplyOutcome {
    pub snapshot: ConfigReloadApplySnapshot,
    completion: ConfigReloadApplyCompletion,
}

#[derive(Debug)]
enum ConfigReloadApplyCompletion {
    None,
    ReplacePlan(Box<RuntimePlan>),
    RequestRuntimeGeneration(Box<RuntimeGenerationReloadRequestInput>),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct ConfigReloadApplySnapshot {
    pub plan: ConfigReloadPlanSnapshot,
    pub actions: Vec<ConfigReloadApplyAction>,
    pub active_plan_updated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "action", content = "outcome")]
pub(crate) enum ConfigReloadApplyAction {
    ReloadPolicies(ConfigReloadApplyActionOutcome),
    ReloadEnforcementPolicy(ConfigReloadApplyActionOutcome),
    RequestRuntimeGeneration(ConfigReloadRuntimeGenerationActionOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub(crate) enum ConfigReloadApplyActionOutcome {
    Succeeded { detail: String },
    Failed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub(crate) enum ConfigReloadRuntimeGenerationActionOutcome {
    Queued { detail: String, request_id: u64 },
    Busy { message: String },
    Failed { message: String },
}

pub(crate) fn complete_config_reload_apply(
    mut outcome: ConfigReloadApplyOutcome,
    plan_handle: &RuntimePlanHandle,
    runtime_generation: Option<&RuntimeGenerationState>,
) -> ConfigReloadApplySnapshot {
    match outcome.completion {
        ConfigReloadApplyCompletion::None => {}
        ConfigReloadApplyCompletion::ReplacePlan(applied_plan) => {
            plan_handle.replace(*applied_plan);
            outcome.snapshot.active_plan_updated = true;
        }
        ConfigReloadApplyCompletion::RequestRuntimeGeneration(request) => {
            outcome.snapshot.actions.push(
                match runtime_generation
                    .map(|runtime_generation| runtime_generation.request_reload(*request))
                {
                    Some(Ok(request)) => ConfigReloadApplyAction::RequestRuntimeGeneration(
                        ConfigReloadRuntimeGenerationActionOutcome::Queued {
                            request_id: request.request_id,
                            detail: format!(
                                "runtime generation reload request {} queued for {}",
                                request.request_id,
                                request
                                    .candidate_config_version
                                    .as_deref()
                                    .unwrap_or("<unknown config_version>")
                            ),
                        },
                    ),
                    Some(Err(error)) => ConfigReloadApplyAction::RequestRuntimeGeneration(
                        ConfigReloadRuntimeGenerationActionOutcome::Busy {
                            message: error.to_string(),
                        },
                    ),
                    None => ConfigReloadApplyAction::RequestRuntimeGeneration(
                        ConfigReloadRuntimeGenerationActionOutcome::Failed {
                            message: "runtime generation owner is unavailable".to_string(),
                        },
                    ),
                },
            );
        }
    }
    outcome.snapshot
}

pub(crate) struct ConfigReloadApplyRuntime<'a> {
    pub(crate) plan_handle: &'a RuntimePlanHandle,
    pub(crate) config_apply_gate: &'a RuntimeReloadGate,
    pub(crate) policy_set: &'a PipelinePolicySet,
    pub(crate) policy_reload_gate: &'a PolicyReloadGate,
    pub(crate) enforcement_runtime_state: Option<&'a EnforcementRuntimeState>,
    pub(crate) enforcement_reload_gate: &'a EnforcementReloadGate,
    pub(crate) runtime_generation: Option<&'a RuntimeGenerationState>,
}

pub(crate) async fn apply_config_reload_to_runtime(
    runtime: ConfigReloadApplyRuntime<'_>,
    candidate_path: &Path,
) -> ConfigReloadApplySnapshot {
    let _apply_guard = runtime.config_apply_gate.lock().await;
    let plan = runtime.plan_handle.snapshot();
    let outcome = apply_config_reload(
        plan.as_ref(),
        runtime.policy_set,
        runtime.policy_reload_gate,
        runtime.enforcement_runtime_state,
        runtime.enforcement_reload_gate,
        candidate_path,
    )
    .await;
    complete_config_reload_apply(outcome, runtime.plan_handle, runtime.runtime_generation)
}

#[derive(Debug, Clone, Copy)]
struct ConfigReloadSectionSpec {
    section: ConfigReloadSection,
    reason: &'static str,
}

#[derive(Debug)]
struct LoadedConfigReloadPlan {
    snapshot: ConfigReloadPlanSnapshot,
    candidate: AgentConfig,
}

pub(crate) fn plan_config_reload(
    current: &AgentConfig,
    candidate_path: &Path,
) -> ConfigReloadPlanSnapshot {
    match load_config_reload_plan(current, candidate_path) {
        Ok(loaded) => loaded.snapshot,
        Err(plan) => *plan,
    }
}

fn load_config_reload_plan(
    current: &AgentConfig,
    candidate_path: &Path,
) -> Result<LoadedConfigReloadPlan, Box<ConfigReloadPlanSnapshot>> {
    let candidate = load_candidate_config(current, candidate_path)?;
    let snapshot = plan_config_reload_for_candidate(current, candidate_path, &candidate);
    Ok(LoadedConfigReloadPlan {
        snapshot,
        candidate,
    })
}

pub(crate) fn plan_config_reload_for_candidate(
    current: &AgentConfig,
    candidate_path: &Path,
    candidate: &AgentConfig,
) -> ConfigReloadPlanSnapshot {
    let candidate_config_version = Some(candidate.config_version.clone());
    let mut comparable_current = current.clone();
    let mut comparable_candidate = candidate.clone();
    normalize_embedded_artifact_paths_for_comparison(&mut comparable_current);
    normalize_embedded_artifact_paths_for_comparison(&mut comparable_candidate);
    let changed_sections = changed_sections(&comparable_current, &comparable_candidate);
    let decision = config_reload_decision(&changed_sections);
    ConfigReloadPlanSnapshot {
        candidate_path: candidate_path.to_path_buf(),
        current_config_version: current.config_version.clone(),
        candidate_config_version,
        decision,
        changed_sections,
        reloadable_runtime_actions: reloadable_runtime_actions(),
    }
}

pub(crate) async fn apply_config_reload(
    current_plan: &RuntimePlan,
    policy_set: &PipelinePolicySet,
    policy_reload_gate: &PolicyReloadGate,
    enforcement_runtime_state: Option<&EnforcementRuntimeState>,
    enforcement_reload_gate: &EnforcementReloadGate,
    candidate_path: &Path,
) -> ConfigReloadApplyOutcome {
    let loaded = match load_config_reload_plan(&current_plan.config, candidate_path) {
        Ok(loaded) => loaded,
        Err(plan) => {
            return ConfigReloadApplyOutcome {
                snapshot: ConfigReloadApplySnapshot {
                    plan: *plan,
                    actions: Vec::new(),
                    active_plan_updated: false,
                },
                completion: ConfigReloadApplyCompletion::None,
            };
        }
    };
    let LoadedConfigReloadPlan {
        snapshot: plan,
        candidate,
    } = loaded;
    match &plan.decision {
        ConfigReloadDecision::QueueRuntimeGeneration { .. } => {
            let runtime_generation_request = runtime_generation_reload_request(&plan, &candidate);
            return ConfigReloadApplyOutcome {
                snapshot: ConfigReloadApplySnapshot {
                    plan,
                    actions: Vec::new(),
                    active_plan_updated: false,
                },
                completion: runtime_generation_request.map_or(
                    ConfigReloadApplyCompletion::None,
                    |request| {
                        ConfigReloadApplyCompletion::RequestRuntimeGeneration(Box::new(request))
                    },
                ),
            };
        }
        ConfigReloadDecision::ApplyOnline { .. } => {}
        ConfigReloadDecision::NoChange
        | ConfigReloadDecision::RestartRequired { .. }
        | ConfigReloadDecision::InvalidCandidate { .. } => {
            return ConfigReloadApplyOutcome {
                snapshot: ConfigReloadApplySnapshot {
                    plan,
                    actions: Vec::new(),
                    active_plan_updated: false,
                },
                completion: ConfigReloadApplyCompletion::None,
            };
        }
    }

    let Some(online_update) = online_reload_config_update(&plan, &candidate) else {
        return ConfigReloadApplyOutcome {
            snapshot: ConfigReloadApplySnapshot {
                plan,
                actions: Vec::new(),
                active_plan_updated: false,
            },
            completion: ConfigReloadApplyCompletion::None,
        };
    };
    let applied_plan = online_applied_plan(current_plan, online_update);

    let mut actions = Vec::new();
    if plan
        .changed_sections
        .iter()
        .any(|change| change.section == ConfigReloadSection::Policies)
    {
        actions.push(
            match reload_policies_from_config(
                &candidate,
                policy_source_load_context_from_plan(current_plan),
                policy_set,
                policy_reload_gate,
            )
            .await
            {
                Ok(summary) => ConfigReloadApplyAction::ReloadPolicies(
                    ConfigReloadApplyActionOutcome::Succeeded {
                        detail: format!(
                            "loaded {} policy bundle(s), active set updated: {}",
                            summary.loaded_count, summary.active_set_updated
                        ),
                    },
                ),
                Err(error) => ConfigReloadApplyAction::ReloadPolicies(
                    ConfigReloadApplyActionOutcome::Failed {
                        message: error.to_string(),
                    },
                ),
            },
        );
    }
    if plan
        .changed_sections
        .iter()
        .any(|change| change.section == ConfigReloadSection::Enforcement)
    {
        actions.push(
            match reload_enforcement_policy(
                &applied_plan,
                enforcement_runtime_state,
                enforcement_reload_gate,
            )
            .await
            {
                Ok(summary) => ConfigReloadApplyAction::ReloadEnforcementPolicy(
                    ConfigReloadApplyActionOutcome::Succeeded {
                        detail: format!(
                            "active enforcement policy reloaded, effective selector configured: {}, protective actions: {:?}",
                            summary.active_policy.effective_selector_configured(),
                            summary.active_policy.protective_actions()
                        ),
                    },
                ),
                Err(error) => ConfigReloadApplyAction::ReloadEnforcementPolicy(
                    ConfigReloadApplyActionOutcome::Failed {
                        message: error.to_string(),
                    },
                ),
            },
        );
    }

    if actions.iter().any(|action| {
        matches!(
            action,
            ConfigReloadApplyAction::ReloadPolicies(ConfigReloadApplyActionOutcome::Failed { .. })
                | ConfigReloadApplyAction::ReloadEnforcementPolicy(
                    ConfigReloadApplyActionOutcome::Failed { .. }
                )
        )
    }) {
        return ConfigReloadApplyOutcome {
            snapshot: ConfigReloadApplySnapshot {
                plan,
                actions,
                active_plan_updated: false,
            },
            completion: ConfigReloadApplyCompletion::None,
        };
    }

    ConfigReloadApplyOutcome {
        snapshot: ConfigReloadApplySnapshot {
            plan,
            actions,
            active_plan_updated: false,
        },
        completion: ConfigReloadApplyCompletion::ReplacePlan(Box::new(applied_plan)),
    }
}

fn online_reload_config_update(
    plan: &ConfigReloadPlanSnapshot,
    candidate: &AgentConfig,
) -> Option<OnlineReloadConfigUpdate> {
    let mut update = OnlineReloadConfigUpdate::default();
    for change in &plan.changed_sections {
        if change.reload_mode != ConfigReloadSectionReloadMode::ApplyOnline {
            return None;
        }
        match change.section {
            ConfigReloadSection::Policies => {
                update.policies = Some(candidate.policies.clone());
            }
            ConfigReloadSection::Export => {
                update.export = Some(OnlineExportConfigUpdate {
                    export: candidate.export.clone(),
                    exporters: candidate.exporters.clone(),
                });
            }
            ConfigReloadSection::Storage => {
                update.storage_retention = Some(candidate.storage.retention.clone());
            }
            ConfigReloadSection::Enforcement => {
                update.enforcement_policy = Some(OnlineEnforcementPolicyConfigUpdate {
                    selector: candidate.enforcement.selector.clone(),
                    source: candidate.enforcement.policy.source.clone(),
                });
            }
            _ => return None,
        }
    }
    (!update.is_empty()).then_some(update)
}

fn online_applied_plan(
    current_plan: &RuntimePlan,
    update: OnlineReloadConfigUpdate,
) -> RuntimePlan {
    current_plan.with_online_reload_update(update)
}

fn load_candidate_config(
    current: &AgentConfig,
    candidate_path: &Path,
) -> Result<AgentConfig, Box<ConfigReloadPlanSnapshot>> {
    let candidate_content = match probe_io::read_bounded_regular_file_to_string(
        candidate_path,
        MAX_CANDIDATE_CONFIG_BYTES,
    ) {
        Ok(content) => content,
        Err(error) => {
            return Err(Box::new(invalid_plan(
                current,
                candidate_path,
                "read",
                format!("failed to read candidate config: {error}"),
                None,
            )));
        }
    };
    let candidate = match AgentConfig::from_toml_str(&candidate_content) {
        Ok(config) => config,
        Err(error) => {
            return Err(Box::new(invalid_plan(
                current,
                candidate_path,
                "parse",
                describe_parse_error(error),
                None,
            )));
        }
    };
    let candidate_config_version = Some(candidate.config_version.clone());
    match validate_static_runtime_config(&candidate) {
        Ok(()) => Ok(candidate),
        Err(error) => Err(Box::new(invalid_plan(
            current,
            candidate_path,
            "validate",
            format!("candidate config failed static runtime validation: {error}"),
            candidate_config_version,
        ))),
    }
}

fn invalid_plan(
    current: &AgentConfig,
    candidate_path: &Path,
    stage: &'static str,
    reason: String,
    candidate_config_version: Option<String>,
) -> ConfigReloadPlanSnapshot {
    ConfigReloadPlanSnapshot {
        candidate_path: candidate_path.to_path_buf(),
        current_config_version: current.config_version.clone(),
        candidate_config_version,
        decision: ConfigReloadDecision::InvalidCandidate {
            stage: stage.to_string(),
            reason,
        },
        changed_sections: Vec::new(),
        reloadable_runtime_actions: reloadable_runtime_actions(),
    }
}

fn describe_parse_error(error: ConfigError) -> String {
    match error {
        ConfigError::Toml(error) => match error.span() {
            Some(span) => format!(
                "failed to parse candidate config TOML: {}; byte span {}..{}",
                error.message(),
                span.start,
                span.end
            ),
            None => format!("failed to parse candidate config TOML: {}", error.message()),
        },
        ConfigError::Validation(error) => {
            format!("candidate config failed validation during parse: {error}")
        }
    }
}

fn changed_sections(
    current: &AgentConfig,
    candidate: &AgentConfig,
) -> Vec<ConfigReloadSectionChange> {
    CONFIG_RELOAD_SECTIONS
        .into_iter()
        .filter(|spec| section_changed(spec.section, current, candidate))
        .map(|spec| ConfigReloadSectionChange {
            section: spec.section,
            reload_mode: section_reload_mode(spec.section, current, candidate),
            reason: section_change_reason(spec.section, current, candidate, spec.reason)
                .to_string(),
        })
        .collect()
}

fn section_reload_mode(
    section: ConfigReloadSection,
    current: &AgentConfig,
    candidate: &AgentConfig,
) -> ConfigReloadSectionReloadMode {
    match section {
        ConfigReloadSection::AgentIdentity
            if agent_identity_can_use_runtime_generation(current, candidate) =>
        {
            ConfigReloadSectionReloadMode::RuntimeGeneration
        }
        ConfigReloadSection::Capture | ConfigReloadSection::Observations => {
            ConfigReloadSectionReloadMode::RuntimeGeneration
        }
        ConfigReloadSection::Policies if policies_can_apply_online(current, candidate) => {
            ConfigReloadSectionReloadMode::ApplyOnline
        }
        ConfigReloadSection::Storage if storage_can_apply_online(current, candidate) => {
            ConfigReloadSectionReloadMode::ApplyOnline
        }
        ConfigReloadSection::Export => ConfigReloadSectionReloadMode::ApplyOnline,
        ConfigReloadSection::Tls if tls_can_use_runtime_generation(current, candidate) => {
            ConfigReloadSectionReloadMode::RuntimeGeneration
        }
        ConfigReloadSection::Enforcement if enforcement_can_apply_online(current, candidate) => {
            ConfigReloadSectionReloadMode::ApplyOnline
        }
        _ => ConfigReloadSectionReloadMode::ProcessRestart,
    }
}

fn section_change_reason(
    section: ConfigReloadSection,
    current: &AgentConfig,
    candidate: &AgentConfig,
    default_reason: &'static str,
) -> &'static str {
    match section {
        ConfigReloadSection::AgentIdentity
            if agent_identity_can_use_runtime_generation(current, candidate) =>
        {
            "config_version is applied by runtime generation swaps while agent_id remains setup-time"
        }
        ConfigReloadSection::Policies if policies_can_apply_online(current, candidate) => {
            "pipeline policy set is owned by an online reload gate"
        }
        ConfigReloadSection::Policies => {
            "policy watcher or poller topology is still owned by startup background services"
        }
        ConfigReloadSection::Storage if storage_can_apply_online(current, candidate) => {
            "durable spool path is setup-time; storage retention is reconciled by a plan-aware online worker"
        }
        ConfigReloadSection::Export => {
            "export worker lifecycle and export retention cursor owners reconcile the active export plan online"
        }
        ConfigReloadSection::Tls if tls_can_use_runtime_generation(current, candidate) => {
            "TLS plaintext instrumentation and decrypt hint materials are rebuilt by runtime generation swaps"
        }
        ConfigReloadSection::Enforcement if enforcement_can_apply_online(current, candidate) => {
            "enforcement policy source and enforcement.selector are owned by an online reload gate"
        }
        ConfigReloadSection::Enforcement => {
            "enforcement mode, backend, interception, or reload topology is still owned by setup-time services"
        }
        _ => default_reason,
    }
}

fn config_reload_decision(changed_sections: &[ConfigReloadSectionChange]) -> ConfigReloadDecision {
    if changed_sections.is_empty() {
        ConfigReloadDecision::NoChange
    } else if changed_sections_can_apply_online(changed_sections) {
        ConfigReloadDecision::ApplyOnline {
            reason: "changed sections are owned by runtime reload gates".to_string(),
        }
    } else if changed_sections_can_use_runtime_generation(changed_sections) {
        ConfigReloadDecision::QueueRuntimeGeneration {
            reason: "changed sections are owned by capture provider generation swaps".to_string(),
        }
    } else {
        ConfigReloadDecision::RestartRequired {
            reason: "candidate config passed static validation, but at least one changed runtime resource is still owned by setup-time services".to_string(),
        }
    }
}

fn changed_sections_can_apply_online(changed_sections: &[ConfigReloadSectionChange]) -> bool {
    let Some((first, rest)) = changed_sections.split_first() else {
        return false;
    };
    let Some(first_owner) = online_reload_owner(first) else {
        return false;
    };
    if first_owner == ConfigReloadOnlineOwner::ActionGated {
        return rest.is_empty();
    }
    rest.iter()
        .all(|change| online_reload_owner(change) == Some(ConfigReloadOnlineOwner::PlanOnly))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfigReloadOnlineOwner {
    PlanOnly,
    ActionGated,
}

fn online_reload_owner(change: &ConfigReloadSectionChange) -> Option<ConfigReloadOnlineOwner> {
    if change.reload_mode != ConfigReloadSectionReloadMode::ApplyOnline {
        return None;
    }
    match change.section {
        ConfigReloadSection::Export | ConfigReloadSection::Storage => {
            Some(ConfigReloadOnlineOwner::PlanOnly)
        }
        ConfigReloadSection::Policies | ConfigReloadSection::Enforcement => {
            Some(ConfigReloadOnlineOwner::ActionGated)
        }
        _ => None,
    }
}

fn changed_sections_can_use_runtime_generation(
    changed_sections: &[ConfigReloadSectionChange],
) -> bool {
    !changed_sections.is_empty()
        && changed_sections
            .iter()
            .all(section_can_use_runtime_generation)
}

fn agent_identity_can_use_runtime_generation(
    current: &AgentConfig,
    candidate: &AgentConfig,
) -> bool {
    current.agent_id == candidate.agent_id && current.config_version != candidate.config_version
}

fn policies_can_apply_online(current: &AgentConfig, candidate: &AgentConfig) -> bool {
    current.policy_reload == candidate.policy_reload
        && !current.policy_reload.watch_local_bundles
        && !current.policy_reload.poll_remote_bundles
}

fn storage_can_apply_online(current: &AgentConfig, candidate: &AgentConfig) -> bool {
    current.storage.path == candidate.storage.path
        && current.storage.retention != candidate.storage.retention
}

fn enforcement_can_apply_online(current: &AgentConfig, candidate: &AgentConfig) -> bool {
    let EnforcementConfig {
        mode: current_mode,
        backend: current_backend,
        selector: _,
        interception: current_interception,
        policy: current_policy,
    } = &current.enforcement;
    let EnforcementConfig {
        mode: candidate_mode,
        backend: candidate_backend,
        selector: _,
        interception: candidate_interception,
        policy: candidate_policy,
    } = &candidate.enforcement;
    let EnforcementPolicyConfig {
        source: _,
        reload: current_reload,
    } = current_policy;
    let EnforcementPolicyConfig {
        source: _,
        reload: candidate_reload,
    } = candidate_policy;

    current_mode == candidate_mode
        && current_backend == candidate_backend
        && current_interception == candidate_interception
        && !current_interception.strategy.is_enabled()
        && enforcement_reload_topology_can_apply_online(current_reload, candidate_reload)
}

fn enforcement_reload_topology_can_apply_online(
    current: &EnforcementPolicyReloadConfig,
    candidate: &EnforcementPolicyReloadConfig,
) -> bool {
    let EnforcementPolicyReloadConfig {
        watch_local_manifest: current_watch_local_manifest,
        debounce_ms: current_debounce_ms,
        poll_remote_manifest: current_poll_remote_manifest,
        remote_poll_interval_ms: current_remote_poll_interval_ms,
    } = current;
    let EnforcementPolicyReloadConfig {
        watch_local_manifest: candidate_watch_local_manifest,
        debounce_ms: candidate_debounce_ms,
        poll_remote_manifest: candidate_poll_remote_manifest,
        remote_poll_interval_ms: candidate_remote_poll_interval_ms,
    } = candidate;

    current_watch_local_manifest == candidate_watch_local_manifest
        && current_debounce_ms == candidate_debounce_ms
        && current_poll_remote_manifest == candidate_poll_remote_manifest
        && current_remote_poll_interval_ms == candidate_remote_poll_interval_ms
        && !*current_watch_local_manifest
        && !*current_poll_remote_manifest
}

fn tls_can_use_runtime_generation(current: &AgentConfig, candidate: &AgentConfig) -> bool {
    tls_setup_time_view(&current.tls) == tls_setup_time_view(&candidate.tls)
}

fn tls_setup_time_view(tls: &TlsConfig) -> TlsSetupTimeView<'_> {
    let setup_time_materials = tls
        .materials
        .iter()
        .filter(|material| tls_material_has_setup_time_owner(material))
        .collect::<Vec<_>>();
    let material_store = (!setup_time_materials.is_empty()).then_some(&tls.material_store);
    TlsSetupTimeView {
        material_store,
        setup_time_materials,
    }
}

fn tls_material_has_setup_time_owner(material: &TlsMaterialConfig) -> bool {
    !matches!(
        material.kind,
        TlsMaterialKind::KeyLogFile | TlsMaterialKind::SessionSecretFile
    )
}

#[derive(Debug, PartialEq, Eq)]
struct TlsSetupTimeView<'a> {
    material_store: Option<&'a probe_config::TlsMaterialStoreConfig>,
    setup_time_materials: Vec<&'a TlsMaterialConfig>,
}

fn section_changed(
    section: ConfigReloadSection,
    current: &AgentConfig,
    candidate: &AgentConfig,
) -> bool {
    match section {
        ConfigReloadSection::AgentIdentity => {
            current.agent_id != candidate.agent_id
                || current.config_version != candidate.config_version
        }
        ConfigReloadSection::Capture => current.capture != candidate.capture,
        ConfigReloadSection::Observations => current.observations != candidate.observations,
        ConfigReloadSection::Storage => current.storage != candidate.storage,
        ConfigReloadSection::Export => {
            current.export != candidate.export || current.exporters != candidate.exporters
        }
        ConfigReloadSection::RuntimeReload => current.runtime_reload != candidate.runtime_reload,
        ConfigReloadSection::PolicyReload => current.policy_reload != candidate.policy_reload,
        ConfigReloadSection::Policies => current.policies != candidate.policies,
        ConfigReloadSection::Selectors => current.selectors != candidate.selectors,
        ConfigReloadSection::Tls => current.tls != candidate.tls,
        ConfigReloadSection::Enforcement => current.enforcement != candidate.enforcement,
        ConfigReloadSection::Admin => current.admin != candidate.admin,
    }
}

fn reloadable_runtime_actions() -> Vec<ConfigReloadRuntimeAction> {
    vec![
        ConfigReloadRuntimeAction::ReloadPolicies,
        ConfigReloadRuntimeAction::ReloadEnforcementPolicy,
        ConfigReloadRuntimeAction::RequestRuntimeGeneration,
    ]
}

pub(crate) fn runtime_generation_reload_request(
    plan: &ConfigReloadPlanSnapshot,
    candidate: &AgentConfig,
) -> Option<RuntimeGenerationReloadRequestInput> {
    if !matches!(
        plan.decision,
        ConfigReloadDecision::QueueRuntimeGeneration { .. }
    ) {
        return None;
    }
    let changed_sections = plan
        .changed_sections
        .iter()
        .filter(|change| section_can_use_runtime_generation(change))
        .map(|change| section_name(change.section).to_string())
        .collect::<Vec<_>>();
    (!changed_sections.is_empty()
        && plan
            .changed_sections
            .iter()
            .all(section_can_use_runtime_generation))
    .then(|| RuntimeGenerationReloadRequestInput {
        candidate_path: plan.candidate_path.clone(),
        candidate_config: candidate.clone(),
        current_config_version: plan.current_config_version.clone(),
        candidate_config_version: plan.candidate_config_version.clone(),
        changed_sections,
    })
}

fn section_can_use_runtime_generation(change: &ConfigReloadSectionChange) -> bool {
    change.reload_mode == ConfigReloadSectionReloadMode::RuntimeGeneration
}

fn section_name(section: ConfigReloadSection) -> &'static str {
    match section {
        ConfigReloadSection::AgentIdentity => "agent_identity",
        ConfigReloadSection::Capture => "capture",
        ConfigReloadSection::Observations => "observations",
        ConfigReloadSection::Storage => "storage",
        ConfigReloadSection::Export => "export",
        ConfigReloadSection::RuntimeReload => "runtime_reload",
        ConfigReloadSection::PolicyReload => "policy_reload",
        ConfigReloadSection::Policies => "policies",
        ConfigReloadSection::Selectors => "selectors",
        ConfigReloadSection::Tls => "tls",
        ConfigReloadSection::Enforcement => "enforcement",
        ConfigReloadSection::Admin => "admin",
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, net::TcpListener, path::PathBuf, sync::Arc};

    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementConfig,
        EnforcementInterceptionConfig, EnforcementPolicyConfig, EnforcementPolicySourceConfig,
        ExporterConfig, ExporterTransportConfig, IngressJournalRetentionConfig, LiveCaptureBackend,
        ObservationDataPathMode, PolicyConfig, PolicySourceConfig, ProcessObservationConfig,
        StorageConfig, StorageRetentionConfig, TlsConfig, TlsMaterialConfig, TlsMaterialKind,
        TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmClientTrustConfig,
        TransparentInterceptionMitmClientTrustModeConfig, TransparentInterceptionMitmConfig,
        TransparentInterceptionProxyConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, Direction, EnforcementMode, ProcessSelector, Selector,
        TrafficSelector,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };

    use super::*;

    #[test]
    fn config_reload_plan_reports_no_change_for_equivalent_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-no-change")?;
        let config = base_config(temp.join("spool"));
        let current = runtime_plan(config.clone())?;
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&config)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(matches!(plan.decision, ConfigReloadDecision::NoChange));
        assert!(plan.changed_sections.is_empty());
        assert_eq!(
            plan.reloadable_runtime_actions,
            vec![
                ConfigReloadRuntimeAction::ReloadPolicies,
                ConfigReloadRuntimeAction::ReloadEnforcementPolicy,
                ConfigReloadRuntimeAction::RequestRuntimeGeneration,
            ]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_compares_raw_config_when_observations_project_capture()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-observation-projection")?;
        let mut config = base_config(temp.join("spool"));
        config.observations.push(process_observation(
            "nginx",
            "/usr/sbin/nginx",
            ObservationDataPathMode::Libpcap,
        ));
        let current = runtime_plan(config.clone())?;
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&config)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(matches!(plan.decision, ConfigReloadDecision::NoChange));
        assert!(plan.changed_sections.is_empty());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_ignores_runtime_generated_process_observation_object_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-generated-object-path")?;
        let mut candidate = base_config(temp.join("spool"));
        candidate.capture.selection = CaptureSelection::Auto;
        let mut current = candidate.clone();
        current.capture.ebpf.object_path =
            Some(crate::artifacts::embedded_process_observation_object_path_for_test());
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current, &candidate_path);

        assert!(matches!(plan.decision, ConfigReloadDecision::NoChange));
        assert!(plan.changed_sections.is_empty());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_reports_restart_sections_for_valid_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-restart")?;
        let current_config = base_config(temp.join("spool"));
        let current = runtime_plan(current_config)?;
        let mut candidate = base_config(temp.join("spool"));
        candidate.config_version = "candidate".to_string();
        candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        candidate.exporters.push(ExporterConfig {
            id: "file".to_string(),
            transport: ExporterTransportConfig::File {
                path: temp.join("events.jsonl"),
            },
            ..ExporterConfig::default()
        });
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        let sections = plan
            .changed_sections
            .iter()
            .map(|change| change.section)
            .collect::<Vec<_>>();
        assert_eq!(
            sections,
            vec![
                ConfigReloadSection::AgentIdentity,
                ConfigReloadSection::Capture,
                ConfigReloadSection::Export,
            ]
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![
                (
                    ConfigReloadSection::AgentIdentity,
                    ConfigReloadSectionReloadMode::RuntimeGeneration,
                ),
                (
                    ConfigReloadSection::Capture,
                    ConfigReloadSectionReloadMode::RuntimeGeneration,
                ),
                (
                    ConfigReloadSection::Export,
                    ConfigReloadSectionReloadMode::ApplyOnline,
                ),
            ]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_reports_process_observation_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-observation-change")?;
        let mut current_config = base_config(temp.join("spool"));
        current_config.observations.push(process_observation(
            "backend",
            "/usr/bin/backend",
            ObservationDataPathMode::Libpcap,
        ));
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.observations = vec![process_observation(
            "worker",
            "/usr/bin/worker",
            ObservationDataPathMode::Libpcap,
        )];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(
                plan.decision,
                ConfigReloadDecision::QueueRuntimeGeneration { .. }
            ),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| change.section)
                .collect::<Vec<_>>(),
            vec![ConfigReloadSection::Observations]
        );
        assert!(
            plan.changed_sections.iter().all(
                |change| change.reload_mode == ConfigReloadSectionReloadMode::RuntimeGeneration
            )
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_builds_runtime_generation_request_for_data_path_sections()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-generation-request")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);
        assert!(
            matches!(
                plan.decision,
                ConfigReloadDecision::QueueRuntimeGeneration { .. }
            ),
            "{:?}",
            plan.decision
        );
        let request = runtime_generation_reload_request(&plan, &candidate)
            .expect("capture-only rebuild should be eligible for generation queue");

        assert_eq!(
            request.current_config_version,
            current.config.config_version
        );
        assert_eq!(
            request.candidate_config_version,
            Some(candidate.config_version.clone())
        );
        assert_eq!(request.changed_sections, ["capture"]);
        assert_eq!(request.candidate_config, candidate);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_can_apply_storage_retention_changes_online()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-storage-retention-online")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.storage.retention = StorageRetentionConfig {
            ingress: IngressJournalRetentionConfig {
                max_age_ms: None,
                max_records: Some(100_000),
                sweep_interval_ms: 5_000,
                prune_batch_limit: 128,
            },
            ..StorageRetentionConfig::default()
        };
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::ApplyOnline { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Storage,
                ConfigReloadSectionReloadMode::ApplyOnline,
            )]
        );
        assert!(
            plan.changed_sections[0]
                .reason
                .contains("storage retention")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_keeps_storage_path_changes_restart_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-storage-path-restart")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.storage.path = temp.join("other-spool");
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Storage,
                ConfigReloadSectionReloadMode::ProcessRestart,
            )]
        );
        assert!(plan.changed_sections[0].reason.contains("spool path"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_can_apply_export_and_storage_retention_changes_online()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-plan-only-online")?;
        let mut current_config = base_config(temp.join("spool"));
        current_config.exporters = vec![webhook_exporter(
            "collector",
            "https://collector.example/probe/batches",
        )];
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.storage.retention = StorageRetentionConfig {
            ingress: IngressJournalRetentionConfig {
                max_age_ms: None,
                max_records: Some(100_000),
                sweep_interval_ms: 5_000,
                prune_batch_limit: 128,
            },
            ..StorageRetentionConfig::default()
        };
        candidate.exporters = vec![webhook_exporter(
            "collector",
            "https://collector.internal/probe/batches",
        )];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::ApplyOnline { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![
                (
                    ConfigReloadSection::Storage,
                    ConfigReloadSectionReloadMode::ApplyOnline,
                ),
                (
                    ConfigReloadSection::Export,
                    ConfigReloadSectionReloadMode::ApplyOnline,
                ),
            ]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_keeps_action_gated_and_plan_only_online_changes_restart_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-online-action-plan-mixed")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.storage.retention = StorageRetentionConfig {
            ingress: IngressJournalRetentionConfig {
                max_age_ms: None,
                max_records: Some(100_000),
                sweep_interval_ms: 5_000,
                prune_batch_limit: 128,
            },
            ..StorageRetentionConfig::default()
        };
        candidate.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: temp.join("guard.bundle"),
            },
            ..PolicyConfig::default()
        });
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![
                (
                    ConfigReloadSection::Storage,
                    ConfigReloadSectionReloadMode::ApplyOnline,
                ),
                (
                    ConfigReloadSection::Policies,
                    ConfigReloadSectionReloadMode::ApplyOnline,
                ),
            ]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_can_apply_export_config_changes_online()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-export-online")?;
        let mut current_config = base_config(temp.join("spool"));
        current_config.exporters = vec![webhook_exporter(
            "collector",
            "https://collector.example/probe/batches",
        )];
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.exporters = vec![webhook_exporter(
            "collector",
            "https://collector.internal/probe/batches",
        )];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(matches!(
            plan.decision,
            ConfigReloadDecision::ApplyOnline { .. }
        ));
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Export,
                ConfigReloadSectionReloadMode::ApplyOnline,
            )]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_can_apply_export_sink_id_changes_online()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-export-sink-ids")?;
        let mut current_config = base_config(temp.join("spool"));
        current_config.exporters = vec![webhook_exporter(
            "primary",
            "https://collector.example/probe/batches",
        )];
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.exporters.push(webhook_exporter(
            "secondary",
            "https://collector.internal/probe/batches",
        ));
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::ApplyOnline { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Export,
                ConfigReloadSectionReloadMode::ApplyOnline,
            )]
        );
        assert!(
            plan.changed_sections[0]
                .reason
                .contains("retention cursor owners")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_can_apply_first_exporter_online() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = test_dir("config-reload-first-exporter")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.exporters.push(webhook_exporter(
            "collector",
            "https://collector.example/probe/batches",
        ));
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::ApplyOnline { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Export,
                ConfigReloadSectionReloadMode::ApplyOnline,
            )]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn complete_config_reload_apply_replaces_plan_for_export_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-export-apply")?;
        let mut current_config = base_config(temp.join("spool"));
        current_config.exporters = vec![webhook_exporter(
            "collector",
            "https://collector.example/probe/batches",
        )];
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.exporters = vec![webhook_exporter(
            "collector",
            "https://collector.internal/probe/batches",
        )];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;
        let plan_handle = RuntimePlanHandle::new(Arc::new(current.clone()));

        let outcome = apply_config_reload(
            &current,
            &PipelinePolicySet::default(),
            &PolicyReloadGate::default(),
            None,
            &EnforcementReloadGate::default(),
            &candidate_path,
        )
        .await;
        let snapshot = complete_config_reload_apply(outcome, &plan_handle, None);

        assert!(snapshot.active_plan_updated);
        assert!(snapshot.actions.is_empty());
        assert_eq!(plan_handle.snapshot().config.exporters, candidate.exporters);
        assert_eq!(plan_handle.snapshot().export.sinks[0].id(), "collector");
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn complete_config_reload_apply_replaces_plan_for_storage_retention_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-storage-retention-apply")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.storage.retention = StorageRetentionConfig {
            ingress: IngressJournalRetentionConfig {
                max_age_ms: None,
                max_records: Some(100_000),
                sweep_interval_ms: 5_000,
                prune_batch_limit: 128,
            },
            ..StorageRetentionConfig::default()
        };
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;
        let plan_handle = RuntimePlanHandle::new(Arc::new(current.clone()));

        let outcome = apply_config_reload(
            &current,
            &PipelinePolicySet::default(),
            &PolicyReloadGate::default(),
            None,
            &EnforcementReloadGate::default(),
            &candidate_path,
        )
        .await;
        let snapshot = complete_config_reload_apply(outcome, &plan_handle, None);

        assert!(snapshot.active_plan_updated);
        assert!(snapshot.actions.is_empty());
        assert_eq!(
            plan_handle.snapshot().storage.retention.ingress.max_records,
            Some(100_000)
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn complete_config_reload_apply_replaces_plan_for_export_and_storage_retention_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-plan-only-apply")?;
        let mut current_config = base_config(temp.join("spool"));
        current_config.exporters = vec![webhook_exporter(
            "collector",
            "https://collector.example/probe/batches",
        )];
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.storage.retention = StorageRetentionConfig {
            ingress: IngressJournalRetentionConfig {
                max_age_ms: None,
                max_records: Some(100_000),
                sweep_interval_ms: 5_000,
                prune_batch_limit: 128,
            },
            ..StorageRetentionConfig::default()
        };
        candidate.exporters = vec![webhook_exporter(
            "collector",
            "https://collector.internal/probe/batches",
        )];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;
        let plan_handle = RuntimePlanHandle::new(Arc::new(current.clone()));

        let outcome = apply_config_reload(
            &current,
            &PipelinePolicySet::default(),
            &PolicyReloadGate::default(),
            None,
            &EnforcementReloadGate::default(),
            &candidate_path,
        )
        .await;
        let snapshot = complete_config_reload_apply(outcome, &plan_handle, None);

        assert!(snapshot.active_plan_updated);
        assert!(snapshot.actions.is_empty());
        let active = plan_handle.snapshot();
        assert_eq!(active.config.exporters, candidate.exporters);
        assert_eq!(active.export.sinks[0].id(), "collector");
        assert_eq!(active.storage.retention.ingress.max_records, Some(100_000));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn complete_config_reload_apply_reports_busy_generation_without_replacing_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-busy-generation")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;
        let plan_handle = RuntimePlanHandle::new(Arc::new(current.clone()));
        let runtime_generation =
            RuntimeGenerationState::for_config_version(current.config.config_version.clone());
        runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path: candidate_path.clone(),
            candidate_config: candidate.clone(),
            current_config_version: current.config.config_version.clone(),
            candidate_config_version: Some(candidate.config_version.clone()),
            changed_sections: vec!["capture".to_string()],
        })?;

        let outcome = apply_config_reload(
            &current,
            &PipelinePolicySet::default(),
            &PolicyReloadGate::default(),
            None,
            &EnforcementReloadGate::default(),
            &candidate_path,
        )
        .await;
        let snapshot =
            complete_config_reload_apply(outcome, &plan_handle, Some(&runtime_generation));

        assert!(!snapshot.active_plan_updated);
        assert!(matches!(
            snapshot.actions.as_slice(),
            [ConfigReloadApplyAction::RequestRuntimeGeneration(
                ConfigReloadRuntimeGenerationActionOutcome::Busy { .. },
            )]
        ));
        assert_eq!(
            plan_handle.snapshot().config.capture.fallback_backends,
            current.config.capture.fallback_backends
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_queues_config_version_with_data_path_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-version-generation-request")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.config_version = "candidate".to_string();
        candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(
                plan.decision,
                ConfigReloadDecision::QueueRuntimeGeneration { .. }
            ),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![
                (
                    ConfigReloadSection::AgentIdentity,
                    ConfigReloadSectionReloadMode::RuntimeGeneration,
                ),
                (
                    ConfigReloadSection::Capture,
                    ConfigReloadSectionReloadMode::RuntimeGeneration,
                ),
            ]
        );
        let request = runtime_generation_reload_request(&plan, &candidate)
            .expect("config version and capture rebuild should queue together");
        assert_eq!(request.changed_sections, ["agent_identity", "capture"]);
        assert_eq!(
            request.candidate_config_version,
            Some("candidate".to_string())
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_queues_tls_decrypt_hint_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-tls-decrypt-hints")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-key-log".to_string()];
        candidate.tls.materials = vec![TlsMaterialConfig {
            id: Some("ssl-key-log".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: temp.join("sslkeys.log"),
        }];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(
                plan.decision,
                ConfigReloadDecision::QueueRuntimeGeneration { .. }
            ),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Tls,
                ConfigReloadSectionReloadMode::RuntimeGeneration,
            )]
        );
        let request = runtime_generation_reload_request(&plan, &candidate)
            .expect("TLS decrypt hints should rebuild the capture generation");
        assert_eq!(request.changed_sections, ["tls"]);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_keeps_setup_time_tls_materials_restart_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-setup-time-tls-material")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.tls.materials = vec![TlsMaterialConfig {
            id: Some("mitm-ca".to_string()),
            kind: TlsMaterialKind::MitmCaCertificate,
            path: temp.join("mitm-ca.pem"),
        }];
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Tls,
                ConfigReloadSectionReloadMode::ProcessRestart,
            )]
        );
        assert!(runtime_generation_reload_request(&plan, &candidate).is_none());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_keeps_mixed_online_and_generation_owner_changes_restart_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-online-then-generation")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        candidate.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: temp.join("guard.bundle"),
            },
            ..PolicyConfig::default()
        });
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![
                (
                    ConfigReloadSection::Capture,
                    ConfigReloadSectionReloadMode::RuntimeGeneration,
                ),
                (
                    ConfigReloadSection::Policies,
                    ConfigReloadSectionReloadMode::ApplyOnline,
                ),
            ]
        );
        assert!(runtime_generation_reload_request(&plan, &candidate).is_none());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_does_not_build_generation_request_for_setup_topology()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-generation-request-reject")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.storage.path = temp.join("other-spool");
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(runtime_generation_reload_request(&plan, &candidate).is_none());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_can_apply_policy_config_changes_online()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-policy-online")?;
        let current_config = base_config(temp.join("spool"));
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: temp.join("guard.bundle"),
            },
            ..PolicyConfig::default()
        });
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::ApplyOnline { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Policies,
                ConfigReloadSectionReloadMode::ApplyOnline
            )]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_can_apply_enforcement_policy_config_changes_online()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-enforcement-online")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.enforcement.selector = Some(Selector::term(
            ProcessSelector {
                names: vec!["backend".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        ));
        candidate.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: temp.join("enforcement.toml"),
        };
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::ApplyOnline { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Enforcement,
                ConfigReloadSectionReloadMode::ApplyOnline
            )]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_keeps_enforcement_reload_topology_changes_restart_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-enforcement-reload-topology")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: temp.join("enforcement.toml"),
        };
        candidate.enforcement.policy.reload.watch_local_manifest = true;
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Enforcement,
                ConfigReloadSectionReloadMode::ProcessRestart
            )]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_keeps_mixed_online_owner_changes_restart_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-mixed-online-owners")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: temp.join("guard.bundle"),
            },
            ..PolicyConfig::default()
        });
        candidate.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: temp.join("enforcement.toml"),
        };
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| change.section)
                .collect::<Vec<_>>(),
            vec![
                ConfigReloadSection::Policies,
                ConfigReloadSection::Enforcement
            ]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_keeps_policy_config_restart_required_when_watcher_topology_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-policy-watcher")?;
        let mut current_config = base_config(temp.join("spool"));
        current_config.policy_reload.watch_local_bundles = true;
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: temp.join("guard.bundle"),
            },
            ..PolicyConfig::default()
        });
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::Policies,
                ConfigReloadSectionReloadMode::ProcessRestart
            )]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_keeps_runtime_reload_topology_changes_restart_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-runtime-watcher")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let mut candidate = current.config.clone();
        candidate.runtime_reload.watch_config = true;
        candidate.runtime_reload.debounce_ms = 250;
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| (change.section, change.reload_mode))
                .collect::<Vec<_>>(),
            vec![(
                ConfigReloadSection::RuntimeReload,
                ConfigReloadSectionReloadMode::ProcessRestart
            )]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_does_not_connect_to_setup_time_probe_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-static-planning")?;
        let readiness_listener = TcpListener::bind(("127.0.0.1", 0))?;
        readiness_listener.set_nonblocking(true)?;
        let readiness_target = readiness_listener.local_addr()?;
        let current_config = base_config(temp.join("spool"));
        let current = runtime_plan(current_config)?;
        let mut candidate = base_config(temp.join("spool"));
        configure_external_mitm_with_readiness(&mut candidate, readiness_target);
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| change.section)
                .collect::<Vec<_>>(),
            vec![ConfigReloadSection::Tls, ConfigReloadSection::Enforcement]
        );
        match readiness_listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok((_, peer)) => panic!("config reload planning connected to readiness target {peer}"),
            Err(error) => return Err(Box::new(error)),
        }
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_reports_invalid_candidate_without_panicking()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-invalid")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let candidate_path = temp.join("agent.toml");
        fs::write(
            &candidate_path,
            "secret_token = \"do-not-leak\"\nnot toml =",
        )?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        let ConfigReloadDecision::InvalidCandidate { stage, reason } = &plan.decision else {
            panic!("expected invalid candidate, got {:?}", plan.decision);
        };
        assert_eq!(*stage, "parse");
        assert!(!reason.contains("do-not-leak"), "{reason}");
        assert!(plan.changed_sections.is_empty());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_rejects_oversized_candidate_before_parse()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-oversized")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let candidate_path = temp.join("agent.toml");
        fs::File::create(&candidate_path)?.set_len(MAX_CANDIDATE_CONFIG_BYTES + 1)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        let ConfigReloadDecision::InvalidCandidate { stage, reason } = &plan.decision else {
            panic!("expected invalid candidate, got {:?}", plan.decision);
        };
        assert_eq!(*stage, "read");
        assert!(reason.contains("too large"), "{reason}");
        assert!(plan.changed_sections.is_empty());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(config, &registry())
    }

    fn registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::available(
                    CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                ),
                CaptureProviderDescriptor::available(
                    CaptureBackend::PlaintextFeed,
                    CaptureProviderBuilder::PlaintextFeed,
                ),
                CaptureProviderDescriptor::available(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                ),
            ],
            test_platform_capabilities(),
        )
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
        ]
    }

    fn base_config(storage_path: PathBuf) -> AgentConfig {
        AgentConfig {
            capture: probe_config::CaptureConfig {
                selection: CaptureSelection::Replay,
                ..probe_config::CaptureConfig::default()
            },
            storage: StorageConfig {
                path: storage_path,
                ..StorageConfig::default()
            },
            ..AgentConfig::default()
        }
    }

    fn webhook_exporter(id: &str, endpoint: &str) -> ExporterConfig {
        ExporterConfig {
            id: id.to_string(),
            transport: ExporterTransportConfig::Webhook {
                endpoint: endpoint.to_string(),
                headers: Default::default(),
                tls: Default::default(),
            },
            ..ExporterConfig::default()
        }
    }

    fn process_observation(
        id: &str,
        exe_path: &str,
        data_path: ObservationDataPathMode,
    ) -> ProcessObservationConfig {
        ProcessObservationConfig {
            id: id.to_string(),
            selector: Selector::term(
                ProcessSelector {
                    exe_path_globs: vec![exe_path.to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
            data_path,
            directions: vec![Direction::Inbound, Direction::Outbound],
        }
    }

    fn configure_external_mitm_with_readiness(
        config: &mut AgentConfig,
        readiness_target: std::net::SocketAddr,
    ) {
        config.tls = TlsConfig {
            materials: vec![
                TlsMaterialConfig {
                    id: Some("mitm-ca".to_string()),
                    kind: TlsMaterialKind::MitmCaCertificate,
                    path: "/etc/traffic-probe/mitm-ca.pem".into(),
                },
                TlsMaterialConfig {
                    id: Some("mitm-ca-key".to_string()),
                    kind: TlsMaterialKind::MitmCaPrivateKey,
                    path: "/etc/traffic-probe/mitm-ca.key".into(),
                },
            ],
            ..TlsConfig::default()
        };
        config.enforcement = EnforcementConfig {
            mode: EnforcementMode::Enforce,
            interception: EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxyMitm,
                selector: Some(Selector::term(
                    ProcessSelector {
                        names: vec!["candidate".to_string()],
                        ..ProcessSelector::default()
                    },
                    TrafficSelector::default(),
                )),
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(readiness_target.port()),
                    ..TransparentInterceptionProxyConfig::default()
                },
                mitm: TransparentInterceptionMitmConfig {
                    backend: TransparentInterceptionMitmBackendConfig::external(
                        TransparentInterceptionMitmBackendReadinessProbeConfig {
                            target: Some(readiness_target.to_string()),
                            ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                        },
                    ),
                    client_trust: TransparentInterceptionMitmClientTrustConfig {
                        mode: TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged,
                    },
                    ca_certificate_ref: Some("mitm-ca".to_string()),
                    ca_private_key_ref: Some("mitm-ca-key".to_string()),
                    ..TransparentInterceptionMitmConfig::default()
                },
            },
            policy: EnforcementPolicyConfig {
                source: EnforcementPolicySourceConfig::File {
                    path: "/etc/traffic-probe/enforcement.toml".into(),
                },
                ..EnforcementPolicyConfig::default()
            },
            ..EnforcementConfig::default()
        };
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let path =
            std::env::temp_dir().join(format!("traffic-probe-{name}-{}", std::process::id()));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}

use std::path::PathBuf;

use crate::configured_enforcement::{
    EnforcementPolicySourceInspection, LoadedEnforcementPolicySource,
    LoadedEnforcementPolicySourceOriginRef, inspect_enforcement_policy_source,
};
use probe_core::{CapabilityKind, EnforcementMode, ProtectiveActionProfile, RuntimeMode};
use runtime::RuntimePlan;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementStatusSnapshot {
    pub configured_mode: EnforcementMode,
    pub status: EnforcementStatusMode,
    pub effective_selector_configured: Option<bool>,
    pub config_selector_configured: bool,
    pub manifest_selector_configured: Option<bool>,
    pub policy: EnforcementPolicyStatusSnapshot,
    pub capability: EnforcementCapabilityStatusSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatusMode {
    Disabled,
    AuditOnly,
    DryRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementCapabilityStatusSnapshot {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementPolicyStatusSnapshot {
    pub source: EnforcementPolicySourceStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum EnforcementPolicySourceStatusSnapshot {
    NotConfigured,
    LocalMetadata {
        reason: String,
        manifest: EnforcementPolicyManifestStatusSnapshot,
    },
    RemoteConfigured {
        endpoint: String,
        reason: String,
    },
    Loaded {
        source: LoadedEnforcementPolicySourceStatusSnapshot,
        manifest: EnforcementPolicyManifestStatusSnapshot,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LoadedEnforcementPolicySourceStatusSnapshot {
    Local { path: PathBuf },
    Remote { endpoint: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementPolicyManifestStatusSnapshot {
    pub id: String,
    pub version: String,
    pub selector_configured: bool,
    pub protective_actions: ProtectiveActionProfile,
}

pub(super) fn enforcement_status(plan: &RuntimePlan) -> EnforcementStatusSnapshot {
    enforcement_status_with_source(plan, EnforcementPolicyStatusSource::Offline)
}

pub(super) fn enforcement_status_with_loaded_source(
    plan: &RuntimePlan,
    source: Option<&LoadedEnforcementPolicySource>,
) -> EnforcementStatusSnapshot {
    enforcement_status_with_source(plan, EnforcementPolicyStatusSource::Loaded(source))
}

fn enforcement_status_with_source(
    plan: &RuntimePlan,
    source: EnforcementPolicyStatusSource<'_>,
) -> EnforcementStatusSnapshot {
    let configured_mode = plan.enforcement.mode;
    let policy = enforcement_policy_status(plan, source);
    let (status, capability) = match configured_mode {
        EnforcementMode::Disabled => (
            EnforcementStatusMode::Disabled,
            EnforcementCapabilityStatusSnapshot::NotRequired,
        ),
        EnforcementMode::AuditOnly => (
            EnforcementStatusMode::AuditOnly,
            EnforcementCapabilityStatusSnapshot::NotRequired,
        ),
        EnforcementMode::DryRun => (
            EnforcementStatusMode::DryRun,
            EnforcementCapabilityStatusSnapshot::Required {
                capability: CapabilityKind::DryRunEnforcement,
                mode: plan.capabilities.mode(CapabilityKind::DryRunEnforcement),
            },
        ),
        EnforcementMode::Enforce => {
            unreachable!("runtime plan validation rejects real enforcement mode")
        }
    };

    EnforcementStatusSnapshot {
        configured_mode,
        status,
        effective_selector_configured: policy.effective_selector_configured,
        config_selector_configured: plan.enforcement.config_selector_configured,
        manifest_selector_configured: policy.manifest_selector_configured,
        policy: policy.snapshot,
        capability,
    }
}

enum EnforcementPolicyStatusSource<'a> {
    Offline,
    Loaded(Option<&'a LoadedEnforcementPolicySource>),
}

fn enforcement_policy_status(
    plan: &RuntimePlan,
    source: EnforcementPolicyStatusSource<'_>,
) -> EnforcementPolicyStatus {
    match source {
        EnforcementPolicyStatusSource::Offline => offline_enforcement_policy_status(plan),
        EnforcementPolicyStatusSource::Loaded(source) => {
            loaded_enforcement_policy_status(plan, source)
        }
    }
}

struct EnforcementPolicyStatus {
    snapshot: EnforcementPolicyStatusSnapshot,
    manifest_selector_configured: Option<bool>,
    effective_selector_configured: Option<bool>,
}

fn offline_enforcement_policy_status(plan: &RuntimePlan) -> EnforcementPolicyStatus {
    match inspect_enforcement_policy_source(&plan.enforcement.policy_source) {
        EnforcementPolicySourceInspection::NotConfigured => not_configured_policy_status(plan),
        EnforcementPolicySourceInspection::LocalMetadata { manifest } => {
            local_metadata_policy_status(
                plan,
                enforcement_policy_manifest_status(manifest),
                "enforcement policy source metadata is available, but status does not execute enforcement actions"
                    .to_string(),
            )
        }
        EnforcementPolicySourceInspection::RemoteConfigured { endpoint } => {
            remote_configured_policy_status(plan, endpoint)
        }
        EnforcementPolicySourceInspection::Unavailable { reason } => {
            unavailable_policy_status(reason)
        }
    }
}

fn loaded_enforcement_policy_status(
    plan: &RuntimePlan,
    source: Option<&LoadedEnforcementPolicySource>,
) -> EnforcementPolicyStatus {
    let Some(source) = source else {
        return not_configured_policy_status(plan);
    };

    let manifest = EnforcementPolicyManifestStatusSnapshot {
        id: source.manifest.id.clone(),
        version: source.manifest.version.clone(),
        selector_configured: source.manifest.selector.is_some(),
        protective_actions: source.manifest.protective_actions.clone(),
    };
    let manifest_selector_configured = Some(manifest.selector_configured);
    EnforcementPolicyStatus {
        effective_selector_configured: Some(
            plan.enforcement.config_selector_configured || manifest.selector_configured,
        ),
        manifest_selector_configured,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::Loaded {
                source: loaded_enforcement_policy_source_status(source),
                manifest,
            },
        },
    }
}

fn loaded_enforcement_policy_source_status(
    source: &LoadedEnforcementPolicySource,
) -> LoadedEnforcementPolicySourceStatusSnapshot {
    match source.origin() {
        LoadedEnforcementPolicySourceOriginRef::LocalPath(path) => {
            LoadedEnforcementPolicySourceStatusSnapshot::Local {
                path: path.to_path_buf(),
            }
        }
        LoadedEnforcementPolicySourceOriginRef::RemoteEndpoint(endpoint) => {
            LoadedEnforcementPolicySourceStatusSnapshot::Remote {
                endpoint: endpoint.to_string(),
            }
        }
    }
}

fn not_configured_policy_status(plan: &RuntimePlan) -> EnforcementPolicyStatus {
    EnforcementPolicyStatus {
        effective_selector_configured: Some(plan.enforcement.config_selector_configured),
        manifest_selector_configured: None,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::NotConfigured,
        },
    }
}

fn local_metadata_policy_status(
    plan: &RuntimePlan,
    manifest: EnforcementPolicyManifestStatusSnapshot,
    reason: String,
) -> EnforcementPolicyStatus {
    let manifest_selector_configured = Some(manifest.selector_configured);
    EnforcementPolicyStatus {
        effective_selector_configured: Some(
            plan.enforcement.config_selector_configured || manifest.selector_configured,
        ),
        manifest_selector_configured,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::LocalMetadata { reason, manifest },
        },
    }
}

fn remote_configured_policy_status(
    plan: &RuntimePlan,
    endpoint: String,
) -> EnforcementPolicyStatus {
    EnforcementPolicyStatus {
        effective_selector_configured: plan.enforcement.config_selector_configured.then_some(true),
        manifest_selector_configured: None,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::RemoteConfigured {
                reason: format!(
                    "remote enforcement policy source {endpoint} is configured, but offline status does not fetch remote policy"
                ),
                endpoint,
            },
        },
    }
}

fn unavailable_policy_status(reason: String) -> EnforcementPolicyStatus {
    EnforcementPolicyStatus {
        effective_selector_configured: None,
        manifest_selector_configured: None,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::Unavailable { reason },
        },
    }
}

fn enforcement_policy_manifest_status(
    manifest: probe_config::EnforcementPolicyManifest,
) -> EnforcementPolicyManifestStatusSnapshot {
    EnforcementPolicyManifestStatusSnapshot {
        id: manifest.id,
        version: manifest.version,
        selector_configured: manifest.selector.is_some(),
        protective_actions: manifest.protective_actions,
    }
}

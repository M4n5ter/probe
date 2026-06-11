use crate::configured_enforcement::{
    LoadedEnforcementPolicySource, inspect_enforcement_policy_source,
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
pub struct EnforcementPolicySourceStatusSnapshot {
    pub mode: EnforcementPolicySourceStatusMode,
    pub reason: Option<String>,
    pub manifest: Option<EnforcementPolicyManifestStatusSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPolicySourceStatusMode {
    NotConfigured,
    MetadataOnly,
    Loaded,
    Unavailable,
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
    let manifest_selector_configured = policy
        .source
        .manifest
        .as_ref()
        .map(|manifest| manifest.selector_configured);
    let effective_selector_configured = match policy.source.mode {
        EnforcementPolicySourceStatusMode::Unavailable => None,
        EnforcementPolicySourceStatusMode::NotConfigured
        | EnforcementPolicySourceStatusMode::MetadataOnly
        | EnforcementPolicySourceStatusMode::Loaded => Some(
            plan.enforcement.config_selector_configured
                || manifest_selector_configured.unwrap_or(false),
        ),
    };
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
        effective_selector_configured,
        config_selector_configured: plan.enforcement.config_selector_configured,
        manifest_selector_configured,
        policy,
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
) -> EnforcementPolicyStatusSnapshot {
    match source {
        EnforcementPolicyStatusSource::Offline => offline_enforcement_policy_status(plan),
        EnforcementPolicyStatusSource::Loaded(source) => loaded_enforcement_policy_status(source),
    }
}

fn offline_enforcement_policy_status(plan: &RuntimePlan) -> EnforcementPolicyStatusSnapshot {
    if matches!(
        plan.enforcement.policy_source,
        runtime::EnforcementPolicySourcePlan::None
    ) {
        return EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot {
                mode: EnforcementPolicySourceStatusMode::NotConfigured,
                reason: None,
                manifest: None,
            },
        };
    }

    let inspection = inspect_enforcement_policy_source(&plan.enforcement.policy_source);
    let (mode, reason, manifest) = match inspection.mode {
        RuntimeMode::Available => (
            EnforcementPolicySourceStatusMode::MetadataOnly,
            Some(
                "enforcement policy source metadata is available, but status does not execute enforcement actions"
                    .to_string(),
            ),
            inspection.manifest.map(|manifest| {
                EnforcementPolicyManifestStatusSnapshot {
                    id: manifest.id,
                    version: manifest.version,
                    selector_configured: manifest.selector.is_some(),
                    protective_actions: manifest.protective_actions,
                }
            }),
        ),
        RuntimeMode::Degraded | RuntimeMode::Unavailable => (
            EnforcementPolicySourceStatusMode::Unavailable,
            inspection.reason,
            None,
        ),
    };

    EnforcementPolicyStatusSnapshot {
        source: EnforcementPolicySourceStatusSnapshot {
            mode,
            reason,
            manifest,
        },
    }
}

fn loaded_enforcement_policy_status(
    source: Option<&LoadedEnforcementPolicySource>,
) -> EnforcementPolicyStatusSnapshot {
    let Some(source) = source else {
        return EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot {
                mode: EnforcementPolicySourceStatusMode::NotConfigured,
                reason: None,
                manifest: None,
            },
        };
    };

    EnforcementPolicyStatusSnapshot {
        source: EnforcementPolicySourceStatusSnapshot {
            mode: EnforcementPolicySourceStatusMode::Loaded,
            reason: None,
            manifest: Some(EnforcementPolicyManifestStatusSnapshot {
                id: source.manifest.id.clone(),
                version: source.manifest.version.clone(),
                selector_configured: source.manifest.selector.is_some(),
                protective_actions: source.manifest.protective_actions.clone(),
            }),
        },
    }
}

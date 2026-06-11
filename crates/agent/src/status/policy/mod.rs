use std::path::{Path, PathBuf};

use crate::configured_policy::{
    ConfiguredPolicySelectionState, ConfiguredPolicySource, configured_policy_selection,
    inspect_policy_source,
};
use probe_core::RuntimeMode;
use runtime::RuntimePlan;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyStatusSnapshot {
    pub mode: PolicyStatusMode,
    pub configured_count: u64,
    pub enabled_count: u64,
    pub active: Option<PolicyBundleStatusSnapshot>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatusMode {
    Inactive,
    MetadataOnly,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBundleStatusSnapshot {
    pub id: String,
    pub path: PathBuf,
    pub selector_configured: bool,
    pub source: PolicySourceStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySourceStatusSnapshot {
    pub check: PolicySourceCheck,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySourceCheck {
    MetadataOnly,
}

pub(super) fn policy_status(plan: &RuntimePlan) -> PolicyStatusSnapshot {
    let selection = configured_policy_selection(&plan.config);
    let policy = match selection.state {
        ConfiguredPolicySelectionState::Inactive => {
            return PolicyStatusSnapshot {
                mode: PolicyStatusMode::Inactive,
                configured_count: selection.configured_count,
                enabled_count: selection.enabled_count,
                active: None,
                reason: None,
            };
        }
        ConfiguredPolicySelectionState::Active { policy } => policy,
        ConfiguredPolicySelectionState::Unsupported { reason } => {
            return PolicyStatusSnapshot {
                mode: PolicyStatusMode::Unavailable,
                configured_count: selection.configured_count,
                enabled_count: selection.enabled_count,
                active: None,
                reason: Some(reason),
            };
        }
    };

    let source = policy_source_status(&policy.path, &policy.id);
    let (mode, reason) = match source.mode {
        RuntimeMode::Available => (
            PolicyStatusMode::MetadataOnly,
            Some(
                "policy source metadata is available, but offline status does not load or execute policy source"
                    .to_string(),
            ),
        ),
        RuntimeMode::Degraded | RuntimeMode::Unavailable => {
            (PolicyStatusMode::Unavailable, source.reason.clone())
        }
    };

    PolicyStatusSnapshot {
        mode,
        configured_count: selection.configured_count,
        enabled_count: selection.enabled_count,
        active: Some(policy_bundle_status(policy, source)),
        reason,
    }
}

fn policy_bundle_status(
    policy: ConfiguredPolicySource,
    source: PolicySourceStatusSnapshot,
) -> PolicyBundleStatusSnapshot {
    PolicyBundleStatusSnapshot {
        id: policy.id,
        path: policy.path,
        selector_configured: policy.selector_configured,
        source,
    }
}

fn policy_source_status(path: &Path, expected_id: &str) -> PolicySourceStatusSnapshot {
    let inspection = inspect_policy_source(path, expected_id);

    PolicySourceStatusSnapshot {
        check: PolicySourceCheck::MetadataOnly,
        mode: inspection.mode,
        reason: inspection.reason,
    }
}

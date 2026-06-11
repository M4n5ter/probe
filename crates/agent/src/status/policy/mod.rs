use std::path::{Path, PathBuf};

use probe_config::PolicyConfig;
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
    let enabled = plan
        .config
        .policies
        .iter()
        .filter(|policy| policy.enabled)
        .collect::<Vec<_>>();
    let configured_count = plan.config.policies.len() as u64;
    let enabled_count = enabled.len() as u64;
    let Some(policy) = enabled.first() else {
        return PolicyStatusSnapshot {
            mode: PolicyStatusMode::Inactive,
            configured_count,
            enabled_count,
            active: None,
            reason: None,
        };
    };

    let source = policy_source_status(&policy.path);
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
        configured_count,
        enabled_count,
        active: Some(policy_bundle_status(policy, source)),
        reason,
    }
}

fn policy_bundle_status(
    policy: &PolicyConfig,
    source: PolicySourceStatusSnapshot,
) -> PolicyBundleStatusSnapshot {
    PolicyBundleStatusSnapshot {
        id: policy.id.clone(),
        path: policy.path.clone(),
        selector_configured: policy.selector.is_some(),
        source,
    }
}

fn policy_source_status(path: &Path) -> PolicySourceStatusSnapshot {
    let (mode, reason) = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => (RuntimeMode::Available, None),
        Ok(metadata) if metadata.is_dir() => (
            RuntimeMode::Unavailable,
            Some("policy source path is a directory".to_string()),
        ),
        Ok(_) => (
            RuntimeMode::Unavailable,
            Some("policy source path is not a regular file".to_string()),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            RuntimeMode::Unavailable,
            Some("policy source path does not exist".to_string()),
        ),
        Err(error) => (
            RuntimeMode::Unavailable,
            Some(format!("failed to inspect policy source: {error}")),
        ),
    };

    PolicySourceStatusSnapshot {
        check: PolicySourceCheck::MetadataOnly,
        mode,
        reason,
    }
}

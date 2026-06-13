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

pub(in crate::status) fn policy_status(plan: &RuntimePlan) -> PolicyStatusSnapshot {
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

#[cfg(test)]
mod tests {
    use std::fs;

    use probe_config::PolicyConfig;
    use probe_core::{RuntimeMode, Selector};
    use serde_json::json;

    use super::super::super::plan_fixture::{
        config_with_storage_path, runtime_plan_from_config, test_dir,
    };
    use super::*;

    #[test]
    fn policy_status_reports_metadata_only_file_without_loading_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(&policy_path, "function on_http_request(")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            path: policy_path.clone(),
            enabled: true,
            selector: Some(Selector::default()),
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = policy_status(&plan);

        assert_eq!(status.mode, PolicyStatusMode::MetadataOnly);
        assert_eq!(status.configured_count, 1);
        assert_eq!(status.enabled_count, 1);
        let active_policy = status.active.as_ref().expect("active policy");
        assert_eq!(active_policy.id, "guard");
        assert_eq!(active_policy.path, policy_path);
        assert!(active_policy.selector_configured);
        assert_eq!(active_policy.source.mode, RuntimeMode::Available);
        assert_eq!(active_policy.source.check, PolicySourceCheck::MetadataOnly);
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("offline status does not load or execute"))
        );
        let value = serde_json::to_value(&status)?;
        assert_eq!(value["mode"], json!("metadata_only"));
        assert_eq!(value["active"]["source"]["check"], json!("metadata_only"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn policy_status_reports_metadata_only_bundle_without_loading_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-policy-bundle")?;
        let policy_path = temp.join("guard.bundle");
        fs::create_dir_all(&policy_path)?;
        fs::write(
            policy_path.join("manifest.toml"),
            r#"
id = "guard"
version = "bundle-v1"
hooks = ["on_http_request_headers"]
"#,
        )?;
        fs::write(
            policy_path.join("main.lua"),
            "function on_http_request_headers(",
        )?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            path: policy_path.clone(),
            enabled: true,
            selector: Some(Selector::default()),
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = policy_status(&plan);

        assert_eq!(status.mode, PolicyStatusMode::MetadataOnly);
        let active_policy = status.active.as_ref().expect("active policy");
        assert_eq!(active_policy.id, "guard");
        assert_eq!(active_policy.path, policy_path);
        assert!(active_policy.selector_configured);
        assert_eq!(active_policy.source.mode, RuntimeMode::Available);
        assert_eq!(active_policy.source.check, PolicySourceCheck::MetadataOnly);
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("offline status does not load or execute"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn missing_policy_source_marks_policy_status_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-missing-policy")?;
        let missing_policy = temp.join("missing.lua");
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "missing".to_string(),
            path: missing_policy,
            enabled: true,
            selector: None,
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = policy_status(&plan);

        assert_eq!(status.mode, PolicyStatusMode::Unavailable);
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("does not exist"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn oversized_policy_source_marks_policy_status_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-oversized-policy")?;
        let policy_path = temp.join("guard.lua");
        let file = fs::File::create(&policy_path)?;
        file.set_len(crate::configured_policy::MAX_POLICY_SOURCE_BYTES + 1)?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            path: policy_path,
            enabled: true,
            selector: None,
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = policy_status(&plan);

        assert_eq!(status.mode, PolicyStatusMode::Unavailable);
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("exceeding"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }
}

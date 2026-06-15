use std::path::{Path, PathBuf};

use crate::configured_policy::{
    ConfiguredPolicySource, configured_policy_selection, inspect_policy_source,
};
use probe_core::RuntimeMode;
use runtime::RuntimePlan;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyStatusSnapshot {
    pub mode: PolicyStatusMode,
    pub configured_count: u64,
    pub enabled_count: u64,
    pub active: Vec<PolicyBundleStatusSnapshot>,
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
    pub policy_version: Option<String>,
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
    let enabled_count = selection.enabled.len() as u64;
    if selection.enabled.is_empty() {
        return PolicyStatusSnapshot {
            mode: PolicyStatusMode::Inactive,
            configured_count: selection.configured_count,
            enabled_count,
            active: Vec::new(),
            reason: None,
        };
    }

    let active = selection
        .enabled
        .into_iter()
        .map(|policy| {
            let source = policy_source_status(&policy.path, &policy.id);
            policy_bundle_status(policy, source)
        })
        .collect::<Vec<_>>();
    let unavailable_reasons = active
        .iter()
        .filter(|policy| policy.source.mode != RuntimeMode::Available)
        .map(|policy| {
            format!(
                "{}: {}",
                policy.id,
                policy
                    .source
                    .reason
                    .as_deref()
                    .unwrap_or("policy source metadata is unavailable")
            )
        })
        .collect::<Vec<_>>();
    let (mode, reason) = if unavailable_reasons.is_empty() {
        (
            PolicyStatusMode::MetadataOnly,
            Some(
                "policy source metadata is available, but offline status does not load or execute policy source"
                    .to_string(),
            ),
        )
    } else {
        (
            PolicyStatusMode::Unavailable,
            Some(unavailable_reasons.join("; ")),
        )
    };

    PolicyStatusSnapshot {
        mode,
        configured_count: selection.configured_count,
        enabled_count,
        active,
        reason,
    }
}

fn policy_bundle_status(
    policy: ConfiguredPolicySource,
    source: PolicySourceStatus,
) -> PolicyBundleStatusSnapshot {
    PolicyBundleStatusSnapshot {
        id: policy.id,
        path: policy.path,
        selector_configured: policy.selector_configured,
        policy_version: source.policy_version,
        source: source.snapshot,
    }
}

struct PolicySourceStatus {
    snapshot: PolicySourceStatusSnapshot,
    policy_version: Option<String>,
}

fn policy_source_status(path: &Path, expected_id: &str) -> PolicySourceStatus {
    let inspection = inspect_policy_source(path, expected_id);
    let policy_version = inspection
        .manifest
        .map(|manifest| format!("{}@{}", manifest.id, manifest.version));

    PolicySourceStatus {
        snapshot: PolicySourceStatusSnapshot {
            check: PolicySourceCheck::MetadataOnly,
            mode: inspection.mode,
            reason: inspection.reason,
        },
        policy_version,
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

    const OVERSIZED_TEST_FILE_BYTES: u64 = 10 * 1024 * 1024;

    #[test]
    fn policy_status_rejects_file_policy_source() -> Result<(), Box<dyn std::error::Error>> {
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

        assert_eq!(status.mode, PolicyStatusMode::Unavailable);
        assert_eq!(status.configured_count, 1);
        assert_eq!(status.enabled_count, 1);
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("must be a policy bundle directory"))
        );
        let value = serde_json::to_value(&status)?;
        assert_eq!(value["mode"], json!("unavailable"));
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
version = "bundle-test"
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
        let active_bundle = status.active.first().expect("active bundle");
        assert_eq!(active_bundle.id, "guard");
        assert_eq!(active_bundle.path, policy_path);
        assert!(active_bundle.selector_configured);
        assert_eq!(
            active_bundle.policy_version.as_deref(),
            Some("guard@bundle-test")
        );
        assert_eq!(active_bundle.source.mode, RuntimeMode::Available);
        assert_eq!(active_bundle.source.check, PolicySourceCheck::MetadataOnly);
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
    fn policy_status_reports_multiple_metadata_only_bundles()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-multiple-policy-bundles")?;
        let first_path = temp.join("first.bundle");
        let second_path = temp.join("second.bundle");
        write_policy_bundle(&first_path, "first")?;
        write_policy_bundle(&second_path, "second")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![
            PolicyConfig {
                id: "first".to_string(),
                path: first_path.clone(),
                enabled: true,
                selector: Some(Selector::default()),
            },
            PolicyConfig {
                id: "second".to_string(),
                path: second_path.clone(),
                enabled: true,
                selector: None,
            },
        ];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = policy_status(&plan);

        assert_eq!(status.mode, PolicyStatusMode::MetadataOnly);
        assert_eq!(status.configured_count, 2);
        assert_eq!(status.enabled_count, 2);
        assert_eq!(status.active.len(), 2);
        assert_eq!(status.active[0].id, "first");
        assert_eq!(status.active[0].path, first_path);
        assert_eq!(
            status.active[0].policy_version.as_deref(),
            Some("first@bundle-test")
        );
        assert!(status.active[0].selector_configured);
        assert_eq!(status.active[1].id, "second");
        assert_eq!(status.active[1].path, second_path);
        assert_eq!(
            status.active[1].policy_version.as_deref(),
            Some("second@bundle-test")
        );
        assert!(!status.active[1].selector_configured);
        assert!(
            status
                .active
                .iter()
                .all(|policy| policy.source.mode == RuntimeMode::Available)
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
        let policy_path = temp.join("guard.bundle");
        fs::create_dir_all(&policy_path)?;
        fs::write(
            policy_path.join("manifest.toml"),
            r#"
id = "guard"
version = "bundle-test"
hooks = ["on_http_request_headers"]
"#,
        )?;
        let file = fs::File::create(policy_path.join("main.lua"))?;
        file.set_len(OVERSIZED_TEST_FILE_BYTES)?;
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

    fn write_policy_bundle(path: &std::path::Path, id: &str) -> Result<(), std::io::Error> {
        fs::create_dir_all(path)?;
        fs::write(
            path.join("manifest.toml"),
            format!(
                r#"
id = "{id}"
version = "bundle-test"
hooks = ["on_http_request_headers"]
"#
            ),
        )?;
        fs::write(path.join("main.lua"), "function on_http_request_headers(")?;
        Ok(())
    }
}

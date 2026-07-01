use std::collections::HashMap;

use crate::configured_policy::{
    ConfiguredPolicySource, PolicySourceSnapshot, configured_policy_selection,
    inspect_policy_source,
};
use pipeline::PipelinePolicyRuntimeSnapshot;
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
    Available,
    MetadataOnly,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBundleStatusSnapshot {
    pub id: String,
    pub source: PolicySourceSnapshot,
    pub selector_configured: bool,
    pub runtime_error_disable_threshold: u64,
    pub policy_version: Option<String>,
    pub runtime: Option<PolicyBundleRuntimeStatusSnapshot>,
    pub inspection: PolicySourceStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBundleRuntimeStatusSnapshot {
    pub policy_version: String,
    pub selector_configured: bool,
    pub runtime_errors: PolicyRuntimeErrorStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRuntimeErrorStatusSnapshot {
    pub disable_threshold: u64,
    pub consecutive_errors: u64,
    pub disabled: bool,
    pub disabled_reason: Option<String>,
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

#[cfg(test)]
fn policy_status(plan: &RuntimePlan) -> PolicyStatusSnapshot {
    policy_status_with_runtime(plan, None)
}

pub(in crate::status) fn policy_status_with_runtime(
    plan: &RuntimePlan,
    runtime: Option<&[PipelinePolicyRuntimeSnapshot]>,
) -> PolicyStatusSnapshot {
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

    let runtime_by_id = runtime
        .into_iter()
        .flat_map(|snapshots| snapshots.iter())
        .map(|snapshot| (snapshot.id.as_str(), snapshot))
        .collect::<HashMap<_, _>>();
    let active = selection
        .enabled
        .into_iter()
        .map(|policy| {
            let source = policy_source_status(&policy.source, &policy.id);
            let runtime = runtime_by_id
                .get(policy.id.as_str())
                .map(|snapshot| policy_bundle_runtime_status(snapshot));
            policy_bundle_status(policy, source, runtime)
        })
        .collect::<Vec<_>>();
    let unavailable_reasons = source_reasons(
        &active,
        RuntimeMode::Unavailable,
        "policy source metadata is unavailable",
    );
    let degraded_reasons = source_reasons(
        &active,
        RuntimeMode::Degraded,
        "policy source metadata is degraded",
    );
    let missing_runtime_reasons = if runtime.is_some() {
        active
            .iter()
            .filter(|policy| policy.runtime.is_none())
            .map(|policy| format!("{}: policy runtime snapshot is missing", policy.id))
            .collect()
    } else {
        Vec::new()
    };
    let disabled_runtime_reasons = if runtime.is_some() {
        active.iter().filter_map(disabled_runtime_reason).collect()
    } else {
        Vec::new()
    };
    let (mode, reason) = if runtime.is_some() {
        runtime_policy_mode(
            unavailable_reasons,
            degraded_reasons,
            missing_runtime_reasons,
            disabled_runtime_reasons,
        )
    } else {
        metadata_policy_mode(unavailable_reasons, degraded_reasons)
    };

    PolicyStatusSnapshot {
        mode,
        configured_count: selection.configured_count,
        enabled_count,
        active,
        reason,
    }
}

fn source_reasons(
    active: &[PolicyBundleStatusSnapshot],
    mode: RuntimeMode,
    fallback: &'static str,
) -> Vec<String> {
    active
        .iter()
        .filter(|policy| policy.inspection.mode == mode)
        .map(|policy| {
            format!(
                "{}: {}",
                policy.id,
                policy.inspection.reason.as_deref().unwrap_or(fallback)
            )
        })
        .collect()
}

fn disabled_runtime_reason(policy: &PolicyBundleStatusSnapshot) -> Option<String> {
    let runtime = policy.runtime.as_ref()?;
    if !runtime.runtime_errors.disabled {
        return None;
    }
    let reason = runtime
        .runtime_errors
        .disabled_reason
        .as_deref()
        .unwrap_or("policy runtime is disabled");
    Some(format!("{}: {reason}", policy.id))
}

fn metadata_policy_mode(
    unavailable_reasons: Vec<String>,
    degraded_reasons: Vec<String>,
) -> (PolicyStatusMode, Option<String>) {
    if unavailable_reasons.is_empty() {
        (
            PolicyStatusMode::MetadataOnly,
            Some(metadata_only_reason(degraded_reasons)),
        )
    } else {
        (
            PolicyStatusMode::Unavailable,
            Some(unavailable_reasons.join("; ")),
        )
    }
}

fn runtime_policy_mode(
    unavailable_reasons: Vec<String>,
    degraded_reasons: Vec<String>,
    missing_runtime_reasons: Vec<String>,
    disabled_runtime_reasons: Vec<String>,
) -> (PolicyStatusMode, Option<String>) {
    if !missing_runtime_reasons.is_empty() {
        return (
            PolicyStatusMode::Unavailable,
            Some(missing_runtime_reasons.join("; ")),
        );
    }

    let mut degraded = unavailable_reasons;
    degraded.extend(degraded_reasons);
    degraded.extend(disabled_runtime_reasons);
    if degraded.is_empty() {
        (PolicyStatusMode::Available, None)
    } else {
        (PolicyStatusMode::Degraded, Some(degraded.join("; ")))
    }
}

fn metadata_only_reason(degraded_reasons: Vec<String>) -> String {
    let base = "policy source metadata is available, but offline status does not load or execute policy source";
    if degraded_reasons.is_empty() {
        base.to_string()
    } else {
        format!("{base}; {}", degraded_reasons.join("; "))
    }
}

fn policy_bundle_status(
    policy: ConfiguredPolicySource,
    source: PolicySourceStatus,
    runtime: Option<PolicyBundleRuntimeStatusSnapshot>,
) -> PolicyBundleStatusSnapshot {
    PolicyBundleStatusSnapshot {
        id: policy.id,
        source: policy.source,
        selector_configured: policy.selector_configured,
        runtime_error_disable_threshold: policy.runtime_error_disable_threshold,
        policy_version: source.policy_version,
        runtime,
        inspection: source.snapshot,
    }
}

fn policy_bundle_runtime_status(
    runtime: &PipelinePolicyRuntimeSnapshot,
) -> PolicyBundleRuntimeStatusSnapshot {
    PolicyBundleRuntimeStatusSnapshot {
        policy_version: runtime.policy_version.clone(),
        selector_configured: runtime.selector_configured,
        runtime_errors: PolicyRuntimeErrorStatusSnapshot {
            disable_threshold: runtime.runtime_errors.disable_threshold,
            consecutive_errors: runtime.runtime_errors.consecutive_errors,
            disabled: runtime.runtime_errors.disabled_reason.is_some(),
            disabled_reason: runtime.runtime_errors.disabled_reason.clone(),
        },
    }
}

struct PolicySourceStatus {
    snapshot: PolicySourceStatusSnapshot,
    policy_version: Option<String>,
}

fn policy_source_status(source: &PolicySourceSnapshot, expected_id: &str) -> PolicySourceStatus {
    let inspection = inspect_policy_source(source, expected_id);
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

    use pipeline::{PipelinePolicyRuntimeErrorSnapshot, PipelinePolicyRuntimeSnapshot};
    use probe_config::{PolicyConfig, PolicySourceConfig};
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
            source: local_source(policy_path.clone()),
            enabled: true,
            selector: Some(Selector::default()),
            ..PolicyConfig::default()
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
            source: local_source(policy_path.clone()),
            enabled: true,
            selector: Some(Selector::default()),
            ..PolicyConfig::default()
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = policy_status(&plan);

        assert_eq!(status.mode, PolicyStatusMode::MetadataOnly);
        let active_bundle = status.active.first().expect("active bundle");
        assert_eq!(active_bundle.id, "guard");
        assert_eq!(
            active_bundle.source,
            PolicySourceSnapshot::LocalDirectory { path: policy_path }
        );
        assert!(active_bundle.selector_configured);
        assert_eq!(
            active_bundle.runtime_error_disable_threshold,
            probe_config::DEFAULT_POLICY_RUNTIME_ERROR_DISABLE_THRESHOLD
        );
        assert_eq!(
            active_bundle.policy_version.as_deref(),
            Some("guard@bundle-test")
        );
        assert_eq!(active_bundle.inspection.mode, RuntimeMode::Available);
        assert_eq!(
            active_bundle.inspection.check,
            PolicySourceCheck::MetadataOnly
        );
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
    fn policy_status_merges_runtime_error_state() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-policy-runtime")?;
        let policy_path = temp.join("guard.bundle");
        write_policy_bundle(&policy_path, "guard")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            source: local_source(policy_path),
            enabled: true,
            selector: Some(Selector::default()),
            ..PolicyConfig::default()
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let runtime = [PipelinePolicyRuntimeSnapshot {
            id: "guard".to_string(),
            version: "live".to_string(),
            policy_version: "guard@live".to_string(),
            selector_configured: true,
            runtime_errors: PipelinePolicyRuntimeErrorSnapshot {
                disable_threshold: 2,
                consecutive_errors: 2,
                disabled_reason: Some(
                    "invalid outcome; policy disabled after 2 consecutive runtime errors"
                        .to_string(),
                ),
            },
        }];

        let status = policy_status_with_runtime(&plan, Some(&runtime));

        assert_eq!(status.mode, PolicyStatusMode::Degraded);
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("policy disabled after 2 consecutive"))
        );
        let active_bundle = status.active.first().expect("active bundle");
        let runtime = active_bundle.runtime.as_ref().expect("runtime status");
        assert_eq!(runtime.policy_version, "guard@live");
        assert!(runtime.selector_configured);
        assert_eq!(runtime.runtime_errors.disable_threshold, 2);
        assert_eq!(runtime.runtime_errors.consecutive_errors, 2);
        assert!(runtime.runtime_errors.disabled);
        assert!(
            runtime
                .runtime_errors
                .disabled_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("policy disabled after 2 consecutive"))
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
                source: local_source(first_path.clone()),
                enabled: true,
                selector: Some(Selector::default()),
                ..PolicyConfig::default()
            },
            PolicyConfig {
                id: "second".to_string(),
                source: local_source(second_path.clone()),
                enabled: true,
                selector: None,
                ..PolicyConfig::default()
            },
        ];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = policy_status(&plan);

        assert_eq!(status.mode, PolicyStatusMode::MetadataOnly);
        assert_eq!(status.configured_count, 2);
        assert_eq!(status.enabled_count, 2);
        assert_eq!(status.active.len(), 2);
        assert_eq!(status.active[0].id, "first");
        assert_eq!(
            status.active[0].source,
            PolicySourceSnapshot::LocalDirectory { path: first_path }
        );
        assert_eq!(
            status.active[0].policy_version.as_deref(),
            Some("first@bundle-test")
        );
        assert!(status.active[0].selector_configured);
        assert_eq!(status.active[1].id, "second");
        assert_eq!(
            status.active[1].source,
            PolicySourceSnapshot::LocalDirectory { path: second_path }
        );
        assert_eq!(
            status.active[1].policy_version.as_deref(),
            Some("second@bundle-test")
        );
        assert!(!status.active[1].selector_configured);
        assert!(
            status
                .active
                .iter()
                .all(|policy| policy.inspection.mode == RuntimeMode::Available)
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
            source: local_source(missing_policy),
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
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
            source: local_source(policy_path),
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
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

    #[test]
    fn remote_policy_source_is_metadata_only_in_offline_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-remote-policy")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::RemoteBundle {
                endpoint: "https://control.example/policies/guard".to_string(),
                max_body_bytes: Some(2 * 1024 * 1024),
            },
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = policy_status(&plan);

        assert_eq!(status.mode, PolicyStatusMode::MetadataOnly);
        assert_eq!(status.active.len(), 1);
        let active = status.active.first().expect("active policy");
        assert_eq!(
            active.source,
            PolicySourceSnapshot::RemoteBundle {
                endpoint: "https://control.example/policies/guard".to_string(),
                max_body_bytes: 2_097_152,
            }
        );
        assert_eq!(active.policy_version, None);
        assert_eq!(active.inspection.mode, RuntimeMode::Degraded);
        assert!(
            active
                .inspection
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("offline status does not fetch"))
        );
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("guard: remote policy bundle source"))
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

    fn local_source(path: std::path::PathBuf) -> PolicySourceConfig {
        PolicySourceConfig::LocalDirectory { path }
    }
}

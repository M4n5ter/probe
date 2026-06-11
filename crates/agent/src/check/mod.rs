use std::path::PathBuf;

use crate::{
    configured_enforcement::build_configured_enforcement,
    configured_policy::{
        ConfiguredPolicyError, LoadedConfiguredPolicy, configured_policy_selection,
        load_configured_policy,
    },
};
use probe_config::AgentConfig;
use probe_core::EnforcementMode;
use runtime::RuntimePlan;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CheckError {
    #[error("{0}")]
    ConfiguredPolicy(#[from] ConfiguredPolicyError),
    #[error("enforcement error: {0}")]
    Enforcement(#[from] enforcement::EnforcementError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckReport {
    pub plan: RuntimePlan,
    pub policy: PolicyCheckSnapshot,
    pub enforcement: EnforcementCheckSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyCheckSnapshot {
    pub mode: PolicyCheckMode,
    pub configured_count: u64,
    pub enabled_count: u64,
    pub active: Option<LoadedPolicySnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCheckMode {
    Inactive,
    Loaded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadedPolicySnapshot {
    pub id: String,
    pub version: String,
    pub path: PathBuf,
    pub selector_configured: bool,
    pub registered_hooks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementCheckSnapshot {
    pub mode: EnforcementMode,
    pub selector_configured: bool,
}

pub fn build_check_report(plan: RuntimePlan) -> Result<CheckReport, CheckError> {
    let policy = check_policy(&plan.config)?;
    let enforcement = check_enforcement(&plan.config)?;
    Ok(CheckReport {
        plan,
        policy,
        enforcement,
    })
}

fn check_policy(config: &AgentConfig) -> Result<PolicyCheckSnapshot, CheckError> {
    let selection = configured_policy_selection(config);
    let policy = load_configured_policy(config)?;
    let Some(policy) = policy else {
        return Ok(PolicyCheckSnapshot {
            mode: PolicyCheckMode::Inactive,
            configured_count: selection.configured_count,
            enabled_count: selection.enabled_count,
            active: None,
        });
    };

    Ok(PolicyCheckSnapshot {
        mode: PolicyCheckMode::Loaded,
        configured_count: selection.configured_count,
        enabled_count: selection.enabled_count,
        active: Some(loaded_policy_snapshot(&policy)),
    })
}

fn check_enforcement(config: &AgentConfig) -> Result<EnforcementCheckSnapshot, CheckError> {
    let enforcement = build_configured_enforcement(config)?;
    Ok(EnforcementCheckSnapshot {
        mode: enforcement.mode,
        selector_configured: enforcement.selector_configured,
    })
}

fn loaded_policy_snapshot(policy: &LoadedConfiguredPolicy) -> LoadedPolicySnapshot {
    let manifest = policy.runtime.manifest();
    LoadedPolicySnapshot {
        id: manifest.id.clone(),
        version: manifest.version.clone(),
        path: policy.source.path.clone(),
        selector_configured: policy.source.selector_configured,
        registered_hooks: manifest.hooks.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use probe_config::{AgentConfig, CaptureBackend};
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};
    use serde_json::json;

    use super::*;

    #[test]
    fn check_report_loads_enabled_policy_bundle() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-valid-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(
            &policy_path,
            "function on_http_request_headers(_) return {} end",
        )?;
        let plan = runtime_plan(config_with_policy(&policy_path)?)?;

        let report = build_check_report(plan)?;

        assert_eq!(report.policy.mode, PolicyCheckMode::Loaded);
        let active = report.policy.active.as_ref().expect("loaded policy");
        assert_eq!(active.id, "guard");
        assert_eq!(active.version, "cfg-test");
        assert_eq!(active.path, policy_path);
        assert!(!active.selector_configured);
        assert!(
            active
                .registered_hooks
                .iter()
                .any(|hook| hook == "on_http_request_headers")
        );
        assert_eq!(report.enforcement.mode, EnforcementMode::AuditOnly);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn check_report_has_stable_json_shape() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-json-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(
            &policy_path,
            "function on_http_request_headers(_) return {} end",
        )?;
        let report = build_check_report(runtime_plan(config_with_policy(&policy_path)?)?)?;

        let value = serde_json::to_value(report)?;

        assert_eq!(value["plan"]["capture"]["mode"], json!("replay"));
        assert_eq!(value["policy"]["mode"], json!("loaded"));
        assert_eq!(value["policy"]["configured_count"], json!(1));
        assert_eq!(value["policy"]["enabled_count"], json!(1));
        assert_eq!(value["policy"]["active"]["id"], json!("guard"));
        assert_eq!(value["policy"]["active"]["version"], json!("cfg-test"));
        assert_eq!(
            value["policy"]["active"]["selector_configured"],
            json!(false)
        );
        assert!(value["policy"]["active"].get("hooks").is_none());
        assert!(
            value["policy"]["active"]["registered_hooks"]
                .as_array()
                .is_some_and(|hooks| hooks.iter().any(|hook| hook == "on_http_request_headers"))
        );
        assert_eq!(value["enforcement"]["mode"], json!("audit_only"));
        assert_eq!(value["enforcement"]["selector_configured"], json!(false));
        assert!(value["enforcement"].get("planner_loaded").is_none());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn check_report_rejects_invalid_policy_source() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-invalid-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(&policy_path, "function on_http_request_headers(")?;
        let plan = runtime_plan(config_with_policy(&policy_path)?)?;

        let error = build_check_report(plan).expect_err("invalid Lua must fail explicit check");

        assert!(matches!(
            error,
            CheckError::ConfiguredPolicy(ConfiguredPolicyError::Policy(_))
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            vec![
                CapabilityState::available(CapabilityKind::Http1),
                CapabilityState::available(CapabilityKind::Sse),
                CapabilityState::available(CapabilityKind::WebSocketHandoff),
                CapabilityState::available(CapabilityKind::DryRunEnforcement),
            ],
        );
        RuntimePlan::build(config, &registry)
    }

    fn config_with_policy(path: &Path) -> Result<AgentConfig, probe_config::ConfigError> {
        AgentConfig::from_toml_str(&format!(
            r#"
agent_id = "agent-1"
config_version = "cfg-test"

[capture]
selection = "replay"

[[policies]]
id = "guard"
enabled = true
path = "{}"

[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
codec = "none"
"#,
            path.display()
        ))
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}

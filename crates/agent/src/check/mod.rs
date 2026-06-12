use std::path::PathBuf;

use crate::configured_enforcement::{
    LoadedEnforcementPolicySource, LoadedEnforcementPolicySourceOriginRef,
};
use crate::{
    configured_enforcement::{ConfiguredEnforcementError, build_configured_enforcement},
    configured_policy::{
        ConfiguredPolicyError, LoadedConfiguredPolicy, configured_policy_selection,
        load_configured_policy,
    },
};
use policy::PolicyHook;
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
    #[error("{0}")]
    ConfiguredEnforcement(#[from] ConfiguredEnforcementError),
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
    pub registered_hooks: Vec<PolicyHook>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementCheckSnapshot {
    pub mode: EnforcementMode,
    pub effective_selector_configured: bool,
    pub config_selector_configured: bool,
    pub manifest_selector_configured: Option<bool>,
    pub policy: EnforcementPolicyCheckSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementPolicyCheckSnapshot {
    pub mode: EnforcementPolicyCheckMode,
    pub active: Option<LoadedEnforcementPolicySnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPolicyCheckMode {
    NotConfigured,
    Loaded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadedEnforcementPolicySnapshot {
    pub id: String,
    pub version: String,
    pub source: LoadedEnforcementPolicySourceSnapshot,
    pub selector_configured: bool,
    pub protective_actions: probe_core::ProtectiveActionProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LoadedEnforcementPolicySourceSnapshot {
    Local { path: PathBuf },
    Remote { endpoint: String },
}

pub async fn build_check_report(plan: RuntimePlan) -> Result<CheckReport, CheckError> {
    let policy = check_policy(&plan.config)?;
    let enforcement = check_enforcement(&plan).await?;
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

async fn check_enforcement(plan: &RuntimePlan) -> Result<EnforcementCheckSnapshot, CheckError> {
    let enforcement = build_configured_enforcement(plan).await?;
    let policy = enforcement.policy_source.as_ref().map_or(
        EnforcementPolicyCheckSnapshot {
            mode: EnforcementPolicyCheckMode::NotConfigured,
            active: None,
        },
        |source| EnforcementPolicyCheckSnapshot {
            mode: EnforcementPolicyCheckMode::Loaded,
            active: Some(LoadedEnforcementPolicySnapshot {
                id: source.manifest.id.clone(),
                version: source.manifest.version.clone(),
                source: loaded_enforcement_policy_source_snapshot(source),
                selector_configured: source.manifest.selector.is_some(),
                protective_actions: source.manifest.protective_actions.clone(),
            }),
        },
    );
    Ok(EnforcementCheckSnapshot {
        mode: enforcement.mode,
        effective_selector_configured: enforcement.effective_selector_configured,
        config_selector_configured: enforcement.config_selector_configured,
        manifest_selector_configured: enforcement.manifest_selector_configured,
        policy,
    })
}

fn loaded_enforcement_policy_source_snapshot(
    source: &LoadedEnforcementPolicySource,
) -> LoadedEnforcementPolicySourceSnapshot {
    match source.origin() {
        LoadedEnforcementPolicySourceOriginRef::LocalPath(path) => {
            LoadedEnforcementPolicySourceSnapshot::Local {
                path: path.to_path_buf(),
            }
        }
        LoadedEnforcementPolicySourceOriginRef::RemoteEndpoint(endpoint) => {
            LoadedEnforcementPolicySourceSnapshot::Remote {
                endpoint: endpoint.to_string(),
            }
        }
    }
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
    use probe_core::{Action, CapabilityKind, CapabilityState, ProtectiveActionProfile, Selector};
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};
    use serde_json::json;

    use crate::test_support::SingleResponseHttpServer;

    use super::*;

    #[tokio::test]
    async fn check_report_loads_enabled_policy_bundle() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-valid-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(
            &policy_path,
            "function on_http_request_headers(_) return {} end",
        )?;
        let plan = runtime_plan(config_with_policy(&policy_path)?)?;

        let report = build_check_report(plan).await?;

        assert_eq!(report.policy.mode, PolicyCheckMode::Loaded);
        let active = report.policy.active.as_ref().expect("loaded policy");
        assert_eq!(active.id, "guard");
        assert_eq!(active.version, "cfg-test");
        assert_eq!(active.path, policy_path);
        assert!(!active.selector_configured);
        assert!(
            active
                .registered_hooks
                .contains(&PolicyHook::HttpRequestHeaders)
        );
        assert_eq!(report.enforcement.mode, EnforcementMode::AuditOnly);
        assert_eq!(
            report.enforcement.policy.mode,
            EnforcementPolicyCheckMode::NotConfigured
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_loads_enforcement_policy_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-enforcement-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(
            &policy_path,
            "function on_http_request_headers(_) return {} end",
        )?;
        let enforcement_path = temp.join("enforcement.toml");
        let manifest = probe_config::EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "v1".to_string(),
            selector: Some(Selector::default()),
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        fs::write(&enforcement_path, toml::to_string(&manifest)?)?;
        let mut config = config_with_policy(&policy_path)?;
        config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::File {
            path: enforcement_path.clone(),
        };
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan).await?;

        assert!(report.enforcement.effective_selector_configured);
        assert!(!report.enforcement.config_selector_configured);
        assert_eq!(report.enforcement.manifest_selector_configured, Some(true));
        assert_eq!(
            report.enforcement.policy.mode,
            EnforcementPolicyCheckMode::Loaded
        );
        let active = report
            .enforcement
            .policy
            .active
            .as_ref()
            .expect("enforcement policy manifest should load");
        assert_eq!(active.id, "managed-apps");
        assert_eq!(active.version, "v1");
        assert_eq!(
            active.source,
            LoadedEnforcementPolicySourceSnapshot::Local {
                path: enforcement_path
            }
        );
        assert!(active.selector_configured);
        assert_eq!(active.protective_actions.actions(), &[Action::Deny]);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_invalid_enforcement_policy_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-invalid-enforcement-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(
            &policy_path,
            "function on_http_request_headers(_) return {} end",
        )?;
        let enforcement_path = temp.join("enforcement.toml");
        fs::write(
            &enforcement_path,
            r#"
id = "managed-apps"
version = "v1"
protective_actions = ["alert"]
"#,
        )?;
        let mut config = config_with_policy(&policy_path)?;
        config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::File {
            path: enforcement_path,
        };
        let plan = runtime_plan(config)?;

        let error = build_check_report(plan)
            .await
            .expect_err("invalid enforcement manifest must fail check");

        assert!(matches!(error, CheckError::ConfiguredEnforcement(_)));
        assert!(
            error
                .to_string()
                .contains("not a protective enforcement action")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_missing_enforcement_policy_directory_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-missing-enforcement-manifest")?;
        let policy_path = temp.join("guard.lua");
        fs::write(
            &policy_path,
            "function on_http_request_headers(_) return {} end",
        )?;
        let mut config = config_with_policy(&policy_path)?;
        config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::Directory {
            path: temp.join("enforcement.d"),
        };
        let plan = runtime_plan(config)?;

        let error = build_check_report(plan)
            .await
            .expect_err("missing enforcement manifest must fail check");

        assert!(matches!(error, CheckError::ConfiguredEnforcement(_)));
        assert!(error.to_string().contains("does not exist"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_loads_remote_enforcement_policy_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-remote-enforcement-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(
            &policy_path,
            "function on_http_request_headers(_) return {} end",
        )?;
        let manifest = probe_config::EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "remote-v1".to_string(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Reset])?,
        };
        let server =
            SingleResponseHttpServer::spawn("/enforcement", "200 OK", toml::to_string(&manifest)?)?;
        let endpoint = server.endpoint();
        let mut config = config_with_policy(&policy_path)?;
        config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::Remote {
            endpoint: endpoint.clone(),
        };
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan).await?;

        assert_eq!(
            report.enforcement.policy.mode,
            EnforcementPolicyCheckMode::Loaded
        );
        let active = report
            .enforcement
            .policy
            .active
            .as_ref()
            .expect("remote enforcement manifest should load");
        assert_eq!(active.id, "managed-apps");
        assert_eq!(active.version, "remote-v1");
        assert_eq!(
            active.source,
            LoadedEnforcementPolicySourceSnapshot::Remote {
                endpoint: endpoint.clone()
            }
        );
        assert_eq!(active.protective_actions.actions(), &[Action::Reset]);
        let value = serde_json::to_value(&report)?;
        assert_eq!(
            value["enforcement"]["policy"]["active"]["source"]["kind"],
            json!("remote")
        );
        assert_eq!(
            value["enforcement"]["policy"]["active"]["source"]["endpoint"],
            json!(endpoint)
        );
        server.join()?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_has_stable_json_shape() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-json-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(
            &policy_path,
            "function on_http_request_headers(_) return {} end",
        )?;
        let report = build_check_report(runtime_plan(config_with_policy(&policy_path)?)?).await?;

        let value = serde_json::to_value(report)?;

        assert_eq!(value["plan"]["capture"]["mode"], json!("replay"));
        assert_eq!(
            value["plan"]["export"]["sinks"][0]["tls"]["trust_anchors"][0]["id"],
            json!("collector-ca")
        );
        assert_eq!(
            value["plan"]["export"]["sinks"][0]["tls"]["trust_anchors"][0]["kind"],
            json!("trust_anchor")
        );
        assert_eq!(
            value["plan"]["export"]["sinks"][0]["tls"]["trust_anchors"][0]["path"],
            json!("/tmp/collector-ca.pem")
        );
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
        assert_eq!(
            value["enforcement"]["effective_selector_configured"],
            json!(false)
        );
        assert_eq!(
            value["enforcement"]["config_selector_configured"],
            json!(false)
        );
        assert_eq!(
            value["enforcement"]["manifest_selector_configured"],
            json!(null)
        );
        assert_eq!(
            value["enforcement"]["policy"]["mode"],
            json!("not_configured")
        );
        assert!(value["enforcement"].get("planner_loaded").is_none());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_invalid_policy_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = test_dir("check-invalid-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(&policy_path, "function on_http_request_headers(")?;
        let plan = runtime_plan(config_with_policy(&policy_path)?)?;

        let error = build_check_report(plan)
            .await
            .expect_err("invalid Lua must fail explicit check");

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
                CapabilityState::available(CapabilityKind::WebSocketFrame),
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

[exporters.tls]
trust_anchor_refs = ["collector-ca"]

[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/tmp/collector-ca.pem"
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

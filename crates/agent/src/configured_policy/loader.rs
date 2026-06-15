use std::path::PathBuf;

use policy::PolicyRuntime;
use probe_config::{AgentConfig, PolicyConfig};
use probe_core::CompiledSelector;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfiguredPolicyError {
    #[error("invalid policy source for {id} at {path}: {reason}")]
    InvalidPolicySource {
        id: String,
        path: String,
        reason: String,
    },
    #[error("failed to read policy file for {id} at {path}: {source}")]
    ReadPolicy {
        id: String,
        path: String,
        source: std::io::Error,
    },
    #[error("failed to initialize policy {id} at {path}: {source}")]
    PolicyLoad {
        id: String,
        path: String,
        #[source]
        source: policy::PolicyError,
    },
    #[error("invalid policy selector for {id} at {path}: {source}")]
    Selector {
        id: String,
        path: String,
        #[source]
        source: probe_core::SelectorError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfiguredPolicySelection {
    pub configured_count: u64,
    pub enabled: Vec<ConfiguredPolicySource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfiguredPolicySource {
    pub id: String,
    pub path: PathBuf,
    pub selector_configured: bool,
}

pub struct LoadedConfiguredPolicy {
    pub runtime: PolicyRuntime,
    pub source: ConfiguredPolicySource,
    pub selector: Option<CompiledSelector>,
}

pub fn configured_policy_selection(config: &AgentConfig) -> ConfiguredPolicySelection {
    let enabled = enabled_policies(config);
    ConfiguredPolicySelection {
        configured_count: config.policies.len() as u64,
        enabled: enabled
            .iter()
            .copied()
            .map(configured_policy_source)
            .collect(),
    }
}

pub fn load_configured_policies(
    config: &AgentConfig,
) -> Result<Vec<LoadedConfiguredPolicy>, ConfiguredPolicyError> {
    enabled_policies(config)
        .into_iter()
        .map(read_configured_policy)
        .collect()
}

fn read_configured_policy(
    policy: &PolicyConfig,
) -> Result<LoadedConfiguredPolicy, ConfiguredPolicyError> {
    let selector = policy
        .selector
        .as_ref()
        .map(|selector| {
            selector
                .compile()
                .map_err(|source| ConfiguredPolicyError::Selector {
                    id: policy.id.clone(),
                    path: policy.path.display().to_string(),
                    source,
                })
        })
        .transpose()?;
    let source = super::source::load_policy_source(policy)?;
    let runtime = PolicyRuntime::from_source_with_required_hooks(source.manifest, &source.source)
        .map_err(|source| ConfiguredPolicyError::PolicyLoad {
        id: policy.id.clone(),
        path: policy.path.display().to_string(),
        source,
    })?;

    Ok(LoadedConfiguredPolicy {
        runtime,
        source: configured_policy_source(policy),
        selector,
    })
}

fn configured_policy_source(policy: &PolicyConfig) -> ConfiguredPolicySource {
    ConfiguredPolicySource {
        id: policy.id.clone(),
        path: policy.path.clone(),
        selector_configured: policy.selector.is_some(),
    }
}

fn enabled_policies(config: &AgentConfig) -> Vec<&PolicyConfig> {
    config
        .policies
        .iter()
        .filter(|policy| policy.enabled)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use capture::ReplayProvider;
    use parsers::Http1ParserFactory;
    use pipeline::{CapturePipeline, PipelinePolicy};
    use policy::{PolicyError, PolicyHook};
    use probe_config::{AgentConfig, PolicyConfig};
    use probe_core::{
        AddressPort, Direction, EventEnvelope, EventKind, FlowContext, FlowIdentity,
        ProcessContext, ProcessIdentity, ProcessSelector, Selector, Timestamp, TrafficSelector,
        TransportProtocol,
    };

    use super::*;

    const OVERSIZED_TEST_FILE_BYTES: u64 = 10 * 1024 * 1024;

    #[test]
    fn load_configured_policies_rejects_incomplete_bundle_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-incomplete-bundle")?;
        let policy_path = temp.join("policy-dir");
        fs::create_dir_all(&policy_path)?;
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policies(&config) else {
            panic!("directory policy source must fail");
        };

        assert!(matches!(
            error,
            ConfiguredPolicyError::InvalidPolicySource { id, path, .. }
                if id == "guard" && path == policy_path.display().to_string()
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn load_configured_policies_loads_bundle_manifest_and_main()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-bundle")?;
        let policy_path = temp.join("guard.bundle");
        write_policy_bundle(
            &policy_path,
            "guard",
            "bundle-test",
            &["on_http_request_headers"],
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("bundle " .. event.kind.target)
end
"#,
        )?;
        let config = config_with_policy(&policy_path)?;

        let loaded = load_configured_policies(&config)?;
        let loaded_policy = loaded.first().expect("configured policy");

        assert_eq!(loaded_policy.runtime.manifest().id, "guard");
        assert_eq!(loaded_policy.runtime.manifest().version, "bundle-test");
        assert_eq!(
            loaded_policy.runtime.manifest().hooks,
            vec![PolicyHook::HttpRequestHeaders]
        );
        assert_eq!(
            policy_alert_versions(
                &temp.join("bundle-spool"),
                loaded,
                flow_with_remote_port(80)
            )?,
            vec!["guard@bundle-test"]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn load_configured_policies_rejects_bundle_id_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-bundle-id-mismatch")?;
        let policy_path = temp.join("guard.bundle");
        write_policy_bundle(
            &policy_path,
            "other",
            "bundle-test",
            &["on_http_request_headers"],
            "function on_http_request_headers(_) return {} end",
        )?;
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policies(&config) else {
            panic!("bundle id mismatch must fail configured policy loading");
        };

        assert!(
            matches!(error, ConfiguredPolicyError::InvalidPolicySource { reason, .. } if reason.contains("does not match configured policy id guard"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn load_configured_policies_rejects_bundle_missing_declared_hook()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-bundle-missing-hook")?;
        let policy_path = temp.join("guard.bundle");
        write_policy_bundle(
            &policy_path,
            "guard",
            "bundle-test",
            &["on_http_request_headers"],
            "function on_sse_event(_) return {} end",
        )?;
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policies(&config) else {
            panic!("bundle missing a declared hook must fail configured policy loading");
        };

        assert!(matches!(
            error,
            ConfiguredPolicyError::PolicyLoad {
                source: PolicyError::MissingHook {
                    hook: PolicyHook::HttpRequestHeaders
                },
                ..
            }
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn load_configured_policies_rejects_symlinked_bundle_main()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-bundle-main-symlink")?;
        let policy_path = temp.join("guard.bundle");
        let external_source = temp.join("external.lua");
        write_policy_bundle(
            &policy_path,
            "guard",
            "bundle-test",
            &["on_http_request_headers"],
            "function on_http_request_headers(_) return {} end",
        )?;
        fs::write(
            &external_source,
            "function on_http_request_headers(_) return {} end",
        )?;
        fs::remove_file(policy_path.join("main.lua"))?;
        std::os::unix::fs::symlink(&external_source, policy_path.join("main.lua"))?;
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policies(&config) else {
            panic!("bundle symlinked main.lua must fail configured policy loading");
        };

        assert!(
            matches!(error, ConfiguredPolicyError::InvalidPolicySource { reason, .. } if reason.contains("must not be a symlink"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn load_configured_policies_rejects_source_above_size_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-too-large")?;
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
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policies(&config) else {
            panic!("oversized policy source must fail");
        };

        assert!(matches!(
            error,
            ConfiguredPolicyError::InvalidPolicySource { .. }
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn loaded_configured_policy_selector_scopes_pipeline_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-selector")?;
        let policy_path = temp.join("guard.bundle");
        write_policy_bundle(
            &policy_path,
            "guard",
            "bundle-test",
            &["on_http_request_headers"],
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("matched " .. event.kind.target)
end
"#,
        )?;
        let mut config = config_with_policy(&policy_path)?;
        config.policies[0].selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                ..TrafficSelector::default()
            },
        ));

        assert_eq!(
            policy_alert_versions(
                &temp.join("miss-spool"),
                load_configured_policies(&config)?,
                flow_with_remote_port(80)
            )?,
            Vec::<String>::new()
        );
        assert_eq!(
            policy_alert_versions(
                &temp.join("hit-spool"),
                load_configured_policies(&config)?,
                flow_with_remote_port(443)
            )?,
            vec!["guard@bundle-test"]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn load_configured_policies_runs_multiple_enabled_bundles_in_config_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-multiple-run")?;
        let first_path = temp.join("first.bundle");
        let second_path = temp.join("second.bundle");
        write_policy_bundle(
            &first_path,
            "first",
            "one",
            &["on_http_request_headers"],
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("first " .. event.kind.target)
end
"#,
        )?;
        write_policy_bundle(
            &second_path,
            "second",
            "two",
            &["on_http_request_headers"],
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("second " .. event.kind.target)
end
"#,
        )?;
        let mut config = config_with_policy(&first_path)?;
        config.policies[0].id = "first".to_string();
        config.policies.push(PolicyConfig {
            id: "second".to_string(),
            path: second_path,
            enabled: true,
            selector: None,
        });

        let loaded = load_configured_policies(&config)?;

        assert_eq!(
            policy_alert_versions(&temp.join("spool"), loaded, flow_with_remote_port(80))?,
            vec!["first@one", "second@two"]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn configured_policy_selection_reports_multiple_enabled_as_active()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-multiple")?;
        let first_path = temp.join("first.bundle");
        let second_path = temp.join("second.bundle");
        let mut config = config_with_policy(&first_path)?;
        config.policies.push(PolicyConfig {
            id: "second".to_string(),
            path: second_path,
            enabled: true,
            selector: None,
        });

        let selection = configured_policy_selection(&config);

        assert_eq!(selection.configured_count, 2);
        assert_eq!(selection.enabled.len(), 2);
        assert_eq!(selection.enabled[0].id, "guard");
        assert_eq!(selection.enabled[1].id, "second");
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn policy_alert_versions(
        spool_path: &Path,
        policies: Vec<LoadedConfiguredPolicy>,
        flow: FlowContext,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let spool = storage::FjallSpool::open(spool_path)?;
        let mut parser_factory = Http1ParserFactory::default();
        let mut provider = ReplayProvider::new(
            flow,
            Direction::Outbound,
            b"GET /scoped HTTP/1.1\r\nHost: test\r\n\r\n",
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
        );
        let mut pipeline = CapturePipeline::new(
            &spool,
            &mut parser_factory,
            policies
                .into_iter()
                .map(|policy| PipelinePolicy::new(policy.runtime, policy.selector))
                .collect(),
            "test",
        );

        pipeline.run_provider(&mut provider)?;
        let exported = spool.read_export_batch("sink", 16)?;
        let envelopes = exported
            .iter()
            .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(envelopes
            .iter()
            .filter_map(|envelope| {
                matches!(envelope.kind, EventKind::PolicyAlert(_))
                    .then(|| envelope.policy_version.clone())
                    .flatten()
            })
            .collect())
    }

    fn flow_with_remote_port(remote_port: u16) -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "replay".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: remote_port,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "replay".to_string(),
                cmdline: vec!["replay".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(remote_port as u64),
            attribution_confidence: 0,
        }
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

    fn write_policy_bundle(
        path: &Path,
        id: &str,
        version: &str,
        hooks: &[&str],
        source: &str,
    ) -> Result<(), std::io::Error> {
        fs::create_dir_all(path)?;
        let hooks = hooks
            .iter()
            .map(|hook| format!(r#""{hook}""#))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            path.join("manifest.toml"),
            format!(
                r#"
id = "{id}"
version = "{version}"
hooks = [{hooks}]
"#
            ),
        )?;
        fs::write(path.join("main.lua"), source)?;
        Ok(())
    }
}

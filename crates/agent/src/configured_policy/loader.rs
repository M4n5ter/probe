use pipeline::{PipelinePolicy, PipelinePolicySet};
use policy::PolicyRuntime;
use probe_config::{AgentConfig, PolicyConfig};
use probe_core::{CompiledSelector, SelectorRegistry};
use serde::Serialize;
use thiserror::Error;

use super::source::PolicySourceLoadContext;

#[derive(Debug, Error)]
pub enum ConfiguredPolicyError {
    #[error("invalid policy source for {id} at {source_ref}: {reason}")]
    InvalidPolicySource {
        id: String,
        source_ref: String,
        reason: String,
    },
    #[error("failed to read policy file for {id} at {source_ref}: {source}")]
    ReadPolicy {
        id: String,
        source_ref: String,
        source: std::io::Error,
    },
    #[error("failed to initialize policy {id} at {source_ref}: {source}")]
    PolicyLoad {
        id: String,
        source_ref: String,
        #[source]
        source: policy::PolicyError,
    },
    #[error("invalid policy selector for {id} at {source_ref}: {source}")]
    Selector {
        id: String,
        source_ref: String,
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
    pub source: super::source::PolicySourceSnapshot,
    pub selector_configured: bool,
    pub runtime_error_disable_threshold: u64,
}

pub struct LoadedConfiguredPolicy {
    pub runtime: PolicyRuntime,
    pub source: ConfiguredPolicySource,
    pub content: ConfiguredPolicyContent,
    pub selector: Option<CompiledSelector>,
}

impl LoadedConfiguredPolicy {
    pub fn into_pipeline_policy(self) -> PipelinePolicy {
        PipelinePolicy::with_runtime_error_disable_threshold(
            self.runtime,
            self.selector,
            self.source.runtime_error_disable_threshold,
        )
    }
}

pub struct LoadedPipelinePolicies {
    pub policies: Vec<PipelinePolicy>,
    pub sources: Vec<ConfiguredPolicySource>,
    pub content: Vec<ConfiguredPolicyContent>,
}

impl LoadedPipelinePolicies {
    pub fn into_policy_set(self) -> PipelinePolicySet {
        PipelinePolicySet::new(self.policies)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredPolicyContent {
    id: String,
    source: super::source::PolicySourceSnapshot,
    manifest: policy::PolicyManifest,
    main: String,
    modules: Vec<policy::PolicyModule>,
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

#[cfg(test)]
pub async fn load_configured_policies(
    config: &AgentConfig,
) -> Result<Vec<LoadedConfiguredPolicy>, ConfiguredPolicyError> {
    load_configured_policies_with_context(config, PolicySourceLoadContext::default()).await
}

pub async fn load_configured_policies_with_context(
    config: &AgentConfig,
    context: PolicySourceLoadContext,
) -> Result<Vec<LoadedConfiguredPolicy>, ConfiguredPolicyError> {
    let mut policies = Vec::new();
    for policy in enabled_policies(config) {
        policies.push(read_configured_policy(policy, &config.selectors, context).await?);
    }
    Ok(policies)
}

pub async fn load_configured_pipeline_policies_with_context(
    config: &AgentConfig,
    context: PolicySourceLoadContext,
) -> Result<LoadedPipelinePolicies, ConfiguredPolicyError> {
    let policies = load_configured_policies_with_context(config, context).await?;
    let sources = policies
        .iter()
        .map(|policy| policy.source.clone())
        .collect::<Vec<_>>();
    let content = policies
        .iter()
        .map(|policy| policy.content.clone())
        .collect::<Vec<_>>();
    let policies = policies
        .into_iter()
        .map(LoadedConfiguredPolicy::into_pipeline_policy)
        .collect::<Vec<_>>();
    Ok(LoadedPipelinePolicies {
        policies,
        sources,
        content,
    })
}

async fn read_configured_policy(
    policy: &PolicyConfig,
    selector_registry: &SelectorRegistry,
    context: PolicySourceLoadContext,
) -> Result<LoadedConfiguredPolicy, ConfiguredPolicyError> {
    let source_ref = configured_policy_source(policy).source.reference();
    let selector = policy
        .selector
        .as_ref()
        .map(|selector| {
            selector
                .compile_with_registry(selector_registry)
                .map_err(|source| ConfiguredPolicyError::Selector {
                    id: policy.id.clone(),
                    source_ref: source_ref.clone(),
                    source,
                })
        })
        .transpose()?;
    let source = super::source::load_policy_source_with_context(policy, context).await?;
    let content = ConfiguredPolicyContent {
        id: policy.id.clone(),
        source: source.source.clone(),
        manifest: source.manifest.clone(),
        main: source.main.clone(),
        modules: source.modules.clone(),
    };
    let runtime = PolicyRuntime::from_bundle_with_required_hooks(
        source.manifest,
        &source.main,
        source.modules,
    )
    .map_err(|source| ConfiguredPolicyError::PolicyLoad {
        id: policy.id.clone(),
        source_ref: source_ref.clone(),
        source,
    })?;

    Ok(LoadedConfiguredPolicy {
        runtime,
        source: ConfiguredPolicySource {
            id: policy.id.clone(),
            source: source.source,
            selector_configured: policy.selector.is_some(),
            runtime_error_disable_threshold: policy.runtime_error_disable_threshold,
        },
        content,
        selector,
    })
}

fn configured_policy_source(policy: &PolicyConfig) -> ConfiguredPolicySource {
    ConfiguredPolicySource {
        id: policy.id.clone(),
        source: super::source::PolicySourceSnapshot::from(&policy.source),
        selector_configured: policy.selector.is_some(),
        runtime_error_disable_threshold: policy.runtime_error_disable_threshold,
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
    use pipeline::CapturePipeline;
    use policy::{PolicyError, PolicyHook};
    use probe_config::{AgentConfig, PolicyConfig, PolicySourceConfig};
    use probe_core::{
        AddressPort, Direction, EventEnvelope, EventKind, FlowContext, FlowIdentity,
        ProcessContext, ProcessIdentity, ProcessSelector, Selector, Timestamp, TrafficSelector,
        TransportProtocol,
    };

    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const OVERSIZED_TEST_FILE_BYTES: u64 = 10 * 1024 * 1024;
    const MODULE_POLICY_SOURCE: &str = r#"
local matcher = require("guard.matcher")

function on_http_request_headers(event)
  if matcher.matches(event.kind.target) then
    return probe.emit_alert("module " .. event.kind.target)
  end
  return nil
end
"#;
    const MATCHER_MODULE_SOURCE: &str = r#"
local M = {}

function M.matches(target)
  return target == "/scoped"
end

return M
"#;

    #[tokio::test]
    async fn load_configured_policies_rejects_incomplete_bundle_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-incomplete-bundle")?;
        let policy_path = temp.join("policy-dir");
        fs::create_dir_all(&policy_path)?;
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policies(&config).await else {
            panic!("directory policy source must fail");
        };

        assert!(matches!(
            error,
            ConfiguredPolicyError::InvalidPolicySource { id, source_ref, .. }
                if id == "guard" && source_ref == policy_path.display().to_string()
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_loads_bundle_manifest_and_main()
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

        let loaded = load_configured_policies(&config).await?;
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

    #[tokio::test]
    async fn load_configured_policies_loads_bundle_local_modules()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-bundle-modules")?;
        let policy_path = temp.join("guard.bundle");
        write_policy_bundle_with_modules(
            &policy_path,
            "guard",
            "module-test",
            &["on_http_request_headers"],
            MODULE_POLICY_SOURCE,
            &[("guard.matcher", MATCHER_MODULE_SOURCE)],
        )?;
        let config = config_with_policy(&policy_path)?;

        let loaded = load_configured_policies(&config).await?;

        assert_eq!(
            policy_alert_versions(
                &temp.join("module-spool"),
                loaded,
                flow_with_remote_port(80)
            )?,
            vec!["guard@module-test"]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_fetches_remote_bundle_document()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-remote-bundle")?;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/policies/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                remote_policy_bundle_document(
                    "guard",
                    "remote-test",
                    r#"
function on_http_request_headers(event)
  return probe.emit_alert("remote " .. event.kind.target)
end
"#,
                ),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let config = config_with_remote_policy(format!("{}/policies/guard", server.uri()), None);

        let loaded = load_configured_policies(&config).await?;

        let loaded_policy = loaded.first().expect("configured policy");
        assert_eq!(loaded_policy.runtime.manifest().id, "guard");
        assert_eq!(loaded_policy.runtime.manifest().version, "remote-test");
        assert_eq!(
            loaded_policy.source.source,
            super::super::source::PolicySourceSnapshot::RemoteBundle {
                endpoint: format!("{}/policies/guard", server.uri()),
                max_body_bytes: probe_config::DEFAULT_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES,
            }
        );
        assert_eq!(
            policy_alert_versions(
                &temp.join("remote-spool"),
                loaded,
                flow_with_remote_port(80)
            )?,
            vec!["guard@remote-test"]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_fetches_remote_bundle_modules()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-remote-bundle-modules")?;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/policies/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                remote_policy_bundle_document_with_modules(
                    "guard",
                    "remote-module-test",
                    MODULE_POLICY_SOURCE,
                    &[("guard.matcher", MATCHER_MODULE_SOURCE)],
                ),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let config = config_with_remote_policy(format!("{}/policies/guard", server.uri()), None);

        let loaded = load_configured_policies(&config).await?;

        assert_eq!(
            policy_alert_versions(
                &temp.join("remote-module-spool"),
                loaded,
                flow_with_remote_port(80)
            )?,
            vec!["guard@remote-module-test"]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_rejects_undeclared_remote_module()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/policies/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"
source = "function on_http_request_headers(_) return nil end"

[manifest]
id = "guard"
version = "remote-module-test"
hooks = ["on_http_request_headers"]

[[modules]]
name = "guard.unlisted"
source = "return {}"
"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let config = config_with_remote_policy(format!("{}/policies/guard", server.uri()), None);

        let Err(error) = load_configured_policies(&config).await else {
            panic!("undeclared remote module must fail");
        };

        assert!(
            matches!(error, ConfiguredPolicyError::InvalidPolicySource { ref reason, .. } if reason.contains("does not declare")),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_rejects_oversized_remote_bundle()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/policies/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                remote_policy_bundle_document(
                    "guard",
                    "remote-test",
                    "function on_http_request_headers(_) return {} end",
                ),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let config =
            config_with_remote_policy(format!("{}/policies/guard", server.uri()), Some(64));

        let Err(error) = load_configured_policies(&config).await else {
            panic!("oversized remote policy bundle must fail");
        };

        assert!(
            matches!(error, ConfiguredPolicyError::InvalidPolicySource { ref reason, .. } if reason.contains("too large")),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_rejects_invalid_remote_body_limit_without_fetch() {
        let endpoint = "https://policy.example.test/policies/guard".to_string();
        let config = config_with_remote_policy(endpoint.clone(), Some(0));

        let Err(error) = load_configured_policies(&config).await else {
            panic!("invalid remote policy body limit must fail");
        };

        assert!(
            matches!(
                error,
                ConfiguredPolicyError::InvalidPolicySource {
                    ref source_ref,
                    ref reason,
                    ..
                } if source_ref == &endpoint
                    && reason.contains("max_body_bytes must be greater than zero")
            ),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn load_configured_policies_rejects_remote_source_above_size_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let oversized_source = "x".repeat(1024 * 1024 + 1);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/policies/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                remote_policy_bundle_document("guard", "remote-test", &oversized_source),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let config = config_with_remote_policy(
            format!("{}/policies/guard", server.uri()),
            Some(2 * 1024 * 1024),
        );

        let Err(error) = load_configured_policies(&config).await else {
            panic!("oversized remote policy source must fail");
        };

        assert!(
            matches!(error, ConfiguredPolicyError::InvalidPolicySource { ref reason, .. } if reason.contains("remote policy bundle source") && reason.contains("exceeding")),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_rejects_bundle_id_mismatch()
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

        let Err(error) = load_configured_policies(&config).await else {
            panic!("bundle id mismatch must fail configured policy loading");
        };

        assert!(
            matches!(error, ConfiguredPolicyError::InvalidPolicySource { reason, .. } if reason.contains("does not match configured policy id guard"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_rejects_bundle_missing_declared_hook()
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

        let Err(error) = load_configured_policies(&config).await else {
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
    #[tokio::test]
    async fn load_configured_policies_rejects_symlinked_bundle_main()
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

        let Err(error) = load_configured_policies(&config).await else {
            panic!("bundle symlinked main.lua must fail configured policy loading");
        };

        assert!(
            matches!(error, ConfiguredPolicyError::InvalidPolicySource { reason, .. } if reason.contains("must not be a symlink"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn load_configured_policies_rejects_symlinked_module_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-bundle-module-dir-symlink")?;
        let policy_path = temp.join("guard.bundle");
        let external_module_dir = temp.join("external-modules").join("guard");
        write_policy_bundle(
            &policy_path,
            "guard",
            "bundle-test",
            &["on_http_request_headers"],
            MODULE_POLICY_SOURCE,
        )?;
        replace_manifest_modules(&policy_path, &["guard.matcher"])?;
        fs::create_dir_all(&external_module_dir)?;
        fs::write(
            external_module_dir.join("matcher.lua"),
            MATCHER_MODULE_SOURCE,
        )?;
        fs::create_dir_all(policy_path.join("modules"))?;
        std::os::unix::fs::symlink(
            &external_module_dir,
            policy_path.join("modules").join("guard"),
        )?;
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policies(&config).await else {
            panic!("bundle module directory symlink must fail configured policy loading");
        };

        assert!(
            matches!(error, ConfiguredPolicyError::InvalidPolicySource { ref reason, .. } if reason.contains("must not be a symlink")),
            "unexpected error: {error}"
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_rejects_source_above_size_limit()
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

        let Err(error) = load_configured_policies(&config).await else {
            panic!("oversized policy source must fail");
        };

        assert!(matches!(
            error,
            ConfiguredPolicyError::InvalidPolicySource { .. }
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn loaded_configured_policy_selector_scopes_pipeline_execution()
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
                load_configured_policies(&config).await?,
                flow_with_remote_port(80)
            )?,
            Vec::<String>::new()
        );
        assert_eq!(
            policy_alert_versions(
                &temp.join("hit-spool"),
                load_configured_policies(&config).await?,
                flow_with_remote_port(443)
            )?,
            vec!["guard@bundle-test"]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn load_configured_policies_runs_multiple_enabled_bundles_in_config_order()
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
            source: probe_config::PolicySourceConfig::LocalDirectory { path: second_path },
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
        });

        let loaded = load_configured_policies(&config).await?;

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
            source: probe_config::PolicySourceConfig::LocalDirectory { path: second_path },
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
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
                .map(LoadedConfiguredPolicy::into_pipeline_policy)
                .collect::<Vec<_>>(),
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
                matches!(envelope.kind(), EventKind::PolicyAlert(_))
                    .then(|| envelope.policy_version().map(str::to_string))
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

[policies.source]
kind = "local_directory"
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

    fn config_with_remote_policy(endpoint: String, max_body_bytes: Option<u64>) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::RemoteBundle {
                endpoint,
                max_body_bytes,
            },
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
        });
        config
    }

    fn remote_policy_bundle_document(id: &str, version: &str, source: &str) -> String {
        format!(
            r#"
source = {source:?}

[manifest]
id = "{id}"
version = "{version}"
hooks = ["on_http_request_headers"]
"#
        )
    }

    fn remote_policy_bundle_document_with_modules(
        id: &str,
        version: &str,
        source: &str,
        modules: &[(&str, &str)],
    ) -> String {
        let module_names = modules
            .iter()
            .map(|(name, _)| format!(r#""{name}""#))
            .collect::<Vec<_>>()
            .join(", ");
        let module_documents = modules
            .iter()
            .map(|(name, source)| {
                format!(
                    r#"
[[modules]]
name = "{name}"
source = {source:?}
"#
                )
            })
            .collect::<String>();
        format!(
            r#"
source = {source:?}

[manifest]
id = "{id}"
version = "{version}"
hooks = ["on_http_request_headers"]
modules = [{module_names}]
{module_documents}
"#
        )
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

    fn replace_manifest_modules(path: &Path, modules: &[&str]) -> Result<(), std::io::Error> {
        let module_names = modules
            .iter()
            .map(|name| format!(r#""{name}""#))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            path.join("manifest.toml"),
            format!(
                r#"
id = "guard"
version = "bundle-test"
hooks = ["on_http_request_headers"]
modules = [{module_names}]
"#
            ),
        )
    }

    fn write_policy_bundle_with_modules(
        path: &Path,
        id: &str,
        version: &str,
        hooks: &[&str],
        source: &str,
        modules: &[(&str, &str)],
    ) -> Result<(), std::io::Error> {
        fs::create_dir_all(path)?;
        let hooks = hooks
            .iter()
            .map(|hook| format!(r#""{hook}""#))
            .collect::<Vec<_>>()
            .join(", ");
        let module_names = modules
            .iter()
            .map(|(name, _)| format!(r#""{name}""#))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            path.join("manifest.toml"),
            format!(
                r#"
id = "{id}"
version = "{version}"
hooks = [{hooks}]
modules = [{module_names}]
"#
            ),
        )?;
        fs::write(path.join("main.lua"), source)?;
        for (name, source) in modules {
            let module_path = module_path(path, name);
            if let Some(parent) = module_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(module_path, source)?;
        }
        Ok(())
    }

    fn module_path(root: &Path, name: &str) -> PathBuf {
        let mut path = root.join("modules");
        for segment in name.split('.') {
            path.push(segment);
        }
        path.set_extension("lua");
        path
    }
}

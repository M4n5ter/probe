use crate::{
    configured_enforcement::ConfiguredEnforcementError,
    configured_policy::{
        ConfiguredPolicyError, LoadedConfiguredPolicy, PolicySourceSnapshot,
        configured_policy_selection, load_configured_policies_with_context,
    },
};
use ::enforcement::EnforcementBackend;
use policy::PolicyHook;
use runtime::RuntimePlan;
use serde::Serialize;
use thiserror::Error;

use super::enforcement::{EnforcementCheckSnapshot, check_enforcement};
use super::tls::{TlsCheckError, TlsCheckSnapshot, check_tls};
use crate::control_plane_http::policy_source_load_context_from_plan;

#[derive(Debug, Error)]
pub enum CheckError {
    #[error("{0}")]
    ConfiguredPolicy(#[from] ConfiguredPolicyError),
    #[error("enforcement error: {0}")]
    Enforcement(#[from] enforcement::EnforcementError),
    #[error("{0}")]
    ConfiguredEnforcement(#[source] Box<ConfiguredEnforcementError>),
    #[error("{0}")]
    Tls(#[from] TlsCheckError),
}

impl From<ConfiguredEnforcementError> for CheckError {
    fn from(error: ConfiguredEnforcementError) -> Self {
        Self::ConfiguredEnforcement(Box::new(error))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckReport {
    pub plan: RuntimePlan,
    pub tls: TlsCheckSnapshot,
    pub policy: PolicyCheckSnapshot,
    pub enforcement: EnforcementCheckSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyCheckSnapshot {
    pub mode: PolicyCheckMode,
    pub configured_count: u64,
    pub enabled_count: u64,
    pub active: Vec<LoadedPolicySnapshot>,
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
    pub source: PolicySourceSnapshot,
    pub selector_configured: bool,
    pub registered_hooks: Vec<PolicyHook>,
}

pub async fn build_check_report(
    plan: RuntimePlan,
    backend: Option<Box<dyn EnforcementBackend>>,
) -> Result<CheckReport, CheckError> {
    let enforcement = check_enforcement(&plan, backend).await?;
    let tls = check_tls(&plan)?;
    let policy = check_policy(&plan).await?;
    Ok(CheckReport {
        plan,
        tls,
        policy,
        enforcement,
    })
}

async fn check_policy(plan: &RuntimePlan) -> Result<PolicyCheckSnapshot, CheckError> {
    let config = &plan.config;
    let selection = configured_policy_selection(config);
    let enabled_count = selection.enabled.len() as u64;
    let policies =
        load_configured_policies_with_context(config, policy_source_load_context_from_plan(plan))
            .await?;
    if policies.is_empty() {
        return Ok(PolicyCheckSnapshot {
            mode: PolicyCheckMode::Inactive,
            configured_count: selection.configured_count,
            enabled_count,
            active: Vec::new(),
        });
    }

    Ok(PolicyCheckSnapshot {
        mode: PolicyCheckMode::Loaded,
        configured_count: selection.configured_count,
        enabled_count,
        active: policies.iter().map(loaded_policy_snapshot).collect(),
    })
}

fn loaded_policy_snapshot(policy: &LoadedConfiguredPolicy) -> LoadedPolicySnapshot {
    let manifest = policy.runtime.manifest();
    LoadedPolicySnapshot {
        id: manifest.id.clone(),
        version: manifest.version.clone(),
        source: policy.source.source.clone(),
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

    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, ConnectionEnforcementBackendConfig,
        TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        Action, CapabilityKind, CapabilityState, Direction, EnforcementMode, ProcessSelector,
        ProtectiveActionProfile, Selector, TrafficSelector,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, PlatformProbeResults, ProviderRegistry,
    };
    use serde_json::json;

    use crate::runtime_composition::{RuntimeComposition, build_runtime_composition_for_test};

    use crate::configured_enforcement::LoadedEnforcementPolicySourceSnapshot;

    use super::super::enforcement::EnforcementPolicyCheckMode;
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const MITM_BRIDGE_CAPTURE_EVENT_FEED_PATH: &str =
        "/run/traffic-probe/mitm-capture-events.jsonl";

    #[tokio::test]
    async fn check_report_loads_enabled_policy_bundle() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-valid-policy")?;
        let policy_path =
            write_policy_bundle(&temp, "function on_http_request_headers(_) return {} end")?;
        let plan = runtime_plan(config_with_policy(&policy_path)?)?;

        let report = build_check_report(plan, None).await?;

        assert_eq!(report.policy.mode, PolicyCheckMode::Loaded);
        assert_eq!(report.policy.active.len(), 1);
        let active = report.policy.active.first().expect("loaded policy");
        assert_eq!(active.id, "guard");
        assert_eq!(active.version, "bundle-test");
        assert_eq!(
            active.source,
            PolicySourceSnapshot::LocalDirectory { path: policy_path }
        );
        assert!(!active.selector_configured);
        assert!(
            active
                .registered_hooks
                .contains(&PolicyHook::HttpRequestHeaders)
        );
        assert_eq!(report.enforcement.mode, EnforcementMode::AuditOnly);
        assert_eq!(
            report.enforcement.connection.backend,
            ConnectionEnforcementBackendConfig::None
        );
        assert_eq!(
            report.enforcement.policy.mode,
            EnforcementPolicyCheckMode::NotConfigured
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_loads_multiple_enabled_policy_bundles()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-multiple-policy-bundles")?;
        let first_path = write_policy_bundle_with_id(
            &temp,
            "first",
            "function on_http_request_headers(_) return {} end",
        )?;
        let second_path = write_policy_bundle_with_id(
            &temp,
            "second",
            "function on_http_request_headers(_) return {} end",
        )?;
        let mut config = config_with_policy(&first_path)?;
        config.policies[0].id = "first".to_string();
        config.policies.push(probe_config::PolicyConfig {
            id: "second".to_string(),
            source: probe_config::PolicySourceConfig::LocalDirectory {
                path: second_path.clone(),
            },
            enabled: true,
            selector: Some(Selector::default()),
        });
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        assert_eq!(report.policy.mode, PolicyCheckMode::Loaded);
        assert_eq!(report.policy.enabled_count, 2);
        assert_eq!(
            report
                .policy
                .active
                .iter()
                .map(|policy| policy.id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(
            report.policy.active[0].source,
            PolicySourceSnapshot::LocalDirectory { path: first_path }
        );
        assert_eq!(
            report.policy.active[1].source,
            PolicySourceSnapshot::LocalDirectory { path: second_path }
        );
        assert!(!report.policy.active[0].selector_configured);
        assert!(report.policy.active[1].selector_configured);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_loads_enforcement_policy_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-enforcement-policy")?;
        let policy_path =
            write_policy_bundle(&temp, "function on_http_request_headers(_) return {} end")?;
        let enforcement_path = temp.join("enforcement.toml");
        let manifest = probe_config::EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selector: Some(Selector::default()),
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        fs::write(&enforcement_path, toml::to_string(&manifest)?)?;
        let mut config = config_with_policy(&policy_path)?;
        config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::File {
            path: enforcement_path.clone(),
        };
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

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
        assert_eq!(active.version, "test-version");
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
        let policy_path =
            write_policy_bundle(&temp, "function on_http_request_headers(_) return {} end")?;
        let enforcement_path = temp.join("enforcement.toml");
        fs::write(
            &enforcement_path,
            r#"
id = "managed-apps"
version = "test-version"
protective_actions = ["alert"]
"#,
        )?;
        let mut config = config_with_policy(&policy_path)?;
        config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::File {
            path: enforcement_path,
        };
        let plan = runtime_plan(config)?;

        let error = build_check_report(plan, None)
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
        let policy_path =
            write_policy_bundle(&temp, "function on_http_request_headers(_) return {} end")?;
        let mut config = config_with_policy(&policy_path)?;
        config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::Directory {
            path: temp.join("enforcement.d"),
        };
        let plan = runtime_plan(config)?;

        let error = build_check_report(plan, None)
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
        let policy_path =
            write_policy_bundle(&temp, "function on_http_request_headers(_) return {} end")?;
        let manifest = probe_config::EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "remote-test".to_string(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Reset])?,
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/enforcement"))
            .respond_with(ResponseTemplate::new(200).set_body_string(toml::to_string(&manifest)?))
            .expect(1)
            .mount(&server)
            .await;
        let endpoint = format!("{}/enforcement", server.uri());
        let mut config = config_with_policy(&policy_path)?;
        config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::Remote {
            endpoint: endpoint.clone(),
            max_body_bytes: None,
        };
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

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
        assert_eq!(active.version, "remote-test");
        assert_eq!(
            active.source,
            LoadedEnforcementPolicySourceSnapshot::Remote {
                endpoint: endpoint.clone(),
                max_body_bytes: probe_config::DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES,
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
        assert_eq!(
            value["enforcement"]["policy"]["active"]["source"]["max_body_bytes"],
            json!(probe_config::DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES)
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_has_stable_json_shape() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-json-policy")?;
        let policy_path =
            write_policy_bundle(&temp, "function on_http_request_headers(_) return {} end")?;
        let report =
            build_check_report(runtime_plan(config_with_policy(&policy_path)?)?, None).await?;

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
        assert_eq!(
            value["tls"]["plaintext"]["instrumentation"]["enabled"],
            json!(false)
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"],
            json!([])
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"],
            json!([])
        );
        assert_eq!(value["policy"]["mode"], json!("loaded"));
        assert_eq!(value["policy"]["configured_count"], json!(1));
        assert_eq!(value["policy"]["enabled_count"], json!(1));
        assert_eq!(value["policy"]["active"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["policy"]["active"][0]["id"], json!("guard"));
        assert_eq!(
            value["policy"]["active"][0]["version"],
            json!("bundle-test")
        );
        assert_eq!(
            value["policy"]["active"][0]["selector_configured"],
            json!(false)
        );
        assert!(value["policy"]["active"][0].get("hooks").is_none());
        assert!(
            value["policy"]["active"][0]["registered_hooks"]
                .as_array()
                .is_some_and(|hooks| hooks.iter().any(|hook| hook == "on_http_request_headers"))
        );
        assert_eq!(value["enforcement"]["mode"], json!("audit_only"));
        assert_eq!(value["enforcement"]["composition"]["kind"], json!("ready"));
        assert!(value["enforcement"]["composition"].get("reason").is_none());
        assert_eq!(value["enforcement"]["connection"]["backend"], json!("none"));
        assert_eq!(
            value["enforcement"]["connection"]["capability"]["kind"],
            json!("not_required")
        );
        assert_eq!(
            value["enforcement"]["interception"]["strategy"],
            json!("none")
        );
        assert_eq!(
            value["enforcement"]["interception"]["proxy"]["listen_port"],
            json!(null)
        );
        assert_eq!(
            value["enforcement"]["interception"]["proxy"]["mode"],
            json!("external")
        );
        assert_eq!(
            value["enforcement"]["interception"]["proxy"]["self_bypass"],
            json!("none")
        );
        assert_eq!(
            value["enforcement"]["interception"]["proxy"]["health_probe"]["mode"],
            json!("disabled")
        );
        assert_eq!(
            value["enforcement"]["interception"]["nftables"]["table_name"],
            json!("traffic_probe")
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["kind"],
            json!("not_configured")
        );
        assert_eq!(
            value["enforcement"]["interception"]["local_setup_projection"]["kind"],
            json!("not_configured")
        );
        assert_eq!(
            value["enforcement"]["interception"]["classification"]["process_classifier"]["kind"],
            json!("transparent_process_classifier")
        );
        assert_eq!(
            value["enforcement"]["interception"]["classification"]["process_classifier"]["mode"],
            json!("unavailable")
        );
        assert_eq!(
            value["enforcement"]["interception"]["classification"]["process_classifier"]["reason"],
            json!(
                "transparent process classifier capability is not provided by this runtime registry"
            )
        );
        assert_eq!(
            value["enforcement"]["interception"]["classification"]["flow_classifier"]["kind"],
            json!("transparent_flow_classifier")
        );
        assert_eq!(
            value["enforcement"]["interception"]["classification"]["flow_classifier"]["mode"],
            json!("unavailable")
        );
        assert_eq!(
            value["enforcement"]["interception"]["classification"]["flow_classifier"]["reason"],
            json!(
                "transparent flow classifier backend is not configured; not/ref transparent interception selectors and any selectors with classifier-only or unconstrained setup branches require flow-aware classification before rule installation"
            )
        );
        assert_eq!(
            plan_capability(&value, "transparent_process_classifier")["mode"],
            json!("unavailable")
        );
        assert_eq!(
            plan_capability(&value, "transparent_process_classifier")["reason"],
            json!(
                "transparent process classifier capability is not provided by this runtime registry"
            )
        );
        assert_eq!(
            plan_capability(&value, "transparent_flow_classifier")["mode"],
            json!("unavailable")
        );
        assert_eq!(
            plan_capability(&value, "transparent_flow_classifier")["reason"],
            json!(
                "transparent flow classifier backend is not configured; not/ref transparent interception selectors and any selectors with classifier-only or unconstrained setup branches require flow-aware classification before rule installation"
            )
        );
        assert_eq!(
            value["enforcement"]["interception"]["capabilities"],
            json!([])
        );
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
    async fn check_report_exposes_process_classifier_setup_block()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        let plan = RuntimePlan::build(
            config,
            &runtime_registry(vec![CapabilityState::available(
                CapabilityKind::TransparentInterception,
            )]),
        )?;

        let report = build_check_report(plan, None).await?;
        let value = serde_json::to_value(report)?;

        assert_eq!(
            value["enforcement"]["composition"]["kind"],
            json!("blocked")
        );
        assert!(
            value["enforcement"]["composition"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("transparent_process_classifier"))
        );
        assert_eq!(
            value["enforcement"]["interception"]["local_setup_projection"]["kind"],
            json!("requires_process_classifier")
        );
        assert_eq!(
            value["enforcement"]["interception"]["local_setup_projection"]["host_rule_boundary"]["kind"],
            json!("host_rules")
        );
        assert_eq!(
            value["enforcement"]["interception"]["local_setup_projection"]["process_scope"]["expression"]
                ["process"]["names"],
            json!(["curl"])
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_report_exposes_outbound_redirect_artifact()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
        config.enforcement.interception.proxy.mode =
            probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let (plan, backend) = build_test_runtime_composition(config)?.into_enforcement_parts();

        let report = build_check_report(plan, backend).await?;
        let value = serde_json::to_value(report)?;

        assert_eq!(value["enforcement"]["composition"]["kind"], json!("ready"));
        assert_eq!(
            value["enforcement"]["interception"]["local_setup_projection"]["kind"],
            json!("host_rules")
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["kind"],
            json!("planned")
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["artifact"]["chain_name"],
            json!("outbound_transparent_proxy")
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["artifact"]["hook"],
            json!("output")
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["artifact"]["proxy_port"],
            json!(15001)
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["artifact"]["proxy_bypass_mark"],
            json!(0x5450_0102)
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_report_exposes_outbound_mitm_capability_requirements()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm;
        config.enforcement.interception.proxy.self_bypass =
            probe_config::TransparentInterceptionProxySelfBypassConfig::UsesReservedMark;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        configure_external_mitm_plaintext_bridge(&mut config, false);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let plan = RuntimePlan::build(
            config,
            &runtime_registry(vec![
                CapabilityState::available(CapabilityKind::TransparentInterception),
                CapabilityState::available(CapabilityKind::L7Mitm),
                CapabilityState::available(CapabilityKind::CaptureEventFeed),
            ]),
        )?;

        let report = build_check_report(plan, None).await?;
        let value = serde_json::to_value(report)?;

        assert_eq!(
            value["enforcement"]["interception"]["strategy"],
            json!("outbound_transparent_mitm")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["strategy"],
            json!("outbound_transparent_mitm")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["execution"]["direction"],
            json!("outbound_transparent_proxy")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["execution"]["l7_mode"],
            json!("mitm")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["mode"],
            json!("external")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["mode"],
            json!("tcp_connect")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["target"],
            json!("127.0.0.1:15002")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["interval_ms"],
            json!(1_000)
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["timeout_ms"],
            json!(200)
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["failure_threshold"],
            json!(3)
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["backend"]["mode"],
            json!("external")
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["mode"],
            json!("tcp_connect")
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["interval_ms"],
            json!(1_000)
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["timeout_ms"],
            json!(200)
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["failure_threshold"],
            json!(3)
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["ca_certificate"]["id"],
            json!("mitm-ca")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["plaintext_bridge"]["mode"],
            json!("capture_event_feed")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["plaintext_bridge"]["path"],
            json!(MITM_BRIDGE_CAPTURE_EVENT_FEED_PATH)
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["plaintext_bridge"]["follow"],
            json!(false)
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["ca_certificate"]["id"],
            json!("mitm-ca")
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["plaintext_bridge"]["mode"],
            json!("capture_event_feed")
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["plaintext_bridge"]["path"],
            json!(MITM_BRIDGE_CAPTURE_EVENT_FEED_PATH)
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["plaintext_bridge"]["follow"],
            json!(false)
        );
        assert_eq!(
            interception_capability(&value, "transparent_interception")["mode"],
            json!("available")
        );
        assert_eq!(
            interception_capability(&value, "l7_mitm")["mode"],
            json!("available")
        );
        assert_eq!(
            interception_capability(&value, "capture_event_feed")["mode"],
            json!("available")
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["kind"],
            json!("planned")
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_report_exposes_managed_process_mitm_backend()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm;
        config.enforcement.interception.proxy.self_bypass =
            probe_config::TransparentInterceptionProxySelfBypassConfig::UsesReservedMark;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        configure_managed_process_mitm_plaintext_bridge(&mut config, false);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let plan = RuntimePlan::build(
            config,
            &runtime_registry(vec![
                CapabilityState::available(CapabilityKind::TransparentInterception),
                CapabilityState::available(CapabilityKind::L7Mitm),
                CapabilityState::available(CapabilityKind::CaptureEventFeed),
            ]),
        )?;

        let value = serde_json::to_value(build_check_report(plan, None).await?)?;

        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["mode"],
            json!("managed_process")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["process"]["program"],
            json!("/bin/true")
        );
        assert_eq!(
            value["plan"]["enforcement"]["interception"]["mitm"]["backend"]["process"]["args"],
            json!(["--listen", "127.0.0.1:15002"])
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["backend"]["mode"],
            json!("managed_process")
        );
        assert_eq!(
            value["enforcement"]["interception"]["mitm"]["backend"]["readiness_probe"]["target"],
            json!("127.0.0.1:15002")
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_report_exposes_external_outbound_proxy_self_bypass_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
        config.enforcement.interception.proxy.mode =
            probe_config::TransparentInterceptionProxyModeConfig::External;
        config.enforcement.interception.proxy.self_bypass =
            probe_config::TransparentInterceptionProxySelfBypassConfig::UsesReservedMark;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let (plan, backend) = build_test_runtime_composition(config)?.into_enforcement_parts();

        let report = build_check_report(plan, backend).await?;
        let value = serde_json::to_value(report)?;

        assert_eq!(value["enforcement"]["composition"]["kind"], json!("ready"));
        assert_eq!(
            value["enforcement"]["interception"]["proxy"]["mode"],
            json!("external")
        );
        assert_eq!(
            value["enforcement"]["interception"]["proxy"]["self_bypass"],
            json!("uses_reserved_mark")
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["artifact"]["proxy_bypass_mark"],
            json!(0x5450_0102)
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_report_exposes_outbound_process_scope_requirement()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
        config.enforcement.interception.proxy.mode =
            probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let (plan, backend) = build_test_runtime_composition(config)?.into_enforcement_parts();

        let report = build_check_report(plan, backend).await?;
        let value = serde_json::to_value(report)?;

        assert_eq!(
            value["enforcement"]["composition"]["kind"],
            json!("blocked")
        );
        assert!(
            value["enforcement"]["composition"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("process classifier"))
        );
        assert_eq!(
            value["enforcement"]["interception"]["local_setup_projection"]["kind"],
            json!("requires_process_classifier")
        );
        assert_eq!(
            value["enforcement"]["interception"]["outbound_redirect"]["kind"],
            json!("planned")
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_invalid_policy_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = test_dir("check-invalid-policy")?;
        let policy_path = write_policy_bundle(&temp, "function on_http_request_headers(")?;
        let plan = runtime_plan(config_with_policy(&policy_path)?)?;

        let error = build_check_report(plan, None)
            .await
            .expect_err("invalid Lua must fail explicit check");

        assert!(matches!(
            error,
            CheckError::ConfiguredPolicy(ConfiguredPolicyError::PolicyLoad { .. })
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_enforce_without_backend_factory_before_loading_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-enforce-without-backend")?;
        let policy_path = temp.join("missing-policy.bundle");
        let mut config = config_with_policy(&policy_path)?;
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;
        let plan = runtime_plan_with_connection_enforcement(config)?;

        let error = build_check_report(plan, None)
            .await
            .expect_err("enforce must require an executable backend factory");

        assert!(matches!(
            error,
            CheckError::ConfiguredEnforcement(error)
                if matches!(*error, ConfiguredEnforcementError::ExecutionBackendUnavailable)
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(config, &runtime_registry(Vec::new()))
    }

    fn build_test_runtime_composition(
        config: AgentConfig,
    ) -> Result<RuntimeComposition, crate::error::AgentError> {
        build_runtime_composition_for_test(
            config,
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            )],
            PlatformProbeResults {
                procfs_socket: Vec::new(),
                connection_enforcement: CapabilityState::unavailable(
                    CapabilityKind::ConnectionEnforcement,
                    "not configured",
                ),
                transparent_interception: CapabilityState::available(
                    CapabilityKind::TransparentInterception,
                ),
                transparent_process_classifier: CapabilityState::degraded(
                    CapabilityKind::TransparentProcessClassifier,
                    "setup-time listener proof only",
                ),
                transparent_flow_classifier:
                    PlatformProbeResults::default_transparent_flow_classifier(),
                l7_mitm: CapabilityState::unavailable(CapabilityKind::L7Mitm, "not configured"),
                libssl_uprobe: CapabilityState::unavailable(
                    CapabilityKind::LibsslUprobe,
                    "not configured",
                ),
            },
        )
    }

    fn runtime_plan_with_connection_enforcement(
        config: AgentConfig,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(
            config,
            &runtime_registry(vec![CapabilityState::available(
                CapabilityKind::ConnectionEnforcement,
            )]),
        )
    }

    fn runtime_registry(extra_capabilities: Vec<CapabilityState>) -> ProviderRegistry {
        ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::available(
                    CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                ),
                CaptureProviderDescriptor::available(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                ),
            ],
            vec![
                CapabilityState::available(CapabilityKind::Http1),
                CapabilityState::available(CapabilityKind::Sse),
                CapabilityState::available(CapabilityKind::WebSocketHandoff),
                CapabilityState::available(CapabilityKind::WebSocketFrame),
                CapabilityState::available(CapabilityKind::DryRunEnforcement),
                PlatformProbeResults::default_transparent_process_classifier(),
                PlatformProbeResults::default_transparent_flow_classifier(),
            ]
            .into_iter()
            .chain(extra_capabilities)
            .collect(),
        )
    }

    fn plan_capability<'a>(value: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
        value["plan"]["capabilities"]["states"]
            .as_array()
            .expect("plan capabilities should serialize as states")
            .iter()
            .find(|state| state["kind"] == json!(kind))
            .unwrap_or_else(|| panic!("missing serialized capability {kind}"))
    }

    fn interception_capability<'a>(
        value: &'a serde_json::Value,
        capability: &str,
    ) -> &'a serde_json::Value {
        value["enforcement"]["interception"]["capabilities"]
            .as_array()
            .expect("interception capabilities should serialize as an array")
            .iter()
            .find(|state| state["capability"] == json!(capability))
            .unwrap_or_else(|| panic!("missing interception capability {capability}"))
    }

    fn configure_external_mitm_backend(config: &mut AgentConfig) {
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some("127.0.0.1:15002".to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
    }

    fn configure_external_mitm_plaintext_bridge(config: &mut AgentConfig, follow: bool) {
        configure_external_mitm_backend(config);
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path =
            Some(MITM_BRIDGE_CAPTURE_EVENT_FEED_PATH.into());
        config.enforcement.interception.mitm.plaintext_bridge.follow = Some(follow);
    }

    fn configure_managed_process_mitm_plaintext_bridge(config: &mut AgentConfig, follow: bool) {
        configure_external_mitm_plaintext_bridge(config, follow);
        let readiness_probe = TransparentInterceptionMitmBackendReadinessProbeConfig {
            target: Some("127.0.0.1:15002".to_string()),
            ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
        };
        let process = probe_config::TransparentInterceptionMitmManagedProcessConfig {
            program: Some("/bin/true".into()),
            args: vec!["--listen".to_string(), "127.0.0.1:15002".to_string()],
            working_dir: None,
        };
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::managed_process(readiness_probe, process);
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

    fn write_policy_bundle(
        temp: &Path,
        source: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        write_policy_bundle_with_id(temp, "guard", source)
    }

    fn write_policy_bundle_with_id(
        temp: &Path,
        id: &str,
        source: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let policy_path = temp.join(format!("{id}.bundle"));
        fs::create_dir_all(&policy_path)?;
        fs::write(
            policy_path.join("manifest.toml"),
            format!(
                r#"
id = "{id}"
version = "bundle-test"
hooks = ["on_http_request_headers"]
"#
            ),
        )?;
        fs::write(policy_path.join("main.lua"), source)?;
        Ok(policy_path)
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

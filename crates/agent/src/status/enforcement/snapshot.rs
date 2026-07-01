use crate::configured_enforcement::{
    ActiveEnforcementPolicy, EnforcementPolicySourceInspection, LoadedEnforcementPolicySource,
    LoadedEnforcementPolicySourceSnapshot, inspect_enforcement_policy_source,
};
use crate::l7_mitm::L7MitmRuntimeSnapshot;
use crate::transparent_interception::TransparentProxyRuntimeSnapshot;
use probe_config::{ConnectionEnforcementBackendConfig, TransparentInterceptionStrategyConfig};
use probe_core::{CapabilityKind, EnforcementMode, ProtectiveActionProfile, RuntimeMode};
use runtime::{
    EnforcementCapabilityPlan, RequiredCapabilityPlan, RuntimePlan,
    TransparentInterceptionClassificationPlan, TransparentInterceptionLocalSetupProjectionPlan,
    TransparentInterceptionMitmPlan, TransparentInterceptionNftablesPlan,
    TransparentInterceptionOutboundRedirectPlan, TransparentInterceptionProxyPlan,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementStatusSnapshot {
    pub configured_mode: EnforcementMode,
    pub status: EnforcementStatusMode,
    pub effective_selector_configured: Option<bool>,
    pub config_selector_configured: bool,
    pub manifest_selector_configured: Option<bool>,
    pub connection: EnforcementConnectionStatusSnapshot,
    pub interception: EnforcementInterceptionStatusSnapshot,
    pub policy: EnforcementPolicyStatusSnapshot,
    pub mode_capability: EnforcementCapabilityStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementConnectionStatusSnapshot {
    pub backend: ConnectionEnforcementBackendConfig,
    pub capability: EnforcementCapabilityStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementInterceptionStatusSnapshot {
    pub strategy: TransparentInterceptionStrategyConfig,
    pub proxy: TransparentInterceptionProxyPlan,
    pub mitm: TransparentInterceptionMitmPlan,
    pub nftables: TransparentInterceptionNftablesPlan,
    pub outbound_redirect: TransparentInterceptionOutboundRedirectPlan,
    pub local_setup_projection: TransparentInterceptionLocalSetupProjectionPlan,
    pub classification: TransparentInterceptionClassificationPlan,
    pub selector_configured: bool,
    pub capabilities: Vec<RequiredCapabilityPlan>,
    pub runtime_l7_mitm: Option<L7MitmRuntimeSnapshot>,
    pub runtime_proxy: Option<TransparentProxyRuntimeSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatusMode {
    Disabled,
    AuditOnly,
    DryRun,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementCapabilityStatusSnapshot {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementPolicyStatusSnapshot {
    pub source: EnforcementPolicySourceStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum EnforcementPolicySourceStatusSnapshot {
    NotConfigured,
    LocalMetadata {
        reason: String,
        manifest: EnforcementPolicyManifestStatusSnapshot,
    },
    RemoteConfigured {
        endpoint: String,
        max_body_bytes: u64,
        reason: String,
    },
    Loaded {
        source: LoadedEnforcementPolicySourceSnapshot,
        manifest: EnforcementPolicyManifestStatusSnapshot,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementPolicyManifestStatusSnapshot {
    pub id: String,
    pub version: String,
    pub selector_configured: bool,
    pub protective_actions: ProtectiveActionProfile,
}

pub(in crate::status) fn enforcement_status_with_transparent_proxy(
    plan: &RuntimePlan,
    l7_mitm: Option<L7MitmRuntimeSnapshot>,
    transparent_proxy: Option<TransparentProxyRuntimeSnapshot>,
) -> EnforcementStatusSnapshot {
    enforcement_status_with_source(
        plan,
        EnforcementPolicyStatusSource::Offline,
        l7_mitm,
        transparent_proxy,
    )
}

pub(in crate::status) fn enforcement_status_with_active_policy(
    plan: &RuntimePlan,
    policy: &ActiveEnforcementPolicy,
    l7_mitm: Option<L7MitmRuntimeSnapshot>,
    transparent_proxy: Option<TransparentProxyRuntimeSnapshot>,
) -> EnforcementStatusSnapshot {
    enforcement_status_with_source(
        plan,
        EnforcementPolicyStatusSource::Active(policy),
        l7_mitm,
        transparent_proxy,
    )
}

fn enforcement_status_with_source(
    plan: &RuntimePlan,
    source: EnforcementPolicyStatusSource<'_>,
    l7_mitm: Option<L7MitmRuntimeSnapshot>,
    transparent_proxy: Option<TransparentProxyRuntimeSnapshot>,
) -> EnforcementStatusSnapshot {
    let configured_mode = plan.enforcement.mode;
    let policy = enforcement_policy_status(plan, source);
    let status = match configured_mode {
        EnforcementMode::Disabled => EnforcementStatusMode::Disabled,
        EnforcementMode::AuditOnly => EnforcementStatusMode::AuditOnly,
        EnforcementMode::DryRun => EnforcementStatusMode::DryRun,
        EnforcementMode::Enforce => EnforcementStatusMode::Enforce,
    };
    let mode_capability = enforcement_capability_status(&plan.enforcement.mode_capability);

    EnforcementStatusSnapshot {
        configured_mode,
        status,
        effective_selector_configured: policy.effective_selector_configured,
        config_selector_configured: plan.enforcement.config_selector_configured,
        manifest_selector_configured: policy.manifest_selector_configured,
        connection: EnforcementConnectionStatusSnapshot {
            backend: plan.enforcement.connection.backend,
            capability: enforcement_capability_status(&plan.enforcement.connection.capability),
        },
        interception: EnforcementInterceptionStatusSnapshot {
            strategy: plan.enforcement.interception.strategy,
            proxy: plan.enforcement.interception.proxy.clone(),
            mitm: plan.enforcement.interception.mitm.clone(),
            nftables: plan.enforcement.interception.nftables.clone(),
            outbound_redirect: plan
                .enforcement
                .interception
                .execution
                .outbound_redirect_plan(),
            local_setup_projection: plan.enforcement.interception.local_setup_projection.clone(),
            classification: plan.enforcement.interception.classification.clone(),
            selector_configured: plan.enforcement.interception.selector_configured,
            capabilities: plan.enforcement.interception.capabilities.clone(),
            runtime_l7_mitm: l7_mitm,
            runtime_proxy: transparent_proxy,
        },
        policy: policy.snapshot,
        mode_capability,
    }
}

fn enforcement_capability_status(
    capability: &EnforcementCapabilityPlan,
) -> EnforcementCapabilityStatusSnapshot {
    match capability {
        EnforcementCapabilityPlan::NotRequired => EnforcementCapabilityStatusSnapshot::NotRequired,
        EnforcementCapabilityPlan::Required {
            capability,
            mode,
            reason,
        } => EnforcementCapabilityStatusSnapshot::Required {
            capability: *capability,
            mode: *mode,
            reason: reason.clone(),
        },
    }
}

enum EnforcementPolicyStatusSource<'a> {
    Offline,
    Active(&'a ActiveEnforcementPolicy),
}

fn enforcement_policy_status(
    plan: &RuntimePlan,
    source: EnforcementPolicyStatusSource<'_>,
) -> EnforcementPolicyStatus {
    match source {
        EnforcementPolicyStatusSource::Offline => offline_enforcement_policy_status(plan),
        EnforcementPolicyStatusSource::Active(policy) => active_enforcement_policy_status(policy),
    }
}

struct EnforcementPolicyStatus {
    snapshot: EnforcementPolicyStatusSnapshot,
    manifest_selector_configured: Option<bool>,
    effective_selector_configured: Option<bool>,
}

fn offline_enforcement_policy_status(plan: &RuntimePlan) -> EnforcementPolicyStatus {
    match inspect_enforcement_policy_source(&plan.enforcement.policy_source) {
        EnforcementPolicySourceInspection::NotConfigured => not_configured_policy_status(plan),
        EnforcementPolicySourceInspection::LocalMetadata { manifest } => {
            local_metadata_policy_status(
                plan,
                enforcement_policy_manifest_status(manifest),
                "enforcement policy source metadata is available, but status does not execute enforcement actions"
                    .to_string(),
            )
        }
        EnforcementPolicySourceInspection::RemoteConfigured {
            endpoint,
            max_body_bytes,
        } => remote_configured_policy_status(plan, endpoint, max_body_bytes),
        EnforcementPolicySourceInspection::Unavailable { reason } => {
            unavailable_policy_status(reason)
        }
    }
}

fn active_enforcement_policy_status(policy: &ActiveEnforcementPolicy) -> EnforcementPolicyStatus {
    let Some(source) = policy.policy_source() else {
        return EnforcementPolicyStatus {
            effective_selector_configured: Some(policy.effective_selector_configured()),
            manifest_selector_configured: None,
            snapshot: EnforcementPolicyStatusSnapshot {
                source: EnforcementPolicySourceStatusSnapshot::NotConfigured,
            },
        };
    };

    let manifest = loaded_enforcement_policy_manifest_status(source);
    let manifest_selector_configured = Some(manifest.selector_configured);
    EnforcementPolicyStatus {
        effective_selector_configured: Some(policy.effective_selector_configured()),
        manifest_selector_configured,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::Loaded {
                source: source.snapshot(),
                manifest,
            },
        },
    }
}

fn loaded_enforcement_policy_manifest_status(
    source: &LoadedEnforcementPolicySource,
) -> EnforcementPolicyManifestStatusSnapshot {
    EnforcementPolicyManifestStatusSnapshot {
        id: source.manifest.id.clone(),
        version: source.manifest.version.clone(),
        selector_configured: source.manifest.selector.is_some(),
        protective_actions: source.manifest.protective_actions.clone(),
    }
}

fn not_configured_policy_status(plan: &RuntimePlan) -> EnforcementPolicyStatus {
    EnforcementPolicyStatus {
        effective_selector_configured: Some(plan.enforcement.config_selector_configured),
        manifest_selector_configured: None,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::NotConfigured,
        },
    }
}

fn local_metadata_policy_status(
    plan: &RuntimePlan,
    manifest: EnforcementPolicyManifestStatusSnapshot,
    reason: String,
) -> EnforcementPolicyStatus {
    let manifest_selector_configured = Some(manifest.selector_configured);
    EnforcementPolicyStatus {
        effective_selector_configured: Some(
            plan.enforcement.config_selector_configured || manifest.selector_configured,
        ),
        manifest_selector_configured,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::LocalMetadata { reason, manifest },
        },
    }
}

fn remote_configured_policy_status(
    plan: &RuntimePlan,
    endpoint: String,
    max_body_bytes: u64,
) -> EnforcementPolicyStatus {
    EnforcementPolicyStatus {
        effective_selector_configured: plan.enforcement.config_selector_configured.then_some(true),
        manifest_selector_configured: None,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::RemoteConfigured {
                reason: format!(
                    "remote enforcement policy source {endpoint} is configured, but offline status does not fetch remote policy"
                ),
                endpoint,
                max_body_bytes,
            },
        },
    }
}

fn unavailable_policy_status(reason: String) -> EnforcementPolicyStatus {
    EnforcementPolicyStatus {
        effective_selector_configured: None,
        manifest_selector_configured: None,
        snapshot: EnforcementPolicyStatusSnapshot {
            source: EnforcementPolicySourceStatusSnapshot::Unavailable { reason },
        },
    }
}

fn enforcement_policy_manifest_status(
    manifest: probe_config::EnforcementPolicyManifest,
) -> EnforcementPolicyManifestStatusSnapshot {
    EnforcementPolicyManifestStatusSnapshot {
        id: manifest.id,
        version: manifest.version,
        selector_configured: manifest.selector.is_some(),
        protective_actions: manifest.protective_actions,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use probe_config::{EnforcementPolicyManifest, EnforcementPolicySourceConfig};
    use probe_core::{
        Action, Direction, ProcessSelector, ProtectiveActionProfile, RuntimeMode, Selector,
        TrafficSelector,
    };
    use serde_json::json;

    use super::super::super::plan_fixture::{
        config_with_storage_path, runtime_plan_from_config, test_dir,
    };
    use super::*;
    use crate::runtime_composition::{RuntimeComposition, build_runtime_composition_for_test};

    const MITM_BRIDGE_CAPTURE_EVENT_FEED_PATH: &str =
        "/run/traffic-probe/mitm-capture-events.jsonl";

    #[test]
    fn enforcement_status_reports_metadata_only_policy_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-enforcement-policy")?;
        let manifest_path = temp.join("enforcement.toml");
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selectors: Default::default(),
            selector: Some(Selector::default()),
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        fs::write(&manifest_path, toml::to_string(&manifest)?)?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path,
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = enforcement_status(&plan);

        assert_eq!(status.effective_selector_configured, Some(true));
        assert!(!status.config_selector_configured);
        assert_eq!(status.manifest_selector_configured, Some(true));
        let EnforcementPolicySourceStatusSnapshot::LocalMetadata {
            reason,
            manifest: manifest_status,
        } = &status.policy.source
        else {
            panic!("local enforcement source should report manifest metadata");
        };
        assert!(reason.contains("status does not execute enforcement actions"));
        assert_eq!(manifest_status.id, "managed-apps");
        assert_eq!(manifest_status.version, "test-version");
        assert!(manifest_status.selector_configured);
        assert_eq!(
            manifest_status.protective_actions.actions(),
            &[Action::Deny]
        );
        let value = serde_json::to_value(&status)?;
        assert_eq!(value["policy"]["source"]["mode"], json!("local_metadata"));
        assert_eq!(
            value["policy"]["source"]["manifest"]["protective_actions"],
            json!(["deny"])
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn missing_enforcement_policy_directory_manifest_marks_source_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-missing-enforcement-manifest")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Directory {
            path: temp.join("enforcement.d"),
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = enforcement_status(&plan);

        assert!(matches!(
            status.policy.source,
            EnforcementPolicySourceStatusSnapshot::Unavailable { .. }
        ));
        assert_eq!(status.effective_selector_configured, None);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn invalid_enforcement_policy_manifest_marks_source_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-invalid-enforcement-manifest")?;
        let manifest_path = temp.join("enforcement.toml");
        fs::write(
            &manifest_path,
            r#"
id = "managed-apps"
version = "test-version"
protective_actions = ["alert"]
"#,
        )?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path,
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = enforcement_status(&plan);

        let EnforcementPolicySourceStatusSnapshot::Unavailable { reason } = &status.policy.source
        else {
            panic!("invalid enforcement source should be unavailable");
        };
        assert!(reason.contains("not a protective enforcement action"));
        assert_eq!(status.effective_selector_configured, None);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn remote_enforcement_policy_source_is_metadata_only_in_offline_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: "https://control.example/enforcement".to_string(),
            max_body_bytes: None,
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = enforcement_status(&plan);

        let EnforcementPolicySourceStatusSnapshot::RemoteConfigured {
            reason,
            max_body_bytes,
            ..
        } = &status.policy.source
        else {
            panic!("remote enforcement source should be metadata-only offline");
        };
        assert!(reason.contains("offline status does not fetch remote policy"));
        assert_eq!(
            *max_body_bytes,
            probe_config::DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES
        );
        assert_eq!(status.effective_selector_configured, None);
        Ok(())
    }

    #[test]
    fn remote_enforcement_policy_source_preserves_config_selector_in_offline_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.enforcement.selector = Some(Selector::default());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: "https://control.example/enforcement".to_string(),
            max_body_bytes: Some(2 * 1024 * 1024),
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = enforcement_status(&plan);

        assert!(matches!(
            status.policy.source,
            EnforcementPolicySourceStatusSnapshot::RemoteConfigured {
                max_body_bytes: 2_097_152,
                ..
            }
        ));
        assert_eq!(status.effective_selector_configured, Some(true));
        Ok(())
    }

    #[test]
    fn loaded_remote_enforcement_policy_status_reports_source_origin()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = "https://control.example/enforcement".to_string();
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: endpoint.clone(),
            max_body_bytes: Some(2 * 1024 * 1024),
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "remote-test".to_string(),
            selectors: Default::default(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Reset])?,
        };

        let policy_source =
            LoadedEnforcementPolicySource::remote(endpoint.clone(), 2 * 1024 * 1024, manifest);
        let active_policy = ActiveEnforcementPolicy::new(
            None,
            policy_source.manifest.protective_actions.clone(),
            Some(policy_source),
        )?;

        let status = enforcement_status_with_active_policy(&plan, &active_policy, None, None);

        let EnforcementPolicySourceStatusSnapshot::Loaded {
            source:
                LoadedEnforcementPolicySourceSnapshot::Remote {
                    endpoint: actual,
                    max_body_bytes,
                },
            manifest,
        } = &status.policy.source
        else {
            panic!("remote loaded enforcement source should keep its origin");
        };
        assert_eq!(actual, &endpoint);
        assert_eq!(*max_body_bytes, 2_097_152);
        assert_eq!(manifest.id, "managed-apps");
        assert_eq!(manifest.version, "remote-test");
        assert_eq!(manifest.protective_actions.actions(), &[Action::Reset]);
        let value = serde_json::to_value(&status)?;
        assert_eq!(value["policy"]["source"]["mode"], json!("loaded"));
        assert_eq!(value["policy"]["source"]["source"]["kind"], json!("remote"));
        assert_eq!(
            value["policy"]["source"]["source"]["endpoint"],
            json!(endpoint)
        );
        assert_eq!(
            value["policy"]["source"]["source"]["max_body_bytes"],
            json!(2_097_152)
        );
        Ok(())
    }

    #[test]
    fn dry_run_enforcement_status_requires_capability() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.enforcement.mode = probe_core::EnforcementMode::DryRun;
        let plan = runtime_plan_from_config(
            config,
            vec![probe_core::CapabilityState::available(
                CapabilityKind::DryRunEnforcement,
            )],
        )?;

        let status = enforcement_status(&plan);

        assert_eq!(status.status, EnforcementStatusMode::DryRun);
        assert_eq!(
            status.mode_capability,
            EnforcementCapabilityStatusSnapshot::Required {
                capability: CapabilityKind::DryRunEnforcement,
                mode: RuntimeMode::Available,
                reason: None,
            }
        );
        Ok(())
    }

    #[test]
    fn enforce_status_reports_connection_enforcement_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.backend =
            probe_config::ConnectionEnforcementBackendConfig::LinuxSocketDestroy;
        attach_test_enforcement_policy_source(&mut config);
        let plan = runtime_plan_from_config(
            config,
            vec![probe_core::CapabilityState::available(
                CapabilityKind::ConnectionEnforcement,
            )],
        )?;

        let status = enforcement_status(&plan);

        assert_eq!(status.status, EnforcementStatusMode::Enforce);
        assert_eq!(
            status.connection.backend,
            probe_config::ConnectionEnforcementBackendConfig::LinuxSocketDestroy
        );
        assert_eq!(
            status.connection.capability,
            EnforcementCapabilityStatusSnapshot::Required {
                capability: CapabilityKind::ConnectionEnforcement,
                mode: RuntimeMode::Available,
                reason: None,
            }
        );
        let value = serde_json::to_value(&status)?;
        assert_eq!(value["status"], json!("enforce"));
        assert_eq!(
            value["connection"]["backend"],
            json!("linux_socket_destroy")
        );
        assert_eq!(
            value["connection"]["capability"]["capability"],
            json!("connection_enforcement")
        );
        Ok(())
    }

    #[test]
    fn enforce_status_reports_transparent_interception_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            probe_config::TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.proxy.health_probe.target =
            Some("127.0.0.1:18080".to_string());
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .interval_ms = 500;
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .timeout_ms = 100;
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .failure_threshold = 2;
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        attach_test_enforcement_policy_source(&mut config);
        let plan = runtime_plan_from_config(
            config,
            vec![
                probe_core::CapabilityState::available(CapabilityKind::TransparentInterception),
                runtime::PlatformProbeResults::default_transparent_process_classifier(),
                runtime::PlatformProbeResults::default_transparent_flow_classifier(),
            ],
        )?;

        let status = enforcement_status(&plan);

        assert_eq!(
            status.connection.capability,
            EnforcementCapabilityStatusSnapshot::NotRequired
        );
        assert_eq!(
            status.interception.strategy,
            probe_config::TransparentInterceptionStrategyConfig::InboundTproxy
        );
        assert_eq!(
            status.interception.proxy.mode,
            probe_config::TransparentInterceptionProxyModeConfig::External
        );
        assert_eq!(
            status.interception.proxy.self_bypass,
            probe_config::TransparentInterceptionProxySelfBypassConfig::None
        );
        assert_eq!(status.interception.proxy.listen_port, Some(15001));
        assert_eq!(status.interception.nftables.table_name, "traffic_probe");
        assert_eq!(
            status.interception.nftables.inbound_tproxy_route_table,
            45_100
        );
        assert_eq!(
            status.interception.outbound_redirect,
            runtime::TransparentInterceptionOutboundRedirectPlan::NotConfigured
        );
        assert!(status.interception.selector_configured);
        assert!(matches!(
            status.interception.local_setup_projection,
            runtime::TransparentInterceptionLocalSetupProjectionPlan::HostRules { .. }
        ));
        assert_eq!(
            status.interception.capabilities,
            vec![RequiredCapabilityPlan {
                capability: CapabilityKind::TransparentInterception,
                mode: RuntimeMode::Available,
                reason: None,
            }]
        );
        assert_eq!(
            status.interception.classification.process_classifier.kind,
            CapabilityKind::TransparentProcessClassifier
        );
        assert_eq!(
            status.interception.classification.process_classifier.mode,
            RuntimeMode::Unavailable
        );
        assert_eq!(
            status.interception.classification.flow_classifier.kind,
            CapabilityKind::TransparentFlowClassifier
        );
        assert_eq!(
            status.interception.classification.flow_classifier.mode,
            RuntimeMode::Unavailable
        );
        let value = serde_json::to_value(&status)?;
        assert_eq!(value["interception"]["strategy"], json!("inbound_tproxy"));
        assert_eq!(value["interception"]["proxy"]["mode"], json!("external"));
        assert_eq!(value["interception"]["proxy"]["self_bypass"], json!("none"));
        assert_eq!(value["interception"]["proxy"]["listen_port"], json!(15001));
        assert_eq!(
            value["interception"]["proxy"]["health_probe"]["mode"],
            json!("enabled")
        );
        assert_eq!(
            value["interception"]["proxy"]["health_probe"]["target"],
            json!("127.0.0.1:18080")
        );
        assert_eq!(
            value["interception"]["proxy"]["health_probe"]["interval_ms"],
            json!(500)
        );
        assert_eq!(
            value["interception"]["proxy"]["health_probe"]["timeout_ms"],
            json!(100)
        );
        assert_eq!(
            value["interception"]["proxy"]["health_probe"]["failure_threshold"],
            json!(2)
        );
        assert_eq!(
            value["interception"]["nftables"]["table_name"],
            json!("traffic_probe")
        );
        assert_eq!(
            value["interception"]["nftables"]["inbound_tproxy_mark"],
            json!(0x5450_0101)
        );
        assert_eq!(
            value["interception"]["nftables"]["outbound_proxy_bypass_mark"],
            json!(0x5450_0102)
        );
        assert_eq!(
            value["interception"]["nftables"]["inbound_tproxy_route_table"],
            json!(45_100)
        );
        assert_eq!(
            value["interception"]["outbound_redirect"]["kind"],
            json!("not_configured")
        );
        assert_eq!(
            value["interception"]["local_setup_projection"]["kind"],
            json!("host_rules")
        );
        assert_eq!(
            value["interception"]["classification"]["process_classifier"]["kind"],
            json!("transparent_process_classifier")
        );
        assert_eq!(
            value["interception"]["classification"]["process_classifier"]["mode"],
            json!("unavailable")
        );
        assert_eq!(
            value["interception"]["classification"]["process_classifier"]["reason"],
            json!(
                "transparent process classifier capability is not provided by this runtime registry"
            )
        );
        assert_eq!(
            value["interception"]["classification"]["flow_classifier"]["kind"],
            json!("transparent_flow_classifier")
        );
        assert_eq!(
            value["interception"]["classification"]["flow_classifier"]["mode"],
            json!("unavailable")
        );
        assert_eq!(
            value["interception"]["classification"]["flow_classifier"]["reason"],
            json!(default_transparent_flow_classifier_reason())
        );
        assert_eq!(
            value["interception"]["capabilities"][0]["capability"],
            json!("transparent_interception")
        );
        Ok(())
    }

    #[test]
    fn enforce_status_reports_external_mitm_plaintext_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let bridge_path = PathBuf::from(MITM_BRIDGE_CAPTURE_EVENT_FEED_PATH);
        let plan = runtime_plan_from_config(
            config_with_external_mitm_plaintext_bridge(bridge_path.clone()),
            vec![
                probe_core::CapabilityState::available(CapabilityKind::TransparentInterception),
                probe_core::CapabilityState::available(CapabilityKind::L7Mitm),
                probe_core::CapabilityState::available(CapabilityKind::CaptureEventFeed),
            ],
        )?;

        let status = enforcement_status(&plan);
        let value = serde_json::to_value(&status)?;

        assert_eq!(
            status.interception.mitm.plaintext_bridge,
            runtime::TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed {
                path: bridge_path,
                follow: false,
            }
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["mode"],
            json!("external")
        );
        assert_eq!(
            value["interception"]["mitm"]["client_trust"]["mode"],
            json!("operator_managed")
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["readiness_probe"]["mode"],
            json!("tcp_connect")
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["readiness_probe"]["target"],
            json!("127.0.0.1:15002")
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["readiness_probe"]["interval_ms"],
            json!(1_000)
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["readiness_probe"]["timeout_ms"],
            json!(200)
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["readiness_probe"]["failure_threshold"],
            json!(3)
        );
        assert_eq!(
            value["interception"]["mitm"]["plaintext_bridge"]["mode"],
            json!("capture_event_feed")
        );
        assert_eq!(
            value["interception"]["mitm"]["plaintext_bridge"]["path"],
            json!(MITM_BRIDGE_CAPTURE_EVENT_FEED_PATH)
        );
        assert_eq!(
            value["interception"]["mitm"]["plaintext_bridge"]["follow"],
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
        Ok(())
    }

    #[test]
    fn enforce_status_reports_managed_process_mitm_backend()
    -> Result<(), Box<dyn std::error::Error>> {
        let bridge_path = PathBuf::from(MITM_BRIDGE_CAPTURE_EVENT_FEED_PATH);
        let plan = runtime_plan_from_config(
            config_with_managed_process_mitm_plaintext_bridge(bridge_path),
            vec![
                probe_core::CapabilityState::available(CapabilityKind::TransparentInterception),
                probe_core::CapabilityState::available(CapabilityKind::L7Mitm),
                probe_core::CapabilityState::available(CapabilityKind::CaptureEventFeed),
            ],
        )?;

        let value = serde_json::to_value(enforcement_status(&plan))?;

        assert_eq!(
            value["interception"]["mitm"]["backend"]["mode"],
            json!("managed_process")
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["process"]["program"],
            json!("/bin/true")
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["process"]["args"],
            json!(["--listen", "127.0.0.1:15002"])
        );
        assert_eq!(
            value["interception"]["mitm"]["backend"]["readiness_probe"]["target"],
            json!("127.0.0.1:15002")
        );
        Ok(())
    }

    #[test]
    fn enforce_status_reports_outbound_redirect_artifact() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.exporters.clear();
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            probe_config::TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
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
        attach_test_enforcement_policy_source(&mut config);
        let plan = build_test_runtime_composition(config)?.into_plan();

        let status = enforcement_status(&plan);
        let value = serde_json::to_value(&status)?;

        assert_eq!(
            status.interception.strategy,
            probe_config::TransparentInterceptionStrategyConfig::OutboundTransparentProxy
        );
        assert!(matches!(
            status.interception.local_setup_projection,
            runtime::TransparentInterceptionLocalSetupProjectionPlan::HostRules { .. }
        ));
        assert_eq!(
            status.interception.capabilities,
            vec![RequiredCapabilityPlan {
                capability: CapabilityKind::TransparentInterception,
                mode: RuntimeMode::Available,
                reason: None,
            }]
        );
        assert_eq!(
            value["interception"]["outbound_redirect"]["kind"],
            json!("planned")
        );
        assert_eq!(
            value["interception"]["outbound_redirect"]["artifact"]["chain_name"],
            json!("outbound_transparent_proxy")
        );
        assert_eq!(
            value["interception"]["outbound_redirect"]["artifact"]["priority"],
            json!("dstnat")
        );
        assert_eq!(
            value["interception"]["outbound_redirect"]["artifact"]["proxy_bypass_mark"],
            json!(0x5450_0102)
        );
        Ok(())
    }

    #[test]
    fn enforce_status_reports_external_outbound_proxy_self_bypass_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.exporters.clear();
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            probe_config::TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
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
        attach_test_enforcement_policy_source(&mut config);
        let plan = build_test_runtime_composition(config)?.into_plan();

        let status = enforcement_status(&plan);
        let value = serde_json::to_value(&status)?;

        assert_eq!(
            status.interception.proxy.mode,
            probe_config::TransparentInterceptionProxyModeConfig::External
        );
        assert_eq!(
            status.interception.proxy.self_bypass,
            probe_config::TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
        );
        assert_eq!(value["interception"]["proxy"]["mode"], json!("external"));
        assert_eq!(
            value["interception"]["proxy"]["self_bypass"],
            json!("uses_reserved_mark")
        );
        assert_eq!(
            value["interception"]["outbound_redirect"]["kind"],
            json!("planned")
        );
        Ok(())
    }

    #[test]
    fn enforce_status_reports_process_classifier_setup_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            probe_config::TransparentInterceptionStrategyConfig::InboundTproxy;
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
        attach_test_enforcement_policy_source(&mut config);
        let plan = runtime_plan_from_config(
            config,
            vec![probe_core::CapabilityState::available(
                CapabilityKind::TransparentInterception,
            )],
        )?;

        let status = enforcement_status(&plan);

        let value = serde_json::to_value(&status)?;
        assert_eq!(
            value["interception"]["local_setup_projection"]["kind"],
            json!("requires_process_classifier")
        );
        assert_eq!(
            value["interception"]["local_setup_projection"]["process_scope"]["expression"]["kind"],
            json!("match")
        );
        assert_eq!(
            value["interception"]["local_setup_projection"]["process_scope"]["expression"]["process"]
                ["names"],
            json!(["curl"])
        );
        assert_eq!(
            value["interception"]["local_setup_projection"]["host_rule_boundary"]["kind"],
            json!("host_rules")
        );
        assert_eq!(
            value["interception"]["local_setup_projection"]["host_rule_boundary"]["scopes"][0]["local_ports"]
                ["kind"],
            json!("only")
        );
        assert_eq!(
            value["interception"]["local_setup_projection"]["host_rule_boundary"]["scopes"][0]["local_ports"]
                ["ports"],
            json!([8443])
        );
        Ok(())
    }

    fn enforcement_status(plan: &RuntimePlan) -> EnforcementStatusSnapshot {
        enforcement_status_with_transparent_proxy(plan, None, None)
    }

    fn attach_test_enforcement_policy_source(config: &mut probe_config::AgentConfig) {
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: "/tmp/traffic-probe-enforcement.toml".into(),
        };
    }

    fn config_with_external_mitm_plaintext_bridge(
        bridge_path: PathBuf,
    ) -> probe_config::AgentConfig {
        let mut config = config_with_storage_path("/tmp/traffic-probe-spool".into());
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.exporters.clear();
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            probe_config::TransparentInterceptionStrategyConfig::OutboundTransparentMitm;
        config.enforcement.interception.proxy.self_bypass =
            probe_config::TransparentInterceptionProxySelfBypassConfig::UsesReservedMark;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        config.enforcement.interception.mitm.backend =
            probe_config::TransparentInterceptionMitmBackendConfig::external(
                probe_config::TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some("127.0.0.1:15002".to_string()),
                    ..probe_config::TransparentInterceptionMitmBackendReadinessProbeConfig::default(
                    )
                },
            );
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            probe_config::TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(bridge_path);
        config.enforcement.interception.mitm.plaintext_bridge.follow = Some(false);
        config.enforcement.interception.mitm.client_trust.mode =
            probe_config::TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        attach_test_enforcement_policy_source(&mut config);
        config.tls.materials = vec![
            probe_config::TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: probe_config::TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            probe_config::TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: probe_config::TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
        config
    }

    fn config_with_managed_process_mitm_plaintext_bridge(
        bridge_path: PathBuf,
    ) -> probe_config::AgentConfig {
        let mut config = config_with_external_mitm_plaintext_bridge(bridge_path);
        let readiness_probe =
            probe_config::TransparentInterceptionMitmBackendReadinessProbeConfig {
                target: Some("127.0.0.1:15002".to_string()),
                ..probe_config::TransparentInterceptionMitmBackendReadinessProbeConfig::default()
            };
        let process = probe_config::TransparentInterceptionMitmManagedProcessConfig {
            program: Some("/bin/true".into()),
            args: vec!["--listen".to_string(), "127.0.0.1:15002".to_string()],
            working_dir: None,
        };
        config.enforcement.interception.mitm.backend =
            probe_config::TransparentInterceptionMitmBackendConfig::managed_process(
                readiness_probe,
                process,
            );
        config
    }

    fn interception_capability<'a>(
        value: &'a serde_json::Value,
        capability: &str,
    ) -> &'a serde_json::Value {
        value["interception"]["capabilities"]
            .as_array()
            .expect("interception capabilities should serialize as an array")
            .iter()
            .find(|state| state["capability"] == json!(capability))
            .unwrap_or_else(|| panic!("missing interception capability {capability}"))
    }

    fn default_transparent_flow_classifier_reason() -> String {
        runtime::PlatformProbeResults::default_transparent_flow_classifier()
            .reason
            .expect("default transparent flow classifier should report a reason")
    }

    fn build_test_runtime_composition(
        config: probe_config::AgentConfig,
    ) -> Result<RuntimeComposition, crate::error::AgentError> {
        build_runtime_composition_for_test(
            config,
            vec![runtime::CaptureProviderDescriptor::available(
                probe_config::CaptureBackend::Libpcap,
                runtime::CaptureProviderBuilder::Libpcap,
            )],
            runtime::PlatformProbeResults {
                procfs_socket: Vec::new(),
                connection_enforcement: probe_core::CapabilityState::unavailable(
                    CapabilityKind::ConnectionEnforcement,
                    "not configured",
                ),
                transparent_interception: probe_core::CapabilityState::available(
                    CapabilityKind::TransparentInterception,
                ),
                transparent_process_classifier:
                    runtime::PlatformProbeResults::default_transparent_process_classifier(),
                transparent_flow_classifier:
                    runtime::PlatformProbeResults::default_transparent_flow_classifier(),
                l7_mitm: probe_core::CapabilityState::unavailable(
                    CapabilityKind::L7Mitm,
                    "not configured",
                ),
                libssl_uprobe: probe_core::CapabilityState::unavailable(
                    CapabilityKind::LibsslUprobe,
                    "not configured",
                ),
            },
        )
    }
}

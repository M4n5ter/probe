use std::path::PathBuf;

use crate::configured_enforcement::{
    ActiveEnforcementPolicy, EnforcementPolicySourceInspection, LoadedEnforcementPolicySource,
    LoadedEnforcementPolicySourceOriginRef, inspect_enforcement_policy_source,
};
use crate::transparent_interception::TransparentProxyRuntimeSnapshot;
use probe_config::{ConnectionEnforcementBackendConfig, TransparentInterceptionStrategyConfig};
use probe_core::{CapabilityKind, EnforcementMode, ProtectiveActionProfile, RuntimeMode};
use runtime::{
    EnforcementCapabilityPlan, RuntimePlan, TransparentInterceptionLocalSetupScopePlan,
    TransparentInterceptionNftablesPlan, TransparentInterceptionProxyPlan,
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
    pub nftables: TransparentInterceptionNftablesPlan,
    pub local_setup_scope: TransparentInterceptionLocalSetupScopePlan,
    pub selector_configured: bool,
    pub capability: EnforcementCapabilityStatusSnapshot,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementCapabilityStatusSnapshot {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
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
        reason: String,
    },
    Loaded {
        source: LoadedEnforcementPolicySourceStatusSnapshot,
        manifest: EnforcementPolicyManifestStatusSnapshot,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LoadedEnforcementPolicySourceStatusSnapshot {
    Local { path: PathBuf },
    Remote { endpoint: String },
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
    transparent_proxy: Option<TransparentProxyRuntimeSnapshot>,
) -> EnforcementStatusSnapshot {
    enforcement_status_with_source(
        plan,
        EnforcementPolicyStatusSource::Offline,
        transparent_proxy,
    )
}

pub(in crate::status) fn enforcement_status_with_active_policy(
    plan: &RuntimePlan,
    policy: &ActiveEnforcementPolicy,
    transparent_proxy: Option<TransparentProxyRuntimeSnapshot>,
) -> EnforcementStatusSnapshot {
    enforcement_status_with_source(
        plan,
        EnforcementPolicyStatusSource::Active(policy),
        transparent_proxy,
    )
}

fn enforcement_status_with_source(
    plan: &RuntimePlan,
    source: EnforcementPolicyStatusSource<'_>,
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
            proxy: plan.enforcement.interception.proxy,
            nftables: plan.enforcement.interception.nftables.clone(),
            local_setup_scope: plan.enforcement.interception.local_setup_scope.clone(),
            selector_configured: plan.enforcement.interception.selector_configured,
            capability: enforcement_capability_status(&plan.enforcement.interception.capability),
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
        EnforcementCapabilityPlan::Required { capability, mode } => {
            EnforcementCapabilityStatusSnapshot::Required {
                capability: *capability,
                mode: *mode,
            }
        }
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
        EnforcementPolicySourceInspection::RemoteConfigured { endpoint } => {
            remote_configured_policy_status(plan, endpoint)
        }
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
                source: loaded_enforcement_policy_source_status(source),
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

fn loaded_enforcement_policy_source_status(
    source: &LoadedEnforcementPolicySource,
) -> LoadedEnforcementPolicySourceStatusSnapshot {
    match source.origin() {
        LoadedEnforcementPolicySourceOriginRef::LocalPath(path) => {
            LoadedEnforcementPolicySourceStatusSnapshot::Local {
                path: path.to_path_buf(),
            }
        }
        LoadedEnforcementPolicySourceOriginRef::RemoteEndpoint(endpoint) => {
            LoadedEnforcementPolicySourceStatusSnapshot::Remote {
                endpoint: endpoint.to_string(),
            }
        }
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
    use std::fs;

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

    #[test]
    fn enforcement_status_reports_metadata_only_policy_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-enforcement-policy")?;
        let manifest_path = temp.join("enforcement.toml");
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
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
        let mut config = config_with_storage_path("/tmp/sssa-spool".into());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: "https://control.example/enforcement".to_string(),
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = enforcement_status(&plan);

        let EnforcementPolicySourceStatusSnapshot::RemoteConfigured { reason, .. } =
            &status.policy.source
        else {
            panic!("remote enforcement source should be metadata-only offline");
        };
        assert!(reason.contains("offline status does not fetch remote policy"));
        assert_eq!(status.effective_selector_configured, None);
        Ok(())
    }

    #[test]
    fn remote_enforcement_policy_source_preserves_config_selector_in_offline_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/sssa-spool".into());
        config.enforcement.selector = Some(Selector::default());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: "https://control.example/enforcement".to_string(),
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = enforcement_status(&plan);

        assert!(matches!(
            status.policy.source,
            EnforcementPolicySourceStatusSnapshot::RemoteConfigured { .. }
        ));
        assert_eq!(status.effective_selector_configured, Some(true));
        Ok(())
    }

    #[test]
    fn loaded_remote_enforcement_policy_status_reports_source_origin()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = "https://control.example/enforcement".to_string();
        let mut config = config_with_storage_path("/tmp/sssa-spool".into());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: endpoint.clone(),
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "remote-test".to_string(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Reset])?,
        };

        let policy_source = LoadedEnforcementPolicySource::remote(endpoint.clone(), manifest);
        let active_policy = ActiveEnforcementPolicy::new(
            None,
            policy_source.manifest.protective_actions.clone(),
            Some(policy_source),
        )?;

        let status = enforcement_status_with_active_policy(&plan, &active_policy, None);

        let EnforcementPolicySourceStatusSnapshot::Loaded {
            source: LoadedEnforcementPolicySourceStatusSnapshot::Remote { endpoint: actual },
            manifest,
        } = &status.policy.source
        else {
            panic!("remote loaded enforcement source should keep its origin");
        };
        assert_eq!(actual, &endpoint);
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
        Ok(())
    }

    #[test]
    fn dry_run_enforcement_status_requires_capability() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/sssa-spool".into());
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
            }
        );
        Ok(())
    }

    #[test]
    fn enforce_status_reports_connection_enforcement_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path("/tmp/sssa-spool".into());
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.backend =
            probe_config::ConnectionEnforcementBackendConfig::LinuxSocketDestroy;
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
        let mut config = config_with_storage_path("/tmp/sssa-spool".into());
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            probe_config::TransparentInterceptionStrategyConfig::OutboundMitm;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let plan = runtime_plan_from_config(
            config,
            vec![probe_core::CapabilityState::available(
                CapabilityKind::TransparentInterception,
            )],
        )?;

        let status = enforcement_status(&plan);

        assert_eq!(
            status.connection.capability,
            EnforcementCapabilityStatusSnapshot::NotRequired
        );
        assert_eq!(
            status.interception.strategy,
            probe_config::TransparentInterceptionStrategyConfig::OutboundMitm
        );
        assert_eq!(
            status.interception.proxy.mode,
            probe_config::TransparentInterceptionProxyModeConfig::External
        );
        assert_eq!(status.interception.proxy.listen_port, Some(15001));
        assert_eq!(status.interception.nftables.table_name, "sssa_probe");
        assert_eq!(status.interception.nftables.route_table, 53_534);
        assert!(status.interception.selector_configured);
        assert!(matches!(
            status.interception.local_setup_scope,
            runtime::TransparentInterceptionLocalSetupScopePlan::Unsupported { .. }
        ));
        assert_eq!(
            status.interception.capability,
            EnforcementCapabilityStatusSnapshot::Required {
                capability: CapabilityKind::TransparentInterception,
                mode: RuntimeMode::Available,
            }
        );
        let value = serde_json::to_value(&status)?;
        assert_eq!(value["interception"]["strategy"], json!("outbound_mitm"));
        assert_eq!(value["interception"]["proxy"]["mode"], json!("external"));
        assert_eq!(value["interception"]["proxy"]["listen_port"], json!(15001));
        assert_eq!(
            value["interception"]["nftables"]["table_name"],
            json!("sssa_probe")
        );
        assert_eq!(
            value["interception"]["local_setup_scope"]["kind"],
            json!("unsupported")
        );
        assert_eq!(
            value["interception"]["capability"]["capability"],
            json!("transparent_interception")
        );
        Ok(())
    }

    fn enforcement_status(plan: &RuntimePlan) -> EnforcementStatusSnapshot {
        enforcement_status_with_transparent_proxy(plan, None)
    }
}

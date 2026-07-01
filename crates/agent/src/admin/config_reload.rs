use std::path::{Path, PathBuf};

use probe_config::{AgentConfig, ConfigError};
use runtime::validate_static_runtime_config;
use serde::Serialize;

const MAX_CANDIDATE_CONFIG_BYTES: u64 = 1024 * 1024;

const CONFIG_RELOAD_SECTIONS: [ConfigReloadSectionSpec; 10] = [
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::AgentIdentity,
        reason: "agent identity and event config_version are bound into status, audit, and durable event metadata",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Capture,
        reason: "capture provider ownership is fixed after the live provider is opened",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Storage,
        reason: "durable spool path and retention workers are owned by the running process",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Export,
        reason: "export sinks and worker cursors are planned before the export worker starts",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::PolicyReload,
        reason: "policy reload watcher and poller topology is created from the startup plan",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Policies,
        reason: "pipeline policy slots are scoped by the startup plan; reload_policies only refreshes configured sources",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Selectors,
        reason: "selectors feed capture, policy, enforcement, and interception planning boundaries",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Tls,
        reason: "TLS materials and plaintext instrumentation are resolved before provider construction",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Enforcement,
        reason: "enforcement backend, transparent rules, and MITM lifecycle ownership are setup-time resources",
    },
    ConfigReloadSectionSpec {
        section: ConfigReloadSection::Admin,
        reason: "admin socket and Prometheus listener are bound by the running admin server",
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ConfigReloadPlanSnapshot {
    pub candidate_path: PathBuf,
    pub current_config_version: String,
    pub candidate_config_version: Option<String>,
    pub decision: ConfigReloadDecision,
    pub changed_sections: Vec<ConfigReloadSectionChange>,
    pub reloadable_runtime_actions: Vec<ConfigReloadRuntimeAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(super) enum ConfigReloadDecision {
    NoChange,
    RestartRequired { reason: String },
    InvalidCandidate { stage: &'static str, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ConfigReloadSectionChange {
    pub section: ConfigReloadSection,
    pub restart_required: bool,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConfigReloadSection {
    AgentIdentity,
    Capture,
    Storage,
    Export,
    PolicyReload,
    Policies,
    Selectors,
    Tls,
    Enforcement,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConfigReloadRuntimeAction {
    ReloadPolicies,
    ReloadEnforcementPolicy,
}

#[derive(Debug, Clone, Copy)]
struct ConfigReloadSectionSpec {
    section: ConfigReloadSection,
    reason: &'static str,
}

pub(super) fn plan_config_reload(
    current: &AgentConfig,
    candidate_path: &Path,
) -> ConfigReloadPlanSnapshot {
    let candidate_content = match probe_io::read_bounded_regular_file_to_string(
        candidate_path,
        MAX_CANDIDATE_CONFIG_BYTES,
    ) {
        Ok(content) => content,
        Err(error) => {
            return invalid_plan(
                current,
                candidate_path,
                "read",
                format!("failed to read candidate config: {error}"),
                None,
            );
        }
    };
    let candidate = match AgentConfig::from_toml_str(&candidate_content) {
        Ok(config) => config,
        Err(error) => {
            return invalid_plan(
                current,
                candidate_path,
                "parse",
                describe_parse_error(error),
                None,
            );
        }
    };
    let candidate_config_version = Some(candidate.config_version.clone());
    match validate_static_runtime_config(&candidate) {
        Ok(()) => {}
        Err(error) => {
            return invalid_plan(
                current,
                candidate_path,
                "validate",
                format!("candidate config failed static runtime validation: {error}"),
                candidate_config_version,
            );
        }
    };
    let changed_sections = changed_sections(current, &candidate);
    let decision = if changed_sections.is_empty() {
        ConfigReloadDecision::NoChange
    } else {
        ConfigReloadDecision::RestartRequired {
            reason: "candidate config passed static validation, but the running process does not yet have swappable owners for changed runtime resources".to_string(),
        }
    };
    ConfigReloadPlanSnapshot {
        candidate_path: candidate_path.to_path_buf(),
        current_config_version: current.config_version.clone(),
        candidate_config_version,
        decision,
        changed_sections,
        reloadable_runtime_actions: reloadable_runtime_actions(),
    }
}

fn invalid_plan(
    current: &AgentConfig,
    candidate_path: &Path,
    stage: &'static str,
    reason: String,
    candidate_config_version: Option<String>,
) -> ConfigReloadPlanSnapshot {
    ConfigReloadPlanSnapshot {
        candidate_path: candidate_path.to_path_buf(),
        current_config_version: current.config_version.clone(),
        candidate_config_version,
        decision: ConfigReloadDecision::InvalidCandidate { stage, reason },
        changed_sections: Vec::new(),
        reloadable_runtime_actions: reloadable_runtime_actions(),
    }
}

fn describe_parse_error(error: ConfigError) -> String {
    match error {
        ConfigError::Toml(error) => match error.span() {
            Some(span) => format!(
                "failed to parse candidate config TOML: {}; byte span {}..{}",
                error.message(),
                span.start,
                span.end
            ),
            None => format!("failed to parse candidate config TOML: {}", error.message()),
        },
        ConfigError::Validation(error) => {
            format!("candidate config failed validation during parse: {error}")
        }
    }
}

fn changed_sections(
    current: &AgentConfig,
    candidate: &AgentConfig,
) -> Vec<ConfigReloadSectionChange> {
    CONFIG_RELOAD_SECTIONS
        .into_iter()
        .filter(|spec| section_changed(spec.section, current, candidate))
        .map(|spec| ConfigReloadSectionChange {
            section: spec.section,
            restart_required: true,
            reason: spec.reason,
        })
        .collect()
}

fn section_changed(
    section: ConfigReloadSection,
    current: &AgentConfig,
    candidate: &AgentConfig,
) -> bool {
    match section {
        ConfigReloadSection::AgentIdentity => {
            current.agent_id != candidate.agent_id
                || current.config_version != candidate.config_version
        }
        ConfigReloadSection::Capture => current.capture != candidate.capture,
        ConfigReloadSection::Storage => current.storage != candidate.storage,
        ConfigReloadSection::Export => {
            current.export != candidate.export || current.exporters != candidate.exporters
        }
        ConfigReloadSection::PolicyReload => current.policy_reload != candidate.policy_reload,
        ConfigReloadSection::Policies => current.policies != candidate.policies,
        ConfigReloadSection::Selectors => current.selectors != candidate.selectors,
        ConfigReloadSection::Tls => current.tls != candidate.tls,
        ConfigReloadSection::Enforcement => current.enforcement != candidate.enforcement,
        ConfigReloadSection::Admin => current.admin != candidate.admin,
    }
}

fn reloadable_runtime_actions() -> Vec<ConfigReloadRuntimeAction> {
    vec![
        ConfigReloadRuntimeAction::ReloadPolicies,
        ConfigReloadRuntimeAction::ReloadEnforcementPolicy,
    ]
}

#[cfg(test)]
mod tests {
    use std::{fs, net::TcpListener, path::PathBuf};

    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementConfig,
        EnforcementInterceptionConfig, EnforcementPolicyConfig, EnforcementPolicySourceConfig,
        ExporterConfig, ExporterTransportConfig, LiveCaptureBackend, StorageConfig, TlsConfig,
        TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmClientTrustConfig,
        TransparentInterceptionMitmClientTrustModeConfig, TransparentInterceptionMitmConfig,
        TransparentInterceptionProxyConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, EnforcementMode, ProcessSelector, Selector,
        TrafficSelector,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };

    use super::*;

    #[test]
    fn config_reload_plan_reports_no_change_for_equivalent_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-no-change")?;
        let config = base_config(temp.join("spool"));
        let current = runtime_plan(config.clone())?;
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&config)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(matches!(plan.decision, ConfigReloadDecision::NoChange));
        assert!(plan.changed_sections.is_empty());
        assert_eq!(
            plan.reloadable_runtime_actions,
            vec![
                ConfigReloadRuntimeAction::ReloadPolicies,
                ConfigReloadRuntimeAction::ReloadEnforcementPolicy,
            ]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_reports_restart_sections_for_valid_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-restart")?;
        let current_config = base_config(temp.join("spool"));
        let current = runtime_plan(current_config)?;
        let mut candidate = base_config(temp.join("spool"));
        candidate.config_version = "candidate".to_string();
        candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        candidate.exporters.push(ExporterConfig {
            id: "file".to_string(),
            transport: ExporterTransportConfig::File {
                path: temp.join("events.jsonl"),
            },
            ..ExporterConfig::default()
        });
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        let sections = plan
            .changed_sections
            .iter()
            .map(|change| change.section)
            .collect::<Vec<_>>();
        assert_eq!(
            sections,
            vec![
                ConfigReloadSection::AgentIdentity,
                ConfigReloadSection::Capture,
                ConfigReloadSection::Export,
            ]
        );
        assert!(
            plan.changed_sections
                .iter()
                .all(|change| change.restart_required)
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_does_not_connect_to_setup_time_probe_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-static-planning")?;
        let readiness_listener = TcpListener::bind(("127.0.0.1", 0))?;
        readiness_listener.set_nonblocking(true)?;
        let readiness_target = readiness_listener.local_addr()?;
        let current_config = base_config(temp.join("spool"));
        let current = runtime_plan(current_config)?;
        let mut candidate = base_config(temp.join("spool"));
        configure_external_mitm_with_readiness(&mut candidate, readiness_target);
        let candidate_path = temp.join("agent.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        assert!(
            matches!(plan.decision, ConfigReloadDecision::RestartRequired { .. }),
            "{:?}",
            plan.decision
        );
        assert_eq!(
            plan.changed_sections
                .iter()
                .map(|change| change.section)
                .collect::<Vec<_>>(),
            vec![ConfigReloadSection::Tls, ConfigReloadSection::Enforcement]
        );
        match readiness_listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok((_, peer)) => panic!("config reload planning connected to readiness target {peer}"),
            Err(error) => return Err(Box::new(error)),
        }
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_reports_invalid_candidate_without_panicking()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-invalid")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let candidate_path = temp.join("agent.toml");
        fs::write(
            &candidate_path,
            "secret_token = \"do-not-leak\"\nnot toml =",
        )?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        let ConfigReloadDecision::InvalidCandidate { stage, reason } = &plan.decision else {
            panic!("expected invalid candidate, got {:?}", plan.decision);
        };
        assert_eq!(*stage, "parse");
        assert!(!reason.contains("do-not-leak"), "{reason}");
        assert!(plan.changed_sections.is_empty());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn config_reload_plan_rejects_oversized_candidate_before_parse()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("config-reload-oversized")?;
        let current = runtime_plan(base_config(temp.join("spool")))?;
        let candidate_path = temp.join("agent.toml");
        fs::File::create(&candidate_path)?.set_len(MAX_CANDIDATE_CONFIG_BYTES + 1)?;

        let plan = plan_config_reload(&current.config, &candidate_path);

        let ConfigReloadDecision::InvalidCandidate { stage, reason } = &plan.decision else {
            panic!("expected invalid candidate, got {:?}", plan.decision);
        };
        assert_eq!(*stage, "read");
        assert!(reason.contains("too large"), "{reason}");
        assert!(plan.changed_sections.is_empty());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(config, &registry())
    }

    fn registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::available(
                    CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                ),
                CaptureProviderDescriptor::available(
                    CaptureBackend::PlaintextFeed,
                    CaptureProviderBuilder::PlaintextFeed,
                ),
                CaptureProviderDescriptor::available(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                ),
            ],
            test_platform_capabilities(),
        )
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
        ]
    }

    fn base_config(storage_path: PathBuf) -> AgentConfig {
        AgentConfig {
            capture: probe_config::CaptureConfig {
                selection: CaptureSelection::Replay,
                ..probe_config::CaptureConfig::default()
            },
            storage: StorageConfig {
                path: storage_path,
                ..StorageConfig::default()
            },
            ..AgentConfig::default()
        }
    }

    fn configure_external_mitm_with_readiness(
        config: &mut AgentConfig,
        readiness_target: std::net::SocketAddr,
    ) {
        config.tls = TlsConfig {
            materials: vec![
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
            ],
            ..TlsConfig::default()
        };
        config.enforcement = EnforcementConfig {
            mode: EnforcementMode::Enforce,
            interception: EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxyMitm,
                selector: Some(Selector::term(
                    ProcessSelector {
                        names: vec!["candidate".to_string()],
                        ..ProcessSelector::default()
                    },
                    TrafficSelector::default(),
                )),
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(readiness_target.port()),
                    ..TransparentInterceptionProxyConfig::default()
                },
                mitm: TransparentInterceptionMitmConfig {
                    backend: TransparentInterceptionMitmBackendConfig::external(
                        TransparentInterceptionMitmBackendReadinessProbeConfig {
                            target: Some(readiness_target.to_string()),
                            ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                        },
                    ),
                    client_trust: TransparentInterceptionMitmClientTrustConfig {
                        mode: TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged,
                    },
                    ca_certificate_ref: Some("mitm-ca".to_string()),
                    ca_private_key_ref: Some("mitm-ca-key".to_string()),
                    ..TransparentInterceptionMitmConfig::default()
                },
            },
            policy: EnforcementPolicyConfig {
                source: EnforcementPolicySourceConfig::File {
                    path: "/etc/traffic-probe/enforcement.toml".into(),
                },
                ..EnforcementPolicyConfig::default()
            },
            ..EnforcementConfig::default()
        };
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let path =
            std::env::temp_dir().join(format!("traffic-probe-{name}-{}", std::process::id()));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}

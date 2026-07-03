use probe_config::{
    AgentConfig, EnforcementPolicySourceConfig, ExportRuntimeConfig, ExporterConfig, PolicyConfig,
};
use probe_core::{CapabilityMatrix, Selector};
use serde::{Deserialize, Serialize};

use super::{
    capture::{CapturePlan, CapturePlanMode},
    enforcement::EnforcementPlan,
    error::RuntimeError,
    export::{ExportPlan, ExportReloadOwnership},
    observation::apply_process_observation_projection,
    registry::ProviderRegistry,
    storage::StoragePlan,
    tls::{TlsMaterialStorePlan, TlsPlan},
    validation::{validate_runtime_config, validate_static_runtime_config_fields},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePlan {
    /// Original user configuration after load-time generated resources are applied.
    pub config: AgentConfig,
    /// Runtime configuration after observation intent is projected into setup-time fields.
    pub effective_config: AgentConfig,
    pub capabilities: CapabilityMatrix,
    pub capture: CapturePlan,
    pub tls_material_store: TlsMaterialStorePlan,
    pub tls: TlsPlan,
    pub storage: StoragePlan,
    pub export: ExportPlan,
    pub enforcement: EnforcementPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnlineReloadConfigUpdate {
    PipelinePolicies {
        policies: Vec<PolicyConfig>,
    },
    Export {
        export: ExportRuntimeConfig,
        exporters: Vec<ExporterConfig>,
    },
    EnforcementPolicy {
        selector: Option<Selector>,
        source: EnforcementPolicySourceConfig,
    },
}

impl RuntimePlan {
    pub fn build(config: AgentConfig, registry: &ProviderRegistry) -> Result<Self, RuntimeError> {
        let effective_config = project_runtime_config(config.clone());
        effective_config.validate_basic()?;
        validate_runtime_config(&effective_config, registry)?;
        let capabilities = registry.capability_matrix();
        let capture = CapturePlan::resolve(&effective_config, registry);
        let tls_material_store = TlsMaterialStorePlan::resolve(&effective_config);
        let tls = TlsPlan::resolve(&effective_config, &capabilities);
        let storage = StoragePlan::resolve(&effective_config);
        let export = ExportPlan::resolve(&effective_config);
        let enforcement =
            EnforcementPlan::resolve(&effective_config, &capabilities, &tls_material_store);
        Ok(Self {
            config,
            effective_config,
            capabilities,
            capture,
            tls_material_store,
            tls,
            storage,
            export,
            enforcement,
        })
    }

    pub fn require_live_capture(&self) -> Result<(), RuntimeError> {
        if self.capture.mode == CapturePlanMode::Live {
            Ok(())
        } else {
            Err(RuntimeError::NoLiveCapture {
                reason: self
                    .capture
                    .reason
                    .clone()
                    .unwrap_or_else(|| "capture plan did not select a live backend".to_string()),
            })
        }
    }

    pub fn with_online_reload_update(&self, update: OnlineReloadConfigUpdate) -> Self {
        let mut config = self.config.clone();
        let mut update_export = false;
        let mut update_enforcement = false;
        match update {
            OnlineReloadConfigUpdate::PipelinePolicies { policies } => {
                config.policies = policies;
            }
            OnlineReloadConfigUpdate::Export { export, exporters } => {
                config.export = export;
                config.exporters = exporters;
                update_export = true;
            }
            OnlineReloadConfigUpdate::EnforcementPolicy { selector, source } => {
                config.enforcement.selector = selector;
                config.enforcement.policy.source = source;
                update_enforcement = true;
            }
        }
        let effective_config = project_runtime_config(config.clone());
        let mut plan = self.clone();
        plan.config = config;
        plan.effective_config = effective_config;
        if update_export {
            plan.export = ExportPlan::resolve(&plan.effective_config);
        }
        if update_enforcement {
            plan.enforcement = EnforcementPlan::resolve(
                &plan.effective_config,
                &plan.capabilities,
                &plan.tls_material_store,
            );
        }
        plan
    }
}

pub fn project_runtime_config(config: AgentConfig) -> AgentConfig {
    apply_process_observation_projection(config)
}

pub fn export_reload_ownership(config: &AgentConfig) -> ExportReloadOwnership {
    let effective_config = project_runtime_config(config.clone());
    ExportReloadOwnership::from_plan(&ExportPlan::resolve(&effective_config))
}

pub fn validate_static_runtime_config(config: &AgentConfig) -> Result<(), RuntimeError> {
    let config = project_runtime_config(config.clone());
    config.validate_basic()?;
    validate_static_runtime_config_fields(&config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicySourceConfig,
        ExporterConfig, ExporterTransportConfig, ObservationDataPathMode, PolicyConfig,
        ProcessObservationConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, Direction, ProcessSelector, RuntimeMode, Selector,
        TrafficSelector,
    };

    use crate::plan::{
        capture::{CaptureProviderBuilder, CaptureProviderDescriptor},
        registry::ProviderRegistry,
    };

    use super::*;

    #[test]
    fn run_requirement_fails_without_live_capture() -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Unimplemented,
                RuntimeMode::Unavailable,
            )],
            test_platform_capabilities(),
        );
        let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

        let error = plan
            .require_live_capture()
            .expect_err("run must fail closed");

        assert!(error.to_string().contains("no live capture provider"));
        Ok(())
    }

    #[test]
    fn process_observations_are_projected_before_capture_plan_resolution()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![
                capture_provider(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Unimplemented,
                    RuntimeMode::Unavailable,
                ),
                capture_provider(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    RuntimeMode::Available,
                ),
            ],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.observations.push(process_observation(
            "nginx",
            "/usr/sbin/nginx",
            ObservationDataPathMode::Libpcap,
        ));

        let plan = RuntimePlan::build(config, &registry)?;

        assert_eq!(plan.capture.selection, CaptureSelection::Libpcap);
        assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Libpcap));
        assert!(plan.config.capture.deep_observe_selector.is_none());
        assert!(
            plan.effective_config
                .capture
                .deep_observe_selector
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn process_observation_projection_runs_before_basic_capture_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.fallback_backends.clear();
        config.observations.push(process_observation(
            "nginx",
            "/usr/sbin/nginx",
            ObservationDataPathMode::Libpcap,
        ));

        let plan = RuntimePlan::build(config, &registry)?;

        assert_eq!(plan.capture.selection, CaptureSelection::Libpcap);
        Ok(())
    }

    #[test]
    fn online_reload_update_preserves_unowned_runtime_config_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.ebpf.object_path = Some("/runtime/generated-ebpf.o".into());
        let plan = RuntimePlan::build(config, &registry)?;

        let updated = plan.with_online_reload_update(OnlineReloadConfigUpdate::PipelinePolicies {
            policies: vec![PolicyConfig {
                id: "guard".to_string(),
                ..PolicyConfig::default()
            }],
        });

        assert_eq!(updated.config.policies.len(), 1);
        assert_eq!(
            updated.config.capture.ebpf.object_path,
            Some("/runtime/generated-ebpf.o".into())
        );
        Ok(())
    }

    #[test]
    fn online_enforcement_policy_update_recomputes_enforcement_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

        let updated = plan.with_online_reload_update(OnlineReloadConfigUpdate::EnforcementPolicy {
            selector: None,
            source: EnforcementPolicySourceConfig::File {
                path: "/tmp/enforcement.toml".into(),
            },
        });

        assert!(matches!(
            updated.enforcement.policy_source,
            crate::plan::EnforcementPolicySourcePlan::LocalManifest { .. }
        ));
        Ok(())
    }

    #[test]
    fn online_export_update_recomputes_export_plan() -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let config = AgentConfig {
            exporters: vec![ExporterConfig {
                id: "collector".to_string(),
                transport: ExporterTransportConfig::Webhook {
                    endpoint: "https://collector.example/probe/batches".to_string(),
                    headers: Default::default(),
                    tls: Default::default(),
                },
                ..ExporterConfig::default()
            }],
            ..AgentConfig::default()
        };
        let plan = RuntimePlan::build(config, &registry)?;
        let export = probe_config::ExportRuntimeConfig::default();
        let exporters = vec![ExporterConfig {
            id: "collector".to_string(),
            transport: ExporterTransportConfig::Webhook {
                endpoint: "https://collector.internal/probe/batches".to_string(),
                headers: Default::default(),
                tls: Default::default(),
            },
            ..ExporterConfig::default()
        }];

        let updated =
            plan.with_online_reload_update(OnlineReloadConfigUpdate::Export { export, exporters });

        assert_eq!(updated.config.exporters.len(), 1);
        assert_eq!(updated.export.sinks.len(), 1);
        assert_eq!(updated.export.sinks[0].id(), "collector");
        assert!(matches!(
            &updated.export.sinks[0],
            crate::plan::ExportSinkPlan::Webhook(sink)
                if sink.endpoint == "https://collector.internal/probe/batches"
        ));
        Ok(())
    }

    #[test]
    fn mixed_explicit_process_observations_use_auto_capture_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![
                capture_provider(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Unimplemented,
                    RuntimeMode::Unavailable,
                ),
                capture_provider(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    RuntimeMode::Available,
                ),
            ],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;
        config.capture.fallback_backends.clear();
        config.capture.libpcap.bpf_filter.clear();
        config.capture.plaintext_feed.path = Some("/tmp/plaintext.jsonl".into());
        config.capture.capture_event_feed.path = Some("/tmp/capture-events.jsonl".into());
        config.capture.capture_event_feed.follow = Some(true);
        config.observations.extend([
            process_observation(
                "frontend",
                "/usr/bin/frontend",
                ObservationDataPathMode::Ebpf,
            ),
            process_observation(
                "worker",
                "/usr/bin/worker",
                ObservationDataPathMode::Libpcap,
            ),
        ]);

        let plan = RuntimePlan::build(config, &registry)?;

        assert_eq!(plan.capture.selection, CaptureSelection::Auto);
        assert_eq!(
            plan.effective_config.capture.fallback_backends,
            probe_config::CaptureConfig::default().fallback_backends
        );
        assert_eq!(
            plan.effective_config.capture.libpcap,
            probe_config::CaptureConfig::default().libpcap
        );
        assert_eq!(
            plan.effective_config.capture.plaintext_feed,
            probe_config::CaptureConfig::default().plaintext_feed
        );
        assert_eq!(
            plan.effective_config.capture.capture_event_feed,
            probe_config::CaptureConfig::default().capture_event_feed
        );
        assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Libpcap));
        Ok(())
    }

    #[test]
    fn explicit_process_observation_resets_stale_target_backend_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;
        config.capture.fallback_backends.clear();
        config.capture.libpcap.bpf_filter.clear();
        config.capture.plaintext_feed.path = Some("/tmp/plaintext.jsonl".into());
        config.capture.capture_event_feed.path = Some("/tmp/capture-events.jsonl".into());
        config.capture.capture_event_feed.follow = Some(true);
        config.observations.push(process_observation(
            "worker",
            "/usr/bin/worker",
            ObservationDataPathMode::Libpcap,
        ));

        let plan = RuntimePlan::build(config, &registry)?;

        assert_eq!(plan.capture.selection, CaptureSelection::Libpcap);
        assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Libpcap));
        assert_eq!(
            plan.effective_config.capture.libpcap,
            probe_config::CaptureConfig::default().libpcap
        );
        assert_eq!(
            plan.effective_config.capture.plaintext_feed,
            probe_config::CaptureConfig::default().plaintext_feed
        );
        assert_eq!(
            plan.effective_config.capture.capture_event_feed,
            probe_config::CaptureConfig::default().capture_event_feed
        );
        Ok(())
    }

    fn process_observation(
        id: &str,
        exe_path: &str,
        data_path: ObservationDataPathMode,
    ) -> ProcessObservationConfig {
        ProcessObservationConfig {
            id: id.to_string(),
            selector: Selector::term(
                ProcessSelector {
                    exe_path_globs: vec![exe_path.to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
            data_path,
            directions: vec![Direction::Inbound, Direction::Outbound],
        }
    }

    fn capture_provider(
        backend: CaptureBackend,
        builder: CaptureProviderBuilder,
        mode: RuntimeMode,
    ) -> CaptureProviderDescriptor {
        match mode {
            RuntimeMode::Available => CaptureProviderDescriptor::available(backend, builder),
            RuntimeMode::Degraded => {
                CaptureProviderDescriptor::degraded(backend, builder, "degraded")
            }
            RuntimeMode::Unavailable => {
                CaptureProviderDescriptor::unavailable(backend, builder, "unavailable")
            }
        }
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
        ]
    }
}

use probe_config::AgentConfig;
use probe_core::CapabilityMatrix;
use serde::{Deserialize, Serialize};

use super::{
    capture::{CapturePlan, CapturePlanMode},
    enforcement::EnforcementPlan,
    error::RuntimeError,
    export::ExportPlan,
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
}

pub fn project_runtime_config(config: AgentConfig) -> AgentConfig {
    apply_process_observation_projection(config)
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
        AgentConfig, CaptureBackend, CaptureSelection, ObservationDataPathMode,
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

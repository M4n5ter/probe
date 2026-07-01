use probe_config::AgentConfig;
use probe_core::CapabilityMatrix;
use serde::{Deserialize, Serialize};

use super::{
    capture::{CapturePlan, CapturePlanMode},
    enforcement::EnforcementPlan,
    error::RuntimeError,
    export::ExportPlan,
    registry::ProviderRegistry,
    storage::StoragePlan,
    tls::{TlsMaterialStorePlan, TlsPlan},
    validation::{validate_runtime_config, validate_static_runtime_config_fields},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePlan {
    pub config: AgentConfig,
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
        config.validate_basic()?;
        validate_runtime_config(&config, registry)?;
        let capabilities = registry.capability_matrix();
        let capture = CapturePlan::resolve(&config, registry);
        let tls_material_store = TlsMaterialStorePlan::resolve(&config);
        let tls = TlsPlan::resolve(&config, &capabilities);
        let storage = StoragePlan::resolve(&config);
        let export = ExportPlan::resolve(&config);
        let enforcement = EnforcementPlan::resolve(&config, &capabilities, &tls_material_store);
        Ok(Self {
            config,
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

pub fn validate_static_runtime_config(config: &AgentConfig) -> Result<(), RuntimeError> {
    config.validate_basic()?;
    validate_static_runtime_config_fields(config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use probe_config::{AgentConfig, CaptureBackend};
    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

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

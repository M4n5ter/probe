mod capture;
mod enforcement;
mod error;
mod export;
mod registry;
mod tls;
mod validation;

pub use capture::{
    CapturePlan, CapturePlanMode, CaptureProviderBuilder, CaptureProviderDescriptor,
    CaptureProviderSelectionPolicy,
};
pub use enforcement::{EnforcementPlan, EnforcementPolicySourceKind, EnforcementPolicySourcePlan};
pub use error::RuntimeError;
pub use export::{
    ExportFailureBackoffPlan, ExportPlan, ExportSinkPlan, ExportSinkTlsPlan, ExportSinkWorkerPlan,
    ExportWorkerPlan,
};
pub use registry::ProviderRegistry;
pub use tls::{
    ExportTlsMaterialPlan, TlsMaterialPlan, TlsPlaintextCapabilityPlan, TlsPlaintextMaterialPlan,
    TlsPlaintextPlan, TlsPlan,
};

use probe_config::AgentConfig;
use probe_core::CapabilityMatrix;
use serde::{Deserialize, Serialize};

use validation::{validate_runtime_config, validate_static_runtime_config_fields};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePlan {
    pub config: AgentConfig,
    pub capabilities: CapabilityMatrix,
    pub capture: CapturePlan,
    pub tls: TlsPlan,
    pub export: ExportPlan,
    pub enforcement: EnforcementPlan,
}

impl RuntimePlan {
    pub fn build(config: AgentConfig, registry: &ProviderRegistry) -> Result<Self, RuntimeError> {
        config.validate_basic()?;
        validate_runtime_config(&config, registry)?;
        let capabilities = registry.capability_matrix();
        let capture = CapturePlan::resolve(&config, registry);
        let tls = TlsPlan::resolve(&config, &capabilities);
        let export = ExportPlan::resolve(&config);
        let enforcement = EnforcementPlan::resolve(&config);
        Ok(Self {
            config,
            capabilities,
            capture,
            tls,
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

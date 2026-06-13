use probe_config::AgentConfig;
use probe_core::CapabilityMatrix;
use serde::{Deserialize, Serialize};

use super::{
    capture::{CapturePlan, CapturePlanMode},
    enforcement::EnforcementPlan,
    error::RuntimeError,
    export::ExportPlan,
    registry::ProviderRegistry,
    tls::TlsPlan,
    validation::{validate_runtime_config, validate_static_runtime_config_fields},
};

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
        let enforcement = EnforcementPlan::resolve(&config, &capabilities);
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

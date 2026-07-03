use serde::{Deserialize, Serialize};

use probe_core::SelectorRegistry;

use crate::{
    AdminConfig, CaptureConfig, ConfigError, EnforcementConfig, ExportRuntimeConfig,
    ExporterConfig, PolicyConfig, PolicyReloadConfig, ProcessObservationConfig, StorageConfig,
    TlsConfig, validation,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub agent_id: String,
    pub config_version: String,
    pub capture: CaptureConfig,
    pub observations: Vec<ProcessObservationConfig>,
    pub storage: StorageConfig,
    pub export: ExportRuntimeConfig,
    pub exporters: Vec<ExporterConfig>,
    pub policy_reload: PolicyReloadConfig,
    pub policies: Vec<PolicyConfig>,
    pub selectors: SelectorRegistry,
    pub tls: TlsConfig,
    pub enforcement: EnforcementConfig,
    pub admin: AdminConfig,
}

impl AgentConfig {
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(ConfigError::Toml)
    }

    pub fn validate_basic(&self) -> Result<(), ConfigError> {
        validation::validate_config(self).map_err(ConfigError::Validation)
    }

    pub fn validate_l7_mitm_contract(&self) -> Result<(), ConfigError> {
        validation::validate_l7_mitm_contract(self).map_err(ConfigError::Validation)
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: "traffic-probe".to_string(),
            config_version: "local".to_string(),
            capture: CaptureConfig::default(),
            observations: Vec::new(),
            storage: StorageConfig::default(),
            export: ExportRuntimeConfig::default(),
            exporters: Vec::new(),
            policy_reload: PolicyReloadConfig::default(),
            policies: Vec::new(),
            selectors: SelectorRegistry::default(),
            tls: TlsConfig::default(),
            enforcement: EnforcementConfig::default(),
            admin: AdminConfig::default(),
        }
    }
}

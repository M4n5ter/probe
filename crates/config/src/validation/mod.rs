mod admin;
mod capture;
mod enforcement;
mod export;
mod observation;
mod policy;
mod remote_endpoint;
mod runtime_reload;
mod selectors;
mod storage;

use crate::{AgentConfig, ConfigValidationError, tls};

pub(crate) fn validate_config(config: &AgentConfig) -> Result<(), ConfigValidationError> {
    let mut violations = Vec::new();

    capture::validate(&config.capture, &mut violations);
    storage::validate(&config.storage, &mut violations);
    tls::validate_tls(&config.tls, &config.capture, &mut violations);
    export::validate_runtime(&config.export, &mut violations);
    export::validate_exporters(&config.exporters, &config.tls, &mut violations);
    runtime_reload::validate(&config.runtime_reload, &mut violations);
    observation::validate(&config.observations, &config.selectors, &mut violations);
    policy::validate(&config.policies, &mut violations);
    policy::validate_reload(&config.policies, &config.policy_reload, &mut violations);
    selectors::validate(&config.selectors, &mut violations);
    enforcement::validate(&config.enforcement, &config.tls, &mut violations);
    admin::validate(&config.admin, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(violations))
    }
}

pub(crate) fn validate_l7_mitm_contract(config: &AgentConfig) -> Result<(), ConfigValidationError> {
    let mut violations = Vec::new();
    tls::validate_tls_material_registry(&config.tls, &mut violations);
    enforcement::validate_l7_mitm_contract(&config.enforcement, &config.tls, &mut violations);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(violations))
    }
}

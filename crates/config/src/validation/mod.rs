mod admin;
mod capture;
mod enforcement;
mod export;
mod policy;

use crate::{AgentConfig, ConfigValidationError, tls};

pub(crate) fn validate_config(config: &AgentConfig) -> Result<(), ConfigValidationError> {
    let mut violations = Vec::new();

    capture::validate(&config.capture, &mut violations);
    tls::validate_tls(&config.tls, &config.capture, &mut violations);
    export::validate_runtime(&config.export, &mut violations);
    export::validate_exporters(&config.exporters, &config.tls, &mut violations);
    policy::validate(&config.policies, &mut violations);
    enforcement::validate(&config.enforcement, &mut violations);
    admin::validate(&config.admin, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(violations))
    }
}

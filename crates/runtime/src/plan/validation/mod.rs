mod capture;
mod enforcement;
mod policy;
mod tls;

use probe_config::{AgentConfig, ConfigValidationError, ConfigViolation};
use probe_core::{CapabilityKind, CapabilityMatrix, RuntimeMode};

use super::registry::ProviderRegistry;

pub(super) fn validate_runtime_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
) -> Result<(), ConfigValidationError> {
    let mut violations = Vec::new();
    collect_static_runtime_config_violations(config, &mut violations);
    capture::validate_config(config, registry, &mut violations);
    tls::validate_registry_config(config, registry, &mut violations);
    tls::validate_capture_constraints(config, registry, &mut violations);
    enforcement::validate_registry_config(config, registry, &mut violations);
    enforcement::validate_capture_constraints(config, registry, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(violations))
    }
}

pub(super) fn validate_static_runtime_config_fields(
    config: &AgentConfig,
) -> Result<(), ConfigValidationError> {
    let mut violations = Vec::new();
    collect_static_runtime_config_violations(config, &mut violations);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(violations))
    }
}

fn collect_static_runtime_config_violations(
    config: &AgentConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    tls::validate_static_config(config, violations);
    policy::validate_config(config, violations);
    enforcement::validate_static_config(config, violations);
}

fn require_available(
    capabilities: &CapabilityMatrix,
    capability: CapabilityKind,
    field: impl Into<String>,
    reason: impl Into<String>,
    violations: &mut Vec<ConfigViolation>,
) {
    let reported_capability = capabilities.reported_state(capability);
    if reported_capability.map_or(RuntimeMode::Unavailable, |state| state.mode)
        != RuntimeMode::Available
    {
        let reason = reported_capability
            .and_then(|state| state.reason.clone())
            .unwrap_or_else(|| reason.into());
        violations.push(ConfigViolation {
            field: field.into(),
            reason,
        });
    }
}

fn require_usable(
    capabilities: &CapabilityMatrix,
    capability: CapabilityKind,
    field: impl Into<String>,
    reason: impl Into<String>,
    violations: &mut Vec<ConfigViolation>,
) {
    let reported_capability = capabilities.reported_state(capability);
    if reported_capability.map_or(RuntimeMode::Unavailable, |state| state.mode)
        == RuntimeMode::Unavailable
    {
        let reason = reported_capability
            .and_then(|state| state.reason.clone())
            .unwrap_or_else(|| reason.into());
        violations.push(ConfigViolation {
            field: field.into(),
            reason,
        });
    }
}

use probe_config::{
    AgentConfig, ConfigValidationError, ConfigViolation, ExporterTransport, TlsPlaintextProvider,
};
use probe_core::{CapabilityKind, CapabilityMatrix, EnforcementMode, RuntimeMode};

use super::capture::{CapturePlan, CapturePlanMode};
use super::enforcement::EnforcementCapabilityPlan;
use super::registry::ProviderRegistry;

pub(super) fn validate_runtime_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
) -> Result<(), ConfigValidationError> {
    let mut violations = Vec::new();
    collect_static_runtime_config_violations(config, &mut violations);
    validate_capture_config(config, registry, &mut violations);
    validate_registry_tls_config(config, registry, &mut violations);
    validate_tls_capture_compatibility(config, registry, &mut violations);
    validate_registry_enforcement_config(config, registry, &mut violations);
    validate_enforcement_capture_compatibility(config, registry, &mut violations);

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
    validate_static_tls_config(config, violations);
    validate_policy_config(config, violations);
    validate_static_enforcement_config(config, violations);
    validate_exporters(config, violations);
}

fn validate_policy_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    for policy in config.policies.iter().filter(|policy| policy.enabled) {
        if let Some(selector) = &policy.selector
            && let Err(error) = selector.compile()
        {
            violations.push(ConfigViolation {
                field: format!("policies.{}.selector", policy.id),
                reason: error.to_string(),
            });
        }
    }
}

fn validate_capture_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    let Some(backend) = config.capture.selection.explicit_backend() else {
        return;
    };
    let provider = registry.capture_provider(backend);
    if !provider.selectable_for(config.capture.selection) {
        violations.push(ConfigViolation {
            field: "capture.selection".to_string(),
            reason: provider.unselectable_reason(),
        });
    }
}

fn validate_static_tls_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    if let Some(selector) = &config.tls.plaintext.selector
        && let Err(error) = selector.compile()
    {
        violations.push(ConfigViolation {
            field: "tls.plaintext.selector".to_string(),
            reason: error.to_string(),
        });
    }
    if !config.tls.plaintext.enabled {
        return;
    }
    if matches!(config.tls.plaintext.provider, TlsPlaintextProvider::Keylog) {
        violations.push(ConfigViolation {
            field: "tls.plaintext.provider".to_string(),
            reason: format!(
                "{:?} plaintext provider is reserved but not implemented",
                config.tls.plaintext.provider
            ),
        });
    }
}

fn validate_registry_tls_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if !config.tls.plaintext.enabled
        || config.tls.plaintext.provider != TlsPlaintextProvider::LibsslUprobe
    {
        return;
    }
    match config.tls.plaintext.provider {
        TlsPlaintextProvider::LibsslUprobe => require_usable(
            &registry.capability_matrix(),
            CapabilityKind::LibsslUprobe,
            "tls.plaintext.enabled",
            "libssl uprobe plaintext provider is not available in this build/runtime",
            violations,
        ),
        TlsPlaintextProvider::Keylog => {}
    }
}

fn validate_tls_capture_compatibility(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if !config.tls.plaintext.enabled
        || config.tls.plaintext.provider != TlsPlaintextProvider::LibsslUprobe
    {
        return;
    }

    let capture = CapturePlan::resolve(config, registry);
    if capture.mode != CapturePlanMode::Live {
        violations.push(ConfigViolation {
            field: "tls.plaintext.enabled".to_string(),
            reason: format!(
                "libssl uprobe TLS plaintext requires live host capture; selected capture mode is {:?}",
                capture.mode
            ),
        });
    }
}

fn validate_static_enforcement_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    if let Some(selector) = &config.enforcement.selector
        && let Err(error) = selector.compile()
    {
        violations.push(ConfigViolation {
            field: "enforcement.selector".to_string(),
            reason: error.to_string(),
        });
    }
}

fn validate_registry_enforcement_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Some(requirement) =
        EnforcementCapabilityPlan::requirement_for_mode(config.enforcement.mode)
    {
        require_available(
            &registry.capability_matrix(),
            requirement.capability,
            "enforcement.mode",
            requirement.unavailable_reason,
            violations,
        );
    }
}

fn validate_enforcement_capture_compatibility(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if config.enforcement.mode != EnforcementMode::Enforce {
        return;
    }

    let capture = CapturePlan::resolve(config, registry);
    if capture.mode != CapturePlanMode::Live {
        violations.push(ConfigViolation {
            field: "enforcement.mode".to_string(),
            reason: format!(
                "enforce mode requires live host capture; selected capture mode is {:?}",
                capture.mode
            ),
        });
    }
}

fn validate_exporters(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    for exporter in &config.exporters {
        match exporter.transport {
            ExporterTransport::Webhook => {}
            ExporterTransport::Grpc | ExporterTransport::Kafka | ExporterTransport::Otlp => {
                violations.push(ConfigViolation {
                    field: format!("exporters.{}.transport", exporter.id),
                    reason: format!(
                        "{:?} exporter is reserved but not implemented",
                        exporter.transport
                    ),
                });
            }
        }
    }
}

fn require_available(
    capabilities: &CapabilityMatrix,
    capability: CapabilityKind,
    field: impl Into<String>,
    reason: impl Into<String>,
    violations: &mut Vec<ConfigViolation>,
) {
    if capabilities.mode(capability) != RuntimeMode::Available {
        let reason = capabilities
            .states()
            .iter()
            .find(|state| state.kind == capability)
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
    if capabilities.mode(capability) == RuntimeMode::Unavailable {
        let reason = capabilities
            .states()
            .iter()
            .find(|state| state.kind == capability)
            .and_then(|state| state.reason.clone())
            .unwrap_or_else(|| reason.into());
        violations.push(ConfigViolation {
            field: field.into(),
            reason,
        });
    }
}

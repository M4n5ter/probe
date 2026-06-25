use probe_config::{AgentConfig, ConfigViolation};

pub(super) fn validate_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
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

#[cfg(test)]
mod tests {
    use probe_config::{
        CaptureBackend, CaptureSelection, ConfigValidationError, PolicyConfig, PolicySourceConfig,
    };
    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode, Selector};

    use crate::plan::{
        capture::{CaptureProviderBuilder, CaptureProviderDescriptor},
        registry::ProviderRegistry,
    };

    use super::super::validate_runtime_config;
    use super::*;

    #[test]
    fn policy_selector_is_validated_by_runtime_validation() {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: "/tmp/guard.bundle".into(),
            },
            selector: Some(Selector::All {
                selectors: Vec::new(),
            }),
            ..PolicyConfig::default()
        }];

        let error = validation_error(config, &registry);

        assert_violation(&error, "policies.guard.selector", "at least one child");
    }

    #[test]
    fn disabled_policy_selector_is_not_validated_by_runtime_validation() {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.policies = vec![PolicyConfig {
            id: "draft".to_string(),
            enabled: false,
            selector: Some(Selector::All {
                selectors: Vec::new(),
            }),
            ..PolicyConfig::default()
        }];

        validate_runtime_config(&config, &registry)
            .expect("disabled policy selector should not be validated");
    }

    fn validation_error(config: AgentConfig, registry: &ProviderRegistry) -> ConfigValidationError {
        validate_runtime_config(&config, registry).expect_err("config should be invalid")
    }

    fn assert_violation(error: &ConfigValidationError, field: &str, reason_fragment: &str) {
        let violation = error
            .violations()
            .iter()
            .find(|violation| violation.field == field)
            .unwrap_or_else(|| panic!("missing violation for {field}: {error}"));
        assert!(
            violation.reason.contains(reason_fragment),
            "violation {field}: {} should contain {reason_fragment}",
            violation.reason
        );
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
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "unavailable"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not built"),
        ]
    }
}

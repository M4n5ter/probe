use probe_config::{AgentConfig, ConfigViolation};
use probe_core::CapabilityKind;

use crate::plan::{
    capture::{CapturePlan, CapturePlanMode},
    registry::ProviderRegistry,
};

use super::require_usable;

pub(super) fn validate_static_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    if let Some(selector) = &config.tls.plaintext.instrumentation.selector
        && let Err(error) = selector.resolve_refs_with_registry(&config.selectors)
    {
        violations.push(ConfigViolation {
            field: "tls.plaintext.instrumentation.selector".to_string(),
            reason: error.to_string(),
        });
    }
}

pub(super) fn validate_registry_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if !config.tls.plaintext.instrumentation.enabled {
        return;
    }
    require_usable(
        &registry.capability_matrix(),
        CapabilityKind::LibsslUprobe,
        "tls.plaintext.instrumentation.enabled",
        "libssl uprobe plaintext provider is not available in this build/runtime",
        violations,
    );
}

pub(super) fn validate_capture_constraints(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if !config.tls.plaintext.instrumentation.enabled {
        return;
    }

    let capture = CapturePlan::resolve(config, registry);
    if capture.mode != CapturePlanMode::Live {
        violations.push(ConfigViolation {
            field: "tls.plaintext.instrumentation.enabled".to_string(),
            reason: format!(
                "libssl uprobe TLS plaintext requires live host capture; selected capture mode is {:?}",
                capture.mode
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{CaptureBackend, CaptureSelection, ConfigValidationError};
    use probe_core::{CapabilityState, RuntimeMode, Selector};

    use crate::plan::capture::{CaptureProviderBuilder, CaptureProviderDescriptor};

    use super::super::validate_runtime_config;
    use super::*;

    #[test]
    fn tls_plaintext_plan_rejects_unavailable_libssl_capability() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            test_platform_capabilities_with_libssl(RuntimeMode::Unavailable),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.tls.plaintext.instrumentation.enabled = true;
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into());

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "tls.plaintext.instrumentation.enabled",
            "unavailable",
        );
    }

    #[test]
    fn tls_plaintext_plan_rejects_non_live_capture_selection() {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities_with_libssl(RuntimeMode::Degraded),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.tls.plaintext.instrumentation.enabled = true;
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into());

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "tls.plaintext.instrumentation.enabled",
            "requires live host capture",
        );
    }

    #[test]
    fn tls_plaintext_selector_is_validated_by_runtime_validation() {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities_with_libssl(RuntimeMode::Unavailable),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.tls.plaintext.instrumentation.selector = Some(Selector::All {
            selectors: Vec::new(),
        });

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "tls.plaintext.instrumentation.selector",
            "at least one child",
        );
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

    fn live_capture_provider() -> CaptureProviderDescriptor {
        capture_provider(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
            RuntimeMode::Available,
        )
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

    fn test_platform_capabilities_with_libssl(mode: RuntimeMode) -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            match mode {
                RuntimeMode::Available => CapabilityState::available(CapabilityKind::LibsslUprobe),
                RuntimeMode::Degraded => {
                    CapabilityState::degraded(CapabilityKind::LibsslUprobe, "degraded")
                }
                RuntimeMode::Unavailable => {
                    CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "unavailable")
                }
            },
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not built"),
        ]
    }
}

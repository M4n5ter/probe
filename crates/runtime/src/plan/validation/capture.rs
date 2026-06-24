use probe_config::{AgentConfig, ConfigViolation};

use crate::plan::registry::ProviderRegistry;

pub(super) fn validate_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Some(selector) = &config.capture.deep_observe_selector
        && let Err(error) = selector.compile()
    {
        violations.push(ConfigViolation {
            field: "capture.deep_observe_selector".to_string(),
            reason: error.to_string(),
        });
    }
    let Some(backend) = config.capture.selection.explicit_backend() else {
        return;
    };
    let provider = registry.capture_provider(backend);
    if !provider.openable() {
        violations.push(ConfigViolation {
            field: "capture.selection".to_string(),
            reason: provider.unselectable_reason(),
        });
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{CaptureBackend, CaptureSelection, ConfigValidationError};
    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

    use crate::plan::capture::{CaptureProviderBuilder, CaptureProviderDescriptor};

    use super::super::validate_runtime_config;
    use super::*;

    #[test]
    fn explicit_degraded_provider_is_accepted_when_runtime_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::degraded(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
                "libpcap stream assembly is best-effort",
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;

        validate_runtime_config(&config, &registry)?;
        Ok(())
    }

    #[test]
    fn explicit_unavailable_backend_does_not_fallback() {
        let registry = ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::unavailable(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Unimplemented,
                    "eBPF host probe: bpffs path /sys/fs/bpf does not exist",
                ),
                capture_provider(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    RuntimeMode::Available,
                ),
            ],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "capture.selection",
            "eBPF host probe: bpffs path /sys/fs/bpf does not exist",
        );
    }

    #[test]
    fn external_plaintext_feed_fails_closed_without_provider() {
        let registry = ProviderRegistry::new(Vec::new(), test_platform_capabilities());
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some("/tmp/feed.jsonl".into());

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "capture.selection",
            "capture backend is not registered",
        );
    }

    #[test]
    fn capture_deep_observe_selector_is_validated() {
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
        config.capture.deep_observe_selector = Some(probe_core::Selector::All {
            selectors: Vec::new(),
        });

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "capture.deep_observe_selector",
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

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

#[cfg(test)]
mod tests {
    use probe_config::{
        CaptureBackend, CaptureSelection, ConnectionEnforcementBackendConfig, TlsPlaintextProvider,
    };
    use probe_core::{CapabilityState, Selector};

    use crate::plan::{
        capture::{CaptureProviderBuilder, CaptureProviderDescriptor},
        registry::ProviderRegistry,
    };

    use super::*;

    #[test]
    fn unsupported_security_features_fail_closed() {
        let registry = ProviderRegistry::new(vec![], test_platform_capabilities());
        let mut config = AgentConfig::default();
        config.tls.plaintext.enabled = true;
        config.enforcement.mode = EnforcementMode::Enforce;

        let error = validation_error(config, &registry);

        assert_violation(&error, "tls.plaintext.enabled", "unavailable");
        assert_violation(&error, "enforcement.mode", "not built");
    }

    #[test]
    fn explicit_degraded_provider_without_selection_policy_is_rejected() {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::degraded(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
                "libpcap provider cannot open the configured device",
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "capture.selection",
            "libpcap provider cannot open the configured device",
        );
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
    fn tls_plaintext_plan_rejects_unavailable_libssl_capability() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            test_platform_capabilities_with_libssl(RuntimeMode::Unavailable),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.tls.plaintext.enabled = true;
        config.tls.plaintext.provider = TlsPlaintextProvider::LibsslUprobe;
        config.tls.plaintext.libssl_uprobe_object_path =
            Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());

        let error = validation_error(config, &registry);

        assert_violation(&error, "tls.plaintext.enabled", "unavailable");
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
        config.tls.plaintext.enabled = true;
        config.tls.plaintext.provider = TlsPlaintextProvider::LibsslUprobe;
        config.tls.plaintext.libssl_uprobe_object_path =
            Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "tls.plaintext.enabled",
            "requires live host capture",
        );
    }

    #[test]
    fn tls_plaintext_plan_rejects_enabled_keylog_provider() {
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
        config.tls.plaintext.enabled = true;
        config.tls.plaintext.provider = TlsPlaintextProvider::Keylog;

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "tls.plaintext.provider",
            "reserved but not implemented",
        );
        assert!(
            !error.to_string().contains("requires live host capture"),
            "keylog provider rejection should happen before live capture compatibility"
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
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.tls.plaintext.selector = Some(Selector::All {
            selectors: Vec::new(),
        });

        let error = validation_error(config, &registry);

        assert_violation(&error, "tls.plaintext.selector", "at least one child");
    }

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
        config.policies = vec![probe_config::PolicyConfig {
            id: "guard".to_string(),
            path: "/tmp/guard.lua".into(),
            selector: Some(Selector::All {
                selectors: Vec::new(),
            }),
            ..probe_config::PolicyConfig::default()
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
        config.policies = vec![probe_config::PolicyConfig {
            id: "draft".to_string(),
            enabled: false,
            selector: Some(Selector::All {
                selectors: Vec::new(),
            }),
            ..probe_config::PolicyConfig::default()
        }];

        validate_runtime_config(&config, &registry)
            .expect("disabled policy selector should not be validated");
    }

    #[test]
    fn enforce_enforcement_requires_connection_capability() {
        let cases = [
            (
                test_platform_capabilities()
                    .into_iter()
                    .filter(|state| state.kind != CapabilityKind::ConnectionEnforcement)
                    .collect::<Vec<_>>(),
                "connection-level enforcement backend is not available",
            ),
            (
                test_platform_capabilities()
                    .into_iter()
                    .map(|state| {
                        if state.kind == CapabilityKind::ConnectionEnforcement {
                            CapabilityState::degraded(
                                CapabilityKind::ConnectionEnforcement,
                                "degraded",
                            )
                        } else {
                            state
                        }
                    })
                    .collect::<Vec<_>>(),
                "degraded",
            ),
        ];

        for (capabilities, expected_reason) in cases {
            let registry = ProviderRegistry::new(
                vec![capture_provider(
                    CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                    RuntimeMode::Available,
                )],
                capabilities,
            );
            let mut config = AgentConfig::default();
            config.capture.selection = CaptureSelection::Replay;
            config.enforcement.mode = EnforcementMode::Enforce;

            let error = validation_error(config, &registry);

            assert_violation(&error, "enforcement.mode", expected_reason);
        }
    }

    #[test]
    fn explicit_enforcement_backend_reports_capability_probe_reason() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            test_platform_capabilities_with_connection_enforcement(RuntimeMode::Unavailable)
                .into_iter()
                .map(|state| {
                    if state.kind == CapabilityKind::ConnectionEnforcement {
                        CapabilityState::unavailable(
                            CapabilityKind::ConnectionEnforcement,
                            "linux socket destroy enforcement requires root because the ss child process must retain socket destroy privileges after exec",
                        )
                    } else {
                        state
                    }
                })
                .collect(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "enforcement.mode",
            "linux socket destroy enforcement requires root",
        );
    }

    #[test]
    fn enforce_enforcement_requires_live_capture_mode() {
        let registry = ProviderRegistry::new(
            vec![
                capture_provider(
                    CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                    RuntimeMode::Available,
                ),
                capture_provider(
                    CaptureBackend::PlaintextFeed,
                    CaptureProviderBuilder::PlaintextFeed,
                    RuntimeMode::Available,
                ),
            ],
            test_platform_capabilities_with_connection_enforcement(RuntimeMode::Available),
        );
        let cases = [
            (CaptureSelection::Replay, "Replay"),
            (CaptureSelection::PlaintextFeed, "PlaintextFeed"),
        ];

        for (selection, mode) in cases {
            let mut config = AgentConfig::default();
            config.capture.selection = selection;
            config.enforcement.mode = EnforcementMode::Enforce;
            config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;
            if selection == CaptureSelection::PlaintextFeed {
                config.capture.plaintext_feed.path = Some("/tmp/feed.jsonl".into());
            }

            let error = validation_error(config, &registry);

            assert_violation(&error, "enforcement.mode", "requires live host capture");
            assert!(
                error.to_string().contains(mode),
                "error {error} should report {mode}"
            );
        }
    }

    #[test]
    fn dry_run_enforcement_fails_closed_without_capability() {
        let cases = [
            (
                test_platform_capabilities()
                    .into_iter()
                    .filter(|state| state.kind != CapabilityKind::DryRunEnforcement)
                    .collect::<Vec<_>>(),
                "dry-run enforcement provider is not available",
            ),
            (
                test_platform_capabilities()
                    .into_iter()
                    .map(|state| {
                        if state.kind == CapabilityKind::DryRunEnforcement {
                            CapabilityState::degraded(CapabilityKind::DryRunEnforcement, "degraded")
                        } else {
                            state
                        }
                    })
                    .collect::<Vec<_>>(),
                "degraded",
            ),
        ];

        for (capabilities, expected_reason) in cases {
            let registry = ProviderRegistry::new(
                vec![capture_provider(
                    CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                    RuntimeMode::Available,
                )],
                capabilities,
            );
            let mut config = AgentConfig::default();
            config.capture.selection = CaptureSelection::Replay;
            config.enforcement.mode = EnforcementMode::DryRun;

            let error = validation_error(config, &registry);

            assert_violation(&error, "enforcement.mode", expected_reason);
        }
    }

    #[test]
    fn enforcement_selector_is_validated_by_runtime_validation() {
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
        config.enforcement.selector = Some(Selector::All {
            selectors: Vec::new(),
        });

        let error = validation_error(config, &registry);

        assert_violation(&error, "enforcement.selector", "at least one child");
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

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        test_platform_capabilities_with_libssl(RuntimeMode::Unavailable)
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
        ]
    }

    fn test_platform_capabilities_with_connection_enforcement(
        mode: RuntimeMode,
    ) -> Vec<CapabilityState> {
        test_platform_capabilities()
            .into_iter()
            .map(|state| {
                if state.kind == CapabilityKind::ConnectionEnforcement {
                    match mode {
                        RuntimeMode::Available => {
                            CapabilityState::available(CapabilityKind::ConnectionEnforcement)
                        }
                        RuntimeMode::Degraded => CapabilityState::degraded(
                            CapabilityKind::ConnectionEnforcement,
                            "degraded",
                        ),
                        RuntimeMode::Unavailable => CapabilityState::unavailable(
                            CapabilityKind::ConnectionEnforcement,
                            "unavailable",
                        ),
                    }
                } else {
                    state
                }
            })
            .collect()
    }
}

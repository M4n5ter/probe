use probe_config::{AgentConfig, ConfigViolation};
use probe_core::EnforcementMode;

use crate::plan::{
    capture::{CapturePlan, CapturePlanMode},
    enforcement::{
        EnforcementCapabilityPlan, EnforcementCapabilityRequirement, enabled_execution_surfaces,
    },
    registry::ProviderRegistry,
};

use super::require_available;

pub(super) fn validate_static_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    if let Some(selector) = &config.enforcement.selector
        && let Err(error) = selector.compile()
    {
        violations.push(ConfigViolation {
            field: "enforcement.selector".to_string(),
            reason: error.to_string(),
        });
    }
    if let Some(selector) = &config.enforcement.interception.selector
        && let Err(error) = selector.compile()
    {
        violations.push(ConfigViolation {
            field: "enforcement.interception.selector".to_string(),
            reason: error.to_string(),
        });
    }
    if config.enforcement.interception.strategy.is_enabled()
        && config.enforcement.mode != EnforcementMode::Enforce
    {
        violations.push(ConfigViolation {
            field: "enforcement.interception.strategy".to_string(),
            reason: "transparent interception strategy requires enforcement.mode = enforce"
                .to_string(),
        });
    }
    if config.enforcement.interception.strategy.is_enabled()
        && config.enforcement.selector.is_none()
        && config.enforcement.interception.selector.is_none()
    {
        violations.push(ConfigViolation {
            field: "enforcement.interception.selector".to_string(),
            reason: "transparent interception requires an explicit local selector before setup-time host rules can be installed".to_string(),
        });
    }
    if config.enforcement.mode == EnforcementMode::Enforce {
        match enabled_execution_surfaces(config).len() {
            0 => violations.push(ConfigViolation {
                field: "enforcement.mode".to_string(),
                reason: "enforce mode requires at least one enforcement execution surface: connection backend or transparent interception strategy".to_string(),
            }),
            1 => {}
            _ => violations.push(ConfigViolation {
                field: "enforcement.mode".to_string(),
                reason: "enforce mode supports exactly one enforcement execution surface until composite enforcement execution is implemented".to_string(),
            }),
        }
    }
}

pub(super) fn validate_registry_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    for check in enforcement_capability_checks(config) {
        require_available(
            &registry.capability_matrix(),
            check.requirement.capability,
            check.field,
            check.requirement.unavailable_reason,
            violations,
        );
    }
}

pub(super) fn validate_capture_constraints(
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
                "enforcement execution requires live host capture; selected capture mode is {:?}",
                capture.mode
            ),
        });
    }
}

fn enforcement_capability_checks(config: &AgentConfig) -> Vec<EnforcementCapabilityCheck> {
    let mut checks = Vec::new();
    if let Some(requirement) =
        EnforcementCapabilityPlan::requirement_for_mode(config.enforcement.mode)
    {
        checks.push(EnforcementCapabilityCheck {
            field: "enforcement.mode",
            requirement,
        });
    }
    if config.enforcement.mode == EnforcementMode::Enforce
        && let Some(requirement) = EnforcementCapabilityPlan::requirement_for_connection_backend(
            config.enforcement.backend,
        )
    {
        checks.push(EnforcementCapabilityCheck {
            field: "enforcement.backend",
            requirement,
        });
    }
    if let Some(requirement) = EnforcementCapabilityPlan::requirement_for_interception_strategy(
        config.enforcement.interception.strategy,
    ) {
        checks.push(EnforcementCapabilityCheck {
            field: "enforcement.interception.strategy",
            requirement,
        });
    }
    checks
}

struct EnforcementCapabilityCheck {
    field: &'static str,
    requirement: EnforcementCapabilityRequirement,
}

#[cfg(test)]
mod tests {
    use probe_config::{
        CaptureBackend, CaptureSelection, ConfigValidationError,
        ConnectionEnforcementBackendConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, Direction, ProcessSelector, RuntimeMode, Selector,
        TrafficSelector,
    };

    use crate::plan::capture::{CaptureProviderBuilder, CaptureProviderDescriptor};

    use super::super::validate_runtime_config;
    use super::*;

    #[test]
    fn unsupported_security_features_fail_closed() {
        let registry = ProviderRegistry::new(vec![], test_platform_capabilities());
        let mut config = AgentConfig::default();
        config.tls.plaintext.instrumentation.enabled = true;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "tls.plaintext.instrumentation.enabled",
            "unavailable",
        );
        assert_violation(&error, "enforcement.backend", "not built");
    }

    #[test]
    fn enforce_enforcement_requires_execution_surface() {
        let registry =
            ProviderRegistry::new(vec![live_capture_provider()], test_platform_capabilities());
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "enforcement.mode",
            "at least one enforcement execution surface",
        );
    }

    #[test]
    fn configured_connection_backend_requires_connection_capability() {
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
            let registry = ProviderRegistry::new(vec![live_capture_provider()], capabilities);
            let mut config = AgentConfig::default();
            config.capture.selection = CaptureSelection::Libpcap;
            config.enforcement.mode = EnforcementMode::Enforce;
            config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;

            let error = validation_error(config, &registry);

            assert_violation(&error, "enforcement.backend", expected_reason);
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
            "enforcement.backend",
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
    fn transparent_interception_strategy_requires_enforce_mode() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            transparent_interception_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        enable_transparent_interception(
            &mut config,
            TransparentInterceptionStrategyConfig::InboundTproxy,
        );

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "enforcement.interception.strategy",
            "requires enforcement.mode = enforce",
        );
    }

    #[test]
    fn transparent_interception_requires_available_capability() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            test_platform_capabilities_with_connection_enforcement(RuntimeMode::Available),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        enable_transparent_interception(
            &mut config,
            TransparentInterceptionStrategyConfig::InboundTproxy,
        );

        let error = validation_error(config, &registry);

        assert_violation(&error, "enforcement.interception.strategy", "not built");
    }

    #[test]
    fn transparent_interception_requires_live_capture_mode() {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            transparent_interception_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.enforcement.mode = EnforcementMode::Enforce;
        enable_transparent_interception(
            &mut config,
            TransparentInterceptionStrategyConfig::InboundTproxy,
        );

        let error = validation_error(config, &registry);

        assert_violation(&error, "enforcement.mode", "requires live host capture");
    }

    #[test]
    fn transparent_interception_can_be_the_only_enforce_execution_surface() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            transparent_interception_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        enable_transparent_interception(
            &mut config,
            TransparentInterceptionStrategyConfig::InboundTproxy,
        );

        validate_runtime_config(&config, &registry)
            .expect("transparent interception should not require a connection backend");
    }

    #[test]
    fn transparent_interception_requires_local_setup_selector() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            transparent_interception_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "enforcement.interception.selector",
            "requires an explicit local selector",
        );
    }

    #[test]
    fn enforce_enforcement_rejects_multiple_execution_surfaces() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            connection_and_transparent_interception_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;
        enable_transparent_interception(
            &mut config,
            TransparentInterceptionStrategyConfig::InboundTproxy,
        );

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "enforcement.mode",
            "composite enforcement execution is implemented",
        );
    }

    #[test]
    fn transparent_interception_selector_is_validated_by_runtime_validation() {
        let registry = ProviderRegistry::new(
            vec![live_capture_provider()],
            transparent_interception_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        enable_transparent_interception(
            &mut config,
            TransparentInterceptionStrategyConfig::InboundTproxy,
        );
        config.enforcement.interception.selector = Some(Selector::All {
            selectors: Vec::new(),
        });

        let error = validation_error(config, &registry);

        assert_violation(
            &error,
            "enforcement.interception.selector",
            "at least one child",
        );
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
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not built"),
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

    fn transparent_interception_capabilities() -> Vec<CapabilityState> {
        test_platform_capabilities()
            .into_iter()
            .map(|state| {
                if state.kind == CapabilityKind::TransparentInterception {
                    CapabilityState::available(CapabilityKind::TransparentInterception)
                } else {
                    state
                }
            })
            .collect()
    }

    fn connection_and_transparent_interception_capabilities() -> Vec<CapabilityState> {
        test_platform_capabilities_with_connection_enforcement(RuntimeMode::Available)
            .into_iter()
            .map(|state| {
                if state.kind == CapabilityKind::TransparentInterception {
                    CapabilityState::available(CapabilityKind::TransparentInterception)
                } else {
                    state
                }
            })
            .collect()
    }

    fn enable_transparent_interception(
        config: &mut AgentConfig,
        strategy: TransparentInterceptionStrategyConfig,
    ) {
        config.enforcement.interception.strategy = strategy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
    }
}

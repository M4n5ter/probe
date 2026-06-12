use probe_config::{
    AgentConfig, CaptureBackend, CaptureSelection, ConnectionEnforcementBackendConfig,
    EnforcementPolicySourceConfig,
};
use probe_core::{CapabilityKind, CapabilityState, EnforcementMode, RuntimeMode, Selector};
use runtime::{
    CaptureProviderBuilder, CaptureProviderDescriptor, EnforcementCapabilityPlan,
    EnforcementPolicySourceKind, EnforcementPolicySourcePlan, ProviderRegistry, RuntimeError,
    RuntimePlan,
};

use super::fixture::{
    capture_provider, test_platform_capabilities,
    test_platform_capabilities_with_connection_enforcement,
};

#[test]
fn unsupported_security_features_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(vec![], test_platform_capabilities());
    let mut config = AgentConfig::default();
    config.tls.plaintext.enabled = true;
    config.enforcement.mode = EnforcementMode::Enforce;

    let error = RuntimePlan::build(config, &registry).expect_err("config must fail closed");
    let RuntimeError::Validation(error) = error else {
        panic!("expected validation error");
    };
    let fields = error
        .violations()
        .iter()
        .map(|violation| violation.field.as_str())
        .collect::<Vec<_>>();

    assert!(fields.contains(&"tls.plaintext.enabled"));
    assert!(fields.contains(&"enforcement.mode"));
    Ok(())
}

#[test]
fn dry_run_enforcement_is_a_supported_runtime_capability() -> Result<(), Box<dyn std::error::Error>>
{
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
    config.enforcement.mode = EnforcementMode::DryRun;

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.capabilities.mode(CapabilityKind::DryRunEnforcement),
        RuntimeMode::Available
    );
    assert_eq!(
        plan.enforcement.capability,
        EnforcementCapabilityPlan::Required {
            capability: CapabilityKind::DryRunEnforcement,
            mode: RuntimeMode::Available,
        }
    );
    Ok(())
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
                        CapabilityState::degraded(CapabilityKind::ConnectionEnforcement, "degraded")
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

        let error = RuntimePlan::build(config, &registry)
            .expect_err("enforce mode must require a connection enforcement backend");

        assert!(
            error.to_string().contains(expected_reason),
            "error {error} should contain {expected_reason}"
        );
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

    let error = RuntimePlan::build(config, &registry)
        .expect_err("explicit unavailable backend should report probe reason");

    assert!(
        error
            .to_string()
            .contains("linux socket destroy enforcement requires root")
    );
}

#[test]
fn enforce_enforcement_plan_records_connection_capability() -> Result<(), Box<dyn std::error::Error>>
{
    let registry = ProviderRegistry::new(
        vec![live_capture_provider()],
        test_platform_capabilities_with_connection_enforcement(RuntimeMode::Available),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Libpcap;
    config.enforcement.mode = EnforcementMode::Enforce;
    config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.enforcement.backend,
        ConnectionEnforcementBackendConfig::LinuxSocketDestroy
    );
    assert_eq!(
        plan.enforcement.capability,
        EnforcementCapabilityPlan::Required {
            capability: CapabilityKind::ConnectionEnforcement,
            mode: RuntimeMode::Available,
        }
    );
    Ok(())
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

        let error = RuntimePlan::build(config, &registry)
            .expect_err("enforce must require live host capture");

        assert!(
            error.to_string().contains("requires live host capture"),
            "error {error} should reject non-live capture"
        );
        assert!(
            error.to_string().contains(mode),
            "error {error} should report {mode}"
        );
    }
}

#[test]
fn enforcement_plan_preserves_external_policy_source() -> Result<(), Box<dyn std::error::Error>> {
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
    config.enforcement.selector = Some(Selector::default());
    config.enforcement.policy.source = EnforcementPolicySourceConfig::Directory {
        path: "/etc/sssa-probe/enforcement.d".into(),
    };

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(plan.enforcement.mode, EnforcementMode::AuditOnly);
    assert!(plan.enforcement.config_selector_configured);
    assert_eq!(
        plan.enforcement.policy_source,
        EnforcementPolicySourcePlan::LocalManifest {
            source_kind: EnforcementPolicySourceKind::Directory,
            path: "/etc/sssa-probe/enforcement.d/manifest.toml".into(),
        }
    );
    Ok(())
}

fn live_capture_provider() -> CaptureProviderDescriptor {
    capture_provider(
        CaptureBackend::Libpcap,
        CaptureProviderBuilder::Libpcap,
        RuntimeMode::Available,
    )
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

        let error = RuntimePlan::build(config, &registry)
            .expect_err("dry-run enforcement must require its runtime capability");

        assert!(
            error.to_string().contains(expected_reason),
            "error {error} should contain {expected_reason}"
        );
    }
}

#[test]
fn enforcement_selector_is_validated_during_plan_build() {
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

    let error = RuntimePlan::build(config, &registry)
        .expect_err("invalid enforcement selector must fail plan build");

    assert!(error.to_string().contains("enforcement.selector"));
}

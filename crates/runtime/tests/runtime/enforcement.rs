use probe_config::{AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicySourceConfig};
use probe_core::{CapabilityKind, CapabilityState, EnforcementMode, RuntimeMode, Selector};
use runtime::{
    CaptureProviderBuilder, EnforcementCapabilityPlan, EnforcementPolicySourceKind,
    EnforcementPolicySourcePlan, ProviderRegistry, RuntimePlan,
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

    assert!(
        error
            .to_string()
            .contains("libssl uprobe plaintext provider is not available")
    );
    assert!(
        error
            .to_string()
            .contains("connection-level enforcement backend is not available")
    );
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
        test_platform_capabilities()
            .into_iter()
            .filter(|state| state.kind != CapabilityKind::ConnectionEnforcement)
            .collect::<Vec<_>>(),
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
    ];

    for capabilities in cases {
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
            error
                .to_string()
                .contains("connection-level enforcement backend is not available")
        );
    }
}

#[test]
fn enforce_enforcement_plan_records_connection_capability() -> Result<(), Box<dyn std::error::Error>>
{
    let registry = ProviderRegistry::new(
        vec![capture_provider(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
            RuntimeMode::Available,
        )],
        test_platform_capabilities_with_connection_enforcement(RuntimeMode::Available),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Replay;
    config.enforcement.mode = EnforcementMode::Enforce;

    let plan = RuntimePlan::build(config, &registry)?;

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

#[test]
fn dry_run_enforcement_fails_closed_without_capability() {
    let cases = [
        test_platform_capabilities()
            .into_iter()
            .filter(|state| state.kind != CapabilityKind::DryRunEnforcement)
            .collect::<Vec<_>>(),
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
    ];

    for capabilities in cases {
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
            error
                .to_string()
                .contains("dry-run enforcement provider is not available")
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

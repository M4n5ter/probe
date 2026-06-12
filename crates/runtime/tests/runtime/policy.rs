use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
use probe_core::{RuntimeMode, Selector};
use runtime::{CapturePlanMode, CaptureProviderBuilder, ProviderRegistry, RuntimePlan};

use super::fixture::{capture_provider, test_platform_capabilities};

#[test]
fn policy_selector_is_validated_during_plan_build() {
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

    let error =
        RuntimePlan::build(config, &registry).expect_err("invalid policy selector must fail");

    assert!(error.to_string().contains("policies.guard.selector"));
}

#[test]
fn disabled_policy_selector_is_not_validated_during_plan_build()
-> Result<(), Box<dyn std::error::Error>> {
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

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(plan.capture.mode, CapturePlanMode::Replay);
    Ok(())
}

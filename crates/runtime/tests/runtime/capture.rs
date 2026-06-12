use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
use probe_core::{CapabilityKind, RuntimeMode};
use runtime::{
    CapturePlanMode, CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry,
    RuntimeError, RuntimePlan,
};

use super::fixture::{capture_provider, test_platform_capabilities};

#[test]
fn default_plan_is_honest_when_live_capture_is_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(
        vec![
            capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            ),
            capture_provider(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Unimplemented,
                RuntimeMode::Unavailable,
            ),
            capture_provider(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Unimplemented,
                RuntimeMode::Unavailable,
            ),
        ],
        test_platform_capabilities(),
    );

    let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

    assert_eq!(plan.capture.mode, CapturePlanMode::Unavailable);
    assert_eq!(plan.capture.selected_backend, None);
    assert!(
        plan.capture
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("no live capture provider"))
    );
    Ok(())
}

#[test]
fn auto_selection_uses_first_available_live_fallback() -> Result<(), Box<dyn std::error::Error>> {
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

    let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

    assert_eq!(plan.capture.mode, CapturePlanMode::Live);
    assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Libpcap));
    assert_eq!(
        plan.capture
            .selected_provider
            .as_ref()
            .map(|provider| provider.builder),
        Some(CaptureProviderBuilder::Libpcap)
    );
    Ok(())
}

#[test]
fn auto_selection_skips_degraded_ebpf_and_uses_available_libpcap()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(
        vec![
            CaptureProviderDescriptor::degraded(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Ebpf,
                "eBPF observation provider does not capture payload",
            )
            .allow_explicit_degraded(),
            capture_provider(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
                RuntimeMode::Available,
            ),
        ],
        test_platform_capabilities(),
    );

    let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

    assert_eq!(plan.capture.mode, CapturePlanMode::Live);
    assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Libpcap));
    assert_eq!(
        registry.capability_matrix().mode(CapabilityKind::Ebpf),
        RuntimeMode::Degraded
    );
    Ok(())
}

#[test]
fn explicit_degraded_provider_with_selection_policy_is_selectable()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(
        vec![
            CaptureProviderDescriptor::degraded(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Ebpf,
                "eBPF observation provider does not capture payload",
            )
            .allow_explicit_degraded(),
        ],
        test_platform_capabilities(),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Ebpf;

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(plan.capture.mode, CapturePlanMode::Live);
    assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Ebpf));
    assert_eq!(
        plan.capture
            .selected_provider
            .as_ref()
            .map(|provider| provider.mode),
        Some(RuntimeMode::Degraded)
    );
    Ok(())
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

    let error = RuntimePlan::build(config, &registry)
        .expect_err("degraded provider without explicit policy must not be selectable");
    let RuntimeError::Validation(error) = error else {
        panic!("expected runtime validation error");
    };
    let violation = error.violations().first().expect("expected one violation");

    assert_eq!(violation.field, "capture.selection");
    assert_eq!(
        violation.reason,
        "libpcap provider cannot open the configured device"
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

    let error = RuntimePlan::build(config, &registry).expect_err("explicit ebpf is unavailable");
    let RuntimeError::Validation(error) = error else {
        panic!("expected runtime validation error");
    };
    let violation = error.violations().first().expect("expected one violation");

    assert_eq!(violation.field, "capture.selection");
    assert_eq!(
        violation.reason,
        "eBPF host probe: bpffs path /sys/fs/bpf does not exist"
    );
}

#[test]
fn available_provider_requires_matching_executable_builder() {
    let registry = ProviderRegistry::new(
        vec![capture_provider(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Unimplemented,
            RuntimeMode::Available,
        )],
        test_platform_capabilities(),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Ebpf;

    let error =
        RuntimePlan::build(config, &registry).expect_err("unimplemented builder is not usable");

    assert!(
        error
            .to_string()
            .contains("Unimplemented builder cannot construct Ebpf capture provider")
    );
    assert_eq!(
        registry.capability_matrix().mode(CapabilityKind::Ebpf),
        RuntimeMode::Unavailable
    );
}

#[test]
fn external_plaintext_feed_resolves_to_feed_mode() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(
        vec![capture_provider(
            CaptureBackend::PlaintextFeed,
            CaptureProviderBuilder::PlaintextFeed,
            RuntimeMode::Available,
        )],
        test_platform_capabilities(),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::PlaintextFeed;
    config.capture.plaintext_feed.path = Some("/tmp/feed.jsonl".into());

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(plan.capture.mode, CapturePlanMode::PlaintextFeed);
    assert_eq!(
        plan.capture.selected_backend,
        Some(CaptureBackend::PlaintextFeed)
    );
    assert_eq!(
        plan.capabilities
            .mode(CapabilityKind::ExternalPlaintextFeed),
        RuntimeMode::Available
    );
    Ok(())
}

#[test]
fn external_plaintext_feed_fails_closed_without_provider() -> Result<(), Box<dyn std::error::Error>>
{
    let registry = ProviderRegistry::new(Vec::new(), test_platform_capabilities());
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::PlaintextFeed;
    config.capture.plaintext_feed.path = Some("/tmp/feed.jsonl".into());

    let error = RuntimePlan::build(config, &registry)
        .expect_err("external feed must have a provider descriptor");

    assert!(
        error
            .to_string()
            .contains("capture backend is not registered")
    );
    Ok(())
}

#[test]
fn replay_backend_resolves_to_replay_mode() -> Result<(), Box<dyn std::error::Error>> {
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

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(plan.capture.mode, CapturePlanMode::Replay);
    assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Replay));
    assert_eq!(
        plan.capture
            .selected_provider
            .as_ref()
            .map(|provider| provider.builder),
        Some(CaptureProviderBuilder::Replay)
    );
    Ok(())
}

#[test]
fn run_requirement_fails_without_live_capture() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(
        vec![capture_provider(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Unimplemented,
            RuntimeMode::Unavailable,
        )],
        test_platform_capabilities(),
    );
    let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

    let error = plan
        .require_live_capture()
        .expect_err("run must fail closed");

    assert!(error.to_string().contains("no live capture provider"));
    Ok(())
}

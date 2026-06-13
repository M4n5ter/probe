use probe_config::{
    AgentConfig, CaptureBackend, CaptureSelection, TlsMaterialConfig, TlsMaterialKind,
    TlsPlaintextProvider,
};
use probe_core::{CapabilityKind, RuntimeMode, Selector};
use runtime::{
    CaptureProviderBuilder, ProviderRegistry, RuntimePlan, TlsPlaintextCapabilityPlan,
    TlsPlaintextMaterialPlan,
};

use super::fixture::{
    capture_provider, test_platform_capabilities, test_platform_capabilities_with_libssl,
};

#[test]
fn tls_plaintext_plan_preserves_selector_and_capability_requirement()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(
        vec![capture_provider(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
            RuntimeMode::Available,
        )],
        test_platform_capabilities_with_libssl(RuntimeMode::Available),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Libpcap;
    config.tls.plaintext.enabled = true;
    config.tls.plaintext.provider = TlsPlaintextProvider::LibsslUprobe;
    config.tls.plaintext.selector = Some(Selector::default());
    config.tls.plaintext.libssl_uprobe_object_path =
        Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());
    config.tls.plaintext.reconcile_interval_ms = 2500;

    let plan = RuntimePlan::build(config, &registry)?;

    assert!(plan.tls.plaintext.enabled);
    assert_eq!(
        plan.tls.plaintext.provider,
        TlsPlaintextProvider::LibsslUprobe
    );
    assert!(plan.tls.plaintext.selector_configured);
    assert_eq!(
        plan.tls.plaintext.libssl_uprobe_object_path,
        Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into())
    );
    assert_eq!(plan.tls.plaintext.reconcile_interval_ms, 2500);
    assert_eq!(
        plan.tls.plaintext.capability,
        TlsPlaintextCapabilityPlan::Required {
            capability: CapabilityKind::LibsslUprobe,
            mode: RuntimeMode::Available,
        }
    );
    assert!(plan.tls.plaintext.key_logs.is_empty());
    assert!(plan.tls.plaintext.session_secrets.is_empty());
    Ok(())
}

#[test]
fn tls_plaintext_plan_allows_degraded_libssl_capability_for_best_effort_instrumentation()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(
        vec![capture_provider(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
            RuntimeMode::Available,
        )],
        test_platform_capabilities_with_libssl(RuntimeMode::Degraded),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Libpcap;
    config.tls.plaintext.enabled = true;
    config.tls.plaintext.provider = TlsPlaintextProvider::LibsslUprobe;
    config.tls.plaintext.libssl_uprobe_object_path =
        Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.tls.plaintext.capability,
        TlsPlaintextCapabilityPlan::Required {
            capability: CapabilityKind::LibsslUprobe,
            mode: RuntimeMode::Degraded,
        }
    );
    Ok(())
}

#[test]
fn tls_plaintext_plan_rejects_unavailable_libssl_capability() {
    let registry = ProviderRegistry::new(
        vec![capture_provider(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
            RuntimeMode::Available,
        )],
        test_platform_capabilities_with_libssl(RuntimeMode::Unavailable),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Libpcap;
    config.tls.plaintext.enabled = true;
    config.tls.plaintext.provider = TlsPlaintextProvider::LibsslUprobe;
    config.tls.plaintext.libssl_uprobe_object_path =
        Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());

    let error = RuntimePlan::build(config, &registry)
        .expect_err("unavailable libssl capability must fail enabled TLS plaintext plan");

    assert!(error.to_string().contains("tls.plaintext.enabled"));
    assert!(error.to_string().contains("unavailable"));
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

    let error = RuntimePlan::build(config, &registry)
        .expect_err("libssl TLS plaintext must require live host capture");

    assert!(error.to_string().contains("tls.plaintext.enabled"));
    assert!(error.to_string().contains("requires live host capture"));
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

    let error = RuntimePlan::build(config, &registry)
        .expect_err("enabled keylog TLS plaintext provider is still reserved");

    let error = error.to_string();
    assert!(error.contains("tls.plaintext.provider"));
    assert!(error.contains("reserved but not implemented"));
    assert!(!error.contains("requires live host capture"));
}

#[test]
fn tls_plaintext_plan_resolves_decrypt_hint_material_refs() -> Result<(), Box<dyn std::error::Error>>
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
    config.tls.plaintext.provider = TlsPlaintextProvider::Keylog;
    config.tls.plaintext.key_log_refs = vec!["ssl-keys".to_string()];
    config.tls.plaintext.session_secret_refs = vec!["session-secrets".to_string()];
    config.tls.materials = vec![
        TlsMaterialConfig {
            id: Some("ssl-keys".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: "/tmp/sslkeylog.log".into(),
        },
        TlsMaterialConfig {
            id: Some("session-secrets".to_string()),
            kind: TlsMaterialKind::SessionSecretFile,
            path: "/tmp/session-secrets.jsonl".into(),
        },
    ];

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.tls.plaintext.capability,
        TlsPlaintextCapabilityPlan::NotRequired
    );
    assert_eq!(
        plan.tls.plaintext.key_logs,
        vec![TlsPlaintextMaterialPlan {
            id: "ssl-keys".to_string(),
            kind: TlsMaterialKind::KeyLogFile,
            path: "/tmp/sslkeylog.log".into(),
        }]
    );
    assert_eq!(
        plan.tls.plaintext.session_secrets,
        vec![TlsPlaintextMaterialPlan {
            id: "session-secrets".to_string(),
            kind: TlsMaterialKind::SessionSecretFile,
            path: "/tmp/session-secrets.jsonl".into(),
        }]
    );
    Ok(())
}

#[test]
fn tls_plaintext_selector_is_validated_during_plan_build() {
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

    let error = RuntimePlan::build(config, &registry)
        .expect_err("invalid TLS plaintext selector must fail plan build");

    assert!(error.to_string().contains("tls.plaintext.selector"));
}

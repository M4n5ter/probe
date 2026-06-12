use std::{num::NonZeroU64, path::PathBuf};

use probe_config::{
    AgentConfig, CaptureBackend, CaptureSelection, CompressionCodecName, ExporterTransport,
    TlsMaterialConfig, TlsMaterialKind, TlsPlaintextProvider,
};
use probe_core::{CapabilityKind, CapabilityState, EnforcementMode, RuntimeMode, Selector};
use runtime::{
    CapturePlanMode, CaptureProviderBuilder, CaptureProviderDescriptor,
    EnforcementPolicySourceKind, EnforcementPolicySourcePlan, ExportFailureBackoffPlan,
    ExportSinkPlan, ExportSinkTlsPlan, ExportSinkWorkerPlan, ExportTlsMaterialPlan,
    ExportWorkerPlan, ProviderRegistry, RuntimeError, RuntimePlan, TlsPlaintextCapabilityPlan,
    TlsPlaintextMaterialPlan,
};

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
fn export_plan_disables_worker_without_sinks() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(vec![], test_platform_capabilities());

    let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

    assert_eq!(
        plan.export.worker,
        ExportWorkerPlan::Disabled {
            reason: "export worker has no planned sinks".to_string(),
        }
    );
    assert_eq!(plan.export.sinks, Vec::<ExportSinkPlan>::new());
    Ok(())
}

#[test]
fn export_plan_normalizes_worker_plan_and_sinks() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(vec![], test_platform_capabilities());
    let mut config = AgentConfig::default();
    config.export.worker.schedule =
        probe_config::ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 250,
            batches_per_sink_per_tick: 3,
            sink_timeout_ms: 2_000,
            failure_backoff: probe_config::ExportFailureBackoffConfig {
                initial_ms: 5_000,
                max_ms: 20_000,
                multiplier: 3,
            },
        };
    config.exporters = vec![probe_config::ExporterConfig {
        id: "primary".to_string(),
        transport: ExporterTransport::Webhook,
        endpoint: "https://collector.example/batches".to_string(),
        codec: CompressionCodecName::None,
        headers: Default::default(),
        tls: probe_config::ExporterTlsConfig {
            trust_anchor_refs: vec!["collector-ca".to_string()],
            client_certificate_refs: vec!["client-cert".to_string()],
            client_private_key_ref: Some("client-key".to_string()),
        },
        worker: probe_config::ExporterWorkerConfig {
            batches_per_tick: Some(2),
        },
    }];
    config.tls.materials = vec![
        probe_config::TlsMaterialConfig {
            id: Some("collector-ca".to_string()),
            kind: probe_config::TlsMaterialKind::TrustAnchor,
            path: PathBuf::from("/etc/ssl/private/collector-ca.pem"),
        },
        probe_config::TlsMaterialConfig {
            id: Some("client-cert".to_string()),
            kind: probe_config::TlsMaterialKind::ClientCertificate,
            path: PathBuf::from("/etc/sssa/client.pem"),
        },
        probe_config::TlsMaterialConfig {
            id: Some("client-key".to_string()),
            kind: probe_config::TlsMaterialKind::ClientPrivateKey,
            path: PathBuf::from("/etc/sssa/client.key"),
        },
        probe_config::TlsMaterialConfig {
            id: Some("keylog".to_string()),
            kind: probe_config::TlsMaterialKind::KeyLogFile,
            path: PathBuf::from("/tmp/ssl-keylog.log"),
        },
    ];

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.export.worker,
        ExportWorkerPlan::FixedIntervalBounded {
            interval_ms: 250,
            batches_per_sink_per_tick: 3,
            sink_timeout_ms: 2_000,
            failure_backoff: ExportFailureBackoffPlan {
                initial_ms: 5_000,
                max_ms: 20_000,
                multiplier: 3,
            },
        }
    );
    assert_eq!(
        plan.export.sinks,
        vec![ExportSinkPlan {
            id: "primary".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: "https://collector.example/batches".to_string(),
            codec: CompressionCodecName::None,
            headers: Default::default(),
            tls: ExportSinkTlsPlan {
                trust_anchors: vec![export_tls_material(
                    "collector-ca",
                    probe_config::TlsMaterialKind::TrustAnchor,
                    "/etc/ssl/private/collector-ca.pem",
                )],
                client_certificates: vec![export_tls_material(
                    "client-cert",
                    probe_config::TlsMaterialKind::ClientCertificate,
                    "/etc/sssa/client.pem",
                )],
                client_private_key: Some(export_tls_material(
                    "client-key",
                    probe_config::TlsMaterialKind::ClientPrivateKey,
                    "/etc/sssa/client.key",
                )),
            },
            worker: ExportSinkWorkerPlan {
                batches_per_tick_override: Some(2),
                effective_batches_per_tick: NonZeroU64::new(2).expect("positive batch quota"),
            },
        }]
    );
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
            .contains("real enforcement is not implemented")
    );
    Ok(())
}

#[test]
fn tls_plaintext_plan_preserves_selector_and_capability_requirement()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(
        vec![capture_provider(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
            RuntimeMode::Available,
        )],
        test_platform_capabilities_with_libssl(RuntimeMode::Available),
    );
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Replay;
    config.tls.plaintext.enabled = true;
    config.tls.plaintext.provider = TlsPlaintextProvider::LibsslUprobe;
    config.tls.plaintext.selector = Some(Selector::default());

    let plan = RuntimePlan::build(config, &registry)?;

    assert!(plan.tls.plaintext.enabled);
    assert_eq!(
        plan.tls.plaintext.provider,
        TlsPlaintextProvider::LibsslUprobe
    );
    assert!(plan.tls.plaintext.selector_configured);
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
    config.enforcement.policy.source = probe_config::EnforcementPolicySourceConfig::Directory {
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
fn websocket_parser_capabilities_are_supported() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::with_default_platform(vec![capture_provider(
        CaptureBackend::Replay,
        CaptureProviderBuilder::Replay,
        RuntimeMode::Available,
    )]);
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Replay;

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.capabilities.mode(CapabilityKind::WebSocketHandoff),
        RuntimeMode::Available
    );
    assert_eq!(
        plan.capabilities.mode(CapabilityKind::WebSocketFrame),
        RuntimeMode::Available
    );
    Ok(())
}

#[test]
fn ingress_journal_recovery_is_degraded_until_parser_checkpoints_are_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::with_default_platform(vec![capture_provider(
        CaptureBackend::Replay,
        CaptureProviderBuilder::Replay,
        RuntimeMode::Available,
    )]);
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Replay;

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.capabilities.mode(CapabilityKind::IngressJournal),
        RuntimeMode::Degraded
    );
    assert_eq!(
        plan.capabilities.mode(CapabilityKind::DurableSpool),
        RuntimeMode::Degraded
    );
    let durable_spool = plan
        .capabilities
        .states()
        .iter()
        .find(|state| state.kind == CapabilityKind::DurableSpool)
        .expect("durable spool capability should be reported");
    assert!(
        durable_spool
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("at-least-once"))
    );
    let ingress_journal = plan
        .capabilities
        .states()
        .iter()
        .find(|state| state.kind == CapabilityKind::IngressJournal)
        .expect("ingress journal capability should be reported");
    assert!(
        ingress_journal
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("parser checkpoints"))
    );
    Ok(())
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

fn capture_provider(
    backend: CaptureBackend,
    builder: CaptureProviderBuilder,
    mode: RuntimeMode,
) -> CaptureProviderDescriptor {
    match mode {
        RuntimeMode::Available => CaptureProviderDescriptor::available(backend, builder),
        RuntimeMode::Degraded => CaptureProviderDescriptor::degraded(backend, builder, "degraded"),
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
        CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
        CapabilityState::available(CapabilityKind::DryRunEnforcement),
    ]
}

fn test_platform_capabilities_with_libssl(mode: RuntimeMode) -> Vec<CapabilityState> {
    test_platform_capabilities()
        .into_iter()
        .map(|state| {
            if state.kind == CapabilityKind::LibsslUprobe {
                match mode {
                    RuntimeMode::Available => {
                        CapabilityState::available(CapabilityKind::LibsslUprobe)
                    }
                    RuntimeMode::Degraded => {
                        CapabilityState::degraded(CapabilityKind::LibsslUprobe, "degraded")
                    }
                    RuntimeMode::Unavailable => {
                        CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "unavailable")
                    }
                }
            } else {
                state
            }
        })
        .collect()
}

fn export_tls_material(
    id: &str,
    kind: probe_config::TlsMaterialKind,
    path: impl Into<PathBuf>,
) -> ExportTlsMaterialPlan {
    ExportTlsMaterialPlan {
        id: id.to_string(),
        kind,
        path: path.into(),
    }
}

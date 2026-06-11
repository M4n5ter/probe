use std::path::PathBuf;

use probe_core::Selector;

use super::*;

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
            capture_provider(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Unimplemented,
                RuntimeMode::Unavailable,
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
            failure_backoff_ms: 5_000,
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
            failure_backoff_ms: 5_000,
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
                trust_anchors: vec![PathBuf::from("/etc/ssl/private/collector-ca.pem")],
                client_certificates: vec![PathBuf::from("/etc/sssa/client.pem")],
                client_private_key: Some(PathBuf::from("/etc/sssa/client.key")),
            },
        }]
    );
    Ok(())
}

#[test]
fn explicit_unavailable_backend_does_not_fallback() {
    let registry = ProviderRegistry::new(
        vec![
            capture_provider(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Unimplemented,
                RuntimeMode::Unavailable,
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

    assert!(
        error
            .to_string()
            .contains("Ebpf capture provider is not available")
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
            .contains("Ebpf capture provider is not available")
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
fn websocket_handoff_is_a_supported_runtime_capability() -> Result<(), Box<dyn std::error::Error>> {
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
            .contains("PlaintextFeed capture provider is not available")
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
        CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
        CapabilityState::available(CapabilityKind::DryRunEnforcement),
    ]
}

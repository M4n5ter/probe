use std::{fs::File, io::BufReader};

use capture::{CaptureMultiplexer, CaptureProvider, MultiplexedProvider};
use probe_config::CaptureBackend;
use runtime::{
    CaptureInputSource, CaptureProviderDescriptor, RuntimePlan,
    TransparentInterceptionMitmBackendPlan, TransparentInterceptionMitmPlaintextBridgePlan,
};

use crate::{
    capture_event_feed::{
        JsonLinesCaptureEventFeedProvider, load_l7_mitm_capture_event_feed_provider,
    },
    capture_provider::{CaptureProviderOpenFailureSnapshot, CaptureProviderRuntimeSnapshot},
    error::AgentError,
    l7_mitm::L7MitmRuntimeHandle,
};

type CaptureEventFeedProvider = JsonLinesCaptureEventFeedProvider<BufReader<File>>;

pub(super) enum MitmPlaintextBridgePreflight {
    NotConfigured,
    Open(CaptureEventFeedProvider),
    DeferredUntilBackendReady,
}

pub(super) struct MitmCaptureEventFeedProviderBuild {
    pub(super) provider: Box<dyn CaptureProvider>,
    pub(super) runtime: CaptureProviderRuntimeSnapshot,
}

pub(super) fn preflight_mitm_plaintext_bridge_provider(
    plan: &RuntimePlan,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
) -> Result<MitmPlaintextBridgePreflight, AgentError> {
    match &plan.enforcement.interception.mitm.plaintext_bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => {
            Ok(MitmPlaintextBridgePreflight::NotConfigured)
        }
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { path, follow } => {
            if matches!(
                plan.enforcement.interception.mitm.backend,
                TransparentInterceptionMitmBackendPlan::ManagedProcess { .. }
                    | TransparentInterceptionMitmBackendPlan::ProductProxy { .. }
            ) {
                return Ok(MitmPlaintextBridgePreflight::DeferredUntilBackendReady);
            }
            let provider = load_l7_mitm_capture_event_feed_provider(path, *follow)?;
            l7_mitm_runtime.record_plaintext_bridge_ready();
            Ok(MitmPlaintextBridgePreflight::Open(provider))
        }
    }
}

pub(super) fn with_mitm_plaintext_bridge_provider(
    plan: &RuntimePlan,
    primary: Box<dyn CaptureProvider>,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    preflight: MitmPlaintextBridgePreflight,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    match &plan.enforcement.interception.mitm.plaintext_bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => Ok(primary),
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { .. } => {
            let bridge = preflight
                .into_provider(plan, l7_mitm_runtime)?
                .ok_or_else(|| {
                    AgentError::L7MitmRuntime(
                        "configured MITM plaintext bridge was not opened during capture preflight"
                            .to_string(),
                    )
                })?;
            let runtime = l7_mitm_runtime.clone();
            let bridge = MultiplexedProvider::best_effort_with_disable_handler(
                Box::new(bridge),
                move |reason| runtime.record_plaintext_bridge_disabled(reason),
            );
            l7_mitm_runtime.record_plaintext_bridge_active();
            Ok(Box::new(CaptureMultiplexer::from_providers([
                MultiplexedProvider::required(primary),
                bridge,
            ])))
        }
    }
}

pub(super) fn build_mitm_capture_event_feed_provider(
    plan: &RuntimePlan,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    preflight: MitmPlaintextBridgePreflight,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let provider = preflight
        .into_provider(plan, l7_mitm_runtime)?
        .ok_or_else(|| {
            AgentError::L7MitmRuntime(
                "MITM capture-event provider was selected without a configured plaintext bridge"
                    .to_string(),
            )
        })?;
    l7_mitm_runtime.record_plaintext_bridge_active();
    Ok(Box::new(provider))
}

pub(super) fn build_mitm_capture_event_feed_provider_after_live_failures(
    plan: &RuntimePlan,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    preflight: MitmPlaintextBridgePreflight,
    descriptor: CaptureProviderDescriptor,
    open_failures: Vec<CaptureProviderOpenFailureSnapshot>,
) -> Result<MitmCaptureEventFeedProviderBuild, AgentError> {
    let provider = build_mitm_capture_event_feed_provider(plan, l7_mitm_runtime, preflight)?;
    Ok(MitmCaptureEventFeedProviderBuild {
        provider,
        runtime: CaptureProviderRuntimeSnapshot {
            selected_backend: CaptureBackend::CaptureEventFeed,
            selected_input_source: CaptureInputSource::MitmPlaintextBridge,
            plan_mode: descriptor.plan_mode(),
            provider_runtime_mode: descriptor.runtime_mode,
            evidence_mode: descriptor.evidence_mode,
            evidence_reason: descriptor.evidence_reason,
            reason: descriptor.reason,
            open_failures,
            provider: None,
        },
    })
}

impl MitmPlaintextBridgePreflight {
    fn into_provider(
        self,
        plan: &RuntimePlan,
        l7_mitm_runtime: &L7MitmRuntimeHandle,
    ) -> Result<Option<CaptureEventFeedProvider>, AgentError> {
        match self {
            Self::NotConfigured => Ok(None),
            Self::Open(provider) => Ok(Some(provider)),
            Self::DeferredUntilBackendReady => {
                open_deferred_mitm_plaintext_bridge_provider(plan, l7_mitm_runtime)
            }
        }
    }
}

fn open_deferred_mitm_plaintext_bridge_provider(
    plan: &RuntimePlan,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
) -> Result<Option<CaptureEventFeedProvider>, AgentError> {
    let TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { path, follow } =
        &plan.enforcement.interception.mitm.plaintext_bridge
    else {
        return Ok(None);
    };
    let provider = load_l7_mitm_capture_event_feed_provider(path, *follow)?;
    l7_mitm_runtime.record_plaintext_bridge_ready();
    Ok(Some(provider))
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, fs, io::Write, path::PathBuf};

    use capture::{CaptureError, CaptureEvent, CapturePoll, CapturedLoss};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicySourceConfig,
        TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmManagedProcessConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, CaptureLoss, CaptureOrigin, CaptureSource, Direction,
        EnforcementEvidence, EnforcementMode, ProcessSelector, RuntimeMode, Selector, Timestamp,
        TrafficSelector,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };
    use tempfile::{NamedTempFile, tempdir};

    use super::*;
    use crate::{
        capture_provider::factory::{CaptureProviderPreflight, build_capture_provider},
        l7_mitm::{
            L7MitmBackendHealthSnapshot, L7MitmPlaintextBridgeMode, L7MitmPlaintextBridgeSnapshot,
            L7MitmRuntimeHandle,
        },
    };

    #[test]
    fn mitm_plaintext_bridge_fans_capture_event_feed_into_live_provider()
    -> Result<(), Box<dyn std::error::Error>> {
        let bridge_file = NamedTempFile::new()?;
        let bridge_path = bridge_file.path().to_path_buf();
        fs::write(
            &bridge_path,
            format!(
                "{}\n",
                serde_json::to_string(&mitm_loss_event("mitm bridge"))?
            ),
        )?;
        let mut plan = plan_with_mitm_plaintext_bridge(bridge_path.clone())?;
        set_mitm_plaintext_bridge_follow(&mut plan, false);
        let primary = Box::new(VecProvider::new([loss_event("primary")]));
        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let preflight = preflight_mitm_plaintext_bridge_provider(&plan, &l7_mitm_runtime)?;
        assert_eq!(
            l7_mitm_runtime.snapshot().plaintext_bridge.mode,
            L7MitmPlaintextBridgeMode::Ready
        );
        fs::remove_file(&bridge_path)?;

        let mut provider =
            with_mitm_plaintext_bridge_provider(&plan, primary, &l7_mitm_runtime, preflight)?;

        assert_loss_reason(provider.next()?, "primary");
        assert_loss_reason(provider.next()?, "mitm bridge");
        assert_eq!(
            l7_mitm_runtime.snapshot().plaintext_bridge.mode,
            L7MitmPlaintextBridgeMode::Active
        );
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn mitm_plaintext_bridge_rejects_non_mitm_origin() -> Result<(), Box<dyn std::error::Error>> {
        let bridge_file = NamedTempFile::new()?;
        let bridge_path = bridge_file.path().to_path_buf();
        fs::write(
            &bridge_path,
            format!(
                "{}\n",
                serde_json::to_string(&loss_event("wrong bridge source"))?
            ),
        )?;
        let mut plan = plan_with_mitm_plaintext_bridge(bridge_path)?;
        set_mitm_plaintext_bridge_follow(&mut plan, false);
        let primary = Box::new(VecProvider::new([
            loss_event("primary before bridge error"),
            loss_event("primary after bridge error"),
        ]));
        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let preflight = preflight_mitm_plaintext_bridge_provider(&plan, &l7_mitm_runtime)?;

        let mut provider =
            with_mitm_plaintext_bridge_provider(&plan, primary, &l7_mitm_runtime, preflight)?;

        assert_loss_reason(provider.next()?, "primary before bridge error");
        assert_loss_reason(provider.next()?, "primary after bridge error");
        let bridge = l7_mitm_runtime.snapshot().plaintext_bridge;
        assert_eq!(bridge.mode, L7MitmPlaintextBridgeMode::DisabledAfterError);
        assert!(
            bridge
                .disable_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("requires source L7MitmPlaintext")),
            "{bridge:?}"
        );
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn mitm_plaintext_bridge_read_error_does_not_stop_primary_live_provider()
    -> Result<(), Box<dyn std::error::Error>> {
        let bridge_file = NamedTempFile::new()?;
        let bridge_path = bridge_file.path().to_path_buf();
        fs::write(&bridge_path, "not-json\n")?;
        let mut plan = plan_with_mitm_plaintext_bridge(bridge_path)?;
        set_mitm_plaintext_bridge_follow(&mut plan, false);
        let primary = Box::new(VecProvider::new([
            loss_event("primary before bridge error"),
            loss_event("primary after bridge error"),
        ]));
        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let preflight = preflight_mitm_plaintext_bridge_provider(&plan, &l7_mitm_runtime)?;

        let mut provider =
            with_mitm_plaintext_bridge_provider(&plan, primary, &l7_mitm_runtime, preflight)?;

        assert_loss_reason(provider.next()?, "primary before bridge error");
        assert_loss_reason(provider.next()?, "primary after bridge error");
        let bridge = l7_mitm_runtime.snapshot().plaintext_bridge;
        assert_eq!(bridge.mode, L7MitmPlaintextBridgeMode::DisabledAfterError);
        assert!(
            bridge
                .disable_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("best-effort capture provider"))
        );
        let bridge_capability = provider_capability(&*provider, CapabilityKind::CaptureEventFeed);
        assert_eq!(bridge_capability.mode, RuntimeMode::Unavailable);
        let reason = bridge_capability
            .reason
            .as_deref()
            .expect("disabled bridge should report a reason");
        assert!(reason.contains("best-effort capture provider capture_event_feed_jsonl disabled"));
        assert!(reason.contains("capture provider capture_event_feed_jsonl failed"));
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn mitm_plaintext_bridge_defaults_to_follow_live_feed() -> Result<(), Box<dyn std::error::Error>>
    {
        let bridge_file = NamedTempFile::new()?;
        let bridge_path = bridge_file.path().to_path_buf();
        let plan = plan_with_mitm_plaintext_bridge(bridge_path.clone())?;
        let primary = Box::new(VecProvider::new([]));
        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let preflight = preflight_mitm_plaintext_bridge_provider(&plan, &l7_mitm_runtime)?;

        let mut provider =
            with_mitm_plaintext_bridge_provider(&plan, primary, &l7_mitm_runtime, preflight)?;

        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));
        fs::OpenOptions::new()
            .append(true)
            .open(&bridge_path)?
            .write_all(
                format!(
                    "{}\n",
                    serde_json::to_string(&mitm_loss_event("late mitm"))?
                )
                .as_bytes(),
            )?;
        assert_loss_reason(provider.next()?, "late mitm");
        Ok(())
    }

    #[test]
    fn mitm_plaintext_bridge_missing_file_fails_during_capture_preflight()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let bridge_path = tempdir
            .path()
            .join("missing-mitm-bridge-capture-events.jsonl");
        let plan = plan_with_mitm_plaintext_bridge(bridge_path.clone())?;

        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let error = match CaptureProviderPreflight::build(&plan, None, &l7_mitm_runtime) {
            Ok(_) => panic!("missing MITM plaintext bridge feed must fail closed"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("failed to open capture event feed")
        );
        assert!(
            error
                .to_string()
                .contains(&bridge_path.display().to_string())
        );
        Ok(())
    }

    #[test]
    fn managed_mitm_plaintext_bridge_is_deferred_until_backend_readiness()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let bridge_path = tempdir
            .path()
            .join("managed-mitm-bridge-capture-events.jsonl");
        let plan = plan_with_managed_mitm_plaintext_bridge(bridge_path.clone())?;

        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let preflight = preflight_mitm_plaintext_bridge_provider(&plan, &l7_mitm_runtime)?;

        assert!(matches!(
            preflight,
            MitmPlaintextBridgePreflight::DeferredUntilBackendReady
        ));
        assert_eq!(
            l7_mitm_runtime.snapshot().plaintext_bridge.mode,
            L7MitmPlaintextBridgeMode::Configured
        );

        fs::write(
            &bridge_path,
            format!(
                "{}\n",
                serde_json::to_string(&mitm_loss_event("managed mitm"))?
            ),
        )?;
        let bridge = preflight
            .into_provider(&plan, &l7_mitm_runtime)?
            .expect("managed backend should open bridge after readiness");
        assert_eq!(
            l7_mitm_runtime.snapshot().plaintext_bridge.mode,
            L7MitmPlaintextBridgeMode::Ready
        );
        drop(bridge);
        Ok(())
    }

    #[test]
    fn auto_capture_can_use_mitm_plaintext_bridge_as_primary_provider()
    -> Result<(), Box<dyn std::error::Error>> {
        let bridge_file = NamedTempFile::new()?;
        let bridge_path = bridge_file.path().to_path_buf();
        fs::write(
            &bridge_path,
            format!(
                "{}\n",
                serde_json::to_string(&mitm_loss_event("mitm primary"))?
            ),
        )?;
        let mut plan = auto_plan_with_mitm_plaintext_bridge_fallback(bridge_path)?;
        set_mitm_plaintext_bridge_follow(&mut plan, false);
        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let preflight = CaptureProviderPreflight::build(&plan, None, &l7_mitm_runtime)?;

        let built_provider = build_capture_provider(&plan, None, &l7_mitm_runtime, preflight)?;
        let mut provider = built_provider.provider;

        assert_eq!(
            built_provider.runtime.selected_backend,
            CaptureBackend::CaptureEventFeed
        );
        assert_eq!(
            built_provider.runtime.selected_input_source,
            CaptureInputSource::MitmPlaintextBridge
        );
        assert_loss_reason(provider.next()?, "mitm primary");
        assert_eq!(
            l7_mitm_runtime.snapshot().plaintext_bridge.mode,
            L7MitmPlaintextBridgeMode::Active
        );
        Ok(())
    }

    fn set_mitm_plaintext_bridge_follow(plan: &mut RuntimePlan, follow: bool) {
        let TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed {
            follow: planned_follow,
            ..
        } = &mut plan.enforcement.interception.mitm.plaintext_bridge
        else {
            panic!("expected capture-event MITM bridge plan");
        };
        *planned_follow = follow;
    }

    fn configured_l7_mitm_runtime() -> L7MitmRuntimeHandle {
        L7MitmRuntimeHandle::for_test(
            L7MitmBackendHealthSnapshot::disabled(),
            L7MitmPlaintextBridgeSnapshot {
                mode: L7MitmPlaintextBridgeMode::Configured,
                disable_reason: None,
            },
            1,
        )
    }

    fn plan_with_mitm_plaintext_bridge(
        bridge_path: PathBuf,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = external_mitm_plaintext_bridge_config(bridge_path);
        config.capture.selection = CaptureSelection::Libpcap;
        RuntimePlan::build(
            config,
            &ProviderRegistry::new(
                vec![
                    CaptureProviderDescriptor::available(
                        CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Libpcap,
                    ),
                    CaptureProviderDescriptor::available(
                        CaptureBackend::CaptureEventFeed,
                        CaptureProviderBuilder::CaptureEventFeed,
                    ),
                ],
                mitm_bridge_platform_capabilities(),
            ),
        )
    }

    fn auto_plan_with_mitm_plaintext_bridge_fallback(
        bridge_path: PathBuf,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(
            external_mitm_plaintext_bridge_config(bridge_path),
            &ProviderRegistry::new(
                vec![
                    CaptureProviderDescriptor::unavailable(
                        CaptureBackend::Ebpf,
                        CaptureProviderBuilder::Unimplemented,
                        "eBPF is unavailable",
                    ),
                    CaptureProviderDescriptor::unavailable(
                        CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Unimplemented,
                        "libpcap is unavailable",
                    ),
                    CaptureProviderDescriptor::available(
                        CaptureBackend::CaptureEventFeed,
                        CaptureProviderBuilder::CaptureEventFeed,
                    ),
                ],
                mitm_bridge_platform_capabilities(),
            ),
        )
    }

    fn external_mitm_plaintext_bridge_config(bridge_path: PathBuf) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some("127.0.0.1:15002".to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(bridge_path);
        config.enforcement.interception.mitm.client_trust.mode =
            probe_config::TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: "/tmp/traffic-probe-enforcement.toml".into(),
        };
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
        config
    }

    fn plan_with_managed_mitm_plaintext_bridge(
        bridge_path: PathBuf,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        let readiness_probe = TransparentInterceptionMitmBackendReadinessProbeConfig {
            target: Some("127.0.0.1:15002".to_string()),
            ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
        };
        let process = TransparentInterceptionMitmManagedProcessConfig {
            program: Some("/bin/true".into()),
            args: Vec::new(),
            working_dir: None,
        };
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::managed_process(readiness_probe, process);
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(bridge_path);
        config.enforcement.interception.mitm.client_trust.mode =
            probe_config::TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: "/tmp/traffic-probe-enforcement.toml".into(),
        };
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
        RuntimePlan::build(
            config,
            &ProviderRegistry::new(
                vec![
                    CaptureProviderDescriptor::available(
                        CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Libpcap,
                    ),
                    CaptureProviderDescriptor::available(
                        CaptureBackend::CaptureEventFeed,
                        CaptureProviderBuilder::CaptureEventFeed,
                    ),
                ],
                mitm_bridge_platform_capabilities(),
            ),
        )
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
        ]
    }

    fn mitm_bridge_platform_capabilities() -> Vec<CapabilityState> {
        let mut capabilities = test_platform_capabilities();
        capabilities.push(CapabilityState::available(
            CapabilityKind::TransparentInterception,
        ));
        capabilities.push(CapabilityState::available(CapabilityKind::L7Mitm));
        capabilities
    }

    struct VecProvider {
        events: VecDeque<CaptureEvent>,
    }

    impl VecProvider {
        fn new(events: impl IntoIterator<Item = CaptureEvent>) -> Self {
            Self {
                events: events.into_iter().collect(),
            }
        }
    }

    impl CaptureProvider for VecProvider {
        fn name(&self) -> &'static str {
            "test_primary"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(self
                .events
                .pop_front()
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Finished))
        }
    }

    fn loss_event(reason: &str) -> CaptureEvent {
        loss_event_with_source(reason, CaptureSource::ExternalPlaintextFeed)
    }

    fn mitm_loss_event(reason: &str) -> CaptureEvent {
        loss_event_with_source(reason, CaptureSource::L7MitmPlaintext)
    }

    fn loss_event_with_source(reason: &str, source: CaptureSource) -> CaptureEvent {
        CaptureEvent::Loss(CapturedLoss {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            origin: CaptureOrigin::from_source(source),
            enforcement_evidence: EnforcementEvidence::default(),
            loss: CaptureLoss {
                lost_events: 1,
                reason: reason.to_string(),
            },
        })
    }

    fn assert_loss_reason(event: Option<CaptureEvent>, reason: &str) {
        let Some(CaptureEvent::Loss(loss)) = event else {
            panic!("expected capture loss event, got {event:?}");
        };
        assert_eq!(loss.loss.reason, reason);
    }

    fn provider_capability(
        provider: &dyn CaptureProvider,
        kind: CapabilityKind,
    ) -> CapabilityState {
        provider
            .capabilities()
            .into_iter()
            .find(|capability| capability.kind == kind)
            .unwrap_or_else(|| panic!("missing provider capability {kind:?}"))
    }
}

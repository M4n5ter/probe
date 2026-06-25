use std::{fs::File, io::BufReader};

use attribution::ProcfsSocketResolver;
use capture::{
    CaptureError, CaptureMultiplexer, CaptureProvider, EbpfProcessObservationProbeConfig,
    EbpfProcessObservationProvider, EbpfResolvedSocketFlow, EbpfSocketFlowLookup,
    EbpfSocketFlowResolver, LibpcapProvider, MultiplexedProvider, ProcessResolver, ResolvedProcess,
};
use probe_config::{CaptureBackend, CaptureSelection};
use probe_core::{CapabilityKind, RuntimeMode, TcpConnection};
use runtime::{
    CaptureProviderDescriptor, RuntimeError, RuntimePlan,
    TransparentInterceptionMitmPlaintextBridgePlan,
};

use crate::{
    capture_event_feed::{JsonLinesCaptureEventFeedProvider, load_capture_event_feed_provider},
    capture_provider::{CaptureProviderOpenFailureSnapshot, CaptureProviderRuntimeSnapshot},
    capture_registry::libpcap_config_from_agent,
    error::AgentError,
    l7_mitm::L7MitmRuntimeHandle,
    plaintext_feed::load_plaintext_feed_provider,
    tls_plaintext::{
        TlsDecryptHintRuntimeState, TlsPlaintextInstrumentationBuild, TlsPlaintextRuntimeState,
        TlsSessionSecretAutoBindingBuild, build_tls_plaintext_instrumentation,
        build_tls_session_secret_auto_binding_with_runtime,
    },
};

type CaptureEventFeedProvider = JsonLinesCaptureEventFeedProvider<BufReader<File>>;

pub(crate) struct CaptureProviderPreflight {
    session_secret_auto_binding: TlsSessionSecretAutoBindingBuild,
    mitm_plaintext_bridge: Option<CaptureEventFeedProvider>,
}

pub(crate) struct BuiltCaptureProvider {
    pub(crate) provider: Box<dyn CaptureProvider>,
    pub(crate) runtime: CaptureProviderRuntimeSnapshot,
}

impl CaptureProviderPreflight {
    pub(crate) fn build(
        plan: &RuntimePlan,
        tls_decrypt_hint_runtime: Option<&TlsDecryptHintRuntimeState>,
        l7_mitm_runtime: &L7MitmRuntimeHandle,
    ) -> Result<Self, AgentError> {
        let session_secret_auto_binding =
            build_tls_session_secret_auto_binding_with_runtime(plan, tls_decrypt_hint_runtime)?;
        let mitm_plaintext_bridge =
            preflight_mitm_plaintext_bridge_provider(plan, l7_mitm_runtime)?;
        Ok(Self {
            session_secret_auto_binding,
            mitm_plaintext_bridge,
        })
    }
}

pub(crate) fn build_capture_provider(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    preflight: CaptureProviderPreflight,
) -> Result<BuiltCaptureProvider, AgentError> {
    match plan.capture.selected_backend {
        Some(CaptureBackend::PlaintextFeed) => Ok(BuiltCaptureProvider {
            provider: build_plaintext_feed_provider(plan)?,
            runtime: CaptureProviderRuntimeSnapshot {
                selected_backend: CaptureBackend::PlaintextFeed,
                plan_mode: plan.capture.mode,
                provider_runtime_mode: RuntimeMode::Available,
                evidence_mode: plan
                    .capture
                    .selected_evidence_mode
                    .unwrap_or(runtime::CaptureEvidenceMode::Nominal),
                evidence_reason: plan.capture.evidence_reason.clone(),
                reason: None,
                open_failures: Vec::new(),
            },
        }),
        Some(CaptureBackend::CaptureEventFeed) => Ok(BuiltCaptureProvider {
            provider: build_capture_event_feed_provider(plan)?,
            runtime: CaptureProviderRuntimeSnapshot {
                selected_backend: CaptureBackend::CaptureEventFeed,
                plan_mode: plan.capture.mode,
                provider_runtime_mode: RuntimeMode::Available,
                evidence_mode: plan
                    .capture
                    .selected_evidence_mode
                    .unwrap_or(runtime::CaptureEvidenceMode::Nominal),
                evidence_reason: plan.capture.evidence_reason.clone(),
                reason: None,
                open_failures: Vec::new(),
            },
        }),
        _ => build_live_capture_provider(
            plan,
            tls_plaintext_runtime,
            l7_mitm_runtime,
            preflight.session_secret_auto_binding,
            preflight.mitm_plaintext_bridge,
        ),
    }
}

fn build_live_capture_provider(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    session_secret_auto_binding: TlsSessionSecretAutoBindingBuild,
    mitm_plaintext_bridge: Option<CaptureEventFeedProvider>,
) -> Result<BuiltCaptureProvider, AgentError> {
    plan.require_live_capture()?;
    let outcome = build_live_primary_with_fallback(plan)?;
    let descriptor = outcome.descriptor;
    let primary = session_secret_auto_binding.wrap(outcome.provider);
    let provider = with_tls_plaintext_provider(plan, primary, tls_plaintext_runtime)?;
    let provider = with_mitm_plaintext_bridge_provider(
        plan,
        provider,
        l7_mitm_runtime,
        mitm_plaintext_bridge,
    )?;
    Ok(BuiltCaptureProvider {
        provider,
        runtime: CaptureProviderRuntimeSnapshot {
            selected_backend: descriptor.backend,
            plan_mode: descriptor.plan_mode(),
            provider_runtime_mode: descriptor.runtime_mode,
            evidence_mode: descriptor.evidence_mode,
            evidence_reason: descriptor.evidence_reason,
            reason: descriptor.reason,
            open_failures: outcome.open_failures,
        },
    })
}

fn build_live_primary_with_fallback(
    plan: &RuntimePlan,
) -> Result<LiveCaptureOpenOutcome<Box<dyn CaptureProvider>>, AgentError> {
    open_live_backend_with_fallback(plan, |backend| build_live_capture_backend(plan, backend))
}

#[derive(Debug)]
struct LiveCaptureOpenOutcome<T> {
    provider: T,
    descriptor: CaptureProviderDescriptor,
    open_failures: Vec<CaptureProviderOpenFailureSnapshot>,
}

fn open_live_backend_with_fallback<T>(
    plan: &RuntimePlan,
    mut open_backend: impl FnMut(CaptureBackend) -> Result<T, AgentError>,
) -> Result<LiveCaptureOpenOutcome<T>, AgentError> {
    let mut failures = Vec::new();
    for descriptor in plan.capture.live_provider_open_candidates() {
        let backend = descriptor.backend;
        match open_backend(backend) {
            Ok(provider) => {
                return Ok(LiveCaptureOpenOutcome {
                    provider,
                    descriptor,
                    open_failures: failures,
                });
            }
            Err(error) if plan.config.capture.selection == CaptureSelection::Auto => {
                failures.push(CaptureProviderOpenFailureSnapshot {
                    backend,
                    reason: error.to_string(),
                });
            }
            Err(error) => return Err(error),
        }
    }
    Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
        reason: live_capture_failure_reason(plan, failures),
    }))
}

fn build_live_capture_backend(
    plan: &RuntimePlan,
    backend: CaptureBackend,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    match backend {
        CaptureBackend::Ebpf => build_ebpf_capture_provider(plan),
        CaptureBackend::Libpcap => Ok(Box::new(LibpcapProvider::open_with_process_resolver(
            libpcap_config_from_agent(&plan.config),
            procfs_tcp_process_resolver_for_plan(plan),
        )?) as Box<dyn CaptureProvider>),
        backend => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
            reason: format!("{backend:?} capture provider is selected but has no agent builder"),
        })),
    }
}

fn live_capture_failure_reason(
    plan: &RuntimePlan,
    failures: Vec<CaptureProviderOpenFailureSnapshot>,
) -> String {
    if failures.is_empty() {
        return plan
            .capture
            .reason
            .clone()
            .unwrap_or_else(|| "capture plan did not select a live backend".to_string());
    }
    format!(
        "all auto live capture providers failed to open: {}",
        failures
            .into_iter()
            .map(|failure| format!("{:?}: {}", failure.backend, failure.reason))
            .collect::<Vec<_>>()
            .join("; ")
    )
}

fn with_tls_plaintext_provider(
    plan: &RuntimePlan,
    primary: Box<dyn CaptureProvider>,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let instrumentation_build = build_tls_plaintext_instrumentation(plan, tls_plaintext_runtime)?;
    if let Some(runtime) = tls_plaintext_runtime {
        runtime.record_instrumentation_build(&instrumentation_build);
    }
    match instrumentation_build {
        TlsPlaintextInstrumentationBuild::NotConfigured => Ok(primary),
        TlsPlaintextInstrumentationBuild::Enabled(plaintext) => {
            let plaintext = match tls_plaintext_runtime {
                Some(runtime) => {
                    let runtime = runtime.clone();
                    MultiplexedProvider::best_effort_with_disable_handler(
                        plaintext,
                        move |reason| {
                            runtime.record_instrumentation_disabled(reason);
                        },
                    )
                }
                None => MultiplexedProvider::best_effort(plaintext),
            };
            Ok(Box::new(CaptureMultiplexer::from_providers([
                MultiplexedProvider::required(primary),
                plaintext,
            ])))
        }
        TlsPlaintextInstrumentationBuild::Disabled { .. } => Ok(primary),
    }
}

fn with_mitm_plaintext_bridge_provider(
    plan: &RuntimePlan,
    primary: Box<dyn CaptureProvider>,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    mitm_plaintext_bridge: Option<CaptureEventFeedProvider>,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    match &plan.enforcement.interception.mitm.plaintext_bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => Ok(primary),
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { .. } => {
            let bridge = mitm_plaintext_bridge.ok_or_else(|| {
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

fn preflight_mitm_plaintext_bridge_provider(
    plan: &RuntimePlan,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
) -> Result<Option<CaptureEventFeedProvider>, AgentError> {
    match &plan.enforcement.interception.mitm.plaintext_bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => Ok(None),
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { path, follow } => {
            let provider = load_capture_event_feed_provider(path, *follow)?;
            l7_mitm_runtime.record_plaintext_bridge_ready();
            Ok(Some(provider))
        }
    }
}

fn build_ebpf_capture_provider(plan: &RuntimePlan) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let object_path = plan
        .config
        .capture
        .ebpf
        .object_path
        .clone()
        .ok_or_else(|| {
            AgentError::UnsupportedRunConfig(
                "ebpf capture requires capture.ebpf.object_path".to_string(),
            )
        })?;
    let deep_observe_selector = plan
        .config
        .capture
        .deep_observe_selector
        .as_ref()
        .map(|selector| {
            selector.compile().map_err(|source| {
                AgentError::UnsupportedRunConfig(format!(
                    "invalid capture.deep_observe_selector: {source}"
                ))
            })
        })
        .transpose()?;
    Ok(Box::new(EbpfProcessObservationProvider::open(
        EbpfProcessObservationProbeConfig::new(object_path),
        Box::<ProcfsTcpProcessResolver>::default(),
        deep_observe_selector,
    )?))
}

fn build_plaintext_feed_provider(
    plan: &RuntimePlan,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let path = plan
        .config
        .capture
        .plaintext_feed
        .path
        .as_ref()
        .ok_or_else(|| {
            AgentError::UnsupportedRunConfig(
                "plaintext_feed capture requires capture.plaintext_feed.path".to_string(),
            )
        })?;
    Ok(Box::new(load_plaintext_feed_provider(path)?))
}

fn build_capture_event_feed_provider(
    plan: &RuntimePlan,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let config = &plan.config.capture.capture_event_feed;
    let path = config.path.as_ref().ok_or_else(|| {
        AgentError::UnsupportedRunConfig(
            "capture_event_feed capture requires capture.capture_event_feed.path".to_string(),
        )
    })?;
    Ok(Box::new(load_capture_event_feed_provider(
        path,
        config.follow_enabled(),
    )?))
}

fn procfs_tcp_process_resolver_for_plan(plan: &RuntimePlan) -> Option<Box<dyn ProcessResolver>> {
    (plan
        .capabilities
        .mode(CapabilityKind::ProcfsSocketAttribution)
        != RuntimeMode::Unavailable)
        .then(|| Box::<ProcfsTcpProcessResolver>::default() as Box<dyn ProcessResolver>)
}

struct ProcfsTcpProcessResolver {
    resolver: ProcfsSocketResolver,
}

impl Default for ProcfsTcpProcessResolver {
    fn default() -> Self {
        Self {
            resolver: ProcfsSocketResolver::new(),
        }
    }
}

impl ProcessResolver for ProcfsTcpProcessResolver {
    fn resolve_tcp_process(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<ResolvedProcess>, CaptureError> {
        self.resolver
            .resolve_tcp_connection(connection)
            .map(|resolved| {
                resolved.map(|resolved| ResolvedProcess {
                    process: resolved.process,
                    confidence: resolved.confidence,
                })
            })
            .map_err(|error| CaptureError::provider("procfs_socket_attribution", error.to_string()))
    }

    fn invalidate_cached_resolution(&mut self) {
        self.resolver.invalidate_snapshot();
    }
}

impl EbpfSocketFlowResolver for ProcfsTcpProcessResolver {
    fn resolve_socket_flow(
        &mut self,
        lookup: EbpfSocketFlowLookup,
    ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
        self.resolver
            .resolve_tcp_fd(attribution::SocketFdLookup {
                tgid: lookup.tgid,
                thread_pid: lookup.thread_pid,
                fd: lookup.fd,
                expected_remote_endpoint: lookup.expected_remote_endpoint,
                process_hint: lookup
                    .process_hint
                    .map(|hint| attribution::SocketProcessHint {
                        name: hint.name,
                        uid: hint.uid,
                        gid: hint.gid,
                    }),
            })
            .map(|resolved| {
                resolved.map(|resolved| EbpfResolvedSocketFlow {
                    process: resolved.process,
                    confidence: resolved.confidence,
                    connection: resolved.connection,
                    socket_cookie: resolved.socket_cookie,
                })
            })
            .map_err(|error| CaptureError::provider("procfs_socket_attribution", error.to_string()))
    }

    fn invalidate_cached_resolution(&mut self) {
        self.resolver.invalidate_snapshot();
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, fs, io::Write, path::PathBuf};

    use capture::{CaptureEvent, CapturePoll, CapturedLoss};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, TlsMaterialConfig, TlsMaterialKind,
        TransparentInterceptionMitmBackendConfig,
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

    use crate::l7_mitm::{
        L7MitmBackendHealthSnapshot, L7MitmPlaintextBridgeMode, L7MitmPlaintextBridgeSnapshot,
        L7MitmRuntimeHandle,
    };

    use super::*;

    #[test]
    fn auto_capture_open_falls_back_after_degraded_ebpf_open_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = auto_plan_with_degraded_ebpf_and_available_libpcap()?;
        let mut attempted = Vec::new();

        let outcome = open_live_backend_with_fallback(&plan, |backend| {
            attempted.push(backend);
            match backend {
                CaptureBackend::Ebpf => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
                    reason: "eBPF attach failed".to_string(),
                })),
                CaptureBackend::Libpcap => Ok(backend),
                backend => panic!("unexpected backend {backend:?}"),
            }
        })?;

        assert_eq!(attempted, [CaptureBackend::Ebpf, CaptureBackend::Libpcap]);
        assert_eq!(outcome.provider, CaptureBackend::Libpcap);
        assert_eq!(outcome.descriptor.backend, CaptureBackend::Libpcap);
        assert_eq!(outcome.open_failures.len(), 1);
        assert_eq!(outcome.open_failures[0].backend, CaptureBackend::Ebpf);
        assert!(
            outcome.open_failures[0]
                .reason
                .contains("eBPF attach failed")
        );
        Ok(())
    }

    #[test]
    fn explicit_capture_open_does_not_fallback_after_ebpf_open_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;
        let plan = plan_with_registry(config)?;
        let mut attempted = Vec::new();

        let error = open_live_backend_with_fallback(&plan, |backend| {
            attempted.push(backend);
            Err::<CaptureBackend, _>(AgentError::Runtime(RuntimeError::NoLiveCapture {
                reason: "eBPF attach failed".to_string(),
            }))
        })
        .expect_err("explicit eBPF must fail fast");

        assert_eq!(attempted, [CaptureBackend::Ebpf]);
        assert!(error.to_string().contains("eBPF attach failed"));
        Ok(())
    }

    #[test]
    fn mitm_plaintext_bridge_fans_capture_event_feed_into_live_provider()
    -> Result<(), Box<dyn std::error::Error>> {
        let bridge_file = NamedTempFile::new()?;
        let bridge_path = bridge_file.path().to_path_buf();
        fs::write(
            &bridge_path,
            format!("{}\n", serde_json::to_string(&loss_event("mitm bridge"))?),
        )?;
        let mut plan = plan_with_mitm_plaintext_bridge(bridge_path.clone())?;
        set_mitm_plaintext_bridge_follow(&mut plan, false);
        let primary = Box::new(VecProvider::new([loss_event("primary")]));
        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let bridge = preflight_mitm_plaintext_bridge_provider(&plan, &l7_mitm_runtime)?
            .expect("configured MITM plaintext bridge should open during preflight");
        assert_eq!(
            l7_mitm_runtime.snapshot().plaintext_bridge.mode,
            L7MitmPlaintextBridgeMode::Ready
        );
        fs::remove_file(&bridge_path)?;

        let mut provider =
            with_mitm_plaintext_bridge_provider(&plan, primary, &l7_mitm_runtime, Some(bridge))?;

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
        let bridge = preflight_mitm_plaintext_bridge_provider(&plan, &l7_mitm_runtime)?
            .expect("configured MITM plaintext bridge should open during preflight");

        let mut provider =
            with_mitm_plaintext_bridge_provider(&plan, primary, &l7_mitm_runtime, Some(bridge))?;

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
        let mut plan = plan_with_mitm_plaintext_bridge(bridge_path.clone())?;
        let TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { follow, .. } =
            &mut plan.enforcement.interception.mitm.plaintext_bridge
        else {
            panic!("expected capture-event MITM bridge plan");
        };
        assert!(*follow);
        let primary = Box::new(VecProvider::new([]));
        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let bridge = preflight_mitm_plaintext_bridge_provider(&plan, &l7_mitm_runtime)?
            .expect("configured MITM plaintext bridge should open during preflight");

        let mut provider =
            with_mitm_plaintext_bridge_provider(&plan, primary, &l7_mitm_runtime, Some(bridge))?;

        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));
        fs::OpenOptions::new()
            .append(true)
            .open(&bridge_path)?
            .write_all(
                format!("{}\n", serde_json::to_string(&loss_event("late mitm"))?).as_bytes(),
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

    fn auto_plan_with_degraded_ebpf_and_available_libpcap()
    -> Result<RuntimePlan, runtime::RuntimeError> {
        plan_with_registry(AgentConfig::default())
    }

    fn plan_with_registry(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(
            config,
            &ProviderRegistry::new(
                vec![
                    CaptureProviderDescriptor::degraded(
                        CaptureBackend::Ebpf,
                        CaptureProviderBuilder::Ebpf,
                        "eBPF provider is best-effort",
                    ),
                    CaptureProviderDescriptor::available(
                        CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Libpcap,
                    ),
                ],
                test_platform_capabilities(),
            ),
        )
    }

    fn plan_with_mitm_plaintext_bridge(
        bridge_path: PathBuf,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::External;
        config
            .enforcement
            .interception
            .mitm
            .backend_readiness_probe
            .target = Some("127.0.0.1:15002".to_string());
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(bridge_path);
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
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/sssa/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/sssa/mitm-ca.key".into(),
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
        CaptureEvent::Loss(CapturedLoss {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            origin: CaptureOrigin::from_source(CaptureSource::ExternalPlaintextFeed),
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

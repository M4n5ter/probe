use attribution::ProcfsSocketResolver;
use capture::{
    CaptureError, CaptureMultiplexer, CaptureProvider, EbpfProcessObservationProbeConfig,
    EbpfProcessObservationProvider, EbpfResolvedSocketFlow, EbpfSocketFlowLookup,
    EbpfSocketFlowResolver, LibpcapProvider, MultiplexedProvider, ProcessResolver, ResolvedProcess,
};
use probe_config::{CaptureBackend, CaptureSelection};
use probe_core::{CapabilityKind, RuntimeMode, TcpConnection};
use runtime::{CaptureProviderDescriptor, RuntimeError, RuntimePlan};

use crate::{
    capture_event_feed::load_capture_event_feed_provider,
    capture_provider::{CaptureProviderOpenFailureSnapshot, CaptureProviderRuntimeSnapshot},
    capture_registry::libpcap_config_from_agent,
    error::AgentError,
    plaintext_feed::load_plaintext_feed_provider,
    tls_plaintext::{
        TlsDecryptHintRuntimeState, TlsPlaintextInstrumentationBuild, TlsPlaintextRuntimeState,
        TlsSessionSecretAutoBindingBuild, build_tls_plaintext_instrumentation,
        build_tls_session_secret_auto_binding_with_runtime,
    },
};

pub(crate) struct CaptureProviderPreflight {
    session_secret_auto_binding: TlsSessionSecretAutoBindingBuild,
}

pub(crate) struct BuiltCaptureProvider {
    pub(crate) provider: Box<dyn CaptureProvider>,
    pub(crate) runtime: CaptureProviderRuntimeSnapshot,
}

impl CaptureProviderPreflight {
    pub(crate) fn build(
        plan: &RuntimePlan,
        tls_decrypt_hint_runtime: Option<&TlsDecryptHintRuntimeState>,
    ) -> Result<Self, AgentError> {
        let session_secret_auto_binding =
            build_tls_session_secret_auto_binding_with_runtime(plan, tls_decrypt_hint_runtime)?;
        Ok(Self {
            session_secret_auto_binding,
        })
    }
}

pub(crate) fn build_capture_provider(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
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
            preflight.session_secret_auto_binding,
        ),
    }
}

fn build_live_capture_provider(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
    session_secret_auto_binding: TlsSessionSecretAutoBindingBuild,
) -> Result<BuiltCaptureProvider, AgentError> {
    plan.require_live_capture()?;
    let outcome = build_live_primary_with_fallback(plan)?;
    let descriptor = outcome.descriptor;
    let primary = session_secret_auto_binding.wrap(outcome.provider);
    let provider = with_tls_plaintext_provider(plan, primary, tls_plaintext_runtime)?;
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
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
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
}

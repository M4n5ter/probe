use attribution::ProcfsSocketResolver;
use capture::{
    CaptureError, CaptureMultiplexer, CaptureProvider, EbpfConnectFlowLookup,
    EbpfConnectFlowResolver, EbpfProcessObservationProbeConfig, EbpfProcessObservationProvider,
    EbpfResolvedConnectFlow, LibpcapProvider, MultiplexedProvider, ProcessResolver,
    ResolvedProcess,
};
use probe_config::CaptureBackend;
use probe_core::{CapabilityKind, RuntimeMode, TcpConnection};
use runtime::{RuntimeError, RuntimePlan};

use crate::{
    capture_registry::libpcap_config_from_agent,
    error::AgentError,
    plaintext_feed::load_plaintext_feed_provider,
    tls_plaintext::{
        TlsPlaintextInstrumentationBuild, TlsPlaintextRuntimeState,
        build_tls_plaintext_instrumentation,
    },
};

pub(crate) fn build_capture_provider(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    match plan.capture.selected_backend {
        Some(CaptureBackend::PlaintextFeed) => build_plaintext_feed_provider(plan),
        _ => build_live_capture_provider(plan, tls_plaintext_runtime),
    }
}

fn build_live_capture_provider(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    plan.require_live_capture()?;
    let primary = match plan.capture.selected_backend {
        Some(CaptureBackend::Ebpf) => build_ebpf_capture_provider(plan),
        Some(CaptureBackend::Libpcap) => Ok(Box::new(LibpcapProvider::open_with_process_resolver(
            libpcap_config_from_agent(&plan.config),
            procfs_tcp_process_resolver_for_plan(plan),
        )?) as Box<dyn CaptureProvider>),
        Some(backend) => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
            reason: format!("{backend:?} capture provider is selected but has no agent builder"),
        })),
        None => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
            reason: plan
                .capture
                .reason
                .clone()
                .unwrap_or_else(|| "capture plan did not select a live backend".to_string()),
        })),
    }?;
    with_tls_plaintext_provider(plan, primary, tls_plaintext_runtime)
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

impl EbpfConnectFlowResolver for ProcfsTcpProcessResolver {
    fn resolve_connect_flow(
        &mut self,
        lookup: EbpfConnectFlowLookup,
    ) -> Result<Option<EbpfResolvedConnectFlow>, CaptureError> {
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
                resolved.map(|resolved| EbpfResolvedConnectFlow {
                    process: resolved.process,
                    confidence: resolved.confidence,
                    connection: resolved.connection,
                })
            })
            .map_err(|error| CaptureError::provider("procfs_socket_attribution", error.to_string()))
    }

    fn invalidate_cached_resolution(&mut self) {
        self.resolver.invalidate_snapshot();
    }
}

use attribution::ProcfsSocketResolver;
use capture::{
    CaptureError, EbpfResolvedSocketFlow, EbpfSocketFlowLookup, EbpfSocketFlowResolver,
    ProcessResolver, ResolvedProcess,
};
use probe_core::{CapabilityKind, ProcessContext, RuntimeMode, TcpConnection, TcpEndpoint};
use runtime::RuntimePlan;

pub(super) fn procfs_tcp_process_resolver_for_plan(
    plan: &RuntimePlan,
) -> Option<Box<dyn ProcessResolver>> {
    (plan
        .capabilities
        .mode(CapabilityKind::ProcfsSocketAttribution)
        != RuntimeMode::Unavailable)
        .then(|| Box::<ProcfsTcpProcessResolver>::default() as Box<dyn ProcessResolver>)
}

pub(super) struct ProcfsTcpProcessResolver {
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

    fn resolve_tcp_listener(
        &mut self,
        local_endpoint: TcpEndpoint,
    ) -> Result<Option<ResolvedProcess>, CaptureError> {
        self.resolver
            .resolve_tcp_listeners_by_local_endpoint(local_endpoint)
            .map(|lookup| {
                let [listener] = lookup.listeners.as_slice() else {
                    return None;
                };
                Some(ResolvedProcess {
                    process: listener.owner.process.clone(),
                    confidence: listener.owner.confidence,
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

    fn resolve_process(&mut self, tgid: u32) -> Result<Option<ProcessContext>, CaptureError> {
        self.resolver
            .resolve_process(tgid)
            .map_err(|error| CaptureError::provider("procfs_socket_attribution", error.to_string()))
    }

    fn invalidate_cached_resolution(&mut self) {
        self.resolver.invalidate_snapshot();
    }
}

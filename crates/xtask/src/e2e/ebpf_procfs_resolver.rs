use attribution::{ProcfsSocketResolver, SocketFdLookup, SocketProcessHint};
use capture::{CaptureError, EbpfResolvedSocketFlow, EbpfSocketFlowLookup, EbpfSocketFlowResolver};

pub(crate) struct ProcfsEbpfFlowResolver {
    resolver: ProcfsSocketResolver,
}

impl Default for ProcfsEbpfFlowResolver {
    fn default() -> Self {
        Self {
            resolver: ProcfsSocketResolver::new(),
        }
    }
}

impl EbpfSocketFlowResolver for ProcfsEbpfFlowResolver {
    fn resolve_socket_flow(
        &mut self,
        lookup: EbpfSocketFlowLookup,
    ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
        self.resolver
            .resolve_tcp_fd(SocketFdLookup {
                tgid: lookup.tgid,
                thread_pid: lookup.thread_pid,
                fd: lookup.fd,
                expected_remote_endpoint: lookup.expected_remote_endpoint,
                process_hint: lookup.process_hint.map(|hint| SocketProcessHint {
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

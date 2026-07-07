use attribution::{ProcfsSocketResolver, TcpListenerProcessLookup};
use capture::{
    CaptureError, EbpfProcessHint, EbpfResolvedSocketFlow, EbpfSocketFlowLookup,
    EbpfSocketFlowResolver, ProcessResolver, ResolvedProcess,
};
use probe_core::{CapabilityKind, ProcessContext, RuntimeMode, TcpConnection, TcpEndpoint};
use runtime::RuntimePlan;

// This is intentionally below direct procfs and hinted-fd attribution confidence, but above
// synthetic unknown-process attribution. It is only used for libpcap passive observation when the
// attributed listener owners agree and some matching listener sockets remain unattributed.
const LIBPCAP_UNATTRIBUTED_LISTENER_CONFIDENCE_CAP: u8 = 35;

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
            .map(libpcap_best_effort_unique_attributed_listener_owner)
            .map_err(|error| CaptureError::provider("procfs_socket_attribution", error.to_string()))
    }

    fn resolve_unique_tcp_listener_owner_by_port(
        &mut self,
        local_port: u16,
    ) -> Result<Option<ResolvedProcess>, CaptureError> {
        self.resolver
            .resolve_tcp_listeners_by_local_port(local_port)
            .map(libpcap_best_effort_unique_attributed_listener_owner)
            .map_err(|error| CaptureError::provider("procfs_socket_attribution", error.to_string()))
    }

    fn invalidate_cached_resolution(&mut self) {
        self.resolver.invalidate_snapshot();
    }
}

fn libpcap_best_effort_unique_attributed_listener_owner(
    lookup: TcpListenerProcessLookup,
) -> Option<ResolvedProcess> {
    let has_unattributed_listeners = !lookup.unattributed_listeners.is_empty();

    let mut listeners = lookup.listeners.into_iter();
    let first = listeners.next()?;
    let mut confidence = first.owner.confidence;
    for listener in listeners {
        if listener.owner.process.identity != first.owner.process.identity {
            return None;
        }
        confidence = confidence.min(listener.owner.confidence);
    }
    if has_unattributed_listeners {
        confidence = confidence.min(LIBPCAP_UNATTRIBUTED_LISTENER_CONFIDENCE_CAP);
    }
    Some(ResolvedProcess {
        process: first.owner.process,
        confidence,
    })
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

    fn resolve_processes_by_hint(
        &mut self,
        hint: EbpfProcessHint,
    ) -> Result<Vec<ProcessContext>, CaptureError> {
        self.resolver
            .resolve_processes_by_hint(attribution::SocketProcessHint {
                name: hint.name,
                uid: hint.uid,
                gid: hint.gid,
            })
            .map_err(|error| CaptureError::provider("procfs_socket_attribution", error.to_string()))
    }

    fn invalidate_cached_resolution(&mut self) {
        self.resolver.invalidate_snapshot();
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use attribution::{
        TcpListenerObservedSocket, TcpListenerOwnerContext, TcpListenerOwnerSource,
        TcpListenerProcessContext, TcpUnattributedListener,
    };
    use probe_core::ProcessIdentity;

    use super::*;

    #[test]
    fn libpcap_listener_owner_accepts_multiple_observed_listeners_for_same_owner() {
        let owner = process(321, "backend");
        let lookup = TcpListenerProcessLookup {
            listeners: vec![
                listener(123, "docker-proxy-v4", owner.clone(), 60, 8081),
                listener(124, "docker-proxy-v6", owner.clone(), 55, 8081),
            ],
            unattributed_listeners: Vec::new(),
        };

        let resolved = libpcap_best_effort_unique_attributed_listener_owner(lookup)
            .expect("owner should be unique");

        assert_eq!(resolved.process.identity.pid, 321);
        assert_eq!(resolved.process.name, "backend");
        assert_eq!(resolved.confidence, 55);
    }

    #[test]
    fn libpcap_listener_owner_rejects_ambiguous_owners() {
        let lookup = TcpListenerProcessLookup {
            listeners: vec![
                listener(123, "first-proxy", process(321, "first-backend"), 60, 8081),
                listener(
                    124,
                    "second-proxy",
                    process(654, "second-backend"),
                    60,
                    8081,
                ),
            ],
            unattributed_listeners: Vec::new(),
        };

        assert!(libpcap_best_effort_unique_attributed_listener_owner(lookup).is_none());
    }

    #[test]
    fn libpcap_listener_owner_degrades_when_unknown_listener_inodes_are_present() {
        let owner = process(321, "backend");
        let lookup = TcpListenerProcessLookup {
            listeners: vec![
                listener(123, "docker-proxy-v4", owner.clone(), 60, 8081),
                listener(124, "docker-proxy-v6", owner, 55, 8081),
            ],
            unattributed_listeners: vec![TcpUnattributedListener {
                socket_inode: 999,
                local: TcpEndpoint::new(Ipv4Addr::UNSPECIFIED.into(), 8081),
            }],
        };

        let resolved = libpcap_best_effort_unique_attributed_listener_owner(lookup)
            .expect("unique owner should resolve");

        assert_eq!(resolved.process.identity.pid, 321);
        assert_eq!(resolved.process.name, "backend");
        assert_eq!(
            resolved.confidence,
            LIBPCAP_UNATTRIBUTED_LISTENER_CONFIDENCE_CAP
        );
    }

    #[test]
    fn libpcap_listener_owner_rejects_only_unknown_listener_inodes() {
        let lookup = TcpListenerProcessLookup {
            listeners: Vec::new(),
            unattributed_listeners: vec![TcpUnattributedListener {
                socket_inode: 999,
                local: TcpEndpoint::new(Ipv4Addr::UNSPECIFIED.into(), 8081),
            }],
        };

        assert!(libpcap_best_effort_unique_attributed_listener_owner(lookup).is_none());
    }

    fn listener(
        observed_pid: u32,
        observed_name: &str,
        owner: ProcessContext,
        owner_confidence: u8,
        port: u16,
    ) -> TcpListenerProcessContext {
        let observed = TcpListenerObservedSocket {
            process: process(observed_pid, observed_name),
            confidence: 60,
            socket_inode: observed_pid as u64,
            local: TcpEndpoint::new(Ipv4Addr::UNSPECIFIED.into(), port),
        };
        TcpListenerProcessContext {
            observed,
            owner: TcpListenerOwnerContext {
                process: owner,
                confidence: owner_confidence,
                source: TcpListenerOwnerSource::SocketHolder,
            },
        }
    }

    fn process(pid: u32, name: &str) -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid,
                tgid: pid,
                start_time_ticks: pid as u64,
                boot_id: "boot".to_string(),
                exe_path: format!("/usr/bin/{name}"),
                cmdline_hash: format!("{name}-hash"),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: name.to_string(),
            cmdline: vec![name.to_string()],
        }
    }
}

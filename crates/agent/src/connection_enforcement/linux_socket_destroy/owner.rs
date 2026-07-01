use attribution::{AttributionError, ProcfsSocketResolver, SocketProcessContext};
use probe_core::{EventEnvelope, ProcessIdentity, TcpConnection};

pub(super) trait FlowOwnerVerifier {
    fn verify(&mut self, event: &EventEnvelope, connection: TcpConnection)
    -> FlowOwnerVerification;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FlowOwnerVerification {
    Matched { socket_inode: u64, confidence: u8 },
    Unsupported { reason: String },
}

impl FlowOwnerVerification {
    pub(super) fn unsupported(reason: impl Into<String>) -> Self {
        Self::Unsupported {
            reason: reason.into(),
        }
    }
}

#[derive(Debug)]
pub(super) struct ProcfsFlowOwnerVerifier<R = ProcfsSocketOwnerResolver> {
    resolver: R,
}

impl Default for ProcfsFlowOwnerVerifier {
    fn default() -> Self {
        Self {
            resolver: ProcfsSocketOwnerResolver::default(),
        }
    }
}

#[cfg(test)]
impl<R> ProcfsFlowOwnerVerifier<R> {
    fn new(resolver: R) -> Self {
        Self { resolver }
    }
}

impl<R> FlowOwnerVerifier for ProcfsFlowOwnerVerifier<R>
where
    R: CurrentSocketOwnerResolver,
{
    fn verify(
        &mut self,
        event: &EventEnvelope,
        connection: TcpConnection,
    ) -> FlowOwnerVerification {
        let Some(flow) = event.flow() else {
            return FlowOwnerVerification::unsupported(
                "procfs owner verification requires a flow-scoped trigger event",
            );
        };

        self.resolver.invalidate_current_owner_snapshot();
        let resolved = match self.resolver.resolve_current_owner(connection) {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                return FlowOwnerVerification::unsupported(format!(
                    "procfs owner verification could not find a current socket owner for flow {}",
                    flow.id.0
                ));
            }
            Err(error) => {
                return FlowOwnerVerification::unsupported(format!(
                    "procfs owner verification failed for flow {}: {error}",
                    flow.id.0
                ));
            }
        };

        if same_process_identity(&flow.process.identity, &resolved.process.identity) {
            FlowOwnerVerification::Matched {
                socket_inode: resolved.socket_inode,
                confidence: resolved.confidence,
            }
        } else {
            FlowOwnerVerification::unsupported(format!(
                "procfs owner verification rejected flow {} because current socket owner {} does not match trigger process {}",
                flow.id.0,
                process_identity_summary(&resolved.process.identity),
                process_identity_summary(&flow.process.identity),
            ))
        }
    }
}

trait CurrentSocketOwnerResolver {
    fn invalidate_current_owner_snapshot(&mut self);

    fn resolve_current_owner(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<SocketProcessContext>, AttributionError>;
}

#[derive(Debug, Default)]
pub(super) struct ProcfsSocketOwnerResolver {
    resolver: ProcfsSocketResolver,
}

impl CurrentSocketOwnerResolver for ProcfsSocketOwnerResolver {
    fn invalidate_current_owner_snapshot(&mut self) {
        self.resolver.invalidate_snapshot();
    }

    fn resolve_current_owner(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<SocketProcessContext>, AttributionError> {
        self.resolver.resolve_tcp_connection(connection)
    }
}

fn same_process_identity(expected: &ProcessIdentity, observed: &ProcessIdentity) -> bool {
    expected.tgid == observed.tgid && expected.stable_key() == observed.stable_key()
}

fn process_identity_summary(identity: &ProcessIdentity) -> String {
    format!(
        "pid={} tgid={} start_time_ticks={} boot_id={} exe_path={}",
        identity.pid, identity.tgid, identity.start_time_ticks, identity.boot_id, identity.exe_path
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
    };

    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EventKind, FlowContext, FlowIdentity,
        OpaqueStream, ProcessContext, TcpEndpoint, Timestamp, TransportProtocol,
    };

    use super::*;

    #[test]
    fn procfs_owner_verifier_matches_current_socket_owner() {
        let event = event_with_process(process_context(42, 42, 7, "/usr/bin/app", "hash"));
        let resolver = FakeSocketOwnerResolver::with_results([Ok(Some(socket_owner(
            event
                .flow()
                .expect("test event is flow scoped")
                .process
                .clone(),
            123,
            60,
        )))]);
        let mut verifier = ProcfsFlowOwnerVerifier::new(resolver.clone());

        let result = verifier.verify(&event, tcp_connection_from_event(&event));

        assert_eq!(
            result,
            FlowOwnerVerification::Matched {
                socket_inode: 123,
                confidence: 60,
            }
        );
        assert_eq!(
            resolver.requested_connections(),
            vec![TcpConnection::new(
                TcpEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41000),
                TcpEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            )]
        );
        assert_eq!(resolver.invalidate_count(), 1);
    }

    #[test]
    fn procfs_owner_verifier_rejects_current_socket_owner_mismatch() {
        let event = event_with_process(process_context(42, 42, 7, "/usr/bin/app", "hash"));
        let resolver = FakeSocketOwnerResolver::with_results([Ok(Some(socket_owner(
            process_context(42, 42, 8, "/usr/bin/app", "hash"),
            123,
            60,
        )))]);
        let mut verifier = ProcfsFlowOwnerVerifier::new(resolver.clone());

        let result = verifier.verify(&event, tcp_connection_from_event(&event));

        assert!(matches!(
            result,
            FlowOwnerVerification::Unsupported { reason } if reason.contains("does not match trigger process")
        ));
        assert_eq!(resolver.invalidate_count(), 1);
    }

    #[test]
    fn procfs_owner_verifier_reports_resolver_errors_as_unsupported() {
        let event = event_with_process(process_context(42, 42, 7, "/usr/bin/app", "hash"));
        let resolver = FakeSocketOwnerResolver::with_results([Err(AttributionError::Read {
            path: "/proc/net/tcp".to_string(),
            source: io::Error::other("boom"),
        })]);
        let mut verifier = ProcfsFlowOwnerVerifier::new(resolver.clone());

        let result = verifier.verify(&event, tcp_connection_from_event(&event));

        assert!(matches!(
            result,
            FlowOwnerVerification::Unsupported { reason }
                if reason.contains("procfs owner verification failed")
                    && reason.contains("/proc/net/tcp")
        ));
        assert_eq!(resolver.invalidate_count(), 1);
    }

    #[derive(Clone)]
    struct FakeSocketOwnerResolver {
        state: Arc<Mutex<FakeSocketOwnerResolverState>>,
    }

    struct FakeSocketOwnerResolverState {
        invalidate_count: usize,
        requested_connections: Vec<TcpConnection>,
        results: VecDeque<Result<Option<SocketProcessContext>, AttributionError>>,
    }

    impl FakeSocketOwnerResolver {
        fn with_results(
            results: impl IntoIterator<Item = Result<Option<SocketProcessContext>, AttributionError>>,
        ) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeSocketOwnerResolverState {
                    invalidate_count: 0,
                    requested_connections: Vec::new(),
                    results: results.into_iter().collect(),
                })),
            }
        }

        fn invalidate_count(&self) -> usize {
            self.state
                .lock()
                .expect("fake owner resolver state poisoned")
                .invalidate_count
        }

        fn requested_connections(&self) -> Vec<TcpConnection> {
            self.state
                .lock()
                .expect("fake owner resolver state poisoned")
                .requested_connections
                .clone()
        }
    }

    impl CurrentSocketOwnerResolver for FakeSocketOwnerResolver {
        fn invalidate_current_owner_snapshot(&mut self) {
            self.state
                .lock()
                .expect("fake owner resolver state poisoned")
                .invalidate_count += 1;
        }

        fn resolve_current_owner(
            &mut self,
            connection: TcpConnection,
        ) -> Result<Option<SocketProcessContext>, AttributionError> {
            let mut state = self
                .state
                .lock()
                .expect("fake owner resolver state poisoned");
            state.requested_connections.push(connection);
            state
                .results
                .pop_front()
                .unwrap_or_else(|| panic!("missing fake socket owner result"))
        }
    }

    fn socket_owner(
        process: ProcessContext,
        socket_inode: u64,
        confidence: u8,
    ) -> SocketProcessContext {
        SocketProcessContext {
            process,
            confidence,
            socket_inode,
        }
    }

    fn event_with_process(process: ProcessContext) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            FlowContext {
                id: FlowIdentity("flow-1".to_string()),
                process,
                local: AddressPort {
                    address: "127.0.0.1".to_string(),
                    port: 41000,
                },
                remote: AddressPort {
                    address: "127.0.0.1".to_string(),
                    port: 8080,
                },
                protocol: TransportProtocol::Tcp,
                start_monotonic_ns: 1,
                socket_cookie: None,
                attribution_confidence: 100,
            },
            CaptureOrigin::from_source(CaptureSource::Libpcap),
            "test-config",
            EventKind::OpaqueStream(OpaqueStream {
                direction: Direction::Outbound,
                fingerprint: Vec::new(),
                reason: "test".to_string(),
            }),
        )
    }

    fn tcp_connection_from_event(event: &EventEnvelope) -> TcpConnection {
        TcpConnection::from_flow_context(event.flow().expect("test event is flow scoped"))
            .expect("test event should have a TCP flow")
    }

    fn process_identity(
        pid: u32,
        tgid: u32,
        start_time_ticks: u64,
        exe_path: &str,
        cmdline_hash: &str,
    ) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            tgid,
            start_time_ticks,
            boot_id: "boot".to_string(),
            exe_path: exe_path.to_string(),
            cmdline_hash: cmdline_hash.to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        }
    }

    fn process_context(
        pid: u32,
        tgid: u32,
        start_time_ticks: u64,
        exe_path: &str,
        cmdline_hash: &str,
    ) -> ProcessContext {
        ProcessContext {
            identity: process_identity(pid, tgid, start_time_ticks, exe_path, cmdline_hash),
            name: "app".to_string(),
            cmdline: vec!["app".to_string()],
        }
    }
}

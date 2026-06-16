use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use probe_core::{
    AddressPort, CaptureSource, Direction, FlowContext, FlowIdentity, Gap, ProcessContext,
    ProcessIdentity, TcpConnection, TcpEndpoint, Timestamp, TransportProtocol,
};

use crate::{CaptureError, CaptureEvent, CaptureProviderKind, CapturedGap};

use super::{EbpfConnectTracepointObservation, EbpfObservedProcess};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfConnectFlowLookup {
    pub tgid: u32,
    pub thread_pid: u32,
    pub fd: i32,
    pub expected_remote_endpoint: Option<TcpEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfResolvedConnectFlow {
    pub process: ProcessContext,
    pub confidence: u8,
    pub connection: TcpConnection,
}

pub trait EbpfConnectFlowResolver {
    fn resolve_connect_flow(
        &mut self,
        lookup: EbpfConnectFlowLookup,
    ) -> Result<Option<EbpfResolvedConnectFlow>, CaptureError>;

    fn invalidate_cached_resolution(&mut self) {}
}

pub(crate) fn connect_opened_event_from_observation(
    connect: &EbpfConnectTracepointObservation,
    timestamp: Timestamp,
    resolver: &mut dyn EbpfConnectFlowResolver,
) -> Result<Option<CaptureEvent>, CaptureError> {
    let resolved = resolver.resolve_connect_flow(EbpfConnectFlowLookup {
        tgid: connect.process.tgid,
        thread_pid: connect.process.pid,
        fd: connect.fd,
        expected_remote_endpoint: connect.endpoint.remote_endpoint(),
    })?;
    Ok(resolved.map(|resolved| CaptureEvent::ConnectionOpened {
        timestamp,
        flow: flow_from_resolved_connect(resolved, timestamp.monotonic_ns),
        source: CaptureSource::EbpfSyscall,
        provider: CaptureProviderKind::Ebpf,
    }))
}

pub(crate) fn unresolved_connect_gap_from_observation(
    connect: &EbpfConnectTracepointObservation,
    timestamp: Timestamp,
    reason: String,
) -> CaptureEvent {
    let process = process_context_from_observed(&connect.process);
    let remote = connect
        .endpoint
        .remote_endpoint()
        .unwrap_or_else(unknown_tcp_endpoint);
    let local = unknown_local_endpoint_for_remote(remote);
    let flow = flow_from_unresolved_connect(process, local, remote, timestamp.monotonic_ns);
    CaptureEvent::Gap(CapturedGap {
        timestamp,
        flow,
        source: CaptureSource::EbpfSyscall,
        provider: CaptureProviderKind::Ebpf,
        gap: Gap {
            direction: Direction::Outbound,
            expected_offset: 0,
            next_offset: None,
            reason,
        },
    })
}

fn flow_from_resolved_connect(
    resolved: EbpfResolvedConnectFlow,
    start_monotonic_ns: u64,
) -> FlowContext {
    let local = AddressPort::from(resolved.connection.local);
    let remote = AddressPort::from(resolved.connection.remote);
    FlowContext {
        id: FlowIdentity::stable(
            &resolved.process.identity,
            &local,
            &remote,
            TransportProtocol::Tcp,
            start_monotonic_ns,
            None,
        ),
        process: resolved.process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns,
        socket_cookie: None,
        attribution_confidence: resolved.confidence,
    }
}

fn flow_from_unresolved_connect(
    process: ProcessContext,
    local_endpoint: TcpEndpoint,
    remote_endpoint: TcpEndpoint,
    start_monotonic_ns: u64,
) -> FlowContext {
    let local = AddressPort::from(local_endpoint);
    let remote = AddressPort::from(remote_endpoint);
    FlowContext {
        id: FlowIdentity::stable(
            &process.identity,
            &local,
            &remote,
            TransportProtocol::Tcp,
            start_monotonic_ns,
            None,
        ),
        process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns,
        socket_cookie: None,
        attribution_confidence: 0,
    }
}

fn process_context_from_observed(process: &EbpfObservedProcess) -> ProcessContext {
    let name = process.command_lossy();
    let name = if name.is_empty() {
        "unknown".to_string()
    } else {
        name
    };
    ProcessContext {
        identity: ProcessIdentity {
            pid: process.tgid,
            tgid: process.tgid,
            start_time_ticks: 0,
            boot_id: String::new(),
            exe_path: String::new(),
            cmdline_hash: String::new(),
            uid: process.uid,
            gid: process.gid,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        },
        name: name.clone(),
        cmdline: vec![name],
    }
}

fn unknown_local_endpoint_for_remote(remote: TcpEndpoint) -> TcpEndpoint {
    let address = match remote.address {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    TcpEndpoint::new(address, 0)
}

fn unknown_tcp_endpoint() -> TcpEndpoint {
    TcpEndpoint::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use probe_core::{ProcessIdentity, TcpEndpoint};

    use crate::ebpf::{EbpfConnectEndpoint, EbpfConnectTracepointObservation, EbpfObservedProcess};

    use super::*;

    #[test]
    fn connect_observation_builds_connection_opened_event_from_fd_resolution()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected_remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let observation = EbpfConnectTracepointObservation {
            process: EbpfObservedProcess {
                pid: 101,
                tgid: 100,
                uid: 1000,
                gid: 1000,
                command: [0; 16],
            },
            fd: 7,
            addrlen: 16,
            fd_table_epoch: 0,
            endpoint: EbpfConnectEndpoint::Remote(expected_remote),
        };
        let mut resolver = ExpectedConnectResolver {
            expected: EbpfConnectFlowLookup {
                tgid: 100,
                thread_pid: 101,
                fd: 7,
                expected_remote_endpoint: Some(expected_remote),
            },
            seen: false,
            resolved: Some(EbpfResolvedConnectFlow {
                process: demo_process(),
                confidence: 80,
                connection: TcpConnection::new(
                    TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000),
                    expected_remote,
                ),
            }),
        };

        let event = connect_opened_event_from_observation(
            &observation,
            Timestamp {
                monotonic_ns: 42,
                wall_time_unix_ns: 99,
            },
            &mut resolver,
        )?
        .expect("expected connection opened event");

        assert!(resolver.seen);
        match event {
            CaptureEvent::ConnectionOpened {
                timestamp,
                flow,
                source,
                provider,
            } => {
                assert_eq!(timestamp.monotonic_ns, 42);
                assert_eq!(source, CaptureSource::EbpfSyscall);
                assert_eq!(provider, CaptureProviderKind::Ebpf);
                assert_eq!(flow.process.identity.pid, 100);
                assert_eq!(flow.local.port, 50_000);
                assert_eq!(flow.remote.port, 443);
                assert_eq!(flow.attribution_confidence, 80);
            }
            event => panic!("unexpected event: {event:?}"),
        }
        Ok(())
    }

    #[test]
    fn connect_observation_without_fd_resolution_yields_no_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let observation = EbpfConnectTracepointObservation {
            process: EbpfObservedProcess {
                pid: 101,
                tgid: 100,
                uid: 1000,
                gid: 1000,
                command: [0; 16],
            },
            fd: 7,
            addrlen: 0,
            fd_table_epoch: 0,
            endpoint: EbpfConnectEndpoint::SockaddrReadFailed,
        };
        let mut resolver = ExpectedConnectResolver {
            expected: EbpfConnectFlowLookup {
                tgid: 100,
                thread_pid: 101,
                fd: 7,
                expected_remote_endpoint: None,
            },
            seen: false,
            resolved: None,
        };

        let event = connect_opened_event_from_observation(
            &observation,
            Timestamp {
                monotonic_ns: 42,
                wall_time_unix_ns: 99,
            },
            &mut resolver,
        )?;

        assert!(event.is_none());
        assert!(resolver.seen);
        Ok(())
    }

    struct ExpectedConnectResolver {
        expected: EbpfConnectFlowLookup,
        seen: bool,
        resolved: Option<EbpfResolvedConnectFlow>,
    }

    impl EbpfConnectFlowResolver for ExpectedConnectResolver {
        fn resolve_connect_flow(
            &mut self,
            lookup: EbpfConnectFlowLookup,
        ) -> Result<Option<EbpfResolvedConnectFlow>, CaptureError> {
            assert_eq!(lookup, self.expected);
            self.seen = true;
            Ok(self.resolved.clone())
        }
    }

    fn demo_process() -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid: 100,
                tgid: 100,
                start_time_ticks: 1234,
                boot_id: "boot".to_string(),
                exe_path: "/usr/bin/curl".to_string(),
                cmdline_hash: "cmd".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "curl".to_string(),
            cmdline: vec!["curl".to_string()],
        }
    }
}

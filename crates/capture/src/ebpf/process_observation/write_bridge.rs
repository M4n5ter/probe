use bytes::Bytes;
use probe_core::{CaptureSource, Direction, FlowContext, Gap, Timestamp};

use crate::{CaptureEvent, CaptureProviderKind, CapturedBytes, CapturedGap};

use super::{EbpfSocketWriteObservation, tracked_flow::TrackedEbpfFlows};

pub(super) fn write_events(
    tracked_flows: &mut TrackedEbpfFlows,
    write: &EbpfSocketWriteObservation,
    timestamp: Timestamp,
) -> Vec<CaptureEvent> {
    let Some(tracked) = tracked_flows.get_write_mut(write) else {
        return Vec::new();
    };
    let start = tracked.outbound_stream_offset;
    let end = start.saturating_add(u64::from(write.original_len));
    if write.read_failed {
        tracked.outbound_stream_offset = end;
        return vec![ebpf_write_gap(
            timestamp,
            tracked.flow.clone(),
            start,
            Some(end),
            "eBPF write sample could not read userspace payload buffer".to_string(),
        )];
    }
    let captured_bytes = write.buffer.as_slice();
    let captured_len = captured_bytes.len() as u64;
    let mut events = Vec::new();
    if !captured_bytes.is_empty() {
        events.push(CaptureEvent::Bytes(CapturedBytes {
            timestamp,
            flow: tracked.flow.clone(),
            source: CaptureSource::EbpfSyscall,
            provider: CaptureProviderKind::Ebpf,
            direction: Direction::Outbound,
            stream_offset: start,
            bytes: Bytes::copy_from_slice(captured_bytes),
            attribution_confidence: tracked.flow.attribution_confidence,
            degraded: write.truncated,
            degradation_reason: write.truncated.then(|| {
                format!(
                    "eBPF write sample truncated payload: captured {} of {} byte(s)",
                    captured_len, write.original_len
                )
            }),
        }));
    }
    if write.truncated && captured_len < u64::from(write.original_len) {
        events.push(ebpf_write_gap(
            timestamp,
            tracked.flow.clone(),
            start.saturating_add(captured_len),
            Some(end),
            format!(
                "eBPF write sample truncated payload after {} of {} byte(s)",
                captured_len, write.original_len
            ),
        ));
    }
    if events.is_empty() {
        events.push(ebpf_write_gap(
            timestamp,
            tracked.flow.clone(),
            start,
            Some(end),
            "eBPF write sample did not contain captured payload bytes".to_string(),
        ));
    }
    tracked.outbound_stream_offset = end;
    events
}

fn ebpf_write_gap(
    timestamp: Timestamp,
    flow: FlowContext,
    expected_offset: u64,
    next_offset: Option<u64>,
    reason: String,
) -> CaptureEvent {
    CaptureEvent::Gap(CapturedGap {
        timestamp,
        flow,
        source: CaptureSource::EbpfSyscall,
        provider: CaptureProviderKind::Ebpf,
        gap: Gap {
            direction: Direction::Outbound,
            expected_offset,
            next_offset,
            reason,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use probe_core::{
        AddressPort, FlowIdentity, ProcessContext, ProcessIdentity, TcpEndpoint, TransportProtocol,
    };

    use super::super::{
        EbpfConnectEndpoint, EbpfConnectTracepointObservation, EbpfObservedProcess,
    };
    use super::*;

    #[test]
    fn write_bridge_emits_bytes_for_tracked_payload() {
        let mut tracked = tracked_flow(7);
        let events = write_events(
            &mut tracked,
            &write_observation(7, 5, b"GET /", false, false),
            timestamp(1),
        );

        let [CaptureEvent::Bytes(bytes)] = events.as_slice() else {
            panic!("expected a single bytes event: {events:?}");
        };
        assert_eq!(bytes.flow.id, flow("flow-7").id);
        assert_eq!(bytes.source, CaptureSource::EbpfSyscall);
        assert_eq!(bytes.provider, CaptureProviderKind::Ebpf);
        assert_eq!(bytes.direction, Direction::Outbound);
        assert_eq!(bytes.stream_offset, 0);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        assert_eq!(bytes.attribution_confidence, 90);
        assert!(!bytes.degraded);
        assert!(bytes.degradation_reason.is_none());
    }

    #[test]
    fn write_bridge_emits_gap_for_truncated_payload_suffix() {
        let mut tracked = tracked_flow(7);
        let events = write_events(
            &mut tracked,
            &write_observation(7, 10, b"GET /", true, false),
            timestamp(1),
        );

        let [CaptureEvent::Bytes(bytes), CaptureEvent::Gap(gap)] = events.as_slice() else {
            panic!("expected bytes plus gap: {events:?}");
        };
        assert_eq!(bytes.stream_offset, 0);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        assert!(bytes.degraded);
        assert!(
            bytes
                .degradation_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("captured 5 of 10"))
        );
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 5);
        assert_eq!(gap.gap.next_offset, Some(10));
        assert!(gap.gap.reason.contains("truncated payload"));
    }

    #[test]
    fn write_bridge_emits_gap_for_failed_payload_read() {
        let mut tracked = tracked_flow(7);
        let events = write_events(
            &mut tracked,
            &write_observation(7, 5, b"", false, true),
            timestamp(1),
        );

        let [CaptureEvent::Gap(gap)] = events.as_slice() else {
            panic!("expected a single gap event: {events:?}");
        };
        assert_eq!(gap.timestamp.monotonic_ns, 1);
        assert_eq!(gap.source, CaptureSource::EbpfSyscall);
        assert_eq!(gap.provider, CaptureProviderKind::Ebpf);
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 0);
        assert_eq!(gap.gap.next_offset, Some(5));
        assert!(gap.gap.reason.contains("could not read"));
    }

    #[test]
    fn write_bridge_ignores_untracked_write() {
        let mut tracked = TrackedEbpfFlows::bounded(8);
        let events = write_events(
            &mut tracked,
            &write_observation(7, 5, b"GET /", false, false),
            timestamp(1),
        );

        assert!(events.is_empty());
    }

    fn tracked_flow(fd: i32) -> TrackedEbpfFlows {
        let mut tracked = TrackedEbpfFlows::bounded(8);
        tracked.insert_connect(&connect_observation(fd), flow(&format!("flow-{fd}")));
        tracked
    }

    fn connect_observation(fd: i32) -> EbpfConnectTracepointObservation {
        EbpfConnectTracepointObservation {
            process: observed_process(),
            fd,
            addrlen: 16,
            fd_table_epoch: 0,
            endpoint: EbpfConnectEndpoint::Remote(TcpEndpoint::new(
                Ipv4Addr::new(127, 0, 0, 1).into(),
                443,
            )),
        }
    }

    fn write_observation(
        fd: i32,
        original_len: u32,
        payload: &[u8],
        truncated: bool,
        read_failed: bool,
    ) -> EbpfSocketWriteObservation {
        EbpfSocketWriteObservation {
            process: observed_process(),
            fd,
            original_len,
            buffer: payload.to_vec(),
            truncated,
            read_failed,
        }
    }

    fn observed_process() -> EbpfObservedProcess {
        EbpfObservedProcess {
            pid: 101,
            tgid: 100,
            uid: 1000,
            gid: 1000,
            command: [0; 16],
        }
    }

    fn flow(id: &str) -> FlowContext {
        FlowContext {
            id: FlowIdentity(id.to_string()),
            process: ProcessContext {
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
            },
            local: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 50_000,
            },
            remote: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 443,
            },
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 90,
        }
    }

    fn timestamp(monotonic_ns: u64) -> Timestamp {
        Timestamp {
            monotonic_ns,
            wall_time_unix_ns: 0,
        }
    }
}

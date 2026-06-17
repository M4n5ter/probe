use bytes::Bytes;
use probe_core::{
    CaptureSource, Direction, EnforcementEvidence, FlowContext, Gap, ObservationOnlyReason,
    Timestamp,
};

use crate::{
    CaptureEvent, CaptureProviderKind, CapturedBytes, CapturedGap, EnforcementEvidencePropagation,
};

use super::{
    EbpfSocketReadObservation, EbpfSocketWriteObservation,
    tracked_flow::{TrackedEbpfFlow, TrackedEbpfFlows},
};

const EBPF_WRITE_ARGUMENT_SAMPLE_REASON: &str = "eBPF outbound syscall sample is an argument snapshot captured before the kernel copies bytes; contents are best-effort and may differ from bytes actually sent";
const EBPF_READ_RESULT_SAMPLE_REASON: &str = "eBPF inbound syscall sample is a result buffer snapshot captured after the kernel returns; contents are best-effort and may omit bytes when truncated";

pub(super) fn write_events(
    tracked_flows: &mut TrackedEbpfFlows,
    write: &EbpfSocketWriteObservation,
    timestamp: Timestamp,
) -> Vec<CaptureEvent> {
    let Some(tracked) = tracked_flows.get_write_mut(write) else {
        return Vec::new();
    };
    payload_events(
        tracked,
        PayloadSample {
            timestamp,
            direction: Direction::Outbound,
            original_len: write.original_len,
            buffer: write.buffer.as_slice(),
            truncated: write.truncated,
            read_failed: write.read_failed,
            base_reason: EBPF_WRITE_ARGUMENT_SAMPLE_REASON,
            read_failed_reason: "eBPF outbound syscall argument sample could not read userspace payload buffer",
            empty_reason: "eBPF outbound syscall sample did not contain captured payload bytes",
            truncated_prefix: "eBPF outbound syscall sample truncated payload",
        },
    )
}

pub(super) fn read_events(
    tracked_flows: &mut TrackedEbpfFlows,
    read: &EbpfSocketReadObservation,
    timestamp: Timestamp,
) -> Vec<CaptureEvent> {
    let Some(tracked) = tracked_flows.get_read_mut(read) else {
        return Vec::new();
    };
    payload_events(
        tracked,
        PayloadSample {
            timestamp,
            direction: Direction::Inbound,
            original_len: read.original_len,
            buffer: read.buffer.as_slice(),
            truncated: read.truncated,
            read_failed: read.read_failed,
            base_reason: EBPF_READ_RESULT_SAMPLE_REASON,
            read_failed_reason: "eBPF inbound syscall result sample could not read userspace payload buffer",
            empty_reason: "eBPF inbound syscall sample did not contain captured payload bytes",
            truncated_prefix: "eBPF inbound syscall sample truncated payload",
        },
    )
}

struct PayloadSample<'a> {
    timestamp: Timestamp,
    direction: Direction,
    original_len: u32,
    buffer: &'a [u8],
    truncated: bool,
    read_failed: bool,
    base_reason: &'static str,
    read_failed_reason: &'static str,
    empty_reason: &'static str,
    truncated_prefix: &'static str,
}

fn payload_events(tracked: &mut TrackedEbpfFlow, sample: PayloadSample<'_>) -> Vec<CaptureEvent> {
    let start = stream_offset(tracked, sample.direction);
    let end = start.saturating_add(u64::from(sample.original_len));
    if sample.read_failed {
        set_stream_offset(tracked, sample.direction, end);
        return vec![ebpf_payload_gap(
            sample.timestamp,
            tracked.flow.clone(),
            sample.direction,
            start,
            Some(end),
            sample.read_failed_reason.to_string(),
        )];
    }
    let captured_len = sample.buffer.len() as u64;
    let mut events = Vec::new();
    if !sample.buffer.is_empty() {
        let degradation_reason = payload_degradation_reason(&sample, captured_len);
        events.push(CaptureEvent::Bytes(CapturedBytes {
            timestamp: sample.timestamp,
            flow: tracked.flow.clone(),
            source: CaptureSource::EbpfSyscall,
            provider: CaptureProviderKind::Ebpf,
            direction: sample.direction,
            stream_offset: start,
            bytes: Bytes::copy_from_slice(sample.buffer),
            attribution_confidence: tracked.flow.attribution_confidence,
            degraded: true,
            degradation_reason: Some(degradation_reason.clone()),
            enforcement_evidence: EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                degradation_reason,
            ),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Flow,
        }));
    }
    if sample.truncated && captured_len < u64::from(sample.original_len) {
        events.push(ebpf_payload_gap(
            sample.timestamp,
            tracked.flow.clone(),
            sample.direction,
            start.saturating_add(captured_len),
            Some(end),
            format!(
                "{} after {} of {} byte(s)",
                sample.truncated_prefix, captured_len, sample.original_len
            ),
        ));
    }
    if events.is_empty() {
        events.push(ebpf_payload_gap(
            sample.timestamp,
            tracked.flow.clone(),
            sample.direction,
            start,
            Some(end),
            sample.empty_reason.to_string(),
        ));
    }
    set_stream_offset(tracked, sample.direction, end);
    events
}

fn stream_offset(tracked: &TrackedEbpfFlow, direction: Direction) -> u64 {
    match direction {
        Direction::Inbound => tracked.inbound_stream_offset,
        Direction::Outbound => tracked.outbound_stream_offset,
    }
}

fn set_stream_offset(tracked: &mut TrackedEbpfFlow, direction: Direction, offset: u64) {
    match direction {
        Direction::Inbound => tracked.inbound_stream_offset = offset,
        Direction::Outbound => tracked.outbound_stream_offset = offset,
    }
}

fn ebpf_payload_gap(
    timestamp: Timestamp,
    flow: FlowContext,
    direction: Direction,
    expected_offset: u64,
    next_offset: Option<u64>,
    reason: String,
) -> CaptureEvent {
    let enforcement_evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        reason.clone(),
    );
    CaptureEvent::Gap(CapturedGap {
        timestamp,
        flow,
        source: CaptureSource::EbpfSyscall,
        provider: CaptureProviderKind::Ebpf,
        enforcement_evidence,
        enforcement_evidence_propagation: EnforcementEvidencePropagation::Flow,
        gap: Gap {
            direction,
            expected_offset,
            next_offset,
            reason,
        },
    })
}

fn payload_degradation_reason(sample: &PayloadSample<'_>, captured_len: u64) -> String {
    if sample.truncated {
        return format!(
            "{}; truncated payload: captured {} of {} byte(s)",
            sample.base_reason, captured_len, sample.original_len
        );
    }
    sample.base_reason.to_string()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use probe_core::{
        AddressPort, FlowIdentity, ProcessContext, ProcessIdentity, TcpEndpoint, TransportProtocol,
    };

    use super::super::{
        EbpfConnectEndpoint, EbpfConnectTracepointObservation, EbpfObservedProcess,
        payload_direction::PayloadDirections,
    };
    use super::*;

    #[test]
    fn payload_bridge_emits_outbound_bytes_for_tracked_write() {
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
        assert!(bytes.degraded);
        assert_outbound_argument_reason(
            bytes
                .degradation_reason
                .as_deref()
                .expect("outbound eBPF bytes must include degradation reason"),
        );
        assert!(
            bytes
                .enforcement_evidence
                .destructive_enforcement_rejection_reason()
                .is_some_and(|reason| reason.contains("syscall payload snapshot"))
        );
    }

    #[test]
    fn payload_bridge_emits_inbound_bytes_for_tracked_read() {
        let mut tracked = tracked_flow(7);
        let events = read_events(
            &mut tracked,
            &read_observation(7, 5, b"HTTP/", false, false),
            timestamp(1),
        );

        let [CaptureEvent::Bytes(bytes)] = events.as_slice() else {
            panic!("expected a single bytes event: {events:?}");
        };
        assert_eq!(bytes.flow.id, flow("flow-7").id);
        assert_eq!(bytes.source, CaptureSource::EbpfSyscall);
        assert_eq!(bytes.provider, CaptureProviderKind::Ebpf);
        assert_eq!(bytes.direction, Direction::Inbound);
        assert_eq!(bytes.stream_offset, 0);
        assert_eq!(bytes.bytes.as_ref(), b"HTTP/");
        assert_eq!(bytes.attribution_confidence, 90);
        assert!(bytes.degraded);
        assert_inbound_result_reason(
            bytes
                .degradation_reason
                .as_deref()
                .expect("inbound eBPF bytes must include degradation reason"),
        );
        assert!(
            bytes
                .enforcement_evidence
                .destructive_enforcement_rejection_reason()
                .is_some_and(|reason| reason.contains("syscall payload snapshot"))
        );
    }

    #[test]
    fn payload_bridge_keeps_independent_offsets_by_direction() {
        let mut tracked = tracked_flow(7);
        let write = write_events(
            &mut tracked,
            &write_observation(7, 5, b"GET /", false, false),
            timestamp(1),
        );
        let read = read_events(
            &mut tracked,
            &read_observation(7, 5, b"HTTP/", false, false),
            timestamp(2),
        );

        let [CaptureEvent::Bytes(write)] = write.as_slice() else {
            panic!("expected outbound bytes: {write:?}");
        };
        let [CaptureEvent::Bytes(read)] = read.as_slice() else {
            panic!("expected inbound bytes: {read:?}");
        };
        assert_eq!(write.direction, Direction::Outbound);
        assert_eq!(write.stream_offset, 0);
        assert_eq!(read.direction, Direction::Inbound);
        assert_eq!(read.stream_offset, 0);
    }

    #[test]
    fn payload_bridge_emits_gap_for_truncated_payload_suffix() {
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
        let degradation_reason = bytes
            .degradation_reason
            .as_deref()
            .expect("truncated bytes must include degradation reason");
        assert_outbound_argument_reason(degradation_reason);
        assert!(degradation_reason.contains("captured 5 of 10"));
        assert!(
            bytes
                .enforcement_evidence
                .destructive_enforcement_rejection_reason()
                .is_some_and(|reason| reason.contains("syscall payload snapshot"))
        );
        assert!(matches!(
            &bytes.enforcement_evidence,
            EnforcementEvidence::ObservationOnly {
                detail: Some(detail),
                ..
            } if detail.contains("captured 5 of 10")
        ));
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 5);
        assert_eq!(gap.gap.next_offset, Some(10));
        assert!(gap.gap.reason.contains("truncated payload"));
    }

    #[test]
    fn payload_bridge_emits_gap_for_failed_payload_read() {
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
    fn payload_bridge_emits_gap_for_truncated_empty_payload() {
        let mut tracked = tracked_flow(7);
        let events = write_events(
            &mut tracked,
            &write_observation(7, 5, b"", true, false),
            timestamp(1),
        );

        let [CaptureEvent::Gap(gap)] = events.as_slice() else {
            panic!("expected a single gap event: {events:?}");
        };
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 0);
        assert_eq!(gap.gap.next_offset, Some(5));
        assert!(gap.gap.reason.contains("truncated payload"));
    }

    #[test]
    fn payload_bridge_ignores_untracked_payload() {
        let mut tracked = TrackedEbpfFlows::bounded(8);
        let events = write_events(
            &mut tracked,
            &write_observation(7, 5, b"GET /", false, false),
            timestamp(1),
        );

        assert!(events.is_empty());
    }

    #[test]
    fn payload_bridge_ignores_payload_from_unallowed_direction() {
        let mut tracked = tracked_flow_with_directions(
            7,
            PayloadDirections::from_directions([Direction::Outbound]),
        );
        let events = read_events(
            &mut tracked,
            &read_observation(7, 5, b"HTTP/", false, false),
            timestamp(1),
        );

        assert!(events.is_empty());
    }

    fn tracked_flow(fd: i32) -> TrackedEbpfFlows {
        tracked_flow_with_directions(
            fd,
            PayloadDirections::from_directions([Direction::Outbound, Direction::Inbound]),
        )
    }

    fn tracked_flow_with_directions(
        fd: i32,
        payload_directions: PayloadDirections,
    ) -> TrackedEbpfFlows {
        let mut tracked = TrackedEbpfFlows::bounded(8);
        tracked.insert_connect(
            &connect_observation(fd),
            flow(&format!("flow-{fd}")),
            payload_directions,
        );
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

    fn read_observation(
        fd: i32,
        original_len: u32,
        payload: &[u8],
        truncated: bool,
        read_failed: bool,
    ) -> EbpfSocketReadObservation {
        EbpfSocketReadObservation {
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

    fn assert_outbound_argument_reason(reason: &str) {
        assert!(reason.contains("outbound syscall sample"));
        assert!(reason.contains("before the kernel copies bytes"));
        assert!(reason.contains("best-effort"));
    }

    fn assert_inbound_result_reason(reason: &str) {
        assert!(reason.contains("inbound syscall sample"));
        assert!(reason.contains("after the kernel returns"));
        assert!(reason.contains("best-effort"));
    }
}

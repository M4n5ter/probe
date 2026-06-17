use capture::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CaptureProviderKind, CapturedBytes,
};
use probe_core::{
    AddressPort, CapabilityState, CaptureLoss, CaptureSource, Direction, EnforcementEvidence,
    EventEnvelope, FlowContext, FlowIdentity, Gap, ObservationOnlyReason, ProcessContext,
    ProcessIdentity, Timestamp, TransportProtocol,
};

pub(super) struct SequenceProvider {
    events: std::vec::IntoIter<CaptureEvent>,
}

impl SequenceProvider {
    pub(super) fn new(events: Vec<CaptureEvent>) -> Self {
        Self {
            events: events.into_iter(),
        }
    }
}

impl CaptureProvider for SequenceProvider {
    fn name(&self) -> &'static str {
        "sequence"
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Replay
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        Vec::new()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        Ok(self
            .events
            .next()
            .map(CapturePoll::event)
            .unwrap_or(CapturePoll::Finished))
    }
}

pub(super) fn captured_bytes(flow: FlowContext, bytes: &'static [u8]) -> CaptureEvent {
    captured_bytes_with_direction(flow, Direction::Outbound, bytes)
}

pub(super) fn observation_only_ebpf_syscall_bytes_with_direction(
    flow: FlowContext,
    direction: Direction,
    bytes: &'static [u8],
) -> CaptureEvent {
    let mut chunk = captured_bytes_chunk(flow, direction, bytes);
    chunk.source = CaptureSource::EbpfSyscall;
    chunk.provider = CaptureProviderKind::Ebpf;
    chunk.degraded = true;
    chunk.degradation_reason = Some("test eBPF syscall payload snapshot".to_string());
    chunk.enforcement_evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "test eBPF syscall payload snapshot",
    );
    chunk.enforcement_evidence_propagation = capture::EnforcementEvidencePropagation::Flow;
    CaptureEvent::Bytes(chunk)
}

pub(super) fn flow_carried_observation_only_ebpf_syscall_gap(flow: FlowContext) -> CaptureEvent {
    let reason = "test eBPF syscall gap";
    CaptureEvent::Gap(capture::CapturedGap {
        timestamp: Timestamp {
            monotonic_ns: 1,
            wall_time_unix_ns: 1,
        },
        flow,
        source: CaptureSource::EbpfSyscall,
        provider: CaptureProviderKind::Ebpf,
        enforcement_evidence: EnforcementEvidence::observation_only_with_detail(
            ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
            reason,
        ),
        enforcement_evidence_propagation: capture::EnforcementEvidencePropagation::Flow,
        gap: Gap {
            direction: Direction::Outbound,
            expected_offset: 0,
            next_offset: Some(5),
            reason: reason.to_string(),
        },
    })
}

pub(super) fn event_local_observation_only_ebpf_unresolved_gap(flow: FlowContext) -> CaptureEvent {
    let reason = "test eBPF unresolved flow gap";
    CaptureEvent::Gap(capture::CapturedGap {
        timestamp: Timestamp {
            monotonic_ns: 1,
            wall_time_unix_ns: 1,
        },
        flow,
        source: CaptureSource::EbpfSyscall,
        provider: CaptureProviderKind::Ebpf,
        enforcement_evidence: EnforcementEvidence::observation_only_with_detail(
            ObservationOnlyReason::EbpfUnresolvedFlow,
            reason,
        ),
        enforcement_evidence_propagation: capture::EnforcementEvidencePropagation::Event,
        gap: Gap {
            direction: Direction::Outbound,
            expected_offset: 0,
            next_offset: None,
            reason: reason.to_string(),
        },
    })
}

pub(super) fn capture_loss(flow: FlowContext, lost_events: u64) -> CaptureEvent {
    let reason = format!("test capture lost {lost_events} event(s)");
    CaptureEvent::Loss(capture::CapturedLoss {
        timestamp: Timestamp {
            monotonic_ns: 1,
            wall_time_unix_ns: 1,
        },
        flow,
        source: CaptureSource::EbpfSyscall,
        provider: CaptureProviderKind::Ebpf,
        enforcement_evidence: EnforcementEvidence::observation_only_with_detail(
            ObservationOnlyReason::EbpfCaptureLoss,
            reason.clone(),
        ),
        loss: CaptureLoss {
            lost_events,
            reason,
        },
    })
}

pub(super) fn captured_bytes_with_direction(
    flow: FlowContext,
    direction: Direction,
    bytes: &'static [u8],
) -> CaptureEvent {
    CaptureEvent::Bytes(captured_bytes_chunk(flow, direction, bytes))
}

fn captured_bytes_chunk(
    flow: FlowContext,
    direction: Direction,
    bytes: &'static [u8],
) -> CapturedBytes {
    CapturedBytes {
        timestamp: Timestamp {
            monotonic_ns: 1,
            wall_time_unix_ns: 1,
        },
        flow,
        source: CaptureSource::Replay,
        provider: CaptureProviderKind::Replay,
        direction,
        stream_offset: 0,
        bytes: bytes.into(),
        attribution_confidence: 0,
        degraded: false,
        degradation_reason: None,
        enforcement_evidence: EnforcementEvidence::default(),
        enforcement_evidence_propagation: capture::EnforcementEvidencePropagation::Event,
    }
}

pub(super) fn connection_closed(flow: FlowContext) -> CaptureEvent {
    CaptureEvent::ConnectionClosed {
        timestamp: Timestamp {
            monotonic_ns: 2,
            wall_time_unix_ns: 2,
        },
        flow,
        source: CaptureSource::Replay,
        provider: CaptureProviderKind::Replay,
    }
}

pub(super) fn exported_envelopes(
    spool: &storage::FjallSpool,
) -> Result<Vec<EventEnvelope>, Box<dyn std::error::Error>> {
    spool
        .read_export_batch("sink", 64)?
        .iter()
        .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub(super) fn demo_flow_with_ports(
    local_port: u16,
    remote_port: u16,
    socket_cookie: u64,
) -> FlowContext {
    let process = ProcessIdentity {
        pid: 1,
        tgid: 1,
        start_time_ticks: 1,
        boot_id: "boot".to_string(),
        exe_path: "replay".to_string(),
        cmdline_hash: "hash".to_string(),
        uid: 0,
        gid: 0,
        cgroup: None,
        systemd_service: None,
        container_id: None,
        runtime_hint: None,
    };
    let local = AddressPort {
        address: "127.0.0.1".to_string(),
        port: local_port,
    };
    let remote = AddressPort {
        address: "127.0.0.1".to_string(),
        port: remote_port,
    };
    FlowContext {
        id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
        process: ProcessContext {
            identity: process,
            name: "replay".to_string(),
            cmdline: vec!["replay".to_string()],
        },
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: 1,
        socket_cookie: Some(socket_cookie),
        attribution_confidence: 0,
    }
}

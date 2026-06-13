use capture::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CaptureProviderKind, CapturedBytes,
};
use probe_core::{
    AddressPort, CapabilityState, CaptureSource, Direction, EventEnvelope, FlowContext,
    FlowIdentity, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
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

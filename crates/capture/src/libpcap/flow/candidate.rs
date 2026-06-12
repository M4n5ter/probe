use probe_core::{
    AddressPort, Direction, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity,
    TcpConnection, TcpEndpoint, TransportProtocol,
};

use crate::{CaptureError, ProcessResolver, ResolvedProcess};

use super::super::decoder::DecodedTcpSegment;

#[derive(Debug, Clone)]
pub(super) struct SelectedFlowCandidate {
    pub(super) direction: Direction,
    pub(super) local_endpoint: TcpEndpoint,
    pub(super) process: ProcessContext,
    pub(super) confidence: u8,
    pub(super) attribution_failure: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct FlowCandidate {
    pub(super) direction: Direction,
    pub(super) local_endpoint: TcpEndpoint,
    remote_endpoint: TcpEndpoint,
    local: AddressPort,
    remote: AddressPort,
}

impl FlowCandidate {
    pub(super) fn from_decoded(decoded: &DecodedTcpSegment<'_>, direction: Direction) -> Self {
        let source = decoded.source_endpoint();
        let destination = decoded.destination_endpoint();
        match direction {
            Direction::Outbound => Self {
                direction,
                local_endpoint: source,
                remote_endpoint: destination,
                local: source.into(),
                remote: destination.into(),
            },
            Direction::Inbound => Self {
                direction,
                local_endpoint: destination,
                remote_endpoint: source,
                local: destination.into(),
                remote: source.into(),
            },
        }
    }
}

pub(super) fn infer_initial_direction(decoded: &DecodedTcpSegment<'_>) -> Direction {
    if decoded.payload.starts_with(b"HTTP/") {
        return Direction::Inbound;
    }
    if looks_like_http_request(decoded.payload) {
        return Direction::Outbound;
    }
    if looks_like_server_port(decoded.source_port)
        && !looks_like_server_port(decoded.destination_port)
    {
        return Direction::Inbound;
    }
    Direction::Outbound
}

pub(super) fn opposite_direction(direction: Direction) -> Direction {
    match direction {
        Direction::Inbound => Direction::Outbound,
        Direction::Outbound => Direction::Inbound,
    }
}

pub(super) fn select_flow_candidate(
    primary: FlowCandidate,
    secondary: FlowCandidate,
    process_resolver: &mut Option<Box<dyn ProcessResolver>>,
) -> SelectedFlowCandidate {
    let mut attribution_failure = None;
    match resolve_candidate_process(&primary, process_resolver) {
        Ok(Some(process)) => {
            return SelectedFlowCandidate {
                direction: primary.direction,
                local_endpoint: primary.local_endpoint,
                process: process.process,
                confidence: process.confidence,
                attribution_failure: None,
            };
        }
        Ok(None) => {}
        Err(error) => attribution_failure = Some(error.to_string()),
    }
    match resolve_candidate_process(&secondary, process_resolver) {
        Ok(Some(process)) => {
            return SelectedFlowCandidate {
                direction: secondary.direction,
                local_endpoint: secondary.local_endpoint,
                process: process.process,
                confidence: process.confidence,
                attribution_failure: None,
            };
        }
        Ok(None) => {}
        Err(error) => {
            if attribution_failure.is_none() {
                attribution_failure = Some(error.to_string());
            }
        }
    }
    SelectedFlowCandidate {
        direction: primary.direction,
        local_endpoint: primary.local_endpoint,
        process: synthetic_libpcap_process(),
        confidence: 0,
        attribution_failure,
    }
}

pub(super) fn flow_from_decoded(
    decoded: &DecodedTcpSegment<'_>,
    direction: Direction,
    process: ProcessContext,
    attribution_confidence: u8,
    start_monotonic_ns: u64,
) -> FlowContext {
    let candidate = FlowCandidate::from_decoded(decoded, direction);
    FlowContext {
        id: FlowIdentity::stable(
            &process.identity,
            &candidate.local,
            &candidate.remote,
            TransportProtocol::Tcp,
            start_monotonic_ns,
            None,
        ),
        process,
        local: candidate.local,
        remote: candidate.remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns,
        socket_cookie: None,
        attribution_confidence,
    }
}

pub(super) fn synthetic_libpcap_process() -> ProcessContext {
    let identity = ProcessIdentity {
        pid: 0,
        tgid: 0,
        start_time_ticks: 0,
        boot_id: "libpcap".to_string(),
        exe_path: "unknown".to_string(),
        cmdline_hash: "unknown".to_string(),
        uid: 0,
        gid: 0,
        cgroup: None,
        systemd_service: None,
        container_id: None,
        runtime_hint: Some("libpcap_fallback".to_string()),
    };
    ProcessContext {
        identity,
        name: "unknown".to_string(),
        cmdline: Vec::new(),
    }
}

fn resolve_candidate_process(
    candidate: &FlowCandidate,
    process_resolver: &mut Option<Box<dyn ProcessResolver>>,
) -> Result<Option<ResolvedProcess>, CaptureError> {
    let Some(resolver) = process_resolver.as_deref_mut() else {
        return Ok(None);
    };
    resolver.resolve_tcp_process(TcpConnection::new(
        candidate.local_endpoint,
        candidate.remote_endpoint,
    ))
}

fn looks_like_http_request(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|method| payload.starts_with(method))
}

fn looks_like_server_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8000 | 8080 | 8443)
}

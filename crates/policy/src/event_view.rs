use probe_core::{
    AddressPort, BodyChunk, CaptureOrigin, CaptureProviderKind, CaptureSource, Direction,
    EnforcementEvidence, EventEnvelope, EventKind, EventType, FlowContext, Gap, HttpHeaders,
    ObservationOnlyReason, OpaqueStream, ProcessContext, ProcessIdentity, ProtocolError, SseEvent,
    Timestamp, TransportProtocol, WebSocketFrame, WebSocketHandoff, WebSocketMessage,
    WebSocketMessageOpcode, WebSocketOpcode,
};
use serde::Serialize;

const MAX_POLICY_WEBSOCKET_PAYLOAD_TEXT_BYTES: usize = 64 * 1024;

pub(crate) struct PolicyEventViewBuildError {
    pub(crate) event_type: EventType,
}

#[derive(Serialize)]
pub(crate) struct PolicyEventView<'a> {
    id: &'a str,
    timestamp: PolicyTimestampView,
    flow: PolicyFlowView<'a>,
    origin: PolicyOriginView,
    config_version: &'a str,
    policy_version: Option<&'a str>,
    degraded: bool,
    enforcement_evidence: PolicyEnforcementEvidenceView<'a>,
    event_type: &'static str,
    direction: Option<&'static str>,
    kind: PolicyEventKindView<'a>,
}

impl<'a> PolicyEventView<'a> {
    pub(crate) fn from_envelope(
        event: &'a EventEnvelope,
    ) -> Result<Self, PolicyEventViewBuildError> {
        let event_type = event.kind().event_type();
        let kind = PolicyEventKindView::from_kind(event.kind())
            .ok_or(PolicyEventViewBuildError { event_type })?;
        let flow = event
            .flow()
            .ok_or(PolicyEventViewBuildError { event_type })?;
        Ok(Self {
            id: event.id().as_str(),
            timestamp: PolicyTimestampView::from_timestamp(event.timestamp()),
            flow: PolicyFlowView::from_flow(flow),
            origin: PolicyOriginView::from_origin(event.origin()),
            config_version: event.config_version(),
            policy_version: event.policy_version(),
            degraded: event.degraded(),
            enforcement_evidence: PolicyEnforcementEvidenceView::from_evidence(
                event.enforcement_evidence(),
            ),
            event_type: event_type.as_str(),
            direction: event.kind().direction().map(direction_name),
            kind,
        })
    }
}

#[derive(Serialize)]
struct PolicyTimestampView {
    monotonic_ns: u64,
    wall_time_unix_ns: i64,
}

impl PolicyTimestampView {
    fn from_timestamp(timestamp: Timestamp) -> Self {
        Self {
            monotonic_ns: timestamp.monotonic_ns,
            wall_time_unix_ns: timestamp.wall_time_unix_ns,
        }
    }
}

#[derive(Serialize)]
struct PolicyOriginView {
    source: &'static str,
    provider: &'static str,
}

impl PolicyOriginView {
    fn from_origin(origin: CaptureOrigin) -> Self {
        Self {
            source: source_name(origin.source()),
            provider: provider_name(origin.provider()),
        }
    }
}

#[derive(Serialize)]
struct PolicyFlowView<'a> {
    id: &'a str,
    process: PolicyProcessView<'a>,
    local_endpoint: PolicyEndpointView<'a>,
    remote_endpoint: PolicyEndpointView<'a>,
    protocol: &'static str,
    start_monotonic_ns: u64,
    socket_cookie: Option<u64>,
    attribution_confidence: u8,
}

impl<'a> PolicyFlowView<'a> {
    fn from_flow(flow: &'a FlowContext) -> Self {
        Self {
            id: flow.id.0.as_str(),
            process: PolicyProcessView::from_process(&flow.process),
            local_endpoint: PolicyEndpointView::from_endpoint(&flow.local),
            remote_endpoint: PolicyEndpointView::from_endpoint(&flow.remote),
            protocol: transport_protocol_name(flow.protocol),
            start_monotonic_ns: flow.start_monotonic_ns,
            socket_cookie: flow.socket_cookie,
            attribution_confidence: flow.attribution_confidence,
        }
    }
}

#[derive(Serialize)]
struct PolicyEndpointView<'a> {
    address: &'a str,
    port: u16,
}

impl<'a> PolicyEndpointView<'a> {
    fn from_endpoint(endpoint: &'a AddressPort) -> Self {
        Self {
            address: &endpoint.address,
            port: endpoint.port,
        }
    }
}

#[derive(Serialize)]
struct PolicyProcessView<'a> {
    identity: PolicyProcessIdentityView<'a>,
    name: &'a str,
    cmdline: &'a [String],
}

impl<'a> PolicyProcessView<'a> {
    fn from_process(process: &'a ProcessContext) -> Self {
        Self {
            identity: PolicyProcessIdentityView::from_identity(&process.identity),
            name: &process.name,
            cmdline: &process.cmdline,
        }
    }
}

#[derive(Serialize)]
struct PolicyProcessIdentityView<'a> {
    pid: u32,
    tgid: u32,
    start_time_ticks: u64,
    boot_id: &'a str,
    exe_path: &'a str,
    cmdline_hash: &'a str,
    uid: u32,
    gid: u32,
    cgroup: Option<&'a str>,
    systemd_service: Option<&'a str>,
    container_id: Option<&'a str>,
    runtime_hint: Option<&'a str>,
}

impl<'a> PolicyProcessIdentityView<'a> {
    fn from_identity(identity: &'a ProcessIdentity) -> Self {
        Self {
            pid: identity.pid,
            tgid: identity.tgid,
            start_time_ticks: identity.start_time_ticks,
            boot_id: &identity.boot_id,
            exe_path: &identity.exe_path,
            cmdline_hash: &identity.cmdline_hash,
            uid: identity.uid,
            gid: identity.gid,
            cgroup: identity.cgroup.as_deref(),
            systemd_service: identity.systemd_service.as_deref(),
            container_id: identity.container_id.as_deref(),
            runtime_hint: identity.runtime_hint.as_deref(),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PolicyEnforcementEvidenceView<'a> {
    DestructiveAllowed,
    ObservationOnly {
        reason: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<&'a str>,
    },
}

impl<'a> PolicyEnforcementEvidenceView<'a> {
    fn from_evidence(evidence: &'a EnforcementEvidence) -> Self {
        match evidence {
            EnforcementEvidence::DestructiveAllowed => Self::DestructiveAllowed,
            EnforcementEvidence::ObservationOnly { reason, detail } => Self::ObservationOnly {
                reason: observation_only_reason_name(*reason),
                detail: detail.as_deref(),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PolicyEventKindView<'a> {
    ConnectionOpened,
    ConnectionClosed,
    HttpRequestHeaders(PolicyHttpHeadersView<'a>),
    HttpResponseHeaders(PolicyHttpHeadersView<'a>),
    HttpBodyChunk(PolicyBodyChunkView<'a>),
    SseEvent(PolicySseEventView<'a>),
    #[serde(rename = "websocket_handoff")]
    WebSocketHandoff(PolicyWebSocketHandoffView<'a>),
    #[serde(rename = "websocket_frame")]
    WebSocketFrame(PolicyWebSocketFrameView<'a>),
    #[serde(rename = "websocket_message")]
    WebSocketMessage(PolicyWebSocketMessageView<'a>),
    OpaqueStream(PolicyOpaqueStreamView<'a>),
    Gap(PolicyGapView<'a>),
    ProtocolError(PolicyProtocolErrorView<'a>),
}

impl<'a> PolicyEventKindView<'a> {
    fn from_kind(kind: &'a EventKind) -> Option<Self> {
        let view = match kind {
            EventKind::ConnectionOpened => Self::ConnectionOpened,
            EventKind::ConnectionClosed => Self::ConnectionClosed,
            EventKind::HttpRequestHeaders(headers) => {
                Self::HttpRequestHeaders(PolicyHttpHeadersView::from_headers(headers))
            }
            EventKind::HttpResponseHeaders(headers) => {
                Self::HttpResponseHeaders(PolicyHttpHeadersView::from_headers(headers))
            }
            EventKind::HttpBodyChunk(chunk) => {
                Self::HttpBodyChunk(PolicyBodyChunkView::from_chunk(chunk))
            }
            EventKind::SseEvent(event) => Self::SseEvent(PolicySseEventView::from_event(event)),
            EventKind::WebSocketHandoff(handoff) => {
                Self::WebSocketHandoff(PolicyWebSocketHandoffView::from_handoff(handoff))
            }
            EventKind::WebSocketFrame(frame) => {
                Self::WebSocketFrame(PolicyWebSocketFrameView::from_frame(frame))
            }
            EventKind::WebSocketMessage(message) => {
                Self::WebSocketMessage(PolicyWebSocketMessageView::from_message(message))
            }
            EventKind::OpaqueStream(stream) => {
                Self::OpaqueStream(PolicyOpaqueStreamView::from_stream(stream))
            }
            EventKind::Gap(gap) => Self::Gap(PolicyGapView::from_gap(gap)),
            EventKind::ProtocolError(error) => {
                Self::ProtocolError(PolicyProtocolErrorView::from_error(error))
            }
            EventKind::CaptureLoss(_)
            | EventKind::PolicyAlert(_)
            | EventKind::PolicyVerdict(_)
            | EventKind::PolicyRuntimeError(_)
            | EventKind::EnforcementDecision(_)
            | EventKind::L7MitmAudit(_) => {
                return None;
            }
        };
        Some(view)
    }
}

#[derive(Serialize)]
struct PolicyHttpHeadersView<'a> {
    direction: &'static str,
    stream_sequence: u64,
    method: Option<&'a str>,
    target: Option<&'a str>,
    status: Option<u16>,
    reason: Option<&'a str>,
    version: &'a str,
    headers: &'a [(String, String)],
}

impl<'a> PolicyHttpHeadersView<'a> {
    fn from_headers(headers: &'a HttpHeaders) -> Self {
        Self {
            direction: direction_name(headers.direction),
            stream_sequence: headers.stream_sequence,
            method: headers.method.as_deref(),
            target: headers.target.as_deref(),
            status: headers.status,
            reason: headers.reason.as_deref(),
            version: &headers.version,
            headers: &headers.headers,
        }
    }
}

#[derive(Serialize)]
struct PolicyBodyChunkView<'a> {
    direction: &'static str,
    stream_sequence: u64,
    offset: u64,
    data: &'a [u8],
    end_stream: bool,
}

impl<'a> PolicyBodyChunkView<'a> {
    fn from_chunk(chunk: &'a BodyChunk) -> Self {
        Self {
            direction: direction_name(chunk.direction),
            stream_sequence: chunk.stream_sequence,
            offset: chunk.offset,
            data: &chunk.data,
            end_stream: chunk.end_stream,
        }
    }
}

#[derive(Serialize)]
struct PolicySseEventView<'a> {
    direction: &'static str,
    stream_sequence: u64,
    event: Option<&'a str>,
    id: Option<&'a str>,
    retry_ms: Option<u64>,
    data: &'a str,
}

impl<'a> PolicySseEventView<'a> {
    fn from_event(event: &'a SseEvent) -> Self {
        Self {
            direction: direction_name(event.direction),
            stream_sequence: event.stream_sequence,
            event: event.event.as_deref(),
            id: event.id.as_deref(),
            retry_ms: event.retry_ms,
            data: &event.data,
        }
    }
}

#[derive(Serialize)]
struct PolicyWebSocketHandoffView<'a> {
    direction: &'static str,
    stream_sequence: u64,
    target: Option<&'a str>,
    subprotocol: Option<&'a str>,
    extensions: &'a [String],
}

impl<'a> PolicyWebSocketHandoffView<'a> {
    fn from_handoff(handoff: &'a WebSocketHandoff) -> Self {
        Self {
            direction: direction_name(handoff.direction),
            stream_sequence: handoff.stream_sequence,
            target: handoff.target.as_deref(),
            subprotocol: handoff.subprotocol.as_deref(),
            extensions: &handoff.extensions,
        }
    }
}

#[derive(Serialize)]
struct PolicyWebSocketFrameView<'a> {
    direction: &'static str,
    stream_sequence: u64,
    frame_sequence: u64,
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: PolicyWebSocketOpcodeView,
    payload_len: u64,
    masked: bool,
    payload_fingerprint: &'a [u8],
}

impl<'a> PolicyWebSocketFrameView<'a> {
    fn from_frame(frame: &'a WebSocketFrame) -> Self {
        Self {
            direction: direction_name(frame.direction),
            stream_sequence: frame.stream_sequence,
            frame_sequence: frame.frame_sequence,
            fin: frame.fin,
            rsv1: frame.rsv1,
            rsv2: frame.rsv2,
            rsv3: frame.rsv3,
            opcode: PolicyWebSocketOpcodeView::from_opcode(frame.opcode),
            payload_len: frame.payload_len,
            masked: frame.masked,
            payload_fingerprint: &frame.payload_fingerprint,
        }
    }
}

#[derive(Serialize)]
struct PolicyWebSocketMessageView<'a> {
    direction: &'static str,
    stream_sequence: u64,
    message_sequence: u64,
    first_frame_sequence: u64,
    final_frame_sequence: u64,
    opcode: PolicyWebSocketMessageOpcodeView,
    payload_len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_text: Option<&'a str>,
    payload_fingerprint: &'a [u8],
}

impl<'a> PolicyWebSocketMessageView<'a> {
    fn from_message(message: &'a WebSocketMessage) -> Self {
        let payload_text = policy_websocket_payload_text(message);
        Self {
            direction: direction_name(message.direction),
            stream_sequence: message.stream_sequence,
            message_sequence: message.message_sequence,
            first_frame_sequence: message.first_frame_sequence,
            final_frame_sequence: message.final_frame_sequence,
            opcode: PolicyWebSocketMessageOpcodeView::from_opcode(message.opcode),
            payload_len: message.payload_len,
            payload_text,
            payload_fingerprint: &message.payload_fingerprint,
        }
    }
}

fn policy_websocket_payload_text(message: &WebSocketMessage) -> Option<&str> {
    if message.opcode != WebSocketMessageOpcode::Text
        || message.payload.len() > MAX_POLICY_WEBSOCKET_PAYLOAD_TEXT_BYTES
    {
        return None;
    }
    std::str::from_utf8(&message.payload).ok()
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PolicyWebSocketMessageOpcodeView {
    Text,
    Binary,
}

impl PolicyWebSocketMessageOpcodeView {
    fn from_opcode(opcode: WebSocketMessageOpcode) -> Self {
        match opcode {
            WebSocketMessageOpcode::Text => Self::Text,
            WebSocketMessageOpcode::Binary => Self::Binary,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PolicyWebSocketOpcodeView {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Other { code: u8 },
}

impl PolicyWebSocketOpcodeView {
    fn from_opcode(opcode: WebSocketOpcode) -> Self {
        match opcode {
            WebSocketOpcode::Continuation => Self::Continuation,
            WebSocketOpcode::Text => Self::Text,
            WebSocketOpcode::Binary => Self::Binary,
            WebSocketOpcode::Close => Self::Close,
            WebSocketOpcode::Ping => Self::Ping,
            WebSocketOpcode::Pong => Self::Pong,
            WebSocketOpcode::Other { code } => Self::Other { code },
        }
    }
}

#[derive(Serialize)]
struct PolicyOpaqueStreamView<'a> {
    direction: &'static str,
    fingerprint: &'a [u8],
    reason: &'a str,
}

impl<'a> PolicyOpaqueStreamView<'a> {
    fn from_stream(stream: &'a OpaqueStream) -> Self {
        Self {
            direction: direction_name(stream.direction),
            fingerprint: &stream.fingerprint,
            reason: &stream.reason,
        }
    }
}

#[derive(Serialize)]
struct PolicyGapView<'a> {
    direction: &'static str,
    expected_offset: u64,
    next_offset: Option<u64>,
    reason: &'a str,
}

impl<'a> PolicyGapView<'a> {
    fn from_gap(gap: &'a Gap) -> Self {
        Self {
            direction: direction_name(gap.direction),
            expected_offset: gap.expected_offset,
            next_offset: gap.next_offset,
            reason: &gap.reason,
        }
    }
}

#[derive(Serialize)]
struct PolicyProtocolErrorView<'a> {
    direction: &'static str,
    reason: &'a str,
}

impl<'a> PolicyProtocolErrorView<'a> {
    fn from_error(error: &'a ProtocolError) -> Self {
        Self {
            direction: direction_name(error.direction),
            reason: &error.reason,
        }
    }
}

fn source_name(source: CaptureSource) -> &'static str {
    match source {
        CaptureSource::EbpfSyscall => "ebpf_syscall",
        CaptureSource::Libpcap => "libpcap",
        CaptureSource::LibsslUprobe => "libssl_uprobe",
        CaptureSource::TlsSessionSecret => "tls_session_secret",
        CaptureSource::ExternalPlaintextFeed => "external_plaintext_feed",
        CaptureSource::L7MitmPlaintext => "l7_mitm_plaintext",
        CaptureSource::L7MitmControlPlane => "l7_mitm_control_plane",
        CaptureSource::Replay => "replay",
        CaptureSource::Mock => "mock",
    }
}

fn provider_name(provider: CaptureProviderKind) -> &'static str {
    match provider {
        CaptureProviderKind::Replay => "replay",
        CaptureProviderKind::Ebpf => "ebpf",
        CaptureProviderKind::Libpcap => "libpcap",
        CaptureProviderKind::Plaintext => "plaintext",
        CaptureProviderKind::Interception => "interception",
    }
}

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
    }
}

fn transport_protocol_name(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    }
}

fn observation_only_reason_name(reason: ObservationOnlyReason) -> &'static str {
    match reason {
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot => "ebpf_syscall_payload_snapshot",
        ObservationOnlyReason::EbpfUnresolvedFlow => "ebpf_unresolved_flow",
        ObservationOnlyReason::EbpfProcessLifecycleBoundary => "ebpf_process_lifecycle_boundary",
        ObservationOnlyReason::ProviderStateBoundary => "provider_state_boundary",
        ObservationOnlyReason::ProviderCaptureLoss => "provider_capture_loss",
    }
}

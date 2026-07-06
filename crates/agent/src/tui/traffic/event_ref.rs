use probe_core::{
    CaptureOrigin, Direction, DomainEvent, EnforcementDecision, EventEnvelope, EventKind,
    EventType, FlowContext, Gap, HttpHeaders, L7MitmAuditEvent, OpaqueStream, PolicyRuntimeError,
    ProtocolError, SseEvent, Verdict, WebSocketFrame, WebSocketHandoff, WebSocketMessageOpcode,
};

use crate::admin::{EventTailEvent, EventTailKind};

#[derive(Clone, Copy)]
pub(super) enum TrafficEventRef<'a> {
    Full(&'a EventEnvelope),
    Tail(&'a EventTailEvent),
}

impl<'a> TrafficEventRef<'a> {
    pub(super) fn event_id(self) -> &'a str {
        match self {
            Self::Full(event) => event.id().as_str(),
            Self::Tail(event) => event.id.as_str(),
        }
    }

    pub(super) fn wall_time_unix_ns(self) -> i64 {
        match self {
            Self::Full(event) => event.timestamp().wall_time_unix_ns,
            Self::Tail(event) => event.timestamp.wall_time_unix_ns,
        }
    }

    pub(super) fn origin(self) -> CaptureOrigin {
        match self {
            Self::Full(event) => event.origin(),
            Self::Tail(event) => event.origin,
        }
    }

    pub(super) fn config_version(self) -> &'a str {
        match self {
            Self::Full(event) => event.config_version(),
            Self::Tail(event) => &event.config_version,
        }
    }

    pub(super) fn policy_version(self) -> Option<&'a str> {
        match self {
            Self::Full(event) => event.policy_version(),
            Self::Tail(event) => event.policy_version.as_deref(),
        }
    }

    pub(super) fn degraded(self) -> bool {
        match self {
            Self::Full(event) => event.degraded(),
            Self::Tail(event) => event.degraded,
        }
    }

    pub(super) fn flow(self) -> Option<&'a FlowContext> {
        match self {
            Self::Full(event) => event.flow(),
            Self::Tail(event) => event.flow.as_ref(),
        }
    }

    pub(super) fn kind(self) -> TrafficEventKindRef<'a> {
        match self {
            Self::Full(event) => TrafficEventKindRef::from_full(event.kind()),
            Self::Tail(event) => TrafficEventKindRef::from_tail(&event.kind),
        }
    }

    pub(super) fn event_type(self) -> EventType {
        self.kind().event_type()
    }

    pub(super) fn direction(self) -> Option<Direction> {
        self.kind().direction()
    }

    pub(super) fn is_tail(self) -> bool {
        matches!(self, Self::Tail(_))
    }

    pub(super) fn http_request_headers(self) -> Option<&'a HttpHeaders> {
        match self.kind() {
            TrafficEventKindRef::HttpRequestHeaders(headers) => Some(headers),
            _ => None,
        }
    }

    pub(super) fn http_response_headers(self) -> Option<&'a HttpHeaders> {
        match self.kind() {
            TrafficEventKindRef::HttpResponseHeaders(headers) => Some(headers),
            _ => None,
        }
    }

    pub(super) fn http_body_chunk(self) -> Option<TrafficHttpBodyChunk<'a>> {
        match self.kind() {
            TrafficEventKindRef::HttpBodyChunk(chunk) => Some(chunk),
            _ => None,
        }
    }

    pub(super) fn gap(self) -> Option<&'a Gap> {
        match self.kind() {
            TrafficEventKindRef::Gap(gap) => Some(gap),
            _ => None,
        }
    }

    pub(super) fn websocket_handoff(self) -> Option<&'a WebSocketHandoff> {
        match self.kind() {
            TrafficEventKindRef::WebSocketHandoff(handoff) => Some(handoff),
            _ => None,
        }
    }

    pub(super) fn websocket_frame(self) -> Option<&'a WebSocketFrame> {
        match self.kind() {
            TrafficEventKindRef::WebSocketFrame(frame) => Some(frame),
            _ => None,
        }
    }

    pub(super) fn websocket_message(self) -> Option<TrafficWebSocketMessage<'a>> {
        match self.kind() {
            TrafficEventKindRef::WebSocketMessage(message) => Some(message),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum TrafficEventKindRef<'a> {
    ConnectionOpened,
    ConnectionClosed,
    HttpRequestHeaders(&'a HttpHeaders),
    HttpResponseHeaders(&'a HttpHeaders),
    HttpBodyChunk(TrafficHttpBodyChunk<'a>),
    SseEvent(TrafficSseEvent<'a>),
    WebSocketHandoff(&'a WebSocketHandoff),
    WebSocketFrame(&'a WebSocketFrame),
    WebSocketMessage(TrafficWebSocketMessage<'a>),
    OpaqueStream(&'a OpaqueStream),
    CaptureLoss(&'a probe_core::CaptureLoss),
    Gap(&'a Gap),
    ProtocolError(&'a ProtocolError),
    PolicyAlert(&'a DomainEvent),
    PolicyVerdict(&'a Verdict),
    PolicyRuntimeError(&'a PolicyRuntimeError),
    EnforcementDecision(&'a EnforcementDecision),
    L7MitmAudit(&'a L7MitmAuditEvent),
}

impl<'a> TrafficEventKindRef<'a> {
    fn from_full(kind: &'a EventKind) -> Self {
        match kind {
            EventKind::ConnectionOpened => Self::ConnectionOpened,
            EventKind::ConnectionClosed => Self::ConnectionClosed,
            EventKind::HttpRequestHeaders(headers) => Self::HttpRequestHeaders(headers),
            EventKind::HttpResponseHeaders(headers) => Self::HttpResponseHeaders(headers),
            EventKind::HttpBodyChunk(chunk) => Self::HttpBodyChunk(TrafficHttpBodyChunk {
                direction: chunk.direction,
                stream_sequence: chunk.stream_sequence,
                offset: chunk.offset,
                data_len: chunk.data.len(),
                data: Some(chunk.data.as_ref()),
                end_stream: chunk.end_stream,
            }),
            EventKind::SseEvent(event) => Self::SseEvent(TrafficSseEvent::from_full(event)),
            EventKind::WebSocketHandoff(handoff) => Self::WebSocketHandoff(handoff),
            EventKind::WebSocketFrame(frame) => Self::WebSocketFrame(frame),
            EventKind::WebSocketMessage(message) => {
                Self::WebSocketMessage(TrafficWebSocketMessage {
                    direction: message.direction,
                    stream_sequence: message.stream_sequence,
                    message_sequence: message.message_sequence,
                    first_frame_sequence: message.first_frame_sequence,
                    final_frame_sequence: message.final_frame_sequence,
                    opcode: message.opcode,
                    payload_len: message.payload_len,
                    payload: Some(message.payload.as_ref()),
                    payload_fingerprint: &message.payload_fingerprint,
                })
            }
            EventKind::OpaqueStream(stream) => Self::OpaqueStream(stream),
            EventKind::CaptureLoss(loss) => Self::CaptureLoss(loss),
            EventKind::Gap(gap) => Self::Gap(gap),
            EventKind::ProtocolError(error) => Self::ProtocolError(error),
            EventKind::PolicyAlert(alert) => Self::PolicyAlert(alert),
            EventKind::PolicyVerdict(verdict) => Self::PolicyVerdict(verdict),
            EventKind::PolicyRuntimeError(error) => Self::PolicyRuntimeError(error),
            EventKind::EnforcementDecision(decision) => Self::EnforcementDecision(decision),
            EventKind::L7MitmAudit(audit) => Self::L7MitmAudit(audit),
        }
    }

    fn from_tail(kind: &'a EventTailKind) -> Self {
        match kind {
            EventTailKind::ConnectionOpened => Self::ConnectionOpened,
            EventTailKind::ConnectionClosed => Self::ConnectionClosed,
            EventTailKind::HttpRequestHeaders(headers) => Self::HttpRequestHeaders(headers),
            EventTailKind::HttpResponseHeaders(headers) => Self::HttpResponseHeaders(headers),
            EventTailKind::HttpBodyChunk(chunk) => Self::HttpBodyChunk(TrafficHttpBodyChunk {
                direction: chunk.direction,
                stream_sequence: chunk.stream_sequence,
                offset: chunk.offset,
                data_len: chunk.data_len,
                data: None,
                end_stream: chunk.end_stream,
            }),
            EventTailKind::SseEvent(event) => Self::SseEvent(TrafficSseEvent {
                direction: event.direction,
                stream_sequence: event.stream_sequence,
                event: event.event.as_deref(),
                id: event.id.as_deref(),
                retry_ms: event.retry_ms,
                data_len: event.data_len,
                data: None,
            }),
            EventTailKind::WebSocketHandoff(handoff) => Self::WebSocketHandoff(handoff),
            EventTailKind::WebSocketFrame(frame) => Self::WebSocketFrame(frame),
            EventTailKind::WebSocketMessage(message) => {
                Self::WebSocketMessage(TrafficWebSocketMessage {
                    direction: message.direction,
                    stream_sequence: message.stream_sequence,
                    message_sequence: message.message_sequence,
                    first_frame_sequence: message.first_frame_sequence,
                    final_frame_sequence: message.final_frame_sequence,
                    opcode: message.opcode,
                    payload_len: message.payload_len,
                    payload: None,
                    payload_fingerprint: &message.payload_fingerprint,
                })
            }
            EventTailKind::OpaqueStream(stream) => Self::OpaqueStream(stream),
            EventTailKind::CaptureLoss(loss) => Self::CaptureLoss(loss),
            EventTailKind::Gap(gap) => Self::Gap(gap),
            EventTailKind::ProtocolError(error) => Self::ProtocolError(error),
            EventTailKind::PolicyAlert(alert) => Self::PolicyAlert(alert),
            EventTailKind::PolicyVerdict(verdict) => Self::PolicyVerdict(verdict),
            EventTailKind::PolicyRuntimeError(error) => Self::PolicyRuntimeError(error),
            EventTailKind::EnforcementDecision(decision) => Self::EnforcementDecision(decision),
            EventTailKind::L7MitmAudit(audit) => Self::L7MitmAudit(audit),
        }
    }

    pub(super) fn event_type(self) -> EventType {
        match self {
            Self::ConnectionOpened => EventType::ConnectionOpened,
            Self::ConnectionClosed => EventType::ConnectionClosed,
            Self::HttpRequestHeaders(_) => EventType::HttpRequestHeaders,
            Self::HttpResponseHeaders(_) => EventType::HttpResponseHeaders,
            Self::HttpBodyChunk(_) => EventType::HttpBodyChunk,
            Self::SseEvent(_) => EventType::SseEvent,
            Self::WebSocketHandoff(_) => EventType::WebSocketHandoff,
            Self::WebSocketFrame(_) => EventType::WebSocketFrame,
            Self::WebSocketMessage(_) => EventType::WebSocketMessage,
            Self::OpaqueStream(_) => EventType::OpaqueStream,
            Self::CaptureLoss(_) => EventType::CaptureLoss,
            Self::Gap(_) => EventType::Gap,
            Self::ProtocolError(_) => EventType::ProtocolError,
            Self::PolicyAlert(_) => EventType::PolicyAlert,
            Self::PolicyVerdict(_) => EventType::PolicyVerdict,
            Self::PolicyRuntimeError(_) => EventType::PolicyRuntimeError,
            Self::EnforcementDecision(_) => EventType::EnforcementDecision,
            Self::L7MitmAudit(_) => EventType::L7MitmAudit,
        }
    }

    pub(super) fn direction(self) -> Option<Direction> {
        match self {
            Self::HttpRequestHeaders(headers) | Self::HttpResponseHeaders(headers) => {
                Some(headers.direction)
            }
            Self::HttpBodyChunk(chunk) => Some(chunk.direction),
            Self::SseEvent(event) => Some(event.direction),
            Self::WebSocketHandoff(handoff) => Some(handoff.direction),
            Self::WebSocketFrame(frame) => Some(frame.direction),
            Self::WebSocketMessage(message) => Some(message.direction),
            Self::OpaqueStream(stream) => Some(stream.direction),
            Self::Gap(gap) => Some(gap.direction),
            Self::ProtocolError(error) => Some(error.direction),
            Self::ConnectionOpened
            | Self::ConnectionClosed
            | Self::CaptureLoss(_)
            | Self::PolicyAlert(_)
            | Self::PolicyVerdict(_)
            | Self::PolicyRuntimeError(_)
            | Self::EnforcementDecision(_)
            | Self::L7MitmAudit(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct TrafficHttpBodyChunk<'a> {
    pub(super) direction: Direction,
    pub(super) stream_sequence: u64,
    pub(super) offset: u64,
    pub(super) data_len: usize,
    pub(super) data: Option<&'a [u8]>,
    pub(super) end_stream: bool,
}

#[derive(Clone, Copy)]
pub(super) struct TrafficSseEvent<'a> {
    pub(super) direction: Direction,
    pub(super) stream_sequence: u64,
    pub(super) event: Option<&'a str>,
    pub(super) id: Option<&'a str>,
    pub(super) retry_ms: Option<u64>,
    pub(super) data_len: usize,
    pub(super) data: Option<&'a str>,
}

impl<'a> TrafficSseEvent<'a> {
    fn from_full(event: &'a SseEvent) -> Self {
        Self {
            direction: event.direction,
            stream_sequence: event.stream_sequence,
            event: event.event.as_deref(),
            id: event.id.as_deref(),
            retry_ms: event.retry_ms,
            data_len: event.data.len(),
            data: Some(&event.data),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct TrafficWebSocketMessage<'a> {
    pub(super) direction: Direction,
    pub(super) stream_sequence: u64,
    pub(super) message_sequence: u64,
    pub(super) first_frame_sequence: u64,
    pub(super) final_frame_sequence: u64,
    pub(super) opcode: WebSocketMessageOpcode,
    pub(super) payload_len: u64,
    pub(super) payload: Option<&'a [u8]>,
    pub(super) payload_fingerprint: &'a [u8],
}

#[cfg(test)]
use probe_core::EventKind;
use probe_core::{
    BodyChunk, CaptureLoss, CaptureOrigin, Direction, DomainEvent, EnforcementDecision,
    EventEnvelope, EventId, EventType, FlowContext, Gap, HttpHeaders, L7MitmAuditEvent,
    OpaqueStream, PolicyRuntimeError, ProtocolError, SseEvent, Timestamp, Verdict, WebSocketFrame,
    WebSocketHandoff, WebSocketMessage, WebSocketMessageOpcode,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventTailAttributionMode {
    #[default]
    Strict,
    IncludeUnknownProcess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailSnapshot {
    pub after_sequence: u64,
    pub next_after_sequence: u64,
    pub last_export_sequence: u64,
    pub attribution_mode: EventTailAttributionMode,
    pub limit: usize,
    pub scanned: usize,
    pub budget: EventTailBudgetSnapshot,
    pub events: Vec<EventTailRecord>,
    pub omissions: Vec<EventTailOmission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailRecord {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub event: EventTailEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EventTailEvent {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub origin: CaptureOrigin,
    pub config_version: String,
    pub policy_version: Option<String>,
    pub degraded: bool,
    pub flow: Option<FlowContext>,
    pub kind: EventTailKind,
}

impl EventTailEvent {
    #[cfg(test)]
    pub(crate) fn from_envelope(event: &EventEnvelope) -> Self {
        Self {
            id: event.id().clone(),
            timestamp: event.timestamp(),
            origin: event.origin(),
            config_version: event.config_version().to_string(),
            policy_version: event.policy_version().map(str::to_string),
            degraded: event.degraded(),
            flow: event.flow().cloned(),
            kind: EventTailKind::from_kind(event.kind()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EventTailKind {
    ConnectionOpened,
    ConnectionClosed,
    HttpRequestHeaders(HttpHeaders),
    HttpResponseHeaders(HttpHeaders),
    HttpBodyChunk(EventTailBodyChunk),
    SseEvent(EventTailSseEvent),
    #[serde(rename = "websocket_handoff")]
    WebSocketHandoff(WebSocketHandoff),
    #[serde(rename = "websocket_frame")]
    WebSocketFrame(WebSocketFrame),
    #[serde(rename = "websocket_message")]
    WebSocketMessage(EventTailWebSocketMessage),
    OpaqueStream(OpaqueStream),
    CaptureLoss(CaptureLoss),
    Gap(Gap),
    ProtocolError(ProtocolError),
    PolicyAlert(DomainEvent),
    PolicyVerdict(Verdict),
    PolicyRuntimeError(PolicyRuntimeError),
    EnforcementDecision(EnforcementDecision),
    #[serde(rename = "l7_mitm_audit")]
    L7MitmAudit(L7MitmAuditEvent),
}

impl EventTailKind {
    #[cfg(test)]
    fn from_kind(kind: &EventKind) -> Self {
        match kind {
            EventKind::ConnectionOpened => Self::ConnectionOpened,
            EventKind::ConnectionClosed => Self::ConnectionClosed,
            EventKind::HttpRequestHeaders(headers) => Self::HttpRequestHeaders(headers.clone()),
            EventKind::HttpResponseHeaders(headers) => Self::HttpResponseHeaders(headers.clone()),
            EventKind::HttpBodyChunk(chunk) => Self::HttpBodyChunk(EventTailBodyChunk::from(chunk)),
            EventKind::SseEvent(event) => Self::SseEvent(EventTailSseEvent::from(event)),
            EventKind::WebSocketHandoff(handoff) => Self::WebSocketHandoff(handoff.clone()),
            EventKind::WebSocketFrame(frame) => Self::WebSocketFrame(frame.clone()),
            EventKind::WebSocketMessage(message) => {
                Self::WebSocketMessage(EventTailWebSocketMessage::from(message))
            }
            EventKind::OpaqueStream(stream) => Self::OpaqueStream(stream.clone()),
            EventKind::CaptureLoss(loss) => Self::CaptureLoss(loss.clone()),
            EventKind::Gap(gap) => Self::Gap(gap.clone()),
            EventKind::ProtocolError(error) => Self::ProtocolError(error.clone()),
            EventKind::PolicyAlert(alert) => Self::PolicyAlert(alert.clone()),
            EventKind::PolicyVerdict(verdict) => Self::PolicyVerdict(verdict.clone()),
            EventKind::PolicyRuntimeError(error) => Self::PolicyRuntimeError(error.clone()),
            EventKind::EnforcementDecision(decision) => Self::EnforcementDecision(decision.clone()),
            EventKind::L7MitmAudit(audit) => Self::L7MitmAudit(audit.clone()),
        }
    }

    pub(crate) fn event_type(&self) -> EventType {
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

    pub(crate) fn direction(&self) -> Option<Direction> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventTailBodyChunk {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub offset: u64,
    pub data_len: usize,
    pub end_stream: bool,
}

impl From<&BodyChunk> for EventTailBodyChunk {
    fn from(chunk: &BodyChunk) -> Self {
        Self {
            direction: chunk.direction,
            stream_sequence: chunk.stream_sequence,
            offset: chunk.offset,
            data_len: chunk.data.len(),
            end_stream: chunk.end_stream,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventTailSseEvent {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub event: Option<String>,
    pub id: Option<String>,
    pub retry_ms: Option<u64>,
    pub data_len: usize,
}

impl From<&SseEvent> for EventTailSseEvent {
    fn from(event: &SseEvent) -> Self {
        Self {
            direction: event.direction,
            stream_sequence: event.stream_sequence,
            event: event.event.clone(),
            id: event.id.clone(),
            retry_ms: event.retry_ms,
            data_len: event.data.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventTailWebSocketMessage {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub message_sequence: u64,
    pub first_frame_sequence: u64,
    pub final_frame_sequence: u64,
    pub opcode: WebSocketMessageOpcode,
    pub payload_len: u64,
    pub payload_fingerprint: Vec<u8>,
}

impl From<&WebSocketMessage> for EventTailWebSocketMessage {
    fn from(message: &WebSocketMessage) -> Self {
        Self {
            direction: message.direction,
            stream_sequence: message.stream_sequence,
            message_sequence: message.message_sequence,
            first_frame_sequence: message.first_frame_sequence,
            final_frame_sequence: message.final_frame_sequence,
            opcode: message.opcode,
            payload_len: message.payload_len,
            payload_fingerprint: message.payload_fingerprint.clone(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventDetailSnapshot {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub payload_schema: String,
    pub payload_bytes: usize,
    pub event: EventEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventDetailTooLargeSnapshot {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub payload_schema: String,
    pub payload_bytes: usize,
    pub max_payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailBudgetSnapshot {
    pub max_event_payload_bytes: usize,
    pub max_record_bytes: usize,
    pub included_record_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailOmission {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub payload_schema: String,
    pub payload_bytes: usize,
    pub reason: EventTailOmissionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventTailOmissionReason {
    EventTooLarge,
    ResponseBudgetExceeded,
}

impl EventTailOmissionReason {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::EventTooLarge => "event too large",
            Self::ResponseBudgetExceeded => "response budget exceeded",
        }
    }
}

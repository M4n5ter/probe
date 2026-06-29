use std::{fmt, str::FromStr};

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{Action, EnforcementDecision, Verdict};

use super::Direction;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventKind {
    ConnectionOpened,
    ConnectionClosed,
    HttpRequestHeaders(HttpHeaders),
    HttpResponseHeaders(HttpHeaders),
    HttpBodyChunk(BodyChunk),
    SseEvent(SseEvent),
    #[serde(rename = "websocket_handoff")]
    WebSocketHandoff(WebSocketHandoff),
    #[serde(rename = "websocket_frame")]
    WebSocketFrame(WebSocketFrame),
    #[serde(rename = "websocket_message")]
    WebSocketMessage(WebSocketMessage),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    ConnectionOpened,
    ConnectionClosed,
    HttpRequestHeaders,
    HttpResponseHeaders,
    HttpBodyChunk,
    SseEvent,
    WebSocketHandoff,
    WebSocketFrame,
    WebSocketMessage,
    OpaqueStream,
    CaptureLoss,
    Gap,
    ProtocolError,
    PolicyAlert,
    PolicyVerdict,
    PolicyRuntimeError,
    EnforcementDecision,
    L7MitmAudit,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionOpened => "connection_opened",
            Self::ConnectionClosed => "connection_closed",
            Self::HttpRequestHeaders => "http_request_headers",
            Self::HttpResponseHeaders => "http_response_headers",
            Self::HttpBodyChunk => "http_body_chunk",
            Self::SseEvent => "sse_event",
            Self::WebSocketHandoff => "websocket_handoff",
            Self::WebSocketFrame => "websocket_frame",
            Self::WebSocketMessage => "websocket_message",
            Self::OpaqueStream => "opaque_stream",
            Self::CaptureLoss => "capture_loss",
            Self::Gap => "gap",
            Self::ProtocolError => "protocol_error",
            Self::PolicyAlert => "policy_alert",
            Self::PolicyVerdict => "policy_verdict",
            Self::PolicyRuntimeError => "policy_runtime_error",
            Self::EnforcementDecision => "enforcement_decision",
            Self::L7MitmAudit => "l7_mitm_audit",
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EventType {
    type Err = UnknownEventType;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "connection_opened" => Ok(Self::ConnectionOpened),
            "connection_closed" => Ok(Self::ConnectionClosed),
            "http_request_headers" => Ok(Self::HttpRequestHeaders),
            "http_response_headers" => Ok(Self::HttpResponseHeaders),
            "http_body_chunk" => Ok(Self::HttpBodyChunk),
            "sse_event" => Ok(Self::SseEvent),
            "websocket_handoff" => Ok(Self::WebSocketHandoff),
            "websocket_frame" => Ok(Self::WebSocketFrame),
            "websocket_message" => Ok(Self::WebSocketMessage),
            "opaque_stream" => Ok(Self::OpaqueStream),
            "capture_loss" => Ok(Self::CaptureLoss),
            "gap" => Ok(Self::Gap),
            "protocol_error" => Ok(Self::ProtocolError),
            "policy_alert" => Ok(Self::PolicyAlert),
            "policy_verdict" => Ok(Self::PolicyVerdict),
            "policy_runtime_error" => Ok(Self::PolicyRuntimeError),
            "enforcement_decision" => Ok(Self::EnforcementDecision),
            "l7_mitm_audit" => Ok(Self::L7MitmAudit),
            _ => Err(UnknownEventType {
                value: value.to_string(),
            }),
        }
    }
}

impl Serialize for EventType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown event type: {value}")]
pub struct UnknownEventType {
    value: String,
}

impl EventKind {
    pub fn name(&self) -> &'static str {
        self.event_type().as_str()
    }

    pub fn event_type(&self) -> EventType {
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

    pub fn direction(&self) -> Option<Direction> {
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
            Self::CaptureLoss(_) => None,
            Self::Gap(gap) => Some(gap.direction),
            Self::ProtocolError(error) => Some(error.direction),
            Self::ConnectionOpened
            | Self::ConnectionClosed
            | Self::PolicyAlert(_)
            | Self::PolicyVerdict(_)
            | Self::PolicyRuntimeError(_)
            | Self::EnforcementDecision(_)
            | Self::L7MitmAudit(_) => None,
        }
    }

    pub(super) fn is_degraded(&self) -> bool {
        matches!(
            self,
            Self::CaptureLoss(_) | Self::Gap(_) | Self::ProtocolError(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHeaders {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub method: Option<String>,
    pub target: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyChunk {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub offset: u64,
    pub data: Bytes,
    pub end_stream: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SseEvent {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub event: Option<String>,
    pub id: Option<String>,
    pub retry_ms: Option<u64>,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketHandoff {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub target: Option<String>,
    pub subprotocol: Option<String>,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketFrame {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub frame_sequence: u64,
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: WebSocketOpcode,
    pub payload_len: u64,
    pub masked: bool,
    pub payload_fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketMessage {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub message_sequence: u64,
    pub first_frame_sequence: u64,
    pub final_frame_sequence: u64,
    pub opcode: WebSocketMessageOpcode,
    pub payload_len: u64,
    pub payload_fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum WebSocketMessageOpcode {
    Text,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum WebSocketOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Other { code: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueStream {
    pub direction: Direction,
    pub fingerprint: Vec<u8>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureLoss {
    pub lost_events: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    pub direction: Direction,
    pub expected_offset: u64,
    pub next_offset: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    pub direction: Direction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainEvent {
    pub name: String,
    pub severity: Action,
    pub message: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuntimeError {
    pub event_type: EventType,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum L7MitmAuditEvent {
    External {
        event: L7MitmExternalBackendAudit,
    },
    ManagedProcess {
        event: L7MitmManagedProcessBackendAudit,
    },
}

impl L7MitmAuditEvent {
    pub fn phase(&self) -> L7MitmAuditPhase {
        match self {
            Self::External { event } => event.phase(),
            Self::ManagedProcess { event } => event.phase(),
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::External { event } => event.reason(),
            Self::ManagedProcess { event } => event.reason(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum L7MitmExternalBackendAudit {
    BackendStarting {
        readiness_probe: L7MitmReadinessProbeAudit,
    },
    BackendHealthProbeStarted {
        readiness_probe: L7MitmReadinessProbeAudit,
    },
    BackendUnhealthy {
        readiness_probe: L7MitmReadinessProbeAudit,
        consecutive_failures: u64,
        reason: String,
    },
    BackendRecovered {
        readiness_probe: L7MitmReadinessProbeAudit,
    },
    BackendStopping {
        readiness_probe: L7MitmReadinessProbeAudit,
    },
    BackendStopped {
        readiness_probe: L7MitmReadinessProbeAudit,
    },
    BackendStopFailed {
        readiness_probe: L7MitmReadinessProbeAudit,
        reason: String,
    },
}

impl L7MitmExternalBackendAudit {
    fn phase(&self) -> L7MitmAuditPhase {
        match self {
            Self::BackendStarting { .. } => L7MitmAuditPhase::BackendStarting,
            Self::BackendHealthProbeStarted { .. } => L7MitmAuditPhase::BackendHealthProbeStarted,
            Self::BackendUnhealthy { .. } => L7MitmAuditPhase::BackendUnhealthy,
            Self::BackendRecovered { .. } => L7MitmAuditPhase::BackendRecovered,
            Self::BackendStopping { .. } => L7MitmAuditPhase::BackendStopping,
            Self::BackendStopped { .. } => L7MitmAuditPhase::BackendStopped,
            Self::BackendStopFailed { .. } => L7MitmAuditPhase::BackendStopFailed,
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::BackendUnhealthy { reason, .. } | Self::BackendStopFailed { reason, .. } => {
                Some(reason)
            }
            Self::BackendStarting { .. }
            | Self::BackendHealthProbeStarted { .. }
            | Self::BackendRecovered { .. }
            | Self::BackendStopping { .. }
            | Self::BackendStopped { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum L7MitmManagedProcessBackendAudit {
    BackendStarting {
        readiness_probe: L7MitmReadinessProbeAudit,
        process: L7MitmManagedProcessAudit,
    },
    BackendReady {
        readiness_probe: L7MitmReadinessProbeAudit,
        process: L7MitmManagedProcessAudit,
    },
    BackendUnhealthy {
        readiness_probe: L7MitmReadinessProbeAudit,
        process: L7MitmManagedProcessAudit,
        consecutive_failures: u64,
        reason: String,
    },
    BackendRecovered {
        readiness_probe: L7MitmReadinessProbeAudit,
        process: L7MitmManagedProcessAudit,
    },
    BackendStartFailed {
        readiness_probe: L7MitmReadinessProbeAudit,
        process: L7MitmManagedProcessAudit,
        reason: String,
    },
    BackendStopping {
        readiness_probe: L7MitmReadinessProbeAudit,
        process: L7MitmManagedProcessAudit,
    },
    BackendStopped {
        readiness_probe: L7MitmReadinessProbeAudit,
        process: L7MitmManagedProcessAudit,
    },
    BackendStopFailed {
        readiness_probe: L7MitmReadinessProbeAudit,
        process: L7MitmManagedProcessAudit,
        reason: String,
    },
}

impl L7MitmManagedProcessBackendAudit {
    fn phase(&self) -> L7MitmAuditPhase {
        match self {
            Self::BackendStarting { .. } => L7MitmAuditPhase::BackendStarting,
            Self::BackendReady { .. } => L7MitmAuditPhase::BackendReady,
            Self::BackendUnhealthy { .. } => L7MitmAuditPhase::BackendUnhealthy,
            Self::BackendRecovered { .. } => L7MitmAuditPhase::BackendRecovered,
            Self::BackendStartFailed { .. } => L7MitmAuditPhase::BackendStartFailed,
            Self::BackendStopping { .. } => L7MitmAuditPhase::BackendStopping,
            Self::BackendStopped { .. } => L7MitmAuditPhase::BackendStopped,
            Self::BackendStopFailed { .. } => L7MitmAuditPhase::BackendStopFailed,
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::BackendUnhealthy { reason, .. }
            | Self::BackendStartFailed { reason, .. }
            | Self::BackendStopFailed { reason, .. } => Some(reason),
            Self::BackendStarting { .. }
            | Self::BackendReady { .. }
            | Self::BackendRecovered { .. }
            | Self::BackendStopping { .. }
            | Self::BackendStopped { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L7MitmAuditPhase {
    BackendStarting,
    BackendHealthProbeStarted,
    BackendReady,
    BackendUnhealthy,
    BackendRecovered,
    BackendStartFailed,
    BackendStopping,
    BackendStopped,
    BackendStopFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7MitmReadinessProbeAudit {
    pub target: String,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7MitmManagedProcessAudit {
    pub program: String,
    pub args_count: u64,
    pub working_dir: Option<String>,
    pub process_group: Option<i32>,
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::{
        Action, BodyChunk, CaptureLoss, Direction, DomainEvent, EnforcementDecision,
        EnforcementMode, EnforcementOutcome, EventKind, EventType, Gap, HttpHeaders,
        L7MitmAuditEvent, L7MitmAuditPhase, L7MitmExternalBackendAudit, L7MitmManagedProcessAudit,
        L7MitmManagedProcessBackendAudit, L7MitmReadinessProbeAudit, OpaqueStream,
        PolicyRuntimeError, ProtocolError, SseEvent, Verdict, VerdictScope, WebSocketFrame,
        WebSocketHandoff, WebSocketMessage, WebSocketMessageOpcode, WebSocketOpcode,
    };

    #[test]
    fn websocket_handoff_wire_type_matches_stable_event_name() {
        let kind = EventKind::WebSocketHandoff(WebSocketHandoff {
            direction: Direction::Inbound,
            stream_sequence: 1,
            target: Some("/chat".to_string()),
            subprotocol: Some("chat".to_string()),
            extensions: Vec::new(),
        });
        let value = serde_json::to_value(&kind).expect("event kind must serialize");

        assert_eq!(kind.event_type(), EventType::WebSocketHandoff);
        assert_eq!(kind.name(), EventType::WebSocketHandoff.as_str());
        assert_eq!(value["type"], EventType::WebSocketHandoff.as_str());
    }

    #[test]
    fn websocket_frame_wire_type_matches_stable_event_name() {
        let kind = EventKind::WebSocketFrame(WebSocketFrame {
            direction: Direction::Inbound,
            stream_sequence: 1,
            frame_sequence: 2,
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: WebSocketOpcode::Text,
            payload_len: 5,
            masked: false,
            payload_fingerprint: vec![1, 2, 3],
        });
        let value = serde_json::to_value(&kind).expect("event kind must serialize");

        assert_eq!(kind.event_type(), EventType::WebSocketFrame);
        assert_eq!(kind.name(), EventType::WebSocketFrame.as_str());
        assert_eq!(value["type"], EventType::WebSocketFrame.as_str());
        assert_eq!(value["opcode"]["kind"], "text");
    }

    #[test]
    fn websocket_message_wire_type_matches_stable_event_name() {
        let kind = EventKind::WebSocketMessage(WebSocketMessage {
            direction: Direction::Inbound,
            stream_sequence: 1,
            message_sequence: 2,
            first_frame_sequence: 3,
            final_frame_sequence: 4,
            opcode: WebSocketMessageOpcode::Text,
            payload_len: 5,
            payload_fingerprint: vec![1, 2, 3],
        });
        let value = serde_json::to_value(&kind).expect("event kind must serialize");

        assert_eq!(kind.event_type(), EventType::WebSocketMessage);
        assert_eq!(kind.name(), EventType::WebSocketMessage.as_str());
        assert_eq!(value["type"], EventType::WebSocketMessage.as_str());
        assert_eq!(value["opcode"]["kind"], "text");
    }

    #[test]
    fn event_type_round_trips_wire_name() -> Result<(), Box<dyn std::error::Error>> {
        for (event_type, expected) in event_type_wire_cases() {
            let value = serde_json::to_value(event_type)?;

            assert_eq!(value, expected);
            assert_eq!(serde_json::from_value::<EventType>(value)?, event_type);
        }
        Ok(())
    }

    #[test]
    fn event_kind_wire_type_matches_event_type() {
        for kind in event_kind_wire_cases() {
            let value = serde_json::to_value(&kind).expect("event kind must serialize");

            assert_eq!(value["type"], kind.event_type().as_str());
        }
    }

    fn event_type_wire_cases() -> [(EventType, &'static str); 18] {
        [
            (EventType::ConnectionOpened, "connection_opened"),
            (EventType::ConnectionClosed, "connection_closed"),
            (EventType::HttpRequestHeaders, "http_request_headers"),
            (EventType::HttpResponseHeaders, "http_response_headers"),
            (EventType::HttpBodyChunk, "http_body_chunk"),
            (EventType::SseEvent, "sse_event"),
            (EventType::WebSocketHandoff, "websocket_handoff"),
            (EventType::WebSocketFrame, "websocket_frame"),
            (EventType::WebSocketMessage, "websocket_message"),
            (EventType::OpaqueStream, "opaque_stream"),
            (EventType::CaptureLoss, "capture_loss"),
            (EventType::Gap, "gap"),
            (EventType::ProtocolError, "protocol_error"),
            (EventType::PolicyAlert, "policy_alert"),
            (EventType::PolicyVerdict, "policy_verdict"),
            (EventType::PolicyRuntimeError, "policy_runtime_error"),
            (EventType::EnforcementDecision, "enforcement_decision"),
            (EventType::L7MitmAudit, "l7_mitm_audit"),
        ]
    }

    fn event_kind_wire_cases() -> [EventKind; 18] {
        [
            EventKind::ConnectionOpened,
            EventKind::ConnectionClosed,
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
            EventKind::HttpResponseHeaders(HttpHeaders {
                direction: Direction::Inbound,
                stream_sequence: 1,
                method: None,
                target: None,
                status: Some(200),
                reason: Some("OK".to_string()),
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
            EventKind::HttpBodyChunk(BodyChunk {
                direction: Direction::Inbound,
                stream_sequence: 1,
                offset: 0,
                data: Bytes::from_static(b"hello"),
                end_stream: true,
            }),
            EventKind::SseEvent(SseEvent {
                direction: Direction::Inbound,
                stream_sequence: 1,
                event: None,
                id: None,
                retry_ms: None,
                data: "hello".to_string(),
            }),
            EventKind::WebSocketHandoff(WebSocketHandoff {
                direction: Direction::Inbound,
                stream_sequence: 1,
                target: Some("/chat".to_string()),
                subprotocol: Some("chat".to_string()),
                extensions: Vec::new(),
            }),
            EventKind::WebSocketFrame(WebSocketFrame {
                direction: Direction::Inbound,
                stream_sequence: 1,
                frame_sequence: 1,
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: WebSocketOpcode::Text,
                payload_len: 5,
                masked: false,
                payload_fingerprint: vec![1, 2, 3],
            }),
            EventKind::WebSocketMessage(WebSocketMessage {
                direction: Direction::Inbound,
                stream_sequence: 1,
                message_sequence: 1,
                first_frame_sequence: 1,
                final_frame_sequence: 1,
                opcode: WebSocketMessageOpcode::Text,
                payload_len: 5,
                payload_fingerprint: vec![1, 2, 3],
            }),
            EventKind::OpaqueStream(OpaqueStream {
                direction: Direction::Inbound,
                fingerprint: vec![1, 2, 3],
                reason: "opaque".to_string(),
            }),
            EventKind::CaptureLoss(CaptureLoss {
                lost_events: 3,
                reason: "eBPF output ring buffer could not accept 3 event(s)".to_string(),
            }),
            EventKind::Gap(Gap {
                direction: Direction::Inbound,
                expected_offset: 1,
                next_offset: Some(2),
                reason: "gap".to_string(),
            }),
            EventKind::ProtocolError(ProtocolError {
                direction: Direction::Inbound,
                reason: "bad frame".to_string(),
            }),
            EventKind::PolicyAlert(DomainEvent {
                name: "alert".to_string(),
                severity: Action::Alert,
                message: "message".to_string(),
                metadata: serde_json::Value::Null,
            }),
            EventKind::PolicyVerdict(Verdict {
                action: Action::Alert,
                scope: VerdictScope::Flow,
                reason: "matched".to_string(),
                confidence: 100,
                ttl_ms: None,
            }),
            EventKind::PolicyRuntimeError(PolicyRuntimeError {
                event_type: EventType::HttpRequestHeaders,
                reason: "policy failed".to_string(),
            }),
            EventKind::EnforcementDecision(EnforcementDecision {
                mode: EnforcementMode::DryRun,
                outcome: EnforcementOutcome::DryRun,
                requested_action: Action::Deny,
                effective_action: Action::Observe,
                scope: VerdictScope::Flow,
                selector_matched: true,
                reason: "dry run".to_string(),
            }),
            EventKind::L7MitmAudit(L7MitmAuditEvent::ManagedProcess {
                event: L7MitmManagedProcessBackendAudit::BackendReady {
                    readiness_probe: readiness_probe_audit(),
                    process: managed_process_audit(),
                },
            }),
        ]
    }

    #[test]
    fn l7_mitm_audit_wire_shape_is_backend_specific() -> Result<(), Box<dyn std::error::Error>> {
        let external = EventKind::L7MitmAudit(L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendHealthProbeStarted {
                readiness_probe: readiness_probe_audit(),
            },
        });
        let managed = EventKind::L7MitmAudit(L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendStartFailed {
                readiness_probe: readiness_probe_audit(),
                process: managed_process_audit(),
                reason: "readiness failed".to_string(),
            },
        });

        let external = serde_json::to_value(&external)?;
        assert_eq!(external["type"], "l7_mitm_audit");
        assert_eq!(external["backend"], "external");
        assert_eq!(external["event"]["phase"], "backend_health_probe_started");
        assert!(external["event"].get("process").is_none());
        assert!(external["event"].get("reason").is_none());

        let managed = serde_json::to_value(&managed)?;
        assert_eq!(managed["type"], "l7_mitm_audit");
        assert_eq!(managed["backend"], "managed_process");
        assert_eq!(managed["event"]["phase"], "backend_start_failed");
        assert_eq!(managed["event"]["reason"], "readiness failed");
        assert_eq!(managed["event"]["process"]["args_count"], 2);
        Ok(())
    }

    #[test]
    fn l7_mitm_health_transition_audit_preserves_reason_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let unhealthy = L7MitmAuditEvent::External {
            event: L7MitmExternalBackendAudit::BackendUnhealthy {
                readiness_probe: readiness_probe_audit(),
                consecutive_failures: 3,
                reason: "connection refused".to_string(),
            },
        };
        let recovered = L7MitmAuditEvent::ManagedProcess {
            event: L7MitmManagedProcessBackendAudit::BackendRecovered {
                readiness_probe: readiness_probe_audit(),
                process: managed_process_audit(),
            },
        };

        assert_eq!(unhealthy.phase(), L7MitmAuditPhase::BackendUnhealthy);
        assert_eq!(unhealthy.reason(), Some("connection refused"));
        assert_eq!(recovered.phase(), L7MitmAuditPhase::BackendRecovered);
        assert_eq!(recovered.reason(), None);

        let unhealthy = serde_json::to_value(EventKind::L7MitmAudit(unhealthy))?;
        assert_eq!(unhealthy["event"]["phase"], "backend_unhealthy");
        assert_eq!(unhealthy["event"]["consecutive_failures"], 3);
        assert_eq!(unhealthy["event"]["reason"], "connection refused");

        let recovered = serde_json::to_value(EventKind::L7MitmAudit(recovered))?;
        assert_eq!(recovered["event"]["phase"], "backend_recovered");
        assert!(recovered["event"].get("reason").is_none());
        Ok(())
    }

    fn readiness_probe_audit() -> L7MitmReadinessProbeAudit {
        L7MitmReadinessProbeAudit {
            target: "127.0.0.1:15002".to_string(),
            interval_ms: 1_000,
            timeout_ms: 100,
            failure_threshold: 3,
        }
    }

    fn managed_process_audit() -> L7MitmManagedProcessAudit {
        L7MitmManagedProcessAudit {
            program: "/usr/local/bin/traffic-probe-mitm-proxy".to_string(),
            args_count: 2,
            working_dir: None,
            process_group: Some(42),
        }
    }
}

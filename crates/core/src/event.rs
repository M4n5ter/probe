use std::{fmt, str::FromStr};

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{Action, EnforcementDecision, FlowContext, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    EbpfSyscall,
    Libpcap,
    LibsslUprobe,
    ExternalPlaintextFeed,
    Replay,
    Mock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    pub monotonic_ns: u64,
    pub wall_time_unix_ns: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub String);

impl EventId {
    pub fn stable(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Self {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part.as_ref());
            hasher.update(&[0]);
        }
        Self(hasher.finalize().to_hex().to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub id: EventId,
    pub timestamp: Timestamp,
    pub flow: FlowContext,
    pub source: CaptureSource,
    pub config_version: String,
    pub policy_version: Option<String>,
    pub degraded: bool,
    pub kind: EventKind,
}

impl EventEnvelope {
    pub fn new(
        timestamp: Timestamp,
        flow: FlowContext,
        source: CaptureSource,
        config_version: impl Into<String>,
        kind: EventKind,
    ) -> Self {
        let config_version = config_version.into();
        let degraded = kind.is_degraded();
        let id = Self::stable_id(timestamp, &flow, source, &config_version, None, &kind);
        Self {
            id,
            timestamp,
            flow,
            source,
            config_version,
            policy_version: None,
            degraded,
            kind,
        }
    }

    pub fn with_policy_version(mut self, policy_version: impl Into<String>) -> Self {
        self.policy_version = Some(policy_version.into());
        self.id = Self::stable_id(
            self.timestamp,
            &self.flow,
            self.source,
            &self.config_version,
            self.policy_version.as_deref(),
            &self.kind,
        );
        self
    }

    pub fn with_degraded(mut self, degraded: bool) -> Self {
        self.degraded = self.degraded || degraded;
        self
    }

    fn stable_id(
        timestamp: Timestamp,
        flow: &FlowContext,
        source: CaptureSource,
        config_version: &str,
        policy_version: Option<&str>,
        kind: &EventKind,
    ) -> EventId {
        let source_fingerprint = format!("{source:?}");
        let monotonic_ns = timestamp.monotonic_ns.to_be_bytes();
        let kind_fingerprint =
            serde_json::to_vec(kind).unwrap_or_else(|_| format!("{kind:?}").into_bytes());
        EventId::stable([
            flow.id.0.as_bytes(),
            config_version.as_bytes(),
            policy_version.unwrap_or_default().as_bytes(),
            source_fingerprint.as_bytes(),
            kind.event_type().as_str().as_bytes(),
            monotonic_ns.as_slice(),
            kind_fingerprint.as_slice(),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    ConnectionOpened,
    ConnectionClosed,
    HttpRequestHeaders(HttpHeaders),
    HttpResponseHeaders(HttpHeaders),
    HttpBodyChunk(BodyChunk),
    SseEvent(SseEvent),
    #[serde(rename = "websocket_handoff")]
    WebSocketHandoff(WebSocketHandoff),
    OpaqueStream(OpaqueStream),
    Gap(Gap),
    ProtocolError(ProtocolError),
    PolicyAlert(DomainEvent),
    PolicyVerdict(Verdict),
    EnforcementDecision(EnforcementDecision),
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
    OpaqueStream,
    Gap,
    ProtocolError,
    PolicyAlert,
    PolicyVerdict,
    EnforcementDecision,
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
            Self::OpaqueStream => "opaque_stream",
            Self::Gap => "gap",
            Self::ProtocolError => "protocol_error",
            Self::PolicyAlert => "policy_alert",
            Self::PolicyVerdict => "policy_verdict",
            Self::EnforcementDecision => "enforcement_decision",
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
            "opaque_stream" => Ok(Self::OpaqueStream),
            "gap" => Ok(Self::Gap),
            "protocol_error" => Ok(Self::ProtocolError),
            "policy_alert" => Ok(Self::PolicyAlert),
            "policy_verdict" => Ok(Self::PolicyVerdict),
            "enforcement_decision" => Ok(Self::EnforcementDecision),
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
            Self::OpaqueStream(_) => EventType::OpaqueStream,
            Self::Gap(_) => EventType::Gap,
            Self::ProtocolError(_) => EventType::ProtocolError,
            Self::PolicyAlert(_) => EventType::PolicyAlert,
            Self::PolicyVerdict(_) => EventType::PolicyVerdict,
            Self::EnforcementDecision(_) => EventType::EnforcementDecision,
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
            Self::OpaqueStream(stream) => Some(stream.direction),
            Self::Gap(gap) => Some(gap.direction),
            Self::ProtocolError(error) => Some(error.direction),
            Self::ConnectionOpened
            | Self::ConnectionClosed
            | Self::PolicyAlert(_)
            | Self::PolicyVerdict(_)
            | Self::EnforcementDecision(_) => None,
        }
    }

    fn is_degraded(&self) -> bool {
        matches!(self, Self::Gap(_) | Self::ProtocolError(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct BodyChunk {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub offset: u64,
    pub data: Bytes,
    pub end_stream: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SseEvent {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub event: Option<String>,
    pub id: Option<String>,
    pub retry_ms: Option<u64>,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketHandoff {
    pub direction: Direction,
    pub stream_sequence: u64,
    pub target: Option<String>,
    pub subprotocol: Option<String>,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueStream {
    pub direction: Direction,
    pub fingerprint: Vec<u8>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    pub direction: Direction,
    pub expected_offset: u64,
    pub next_offset: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolError {
    pub direction: Direction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEvent {
    pub name: String,
    pub severity: Action,
    pub message: String,
    pub metadata: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use crate::{
        Action, AddressPort, CaptureSource, Direction, DomainEvent, EnforcementDecision,
        EnforcementMode, EnforcementOutcome, EventEnvelope, EventKind, EventType, FlowContext,
        FlowIdentity, Gap, HttpHeaders, OpaqueStream, ProcessContext, ProcessIdentity,
        ProtocolError, SseEvent, Timestamp, TransportProtocol, Verdict, VerdictScope,
        WebSocketHandoff,
    };

    #[test]
    fn event_id_changes_when_event_payload_changes() {
        let first = request_event(CaptureSource::Replay, "/first");
        let second = request_event(CaptureSource::Replay, "/second");

        assert_ne!(first.id, second.id);
    }

    #[test]
    fn event_id_changes_when_capture_source_changes() {
        let replay = request_event(CaptureSource::Replay, "/same");
        let mock = request_event(CaptureSource::Mock, "/same");

        assert_ne!(replay.id, mock.id);
    }

    #[test]
    fn event_id_changes_when_policy_version_changes() {
        let first = request_event(CaptureSource::Replay, "/same").with_policy_version("policy@1");
        let second = request_event(CaptureSource::Replay, "/same").with_policy_version("policy@2");

        assert_ne!(first.id, second.id);
    }

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

    fn event_type_wire_cases() -> [(EventType, &'static str); 13] {
        [
            (EventType::ConnectionOpened, "connection_opened"),
            (EventType::ConnectionClosed, "connection_closed"),
            (EventType::HttpRequestHeaders, "http_request_headers"),
            (EventType::HttpResponseHeaders, "http_response_headers"),
            (EventType::HttpBodyChunk, "http_body_chunk"),
            (EventType::SseEvent, "sse_event"),
            (EventType::WebSocketHandoff, "websocket_handoff"),
            (EventType::OpaqueStream, "opaque_stream"),
            (EventType::Gap, "gap"),
            (EventType::ProtocolError, "protocol_error"),
            (EventType::PolicyAlert, "policy_alert"),
            (EventType::PolicyVerdict, "policy_verdict"),
            (EventType::EnforcementDecision, "enforcement_decision"),
        ]
    }

    fn event_kind_wire_cases() -> [EventKind; 13] {
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
            EventKind::HttpBodyChunk(crate::BodyChunk {
                direction: Direction::Inbound,
                stream_sequence: 1,
                offset: 0,
                data: bytes::Bytes::from_static(b"hello"),
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
            EventKind::OpaqueStream(OpaqueStream {
                direction: Direction::Inbound,
                fingerprint: vec![1, 2, 3],
                reason: "opaque".to_string(),
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
            EventKind::EnforcementDecision(EnforcementDecision {
                mode: EnforcementMode::DryRun,
                outcome: EnforcementOutcome::DryRun,
                requested_action: Action::Deny,
                effective_action: Action::Observe,
                scope: VerdictScope::Flow,
                selector_matched: true,
                reason: "dry run".to_string(),
            }),
        ]
    }

    fn request_event(source: CaptureSource, target: &str) -> EventEnvelope {
        EventEnvelope::new(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            source,
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some(target.to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

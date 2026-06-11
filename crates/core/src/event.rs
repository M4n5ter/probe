use bytes::Bytes;
use serde::{Deserialize, Serialize};

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
            kind.stable_discriminant().as_bytes(),
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

impl EventKind {
    pub fn name(&self) -> &'static str {
        self.stable_discriminant()
    }

    fn stable_discriminant(&self) -> &'static str {
        match self {
            Self::ConnectionOpened => "connection_opened",
            Self::ConnectionClosed => "connection_closed",
            Self::HttpRequestHeaders(_) => "http_request_headers",
            Self::HttpResponseHeaders(_) => "http_response_headers",
            Self::HttpBodyChunk(_) => "http_body_chunk",
            Self::SseEvent(_) => "sse_event",
            Self::WebSocketHandoff(_) => "websocket_handoff",
            Self::OpaqueStream(_) => "opaque_stream",
            Self::Gap(_) => "gap",
            Self::ProtocolError(_) => "protocol_error",
            Self::PolicyAlert(_) => "policy_alert",
            Self::PolicyVerdict(_) => "policy_verdict",
            Self::EnforcementDecision(_) => "enforcement_decision",
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
        AddressPort, CaptureSource, Direction, EventEnvelope, EventKind, FlowContext, FlowIdentity,
        HttpHeaders, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
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
        let value = serde_json::to_value(EventKind::WebSocketHandoff(WebSocketHandoff {
            direction: Direction::Inbound,
            stream_sequence: 1,
            target: Some("/chat".to_string()),
            subprotocol: Some("chat".to_string()),
            extensions: Vec::new(),
        }))
        .expect("event kind must serialize");

        assert_eq!(value["type"], "websocket_handoff");
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

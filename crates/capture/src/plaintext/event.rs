use bytes::Bytes;
use probe_core::{
    CaptureOrigin, CaptureSource, Direction, EnforcementEvidence, FlowContext, Gap, Timestamp,
};
use serde::{Deserialize, Serialize};

use crate::{CaptureEvent, CapturedBytes, CapturedGap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextSource {
    ExternalPlaintextFeed,
    LibsslUprobe,
    TlsSessionSecret,
}

impl PlaintextSource {
    pub fn capture_source(self) -> CaptureSource {
        match self {
            Self::ExternalPlaintextFeed => CaptureSource::ExternalPlaintextFeed,
            Self::LibsslUprobe => CaptureSource::LibsslUprobe,
            Self::TlsSessionSecret => CaptureSource::TlsSessionSecret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextChunk {
    pub timestamp: Timestamp,
    pub flow: FlowContext,
    pub direction: Direction,
    pub stream_offset: u64,
    pub bytes: Bytes,
    pub attribution_confidence: u8,
    pub degraded: bool,
    pub degradation_reason: Option<String>,
}

impl PlaintextChunk {
    pub fn new(
        timestamp: Timestamp,
        flow: FlowContext,
        direction: Direction,
        bytes: impl AsRef<[u8]>,
    ) -> Self {
        let attribution_confidence = flow.attribution_confidence;
        Self {
            timestamp,
            flow,
            direction,
            stream_offset: 0,
            bytes: Bytes::copy_from_slice(bytes.as_ref()),
            attribution_confidence,
            degraded: false,
            degradation_reason: None,
        }
    }

    pub fn with_stream_offset(mut self, stream_offset: u64) -> Self {
        self.stream_offset = stream_offset;
        self
    }

    pub fn with_degradation(mut self, reason: impl Into<String>) -> Self {
        self.degraded = true;
        self.degradation_reason = Some(reason.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextConnection {
    pub timestamp: Timestamp,
    pub flow: FlowContext,
}

impl PlaintextConnection {
    pub fn new(timestamp: Timestamp, flow: FlowContext) -> Self {
        Self { timestamp, flow }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextGap {
    pub timestamp: Timestamp,
    pub flow: FlowContext,
    pub gap: Gap,
}

impl PlaintextGap {
    pub fn new(timestamp: Timestamp, flow: FlowContext, gap: Gap) -> Self {
        Self {
            timestamp,
            flow,
            gap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextEvent {
    pub source: PlaintextSource,
    #[serde(flatten)]
    pub kind: PlaintextEventKind,
}

impl PlaintextEvent {
    pub fn new(source: PlaintextSource, kind: PlaintextEventKind) -> Self {
        Self { source, kind }
    }

    pub fn bytes(source: PlaintextSource, chunk: PlaintextChunk) -> Self {
        Self::new(source, PlaintextEventKind::Bytes(chunk))
    }

    pub fn gap(source: PlaintextSource, gap: PlaintextGap) -> Self {
        Self::new(source, PlaintextEventKind::Gap(gap))
    }

    pub fn connection_opened(source: PlaintextSource, connection: PlaintextConnection) -> Self {
        Self::new(source, PlaintextEventKind::ConnectionOpened(connection))
    }

    pub fn connection_closed(source: PlaintextSource, connection: PlaintextConnection) -> Self {
        Self::new(source, PlaintextEventKind::ConnectionClosed(connection))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlaintextEventKind {
    Bytes(PlaintextChunk),
    Gap(PlaintextGap),
    ConnectionOpened(PlaintextConnection),
    ConnectionClosed(PlaintextConnection),
}

impl From<PlaintextEvent> for CaptureEvent {
    fn from(value: PlaintextEvent) -> Self {
        let source = value.source.capture_source();
        match value.kind {
            PlaintextEventKind::Bytes(chunk) => CaptureEvent::Bytes(CapturedBytes {
                timestamp: chunk.timestamp,
                flow: chunk.flow,
                origin: CaptureOrigin::from_source(source),
                direction: chunk.direction,
                stream_offset: chunk.stream_offset,
                bytes: chunk.bytes,
                attribution_confidence: chunk.attribution_confidence,
                degraded: chunk.degraded,
                degradation_reason: chunk.degradation_reason,
                enforcement_evidence: EnforcementEvidence::default(),
                enforcement_evidence_propagation: crate::EnforcementEvidencePropagation::Event,
            }),
            PlaintextEventKind::Gap(gap) => CaptureEvent::Gap(CapturedGap {
                timestamp: gap.timestamp,
                flow: gap.flow,
                origin: CaptureOrigin::from_source(source),
                enforcement_evidence: EnforcementEvidence::default(),
                enforcement_evidence_propagation: crate::EnforcementEvidencePropagation::Event,
                gap: gap.gap,
            }),
            PlaintextEventKind::ConnectionOpened(connection) => CaptureEvent::ConnectionOpened {
                timestamp: connection.timestamp,
                flow: connection.flow,
                origin: CaptureOrigin::from_source(source),
            },
            PlaintextEventKind::ConnectionClosed(connection) => CaptureEvent::ConnectionClosed {
                timestamp: connection.timestamp,
                flow: connection.flow,
                origin: CaptureOrigin::from_source(source),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::CaptureProviderKind;

    use probe_core::{
        AddressPort, FlowIdentity, ProcessContext, ProcessIdentity, TransportProtocol,
    };

    use super::*;

    #[test]
    fn plaintext_event_preserves_chunk_metadata() {
        let timestamp = Timestamp {
            monotonic_ns: 7,
            wall_time_unix_ns: 11,
        };
        let flow = demo_flow();
        let chunk = PlaintextChunk::new(
            timestamp,
            flow.clone(),
            Direction::Outbound,
            b"GET / HTTP/1.1\r\n\r\n",
        )
        .with_stream_offset(5)
        .with_degradation("source reported a partial plaintext stream");
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(PlaintextEvent::bytes(
            PlaintextSource::ExternalPlaintextFeed,
            chunk,
        )) else {
            panic!("expected plaintext bytes");
        };

        assert_eq!(bytes.timestamp, timestamp);
        assert_eq!(bytes.flow, flow);
        assert_eq!(bytes.origin.source(), CaptureSource::ExternalPlaintextFeed);
        assert_eq!(bytes.origin.provider(), CaptureProviderKind::Plaintext);
        assert_eq!(bytes.direction, Direction::Outbound);
        assert_eq!(bytes.stream_offset, 5);
        assert_eq!(bytes.bytes.as_ref(), b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(bytes.attribution_confidence, 100);
        assert!(bytes.degraded);
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some("source reported a partial plaintext stream")
        );
    }

    #[test]
    fn plaintext_event_wire_type_is_stable() {
        let value = serde_json::to_value(PlaintextEvent::bytes(
            PlaintextSource::ExternalPlaintextFeed,
            PlaintextChunk::new(
                Timestamp {
                    monotonic_ns: 1,
                    wall_time_unix_ns: 1,
                },
                demo_flow(),
                Direction::Outbound,
                b"GET / HTTP/1.1\r\n\r\n",
            ),
        ))
        .expect("plaintext event must serialize");

        assert_eq!(value["type"], "bytes");
        assert_eq!(value["source"], "external_plaintext_feed");
    }

    #[test]
    fn plaintext_event_source_controls_capture_source() {
        let event = PlaintextEvent::bytes(
            PlaintextSource::TlsSessionSecret,
            PlaintextChunk::new(
                Timestamp {
                    monotonic_ns: 1,
                    wall_time_unix_ns: 1,
                },
                demo_flow(),
                Direction::Outbound,
                b"GET / HTTP/1.1\r\n\r\n",
            ),
        );

        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(event) else {
            panic!("expected plaintext bytes");
        };

        assert_eq!(bytes.origin.source(), CaptureSource::TlsSessionSecret);
        assert_eq!(bytes.origin.provider(), CaptureProviderKind::Plaintext);
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/bin/demo".to_string(),
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
            port: 12345,
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

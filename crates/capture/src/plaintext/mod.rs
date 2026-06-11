use std::collections::VecDeque;

use bytes::Bytes;
use probe_core::{
    CapabilityKind, CapabilityState, CaptureSource, Direction, FlowContext, Gap, Timestamp,
};
use serde::{Deserialize, Serialize};

use crate::{
    CaptureError, CaptureEvent, CaptureProvider, CaptureProviderKind, CapturedBytes, CapturedGap,
};

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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlaintextFeedEvent {
    Bytes(PlaintextChunk),
    Gap(PlaintextGap),
    ConnectionOpened(PlaintextConnection),
    ConnectionClosed(PlaintextConnection),
}

impl From<PlaintextChunk> for PlaintextFeedEvent {
    fn from(value: PlaintextChunk) -> Self {
        Self::Bytes(value)
    }
}

impl From<PlaintextFeedEvent> for CaptureEvent {
    fn from(value: PlaintextFeedEvent) -> Self {
        match value {
            PlaintextFeedEvent::Bytes(chunk) => CaptureEvent::Bytes(CapturedBytes {
                timestamp: chunk.timestamp,
                flow: chunk.flow,
                source: CaptureSource::ExternalPlaintextFeed,
                provider: CaptureProviderKind::Plaintext,
                direction: chunk.direction,
                stream_offset: chunk.stream_offset,
                bytes: chunk.bytes,
                attribution_confidence: chunk.attribution_confidence,
                degraded: chunk.degraded,
                degradation_reason: chunk.degradation_reason,
            }),
            PlaintextFeedEvent::Gap(gap) => CaptureEvent::Gap(CapturedGap {
                timestamp: gap.timestamp,
                flow: gap.flow,
                source: CaptureSource::ExternalPlaintextFeed,
                provider: CaptureProviderKind::Plaintext,
                gap: gap.gap,
            }),
            PlaintextFeedEvent::ConnectionOpened(connection) => CaptureEvent::ConnectionOpened {
                timestamp: connection.timestamp,
                flow: connection.flow,
                source: CaptureSource::ExternalPlaintextFeed,
                provider: CaptureProviderKind::Plaintext,
            },
            PlaintextFeedEvent::ConnectionClosed(connection) => CaptureEvent::ConnectionClosed {
                timestamp: connection.timestamp,
                flow: connection.flow,
                source: CaptureSource::ExternalPlaintextFeed,
                provider: CaptureProviderKind::Plaintext,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextFeedProvider {
    events: VecDeque<PlaintextFeedEvent>,
}

impl PlaintextFeedProvider {
    pub fn new(events: impl IntoIterator<Item = PlaintextFeedEvent>) -> Self {
        Self {
            events: events.into_iter().collect(),
        }
    }

    pub fn from_chunks(chunks: impl IntoIterator<Item = PlaintextChunk>) -> Self {
        Self::new(chunks.into_iter().map(PlaintextFeedEvent::from))
    }
}

impl CaptureProvider for PlaintextFeedProvider {
    fn name(&self) -> &'static str {
        "plaintext_feed"
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Plaintext
    }

    fn source(&self) -> CaptureSource {
        CaptureSource::ExternalPlaintextFeed
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(
            CapabilityKind::ExternalPlaintextFeed,
        )]
    }

    fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        Ok(self.events.pop_front().map(CaptureEvent::from))
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, FlowIdentity, ProcessContext, ProcessIdentity, TransportProtocol,
    };

    use super::*;

    #[test]
    fn plaintext_feed_provider_preserves_chunk_metadata() -> Result<(), Box<dyn std::error::Error>>
    {
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
        let mut provider = PlaintextFeedProvider::from_chunks([chunk]);

        let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected plaintext bytes");
        };

        assert_eq!(bytes.timestamp, timestamp);
        assert_eq!(bytes.flow, flow);
        assert_eq!(bytes.source, CaptureSource::ExternalPlaintextFeed);
        assert_eq!(bytes.provider, CaptureProviderKind::Plaintext);
        assert_eq!(bytes.direction, Direction::Outbound);
        assert_eq!(bytes.stream_offset, 5);
        assert_eq!(bytes.bytes.as_ref(), b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(bytes.attribution_confidence, 100);
        assert!(bytes.degraded);
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some("source reported a partial plaintext stream")
        );
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn plaintext_feed_event_wire_type_is_stable() {
        let value = serde_json::to_value(PlaintextFeedEvent::Bytes(PlaintextChunk::new(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            Direction::Outbound,
            b"GET / HTTP/1.1\r\n\r\n",
        )))
        .expect("plaintext feed event must serialize");

        assert_eq!(value["type"], "bytes");
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

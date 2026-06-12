use bytes::Bytes;
use probe_core::{
    CapabilityKind, CapabilityState, CaptureSource, Direction, FlowContext, Timestamp,
};

use crate::{
    CapturedBytes,
    event::CaptureEvent,
    provider::{CaptureError, CaptureProvider, CaptureProviderKind},
};

pub struct ReplayProvider {
    flow: FlowContext,
    direction: Direction,
    timestamp: Timestamp,
    bytes: Option<Bytes>,
}

impl ReplayProvider {
    pub fn new(
        flow: FlowContext,
        direction: Direction,
        bytes: impl AsRef<[u8]>,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            flow,
            direction,
            timestamp,
            bytes: Some(Bytes::copy_from_slice(bytes.as_ref())),
        }
    }
}

impl CaptureProvider for ReplayProvider {
    fn name(&self) -> &'static str {
        "replay"
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Replay
    }

    fn source(&self) -> CaptureSource {
        CaptureSource::Replay
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(CapabilityKind::ReplayCapture)]
    }

    fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        let Some(bytes) = self.bytes.take() else {
            return Ok(None);
        };
        Ok(Some(CaptureEvent::Bytes(CapturedBytes {
            timestamp: self.timestamp,
            flow: self.flow.clone(),
            source: self.source(),
            provider: self.kind(),
            direction: self.direction,
            stream_offset: 0,
            bytes,
            attribution_confidence: self.flow.attribution_confidence,
            degraded: false,
            degradation_reason: None,
        })))
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, FlowIdentity, ProcessContext, ProcessIdentity, TransportProtocol,
    };

    use super::*;

    #[test]
    fn replay_provider_yields_one_chunk() -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = Timestamp {
            monotonic_ns: 7,
            wall_time_unix_ns: 11,
        };
        let mut provider = ReplayProvider::new(
            demo_flow(),
            Direction::Outbound,
            b"GET / HTTP/1.1\r\n\r\n",
            timestamp,
        );

        let Some(CaptureEvent::Bytes(chunk)) = provider.next()? else {
            panic!("expected replay bytes");
        };
        assert_eq!(chunk.timestamp, timestamp);
        assert_eq!(chunk.source, CaptureSource::Replay);
        assert_eq!(chunk.provider, CaptureProviderKind::Replay);
        assert_eq!(chunk.bytes.as_ref(), b"GET / HTTP/1.1\r\n\r\n");
        assert!(provider.next()?.is_none());
        Ok(())
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

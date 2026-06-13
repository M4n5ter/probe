use std::collections::VecDeque;

use probe_core::{CapabilityKind, CapabilityState};
use thiserror::Error;

use crate::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CaptureProviderKind};

use super::{PlaintextChunk, PlaintextEvent, PlaintextSource};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextEventProvider {
    source: PlaintextSource,
    events: VecDeque<PlaintextEvent>,
}

impl PlaintextEventProvider {
    pub fn new(
        source: PlaintextSource,
        events: impl IntoIterator<Item = PlaintextEvent>,
    ) -> Result<Self, PlaintextEventProviderError> {
        let events = events.into_iter().try_fold(
            VecDeque::new(),
            |mut events, event| -> Result<_, PlaintextEventProviderError> {
                let actual = event.source;
                if actual != source {
                    return Err(PlaintextEventProviderError::SourceMismatch {
                        expected: source,
                        actual,
                    });
                }
                events.push_back(event);
                Ok(events)
            },
        )?;
        Ok(Self { source, events })
    }

    pub fn from_chunks(
        source: PlaintextSource,
        chunks: impl IntoIterator<Item = PlaintextChunk>,
    ) -> Self {
        Self {
            source,
            events: chunks
                .into_iter()
                .map(|chunk| PlaintextEvent::bytes(source, chunk))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlaintextEventProviderError {
    #[error("plaintext event source mismatch: expected {expected:?}, got {actual:?}")]
    SourceMismatch {
        expected: PlaintextSource,
        actual: PlaintextSource,
    },
}

impl CaptureProvider for PlaintextEventProvider {
    fn name(&self) -> &'static str {
        match self.source {
            PlaintextSource::ExternalPlaintextFeed => "plaintext_event_external_feed",
            PlaintextSource::LibsslUprobe => "plaintext_event_libssl_uprobe",
        }
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Plaintext
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(match self.source {
            PlaintextSource::ExternalPlaintextFeed => CapabilityKind::ExternalPlaintextFeed,
            PlaintextSource::LibsslUprobe => CapabilityKind::LibsslUprobe,
        })]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        Ok(self
            .events
            .pop_front()
            .map(CaptureEvent::from)
            .map(CapturePoll::event)
            .unwrap_or(CapturePoll::Finished))
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureSource, Direction, FlowContext, FlowIdentity, ProcessContext,
        ProcessIdentity, Timestamp, TransportProtocol,
    };

    use super::*;

    #[test]
    fn provider_preserves_single_source_events() -> Result<(), Box<dyn std::error::Error>> {
        let mut provider = PlaintextEventProvider::from_chunks(
            PlaintextSource::LibsslUprobe,
            [PlaintextChunk::new(
                Timestamp {
                    monotonic_ns: 1,
                    wall_time_unix_ns: 1,
                },
                demo_flow(),
                Direction::Outbound,
                b"GET / HTTP/1.1\r\n\r\n",
            )],
        );

        let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected plaintext bytes");
        };

        assert_eq!(bytes.source, CaptureSource::LibsslUprobe);
        assert_eq!(
            provider.capabilities(),
            vec![CapabilityState::available(CapabilityKind::LibsslUprobe)]
        );
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn provider_rejects_mismatched_event_source() {
        let error = PlaintextEventProvider::new(
            PlaintextSource::LibsslUprobe,
            [PlaintextEvent::bytes(
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
            )],
        )
        .expect_err("provider source must match queued events");

        assert_eq!(
            error,
            PlaintextEventProviderError::SourceMismatch {
                expected: PlaintextSource::LibsslUprobe,
                actual: PlaintextSource::ExternalPlaintextFeed,
            }
        );
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

use std::time::{SystemTime, UNIX_EPOCH};

use capture::{
    CAPTURE_BYTES_JSON_SCHEMA, CaptureError, CaptureEvent, CaptureProvider, CapturedBytes,
};
use parsers::{ParserInput, ProtocolParserFactory};
use policy::{PolicyOutcome, PolicyRuntime, hook_for_event};
use probe_core::{EventEnvelope, EventKind, Timestamp};
use proto::EVENT_ENVELOPE_JSON_SCHEMA;
use storage::{DurableSpool, SpoolPayload};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("capture error: {0}")]
    Capture(#[from] CaptureError),
    #[error("failed to serialize pipeline payload: {0}")]
    Json(#[from] serde_json::Error),
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("policy error: {0}")]
    Policy(#[from] policy::PolicyError),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PipelineSummary {
    pub ingress_chunks: u64,
    pub export_events: u64,
}

pub struct CapturePipeline<'a, S> {
    spool: &'a S,
    parser_factory: &'a mut dyn ProtocolParserFactory,
    policy: Option<&'a PolicyRuntime>,
    config_version: String,
    clock: PipelineClock,
}

impl<'a, S> CapturePipeline<'a, S>
where
    S: DurableSpool,
{
    pub fn new(
        spool: &'a S,
        parser_factory: &'a mut dyn ProtocolParserFactory,
        policy: Option<&'a PolicyRuntime>,
        config_version: impl Into<String>,
    ) -> Self {
        Self {
            spool,
            parser_factory,
            policy,
            config_version: config_version.into(),
            clock: PipelineClock::default(),
        }
    }

    pub fn run_provider(
        &mut self,
        provider: &mut dyn CaptureProvider,
    ) -> Result<PipelineSummary, PipelineError> {
        let mut summary = PipelineSummary::default();
        while let Some(capture_event) = provider.next()? {
            self.handle_capture_event(capture_event, &mut summary)?;
        }
        Ok(summary)
    }

    fn handle_capture_event(
        &mut self,
        capture_event: CaptureEvent,
        summary: &mut PipelineSummary,
    ) -> Result<(), PipelineError> {
        match capture_event {
            CaptureEvent::Bytes(chunk) => {
                let capture_sequence = self.append_capture_chunk(&chunk)?;
                summary.ingress_chunks = summary.ingress_chunks.saturating_add(1);
                let events = self
                    .parser_factory
                    .parser_for_flow(&chunk.flow.id)
                    .ingest(ParserInput::Data {
                        direction: chunk.direction,
                        bytes: chunk.bytes.as_ref(),
                    })
                    .into_events();

                for event in events {
                    let envelope = EventEnvelope::new(
                        self.clock.next_timestamp(),
                        chunk.flow.clone(),
                        chunk.source,
                        self.config_version.clone(),
                        event,
                    )
                    .with_degraded(chunk.degraded);
                    summary.export_events = summary
                        .export_events
                        .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
                }
                self.spool.ack_ingress("parser", capture_sequence)?;
            }
            CaptureEvent::Gap(gap) => {
                let parser_events = self
                    .parser_factory
                    .parser_for_flow(&gap.flow.id)
                    .ingest(ParserInput::Gap {
                        direction: gap.gap.direction,
                        expected_offset: gap.gap.expected_offset,
                        next_offset: gap.gap.next_offset,
                        reason: &gap.gap.reason,
                    })
                    .into_events();
                for event in parser_events {
                    let envelope = EventEnvelope::new(
                        gap.timestamp,
                        gap.flow.clone(),
                        gap.source,
                        self.config_version.clone(),
                        event,
                    );
                    summary.export_events = summary
                        .export_events
                        .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
                }
            }
            CaptureEvent::ConnectionOpened {
                timestamp,
                flow,
                source,
                ..
            } => {
                let envelope = EventEnvelope::new(
                    timestamp,
                    flow,
                    source,
                    self.config_version.clone(),
                    EventKind::ConnectionOpened,
                );
                summary.export_events = summary
                    .export_events
                    .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
            }
            CaptureEvent::ConnectionClosed {
                timestamp,
                flow,
                source,
                ..
            } => {
                let flow_id = flow.id.clone();
                let envelope = EventEnvelope::new(
                    timestamp,
                    flow,
                    source,
                    self.config_version.clone(),
                    EventKind::ConnectionClosed,
                );
                summary.export_events = summary
                    .export_events
                    .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
                self.parser_factory.remove_flow(&flow_id);
            }
        }
        Ok(())
    }

    fn append_capture_chunk(&self, chunk: &CapturedBytes) -> Result<u64, PipelineError> {
        let payload = serde_json::to_vec(chunk)?;
        let stored = self
            .spool
            .append_ingress(SpoolPayload::new(CAPTURE_BYTES_JSON_SCHEMA, payload))?;
        Ok(stored.sequence)
    }

    fn append_envelope_and_policy_outcomes(
        &mut self,
        envelope: EventEnvelope,
    ) -> Result<u64, PipelineError> {
        self.append_envelope(&envelope)?;
        let mut written = 1;

        let Some(policy) = self.policy else {
            return Ok(written);
        };
        let outcomes = policy.handle_event(hook_for_event(&envelope), &envelope)?;
        for outcome in outcomes {
            let kind = match outcome {
                PolicyOutcome::Alert(alert) => EventKind::PolicyAlert(alert),
                PolicyOutcome::Verdict(verdict) => EventKind::PolicyVerdict(verdict),
            };
            let policy_version = format!("{}@{}", policy.manifest().id, policy.manifest().version);
            let policy_envelope = EventEnvelope::new(
                self.clock.next_timestamp(),
                envelope.flow.clone(),
                envelope.source,
                envelope.config_version.clone(),
                kind,
            )
            .with_policy_version(policy_version)
            .with_degraded(envelope.degraded);
            self.append_envelope(&policy_envelope)?;
            written += 1;
        }

        Ok(written)
    }

    fn append_envelope(&self, envelope: &EventEnvelope) -> Result<(), PipelineError> {
        let payload = serde_json::to_vec(envelope)?;
        self.spool
            .append_export(SpoolPayload::new(EVENT_ENVELOPE_JSON_SCHEMA, payload))?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct PipelineClock {
    next_monotonic_ns: u64,
}

impl PipelineClock {
    fn next_timestamp(&mut self) -> Timestamp {
        self.next_monotonic_ns = self.next_monotonic_ns.saturating_add(1);
        Timestamp {
            monotonic_ns: self.next_monotonic_ns,
            wall_time_unix_ns: wall_time_unix_ns(),
        }
    }
}

fn wall_time_unix_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as i128)
}

#[cfg(test)]
mod tests {
    use capture::{CaptureProviderKind, CapturedBytes, ReplayProvider};
    use parsers::Http1ParserFactory;
    use probe_core::{
        AddressPort, CapabilityState, CaptureSource, Direction, EventEnvelope, FlowContext,
        FlowIdentity, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn replay_provider_writes_ingress_and_export_lanes() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = storage::FjallSpool::open(temp.path())?;
        let mut parser_factory = Http1ParserFactory::default();
        let mut provider = ReplayProvider::new(
            demo_flow(),
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
        );
        let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, None, "test");

        let summary = pipeline.run_provider(&mut provider)?;

        assert_eq!(summary.ingress_chunks, 1);
        assert_eq!(summary.export_events, 2);
        assert_eq!(spool.ingress_cursor("parser")?, 1);
        assert_eq!(spool.read_ingress_batch("debug", 10)?.len(), 1);
        assert_eq!(spool.read_export_batch("sink", 10)?.len(), 2);
        Ok(())
    }

    #[test]
    fn live_pipeline_isolates_parser_state_per_flow() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = storage::FjallSpool::open(temp.path())?;
        let mut parser_factory = Http1ParserFactory::default();
        let flow_a = demo_flow_with_ports(50_000, 80, 1);
        let flow_b = demo_flow_with_ports(50_001, 80, 2);
        let mut provider = SequenceProvider::new(vec![
            captured_bytes(
                flow_a.clone(),
                b"POST /a HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\nhe",
            ),
            captured_bytes(
                flow_b.clone(),
                b"GET /b HTTP/1.1\r\nHost: b.test\r\nContent-Length: 0\r\n\r\n",
            ),
            captured_bytes(flow_a, b"llo"),
        ]);
        let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, None, "test");

        let summary = pipeline.run_provider(&mut provider)?;

        assert_eq!(summary.ingress_chunks, 3);
        let exported = spool.read_export_batch("sink", 16)?;
        let envelopes = exported
            .iter()
            .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(envelopes.iter().any(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers) if headers.target.as_deref() == Some("/a")
            )
        }));
        assert!(envelopes.iter().any(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers) if headers.target.as_deref() == Some("/b")
            )
        }));
        assert!(envelopes.iter().any(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::HttpBodyChunk(chunk) if chunk.data.as_ref() == b"llo" && chunk.end_stream
            )
        }));
        assert!(
            !envelopes
                .iter()
                .any(|envelope| matches!(envelope.kind, EventKind::ProtocolError(_)))
        );
        Ok(())
    }

    struct SequenceProvider {
        events: std::vec::IntoIter<CaptureEvent>,
    }

    impl SequenceProvider {
        fn new(events: Vec<CaptureEvent>) -> Self {
            Self {
                events: events.into_iter(),
            }
        }
    }

    impl CaptureProvider for SequenceProvider {
        fn name(&self) -> &'static str {
            "sequence"
        }

        fn kind(&self) -> CaptureProviderKind {
            CaptureProviderKind::Replay
        }

        fn source(&self) -> CaptureSource {
            CaptureSource::Replay
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
            Ok(self.events.next())
        }
    }

    fn captured_bytes(flow: FlowContext, bytes: &'static [u8]) -> CaptureEvent {
        CaptureEvent::Bytes(CapturedBytes {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow,
            source: CaptureSource::Replay,
            provider: CaptureProviderKind::Replay,
            direction: Direction::Outbound,
            stream_offset: 0,
            bytes: bytes.into(),
            attribution_confidence: 0,
            degraded: false,
            degradation_reason: None,
        })
    }

    fn demo_flow() -> FlowContext {
        demo_flow_with_ports(50_000, 80, 1)
    }

    fn demo_flow_with_ports(local_port: u16, remote_port: u16, socket_cookie: u64) -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "replay".to_string(),
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
            port: local_port,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: remote_port,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "replay".to_string(),
                cmdline: vec!["replay".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(socket_cookie),
            attribution_confidence: 0,
        }
    }
}

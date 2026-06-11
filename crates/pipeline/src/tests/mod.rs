use capture::{
    CaptureProviderKind, CapturedBytes, PlaintextChunk, PlaintextFeedProvider, ReplayProvider,
};
use enforcement::ScopedEnforcementPlanner;
use parsers::Http1ParserFactory;
use policy::{PolicyManifest, PolicyRuntime};
use probe_core::{
    Action, AddressPort, CapabilityState, CaptureSource, Direction, EnforcementMode,
    EnforcementOutcome, EventEnvelope, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity,
    ProcessSelector, Selector, Timestamp, TrafficSelector, TransportProtocol,
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
fn plaintext_feed_provider_writes_ingress_and_http_export_events()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(50_000, 443, 13);
    let mut provider = PlaintextFeedProvider::from_chunks([PlaintextChunk::new(
        Timestamp {
            monotonic_ns: 1,
            wall_time_unix_ns: 1,
        },
        flow,
        Direction::Outbound,
        b"GET /plaintext HTTP/1.1\r\nHost: tls.example\r\n\r\n",
    )]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, None, "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.capture_events, 1);
    assert_eq!(summary.ingress_chunks, 1);
    let exported = spool.read_export_batch("sink", 16)?;
    let envelopes = exported
        .iter()
        .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(envelopes.iter().any(|envelope| {
        envelope.source == CaptureSource::ExternalPlaintextFeed
            && matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.target.as_deref() == Some("/plaintext")
            )
    }));
    assert!(
        !envelopes
            .iter()
            .any(|envelope| matches!(envelope.kind, EventKind::ProtocolError(_)))
    );
    Ok(())
}

#[test]
fn policy_verdicts_are_evaluated_by_scoped_enforcement_planner()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "deny-policy".to_string(),
            version: "v1".to_string(),
            hooks: vec!["on_http_request_headers".to_string()],
        },
        r#"
function on_http_request_headers(event)
  return probe.verdict({
action = "deny",
scope = "request",
reason = "blocked in test",
confidence = 100,
  })
end
"#,
    )?;
    let mut enforcement_planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, None)?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(50_000, 80, 4);
    let mut provider = SequenceProvider::new(vec![captured_bytes(
        flow,
        b"GET /blocked HTTP/1.1\r\nHost: test\r\n\r\n",
    )]);
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        Some(PipelinePolicy::unscoped(&policy)),
        "test",
    )
    .with_enforcement_planner(&mut enforcement_planner);

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_chunks, 1);
    let exported = spool.read_export_batch("sink", 16)?;
    let envelopes = exported
        .iter()
        .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::PolicyVerdict(verdict) if verdict.action == Action::Deny
        )
    }));
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::EnforcementDecision(decision)
                if decision.outcome == EnforcementOutcome::DryRun
                    && decision.requested_action == Action::Deny
                    && decision.effective_action == Action::Observe
                    && decision.selector_matched
        )
    }));
    Ok(())
}

#[test]
fn policy_selector_scopes_policy_execution() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "scoped-policy".to_string(),
            version: "v1".to_string(),
            hooks: vec!["on_http_request_headers".to_string()],
        },
        r#"
function on_http_request_headers(event)
  return probe.emit_alert("matched " .. event.kind.target)
end
"#,
    )?;
    let selector = Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            remote_ports: vec![443],
            ..TrafficSelector::default()
        },
    )
    .compile()?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(vec![
        captured_bytes(
            demo_flow_with_ports(50_000, 80, 20),
            b"GET /miss HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_001, 443, 21),
            b"GET /hit HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
    ]);
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        Some(PipelinePolicy::new(&policy, Some(&selector))),
        "test",
    );

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_chunks, 2);
    let exported = spool.read_export_batch("sink", 16)?;
    let envelopes = exported
        .iter()
        .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let alerts = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind, EventKind::PolicyAlert(_)))
        .collect::<Vec<_>>();
    assert_eq!(alerts.len(), 1);
    assert!(matches!(
        &alerts[0].kind,
        EventKind::PolicyAlert(alert) if alert.message == "matched /hit"
    ));
    Ok(())
}

#[test]
fn websocket_handoff_reaches_policy_and_export_spool() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "websocket-policy".to_string(),
            version: "v1".to_string(),
            hooks: vec!["on_websocket_handoff".to_string()],
        },
        r#"
function on_websocket_handoff(event)
  return probe.emit_alert("websocket " .. event.kind.target .. " " .. event.kind.subprotocol)
end
"#,
    )?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(50_000, 80, 12);
    let mut provider = SequenceProvider::new(vec![
        captured_bytes_with_direction(
            flow.clone(),
            Direction::Outbound,
            b"GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test\r\n\r\n",
        ),
        captured_bytes_with_direction(
            flow.clone(),
            Direction::Inbound,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: chat\r\n\r\n",
        ),
        captured_bytes_with_direction(flow, Direction::Inbound, b"\x81\x02hi"),
    ]);
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        Some(PipelinePolicy::unscoped(&policy)),
        "test",
    );

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_chunks, 3);
    assert!(
        summary.export_events >= 5,
        "request, response, handoff, policy alert, and opaque events should be exported"
    );

    let exported = spool.read_export_batch("sink", 16)?;
    let envelopes = exported
        .iter()
        .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let values = exported
        .iter()
        .map(|event| serde_json::from_slice::<serde_json::Value>(event.payload.bytes()))
        .collect::<Result<Vec<_>, _>>()?;

    assert!(values.iter().any(|event| {
        event["kind"]["type"] == "websocket_handoff"
            && event["kind"]["target"] == "/chat"
            && event["kind"]["subprotocol"] == "chat"
    }));
    let handoff_index = envelopes
        .iter()
        .position(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::WebSocketHandoff(handoff)
                    if handoff.direction == Direction::Inbound
                        && handoff.target.as_deref() == Some("/chat")
                        && handoff.subprotocol.as_deref() == Some("chat")
            )
        })
        .expect("websocket handoff should be exported");
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::PolicyAlert(alert)
                if alert.message == "websocket /chat chat"
        )
    }));
    let opaque_index = envelopes
        .iter()
        .position(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::OpaqueStream(opaque) if opaque.direction == Direction::Inbound
            )
        })
        .expect("websocket bytes after handoff should be opaque");
    assert!(handoff_index < opaque_index);
    assert!(
        !envelopes
            .iter()
            .skip(handoff_index + 1)
            .any(|envelope| matches!(envelope.kind, EventKind::HttpBodyChunk(_)))
    );
    assert!(
        !envelopes
            .iter()
            .any(|envelope| matches!(envelope.kind, EventKind::ProtocolError(_)))
    );
    Ok(())
}

#[test]
fn connection_close_flushes_close_delimited_http_body() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(50_000, 80, 5);
    let mut provider = SequenceProvider::new(vec![
        captured_bytes_with_direction(
            flow.clone(),
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\n\r\nhello",
        ),
        connection_closed(flow),
    ]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, None, "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_chunks, 1);
    let exported = spool.read_export_batch("sink", 16)?;
    let envelopes = exported
        .iter()
        .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let body_chunk_index = envelopes
        .iter()
        .position(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::HttpBodyChunk(chunk)
                    if chunk.direction == Direction::Inbound
                        && chunk.data.as_ref() == b"hello"
                        && !chunk.end_stream
            )
        })
        .expect("close-delimited body bytes should be exported");
    let end_stream_index = envelopes
        .iter()
        .position(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::HttpBodyChunk(chunk)
                    if chunk.direction == Direction::Inbound
                        && chunk.data.is_empty()
                        && chunk.end_stream
            )
        })
        .expect("connection close should flush end_stream marker");
    let close_index = envelopes
        .iter()
        .position(|envelope| matches!(envelope.kind, EventKind::ConnectionClosed))
        .expect("connection close should be exported");
    assert!(body_chunk_index < end_stream_index);
    assert!(end_stream_index < close_index);
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

#[test]
fn run_provider_with_options_stops_after_max_capture_events()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(vec![
        captured_bytes(
            demo_flow_with_ports(50_000, 80, 10),
            b"GET /one HTTP/1.1\r\nHost: one.test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_001, 80, 11),
            b"GET /two HTTP/1.1\r\nHost: two.test\r\n\r\n",
        ),
    ]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, None, "test");

    let summary =
        pipeline.run_provider_with_options(&mut provider, PipelineRunOptions::max_events(1))?;

    assert_eq!(summary.capture_events, 1);
    assert_eq!(summary.ingress_chunks, 1);
    assert_eq!(spool.read_ingress_batch("debug", 10)?.len(), 1);
    assert_eq!(spool.read_export_batch("sink", 10)?.len(), 1);
    Ok(())
}

#[test]
fn run_provider_with_zero_max_events_does_not_read_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = UnreadableProvider;
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, None, "test");

    let summary =
        pipeline.run_provider_with_options(&mut provider, PipelineRunOptions::max_events(0))?;

    assert_eq!(summary.capture_events, 0);
    assert_eq!(summary.ingress_chunks, 0);
    assert!(spool.read_ingress_batch("debug", 10)?.is_empty());
    assert!(spool.read_export_batch("sink", 10)?.is_empty());
    Ok(())
}

#[test]
fn live_pipeline_parses_process_inbound_request_as_request()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(80, 50_000, 3);
    let mut provider = SequenceProvider::new(vec![captured_bytes_with_direction(
        flow,
        Direction::Inbound,
        b"GET /server HTTP/1.1\r\nHost: server.test\r\n\r\n",
    )]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, None, "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_chunks, 1);
    let exported = spool.read_export_batch("sink", 16)?;
    let envelopes = exported
        .iter()
        .map(|event| serde_json::from_slice::<EventEnvelope>(event.payload.bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::HttpRequestHeaders(headers)
                if headers.direction == Direction::Inbound
                    && headers.target.as_deref() == Some("/server")
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

struct UnreadableProvider;

impl CaptureProvider for UnreadableProvider {
    fn name(&self) -> &'static str {
        "unreadable"
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
        Err(CaptureError::provider(
            "unreadable",
            "provider.next must not be called when max_events is zero",
        ))
    }
}

fn captured_bytes(flow: FlowContext, bytes: &'static [u8]) -> CaptureEvent {
    captured_bytes_with_direction(flow, Direction::Outbound, bytes)
}

fn captured_bytes_with_direction(
    flow: FlowContext,
    direction: Direction,
    bytes: &'static [u8],
) -> CaptureEvent {
    CaptureEvent::Bytes(CapturedBytes {
        timestamp: Timestamp {
            monotonic_ns: 1,
            wall_time_unix_ns: 1,
        },
        flow,
        source: CaptureSource::Replay,
        provider: CaptureProviderKind::Replay,
        direction,
        stream_offset: 0,
        bytes: bytes.into(),
        attribution_confidence: 0,
        degraded: false,
        degradation_reason: None,
    })
}

fn connection_closed(flow: FlowContext) -> CaptureEvent {
    CaptureEvent::ConnectionClosed {
        timestamp: Timestamp {
            monotonic_ns: 2,
            wall_time_unix_ns: 2,
        },
        flow,
        source: CaptureSource::Replay,
        provider: CaptureProviderKind::Replay,
    }
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

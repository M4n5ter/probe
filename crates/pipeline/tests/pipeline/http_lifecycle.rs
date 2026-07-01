use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelinePolicy};
use policy::{PolicyHook, PolicyManifest, PolicyRuntime};
use probe_core::{Direction, EventKind};
use tempfile::tempdir;

use super::fixture::{
    SequenceProvider, captured_bytes, captured_bytes_with_direction, connection_closed,
    demo_flow_with_ports, exported_envelopes,
};

#[test]
fn websocket_handoff_reaches_policy_and_export_spool() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "websocket-policy".to_string(),
            version: "test-version".to_string(),
            hooks: vec![PolicyHook::WebSocketHandoff],
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
        vec![PipelinePolicy::unscoped(policy)],
        "test",
    );

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 3);
    assert_eq!(summary.ingress_records_processed, 3);
    assert!(
        summary.export_events_written >= 6,
        "request, response, handoff, policy alert, websocket frame, and websocket message events should be exported"
    );

    let exported = spool.read_export_batch("sink", 16)?;
    let envelopes = exported_envelopes(&spool)?;
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
                envelope.kind(),
                EventKind::WebSocketHandoff(handoff)
                    if handoff.direction == Direction::Inbound
                        && handoff.target.as_deref() == Some("/chat")
                        && handoff.subprotocol.as_deref() == Some("chat")
            )
        })
        .expect("websocket handoff should be exported");
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::PolicyAlert(alert)
                if alert.message == "websocket /chat chat"
        )
    }));
    let frame_index = envelopes
        .iter()
        .position(|envelope| {
            matches!(
                envelope.kind(),
                EventKind::WebSocketFrame(frame)
                    if frame.direction == Direction::Inbound
                        && frame.payload_len == 2
                        && frame.frame_sequence == 1
            )
        })
        .expect("websocket bytes after handoff should be parsed as frame metadata");
    let message_index = envelopes
        .iter()
        .position(|envelope| {
            matches!(
                envelope.kind(),
                EventKind::WebSocketMessage(message)
                    if message.direction == Direction::Inbound
                        && message.payload_len == 2
                        && message.payload.as_ref() == b"hi"
                        && message.message_sequence == 1
                        && message.first_frame_sequence == 1
                        && message.final_frame_sequence == 1
            )
        })
        .expect("websocket bytes after handoff should be parsed as message metadata");
    assert!(handoff_index < frame_index);
    assert!(frame_index < message_index);
    assert!(
        !envelopes
            .iter()
            .skip(handoff_index + 1)
            .any(|envelope| matches!(envelope.kind(), EventKind::HttpBodyChunk(_)))
    );
    assert!(
        !envelopes
            .iter()
            .any(|envelope| matches!(envelope.kind(), EventKind::ProtocolError(_)))
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
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 2);
    assert_eq!(summary.ingress_records_processed, 2);
    let envelopes = exported_envelopes(&spool)?;
    let body_chunk_index = envelopes
        .iter()
        .position(|envelope| {
            matches!(
                envelope.kind(),
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
                envelope.kind(),
                EventKind::HttpBodyChunk(chunk)
                    if chunk.direction == Direction::Inbound
                        && chunk.data.is_empty()
                        && chunk.end_stream
            )
        })
        .expect("connection close should flush end_stream marker");
    let close_index = envelopes
        .iter()
        .position(|envelope| matches!(envelope.kind(), EventKind::ConnectionClosed))
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
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 3);
    assert_eq!(summary.ingress_records_processed, 3);
    let envelopes = exported_envelopes(&spool)?;
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::HttpRequestHeaders(headers) if headers.target.as_deref() == Some("/a")
        )
    }));
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::HttpRequestHeaders(headers) if headers.target.as_deref() == Some("/b")
        )
    }));
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::HttpBodyChunk(chunk) if chunk.data.as_ref() == b"llo" && chunk.end_stream
        )
    }));
    assert!(
        !envelopes
            .iter()
            .any(|envelope| matches!(envelope.kind(), EventKind::ProtocolError(_)))
    );
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
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    let envelopes = exported_envelopes(&spool)?;
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::HttpRequestHeaders(headers)
                if headers.direction == Direction::Inbound
                    && headers.target.as_deref() == Some("/server")
        )
    }));
    assert!(
        !envelopes
            .iter()
            .any(|envelope| matches!(envelope.kind(), EventKind::ProtocolError(_)))
    );
    Ok(())
}

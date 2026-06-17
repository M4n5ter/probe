use std::{fs, path::Path, process::ExitCode};

use capture::CaptureEvent;
use probe_core::{
    CaptureProviderKind, CaptureSource, Direction, EventEnvelope, EventKind, WebSocketOpcode,
};
use storage::{FjallSpool, StoredEvent};

use super::harness::{
    decode_capture_event, decode_envelope, e2e_error, run_agent_with_max_events, run_with_temp_root,
};
use super::plaintext_scenario::{
    PlaintextFeedRecord, PlaintextFeedScenario, PlaintextFlow, PlaintextHttpRequest,
    PlaintextPolicy, PlaintextProcess, PlaintextScenarioIds,
};

const WEBSOCKET_FEED_EVENT_COUNT: usize = 5;
const WEBSOCKET_EXPORT_EVENT_COUNT: usize = 8;
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";
const AGENT_ID: &str = "e2e-websocket-agent";
const CONFIG_VERSION: &str = "e2e-websocket-plaintext-feed";
const CONNECTION_ID: &str = "xtask-e2e-websocket-conn";
const POLICY_ID: &str = "e2e-websocket-policy";
const POLICY_VERSION: &str = "e2e";
const REQUEST_TARGET: &str = "/chat";
const SUBPROTOCOL: &str = "chat";
const RFC_SAMPLE_WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const RFC_SAMPLE_WEBSOCKET_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const FRAME_PAYLOAD: &[u8] = b"hi";
const FRAME_PAYLOAD_FINGERPRINT: [u8; 16] = [
    133, 5, 46, 154, 171, 27, 103, 182, 98, 45, 148, 160, 132, 65, 176, 159,
];
const HANDOFF_ALERT: &str = "websocket handoff /chat chat";
const FRAME_ALERT: &str = "websocket frame text 2";

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e websocket plaintext feed failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("websocket-plaintext-feed", run_at)?;
    println!("e2e websocket plaintext feed passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("feed.jsonl");
    let policy_path = root.join("e2e-websocket-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let scenario = scenario();
    write_feed(&scenario, &feed_path)?;
    write_policy_bundle(&policy_path)?;
    let mut config = scenario.agent_config(feed_path, policy_path, spool_path.clone());
    config.export.worker.enabled = false;
    fs::write(&config_path, toml::to_string(&config)?)?;
    run_agent_with_max_events(&config_path, WEBSOCKET_FEED_EVENT_COUNT)?;
    assert_spool_outputs(&spool_path, &scenario)?;

    Ok(())
}

fn scenario() -> PlaintextFeedScenario {
    PlaintextFeedScenario::new(
        PlaintextScenarioIds::new(
            AGENT_ID,
            CONFIG_VERSION,
            POLICY_ID,
            POLICY_VERSION,
            CONNECTION_ID,
        ),
        PlaintextHttpRequest::get(REQUEST_TARGET, "websocket.e2e.test"),
        PlaintextPolicy::alerting("websocket policy observed "),
    )
    .with_flow(PlaintextFlow::new(
        52_100,
        8_080,
        2003,
        PlaintextProcess::new(
            422,
            755,
            "sssa-e2e-websocket",
            "/usr/bin/sssa-e2e-websocket",
            "websocket-hash",
        ),
    ))
}

fn write_feed(
    scenario: &PlaintextFeedScenario,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = websocket_upgrade_request();
    let response = websocket_upgrade_response();
    let frame = websocket_text_frame(FRAME_PAYLOAD);
    scenario.write_feed_records(
        path,
        [
            PlaintextFeedRecord::connection_opened(),
            PlaintextFeedRecord::bytes(Direction::Outbound, 0, request.clone()),
            PlaintextFeedRecord::bytes(Direction::Inbound, 0, response.clone()),
            PlaintextFeedRecord::bytes(
                Direction::Inbound,
                u64::try_from(response.len())?,
                frame.clone(),
            ),
            PlaintextFeedRecord::connection_closed(),
        ],
    )
}

fn websocket_upgrade_request() -> Vec<u8> {
    format!(
        "GET {REQUEST_TARGET} HTTP/1.1\r\nHost: websocket.e2e.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {RFC_SAMPLE_WEBSOCKET_KEY}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n"
    )
    .into_bytes()
}

fn websocket_upgrade_response() -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {RFC_SAMPLE_WEBSOCKET_ACCEPT}\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n"
    )
    .into_bytes()
}

fn websocket_text_frame(payload: &[u8]) -> Vec<u8> {
    let len =
        u8::try_from(payload.len()).expect("e2e websocket frame payload must fit short frame");
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x81);
    frame.push(len);
    frame.extend_from_slice(payload);
    frame
}

fn write_policy_bundle(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)?;
    fs::write(
        path.join("manifest.toml"),
        format!(
            r#"
id = "{POLICY_ID}"
version = "{POLICY_VERSION}"
hooks = ["on_websocket_handoff", "on_websocket_frame"]
"#
        ),
    )?;
    fs::write(
        path.join("main.lua"),
        r#"
function on_websocket_handoff(event)
  return probe.emit_alert("websocket handoff " .. event.kind.target .. " " .. event.kind.subprotocol)
end

function on_websocket_frame(event)
  return probe.emit_alert(
    "websocket frame " .. event.kind.opcode.kind .. " " .. tostring(event.kind.payload_len)
  )
end
"#,
    )
}

fn assert_spool_outputs(
    spool_path: &Path,
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    if ingress.len() != WEBSOCKET_FEED_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {WEBSOCKET_FEED_EVENT_COUNT} websocket ingress records, got {}",
            ingress.len()
        ))
        .into());
    }
    assert_ingress_events(&ingress, scenario)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 64)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    if envelopes.len() != WEBSOCKET_EXPORT_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {WEBSOCKET_EXPORT_EVENT_COUNT} websocket export records, got {}",
            envelopes.len()
        ))
        .into());
    }
    assert_websocket_exports(&envelopes, scenario)?;

    println!(
        "e2e websocket plaintext feed observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}
fn assert_ingress_events(
    events: &[StoredEvent],
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    let [opened, request, response, frame, closed] = capture_events.as_slice() else {
        return Err(e2e_error(format!(
            "expected {WEBSOCKET_FEED_EVENT_COUNT} ordered websocket ingress events, got {}",
            capture_events.len()
        ))
        .into());
    };

    if !matches!(
        opened,
        CaptureEvent::ConnectionOpened { origin, flow, .. }
            if origin.source() == CaptureSource::ExternalPlaintextFeed
                && origin.provider() == CaptureProviderKind::Plaintext
                && flow.id.0 == scenario.expected_flow_id()
    ) {
        return Err(e2e_error("missing websocket ingress connection_opened event").into());
    }
    assert_bytes_event(
        request,
        scenario,
        Direction::Outbound,
        0,
        websocket_upgrade_request().as_slice(),
        "upgrade request",
    )?;
    let upgrade_response = websocket_upgrade_response();
    assert_bytes_event(
        response,
        scenario,
        Direction::Inbound,
        0,
        upgrade_response.as_slice(),
        "upgrade response",
    )?;
    assert_bytes_event(
        frame,
        scenario,
        Direction::Inbound,
        u64::try_from(upgrade_response.len())?,
        websocket_text_frame(FRAME_PAYLOAD).as_slice(),
        "websocket frame",
    )?;
    if !matches!(
        closed,
        CaptureEvent::ConnectionClosed { origin, flow, .. }
            if origin.source() == CaptureSource::ExternalPlaintextFeed
                && origin.provider() == CaptureProviderKind::Plaintext
                && flow.id.0 == scenario.expected_flow_id()
    ) {
        return Err(e2e_error("missing websocket ingress connection_closed event").into());
    }
    Ok(())
}

fn assert_bytes_event(
    event: &CaptureEvent,
    scenario: &PlaintextFeedScenario,
    direction: Direction,
    stream_offset: u64,
    expected: &[u8],
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        event,
        CaptureEvent::Bytes(bytes)
            if bytes.origin.source() == CaptureSource::ExternalPlaintextFeed
                && bytes.origin.provider() == CaptureProviderKind::Plaintext
                && bytes.flow.id.0 == scenario.expected_flow_id()
                && bytes.direction == direction
                && bytes.stream_offset == stream_offset
                && bytes.bytes.as_ref() == expected
    ) {
        return Ok(());
    }
    Err(e2e_error(format!(
        "missing expected websocket ingress {label} bytes event"
    ))
    .into())
}

fn assert_websocket_exports(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_index =
        single_event_position(envelopes, scenario, "HTTP upgrade request", |kind| {
            matches!(
                kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.direction == Direction::Outbound
                        && headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(REQUEST_TARGET)
            )
        })?;
    let response_index = single_event_position(envelopes, scenario, "HTTP 101 response", |kind| {
        matches!(
            kind,
            EventKind::HttpResponseHeaders(headers)
                if headers.direction == Direction::Inbound
                    && headers.status == Some(101)
                    && has_header(
                        &headers.headers,
                        "sec-websocket-accept",
                        RFC_SAMPLE_WEBSOCKET_ACCEPT,
                    )
                    && has_header(&headers.headers, "sec-websocket-protocol", SUBPROTOCOL)
        )
    })?;
    let handoff_index = single_event_position(envelopes, scenario, "WebSocket handoff", |kind| {
        matches!(
            kind,
            EventKind::WebSocketHandoff(handoff)
                if handoff.direction == Direction::Inbound
                    && handoff.target.as_deref() == Some(REQUEST_TARGET)
                    && handoff.subprotocol.as_deref() == Some(SUBPROTOCOL)
        )
    })?;
    let frame_index = single_event_position(envelopes, scenario, "WebSocket frame", |kind| {
        matches!(
            kind,
            EventKind::WebSocketFrame(frame)
                if frame.direction == Direction::Inbound
                    && frame.frame_sequence == 1
                    && frame.fin
                    && !frame.masked
                    && matches!(frame.opcode, WebSocketOpcode::Text)
                    && frame.payload_len == u64::try_from(FRAME_PAYLOAD.len()).unwrap_or(u64::MAX)
                    && frame.payload_fingerprint.as_slice() == FRAME_PAYLOAD_FINGERPRINT.as_slice()
        )
    })?;

    if !(request_index < response_index
        && response_index < handoff_index
        && handoff_index < frame_index)
    {
        return Err(e2e_error(format!(
            "websocket export order was request={request_index}, response={response_index}, handoff={handoff_index}, frame={frame_index}"
        ))
        .into());
    }
    assert_policy_alert(envelopes, scenario, HANDOFF_ALERT)?;
    assert_policy_alert(envelopes, scenario, FRAME_ALERT)?;
    assert_lifecycle_exports(envelopes, scenario)?;
    assert_no_protocol_errors_after_handoff(envelopes, handoff_index)?;
    Ok(())
}

fn single_event_position(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedScenario,
    label: &str,
    matches_kind: impl Fn(&EventKind) -> bool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let matching_positions = envelopes
        .iter()
        .enumerate()
        .filter_map(|(position, envelope)| {
            (is_expected_feed_flow(envelope, scenario) && matches_kind(envelope.kind()))
                .then_some(position)
        })
        .collect::<Vec<_>>();
    let [position] = matching_positions.as_slice() else {
        return Err(e2e_error(format!(
            "expected exactly one websocket export event for {label}, got {} at positions {matching_positions:?}",
            matching_positions.len()
        ))
        .into());
    };
    Ok(*position)
}

fn has_header(headers: &[(String, String)], name: &str, value: &str) -> bool {
    headers
        .iter()
        .any(|(header_name, header_value)| header_name == name && header_value == value)
}

fn assert_policy_alert(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedScenario,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_policy_version = scenario.expected_policy_version();
    let matching_alerts = envelopes
        .iter()
        .filter(|envelope| {
            is_expected_feed_flow(envelope, scenario)
                && envelope.policy_version() == Some(expected_policy_version.as_str())
                && matches!(
                    envelope.kind(),
                    EventKind::PolicyAlert(alert) if alert.message == message
                )
        })
        .count();
    if matching_alerts == 1 {
        return Ok(());
    }
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert) => Some(alert.message.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    Err(e2e_error(format!(
        "expected exactly one websocket policy alert {message}, got {matching_alerts}; observed alerts {observed:?}"
    ))
    .into())
}

fn assert_lifecycle_exports(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let opened = envelopes
        .iter()
        .filter(|envelope| {
            is_expected_feed_flow(envelope, scenario)
                && matches!(envelope.kind(), EventKind::ConnectionOpened)
        })
        .count();
    let closed = envelopes
        .iter()
        .filter(|envelope| {
            is_expected_feed_flow(envelope, scenario)
                && matches!(envelope.kind(), EventKind::ConnectionClosed)
        })
        .count();
    if opened == 1 && closed == 1 {
        return Ok(());
    }
    Err(e2e_error(format!(
        "expected exactly one websocket connection_opened and connection_closed export, got opened={opened}, closed={closed}"
    ))
    .into())
}

fn assert_no_protocol_errors_after_handoff(
    envelopes: &[EventEnvelope],
    handoff_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes
        .iter()
        .skip(handoff_index + 1)
        .any(|envelope| matches!(envelope.kind(), EventKind::HttpBodyChunk(_)))
    {
        return Err(e2e_error("websocket payload was parsed as HTTP body after handoff").into());
    }
    if envelopes
        .iter()
        .any(|envelope| matches!(envelope.kind(), EventKind::ProtocolError(_)))
    {
        return Err(e2e_error("websocket plaintext feed produced a protocol error").into());
    }
    Ok(())
}

fn is_expected_feed_flow(envelope: &EventEnvelope, scenario: &PlaintextFeedScenario) -> bool {
    envelope.origin().source() == CaptureSource::ExternalPlaintextFeed
        && envelope.origin().provider() == CaptureProviderKind::Plaintext
        && envelope
            .flow()
            .is_some_and(|flow| flow.id.0 == scenario.expected_flow_id())
}

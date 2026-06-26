use std::{fs, path::Path, process::ExitCode};

use probe_core::{Direction, EventEnvelope, EventKind, WebSocketOpcode};
use storage::{FjallSpool, StoredEvent};

use super::harness::{decode_envelope, e2e_error, run_agent_with_max_events, run_with_temp_root};
use super::plaintext_assertions::{
    assert_no_http_body_chunks_after, assert_no_protocol_errors, assert_ordered_export_positions,
    assert_plaintext_feed_records, assert_policy_alert, export_event_position, has_header,
};
use super::plaintext_scenario::{
    PlaintextFeedCase, PlaintextFeedRecord, PlaintextFlow, PlaintextProcess,
};
use super::websocket_expectations::{
    FRAME_PAYLOAD, FRAME_PAYLOAD_FINGERPRINT, FRAME_PAYLOAD_LEN, REQUEST_TARGET,
    RFC_SAMPLE_WEBSOCKET_ACCEPT, RFC_SAMPLE_WEBSOCKET_KEY, SUBPROTOCOL,
};

const CONTEXT: &str = "websocket";
const WEBSOCKET_FEED_EVENT_COUNT: usize = 5;
const WEBSOCKET_CAPTURE_READ_LIMIT: usize = WEBSOCKET_FEED_EVENT_COUNT + 1;
const WEBSOCKET_EXPORT_EVENT_COUNT: usize = 8;
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";
const AGENT_ID: &str = "e2e-websocket-agent";
const CONFIG_VERSION: &str = "e2e-websocket-plaintext-feed";
const CONNECTION_ID: &str = "xtask-e2e-websocket-conn";
const POLICY_ID: &str = "e2e-websocket-policy";
const POLICY_VERSION: &str = "e2e";
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
    let mut config =
        scenario.agent_config_with_policy(feed_path, policy_path, spool_path.clone(), POLICY_ID);
    config.export.worker.enabled = false;
    fs::write(&config_path, toml::to_string(&config)?)?;
    run_agent_with_max_events(&config_path, WEBSOCKET_CAPTURE_READ_LIMIT)?;
    assert_spool_outputs(&spool_path, &scenario)?;

    Ok(())
}

fn scenario() -> PlaintextFeedCase {
    PlaintextFeedCase::new(
        AGENT_ID,
        CONFIG_VERSION,
        CONNECTION_ID,
        PlaintextFlow::new(
            52_100,
            8_080,
            2003,
            PlaintextProcess::new(
                422,
                755,
                "traffic-probe-e2e-websocket",
                "/usr/bin/traffic-probe-e2e-websocket",
                "websocket-hash",
            ),
        ),
    )
}

fn write_feed(scenario: &PlaintextFeedCase, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    scenario.write_feed_records(path, feed_records()?)
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

fn feed_records() -> Result<Vec<PlaintextFeedRecord>, Box<dyn std::error::Error>> {
    let response = websocket_upgrade_response();
    Ok(vec![
        PlaintextFeedRecord::connection_opened(),
        PlaintextFeedRecord::bytes(Direction::Outbound, 0, websocket_upgrade_request()),
        PlaintextFeedRecord::bytes(Direction::Inbound, 0, response.clone()),
        PlaintextFeedRecord::bytes(
            Direction::Inbound,
            u64::try_from(response.len())?,
            websocket_text_frame(FRAME_PAYLOAD),
        ),
        PlaintextFeedRecord::connection_closed(),
    ])
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
    scenario: &PlaintextFeedCase,
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
    scenario: &PlaintextFeedCase,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_plaintext_feed_records(events, scenario, &feed_records()?, CONTEXT)
}

fn assert_websocket_exports(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let opened_index =
        export_event_position(envelopes, scenario, CONTEXT, "connection opened", |kind| {
            matches!(kind, EventKind::ConnectionOpened)
        })?;
    let request_index = export_event_position(
        envelopes,
        scenario,
        CONTEXT,
        "HTTP upgrade request",
        |kind| {
            matches!(
                kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.direction == Direction::Outbound
                        && headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(REQUEST_TARGET)
            )
        },
    )?;
    let response_index =
        export_event_position(envelopes, scenario, CONTEXT, "HTTP 101 response", |kind| {
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
    let handoff_index =
        export_event_position(envelopes, scenario, CONTEXT, "WebSocket handoff", |kind| {
            matches!(
                kind,
                EventKind::WebSocketHandoff(handoff)
                    if handoff.direction == Direction::Inbound
                        && handoff.target.as_deref() == Some(REQUEST_TARGET)
                        && handoff.subprotocol.as_deref() == Some(SUBPROTOCOL)
            )
        })?;
    let frame_index =
        export_event_position(envelopes, scenario, CONTEXT, "WebSocket frame", |kind| {
            matches!(
                kind,
                EventKind::WebSocketFrame(frame)
                    if frame.direction == Direction::Inbound
                        && frame.frame_sequence == 1
                        && frame.fin
                        && !frame.masked
                        && matches!(frame.opcode, WebSocketOpcode::Text)
                        && frame.payload_len == FRAME_PAYLOAD_LEN
                        && frame.payload_fingerprint.as_slice()
                            == FRAME_PAYLOAD_FINGERPRINT.as_slice()
            )
        })?;
    let closed_index =
        export_event_position(envelopes, scenario, CONTEXT, "connection closed", |kind| {
            matches!(kind, EventKind::ConnectionClosed)
        })?;
    assert_ordered_export_positions(
        CONTEXT,
        &[
            ("connection opened", opened_index),
            ("HTTP upgrade request", request_index),
            ("HTTP 101 response", response_index),
            ("WebSocket handoff", handoff_index),
            ("WebSocket frame", frame_index),
            ("connection closed", closed_index),
        ],
    )?;

    let expected_policy_version = expected_policy_version();
    assert_policy_alert(
        envelopes,
        scenario,
        &expected_policy_version,
        CONTEXT,
        HANDOFF_ALERT,
    )?;
    assert_policy_alert(
        envelopes,
        scenario,
        &expected_policy_version,
        CONTEXT,
        FRAME_ALERT,
    )?;
    assert_no_protocol_errors_after_handoff(envelopes, handoff_index)?;
    Ok(())
}

fn assert_no_protocol_errors_after_handoff(
    envelopes: &[EventEnvelope],
    handoff_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_no_http_body_chunks_after(envelopes, handoff_index, CONTEXT, "handoff")?;
    assert_no_protocol_errors(envelopes, CONTEXT)?;
    Ok(())
}

fn expected_policy_version() -> String {
    format!("{POLICY_ID}@{POLICY_VERSION}")
}

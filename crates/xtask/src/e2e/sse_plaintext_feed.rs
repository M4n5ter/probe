use std::{fs, path::Path, process::ExitCode};

use probe_core::{Direction, EventEnvelope, EventKind};
use storage::{FjallSpool, StoredEvent};

use super::harness::{decode_envelope, e2e_error, run_agent_with_max_events, run_with_temp_root};
use super::plaintext_assertions::{
    assert_no_protocol_errors, assert_ordered_export_positions, assert_plaintext_feed_records,
    assert_policy_alert, export_event_position, has_header,
};
use super::plaintext_scenario::{
    PlaintextFeedCase, PlaintextFeedRecord, PlaintextFlow, PlaintextProcess,
};

const CONTEXT: &str = "SSE";
const SSE_FEED_EVENT_COUNT: usize = 5;
const SSE_CAPTURE_READ_LIMIT: usize = SSE_FEED_EVENT_COUNT + 1;
const SSE_EXPORT_EVENT_COUNT: usize = 11;
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";
const AGENT_ID: &str = "e2e-sse-agent";
const CONFIG_VERSION: &str = "e2e-sse-plaintext-feed";
const CONNECTION_ID: &str = "xtask-e2e-sse-conn";
const POLICY_ID: &str = "e2e-sse-policy";
const POLICY_VERSION: &str = "e2e";
const REQUEST_TARGET: &str = "/events";
const FIRST_EVENT_NAME: &str = "update";
const FIRST_EVENT_ID: &str = "42";
const FIRST_EVENT_RETRY_MS: u64 = 1000;
const FIRST_EVENT_DATA: &str = "first line\nsecond line";
const SECOND_EVENT_NAME: &str = "done";
const SECOND_EVENT_ID: &str = "43";
const SECOND_EVENT_RETRY_MS: u64 = 1500;
const SECOND_EVENT_DATA: &str = "goodbye";
const FIRST_ALERT: &str = "sse update 42 1000 first line\nsecond line";
const SECOND_ALERT: &str = "sse done 43 1500 goodbye";

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e SSE plaintext feed failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("sse-plaintext-feed", run_at)?;
    println!("e2e SSE plaintext feed passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("feed.jsonl");
    let policy_path = root.join("e2e-sse-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let scenario = scenario();
    write_feed(&scenario, &feed_path)?;
    write_policy_bundle(&policy_path)?;
    let mut config =
        scenario.agent_config_with_policy(feed_path, policy_path, spool_path.clone(), POLICY_ID);
    config.export.worker.enabled = false;
    fs::write(&config_path, toml::to_string(&config)?)?;
    run_agent_with_max_events(&config_path, SSE_CAPTURE_READ_LIMIT)?;
    assert_spool_outputs(&spool_path, &scenario)?;

    Ok(())
}

fn scenario() -> PlaintextFeedCase {
    PlaintextFeedCase::new(
        AGENT_ID,
        CONFIG_VERSION,
        CONNECTION_ID,
        PlaintextFlow::new(
            52_200,
            8_080,
            2004,
            PlaintextProcess::new(
                423,
                756,
                "sssa-e2e-sse",
                "/usr/bin/sssa-e2e-sse",
                "sse-hash",
            ),
        ),
    )
}

fn write_feed(scenario: &PlaintextFeedCase, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    scenario.write_feed_records(path, feed_records()?)
}

fn sse_request() -> Vec<u8> {
    format!(
        "GET {REQUEST_TARGET} HTTP/1.1\r\nHost: sse.e2e.test\r\nAccept: text/event-stream\r\n\r\n"
    )
    .into_bytes()
}

fn sse_response_with_first_event() -> Vec<u8> {
    [
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n",
        first_event_body(),
    ]
    .concat()
    .into_bytes()
}

fn sse_second_event() -> Vec<u8> {
    [": keepalive\n\n", second_event_body()]
        .concat()
        .into_bytes()
}

fn first_event_body() -> &'static str {
    "event: update\nid: 42\nretry: 1000\ndata: first line\ndata: second line\n\n"
}

fn second_event_body() -> &'static str {
    "event: done\nid: 43\nretry: 1500\ndata: goodbye\n\n"
}

fn feed_records() -> Result<Vec<PlaintextFeedRecord>, Box<dyn std::error::Error>> {
    let first_response = sse_response_with_first_event();
    Ok(vec![
        PlaintextFeedRecord::connection_opened(),
        PlaintextFeedRecord::bytes(Direction::Outbound, 0, sse_request()),
        PlaintextFeedRecord::bytes(Direction::Inbound, 0, first_response.clone()),
        PlaintextFeedRecord::bytes(
            Direction::Inbound,
            u64::try_from(first_response.len())?,
            sse_second_event(),
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
hooks = ["on_sse_event"]
"#
        ),
    )?;
    fs::write(
        path.join("main.lua"),
        r#"
function on_sse_event(event)
  return probe.emit_alert(
    "sse "
      .. event.kind.event
      .. " "
      .. event.kind.id
      .. " "
      .. tostring(event.kind.retry_ms)
      .. " "
      .. event.kind.data
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
    if ingress.len() != SSE_FEED_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {SSE_FEED_EVENT_COUNT} SSE ingress records, got {}",
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
    if envelopes.len() != SSE_EXPORT_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {SSE_EXPORT_EVENT_COUNT} SSE export records, got {}",
            envelopes.len()
        ))
        .into());
    }
    assert_sse_exports(&envelopes, scenario)?;

    println!(
        "e2e SSE plaintext feed observed {} ingress records and {} export records",
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

fn assert_sse_exports(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let second_body = sse_second_event();
    let second_body_offset = u64::try_from(first_event_body().len())?;
    let end_body_offset = second_body_offset.saturating_add(u64::try_from(second_body.len())?);
    let opened_index =
        export_event_position(envelopes, scenario, CONTEXT, "connection opened", |kind| {
            matches!(kind, EventKind::ConnectionOpened)
        })?;
    let request_index =
        export_event_position(envelopes, scenario, CONTEXT, "HTTP SSE request", |kind| {
            matches!(
                kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.direction == Direction::Outbound
                        && headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(REQUEST_TARGET)
                        && has_header(&headers.headers, "accept", "text/event-stream")
            )
        })?;
    let response_index =
        export_event_position(envelopes, scenario, CONTEXT, "HTTP SSE response", |kind| {
            matches!(
                kind,
                EventKind::HttpResponseHeaders(headers)
                    if headers.direction == Direction::Inbound
                        && headers.status == Some(200)
                        && has_header(&headers.headers, "content-type", "text/event-stream")
            )
        })?;
    let first_body_index = export_event_position(
        envelopes,
        scenario,
        CONTEXT,
        "first SSE body chunk",
        |kind| {
            matches!(
                kind,
                EventKind::HttpBodyChunk(chunk)
                    if chunk.direction == Direction::Inbound
                        && chunk.stream_sequence == 1
                        && chunk.offset == 0
                        && chunk.data.as_ref() == first_event_body().as_bytes()
                        && !chunk.end_stream
            )
        },
    )?;
    let first_sse_index =
        export_event_position(envelopes, scenario, CONTEXT, "first SSE event", |kind| {
            matches!(
                kind,
                EventKind::SseEvent(event)
                    if event.direction == Direction::Inbound
                        && event.stream_sequence == 1
                        && event.event.as_deref() == Some(FIRST_EVENT_NAME)
                        && event.id.as_deref() == Some(FIRST_EVENT_ID)
                        && event.retry_ms == Some(FIRST_EVENT_RETRY_MS)
                        && event.data == FIRST_EVENT_DATA
            )
        })?;
    let second_body_index = export_event_position(
        envelopes,
        scenario,
        CONTEXT,
        "second SSE body chunk",
        |kind| {
            matches!(
                kind,
                EventKind::HttpBodyChunk(chunk)
                    if chunk.direction == Direction::Inbound
                        && chunk.stream_sequence == 1
                        && chunk.offset == second_body_offset
                        && chunk.data.as_ref() == second_body.as_slice()
                        && !chunk.end_stream
            )
        },
    )?;
    let second_sse_index =
        export_event_position(envelopes, scenario, CONTEXT, "second SSE event", |kind| {
            matches!(
                kind,
                EventKind::SseEvent(event)
                    if event.direction == Direction::Inbound
                        && event.stream_sequence == 1
                        && event.event.as_deref() == Some(SECOND_EVENT_NAME)
                        && event.id.as_deref() == Some(SECOND_EVENT_ID)
                        && event.retry_ms == Some(SECOND_EVENT_RETRY_MS)
                        && event.data == SECOND_EVENT_DATA
            )
        })?;
    let end_body_index =
        export_event_position(envelopes, scenario, CONTEXT, "SSE stream end", |kind| {
            matches!(
                kind,
                EventKind::HttpBodyChunk(chunk)
                    if chunk.direction == Direction::Inbound
                        && chunk.stream_sequence == 1
                        && chunk.offset == end_body_offset
                        && chunk.data.is_empty()
                        && chunk.end_stream
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
            ("HTTP SSE request", request_index),
            ("HTTP SSE response", response_index),
            ("first SSE body chunk", first_body_index),
            ("first SSE event", first_sse_index),
            ("second SSE body chunk", second_body_index),
            ("second SSE event", second_sse_index),
            ("SSE stream end", end_body_index),
            ("connection closed", closed_index),
        ],
    )?;

    let expected_policy_version = expected_policy_version();
    assert_policy_alert(
        envelopes,
        scenario,
        &expected_policy_version,
        CONTEXT,
        FIRST_ALERT,
    )?;
    assert_policy_alert(
        envelopes,
        scenario,
        &expected_policy_version,
        CONTEXT,
        SECOND_ALERT,
    )?;
    assert_no_protocol_errors(envelopes, CONTEXT)?;
    Ok(())
}

fn expected_policy_version() -> String {
    format!("{POLICY_ID}@{POLICY_VERSION}")
}

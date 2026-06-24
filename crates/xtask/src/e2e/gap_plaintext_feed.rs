use std::{fs, path::Path, process::ExitCode};

use probe_core::{Direction, EventEnvelope, EventKind};
use storage::{FjallSpool, StoredEvent};

use super::harness::{decode_envelope, e2e_error, run_agent_with_max_events, run_with_temp_root};
use super::plaintext_assertions::{
    assert_no_http_body_chunks_after, assert_no_protocol_errors, assert_ordered_export_positions,
    assert_plaintext_feed_records, export_event_position,
};
use super::plaintext_scenario::{
    PlaintextFeedCase, PlaintextFeedRecord, PlaintextFlow, PlaintextProcess,
};

const CONTEXT: &str = "gap";
const GAP_FEED_EVENT_COUNT: usize = 6;
const GAP_CAPTURE_READ_LIMIT: usize = GAP_FEED_EVENT_COUNT + 1;
const GAP_EXPORT_EVENT_COUNT: usize = 7;
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";
const AGENT_ID: &str = "e2e-gap-agent";
const CONFIG_VERSION: &str = "e2e-gap-plaintext-feed";
const CONNECTION_ID: &str = "xtask-e2e-gap-conn";
const REQUEST_TARGET: &str = "/gap";
const GAP_REASON: &str = "synthetic plaintext feed gap";
const RESPONSE_BODY_PREFIX: &[u8] = b"hel";
const RESPONSE_BODY_REMAINDER: &[u8] = b"lo gap";
const POST_GAP_STATUS: u16 = 204;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e gap plaintext feed failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("gap-plaintext-feed", run_at)?;
    println!("e2e gap plaintext feed passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("feed.jsonl");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let scenario = scenario();
    write_feed(&scenario, &feed_path)?;
    let mut config = scenario.agent_config(feed_path, spool_path.clone());
    config.export.worker.enabled = false;
    fs::write(&config_path, toml::to_string(&config)?)?;
    run_agent_with_max_events(&config_path, GAP_CAPTURE_READ_LIMIT)?;
    assert_spool_outputs(&spool_path, &scenario)?;

    Ok(())
}

fn scenario() -> PlaintextFeedCase {
    PlaintextFeedCase::new(
        AGENT_ID,
        CONFIG_VERSION,
        CONNECTION_ID,
        PlaintextFlow::new(
            52_300,
            8_080,
            2005,
            PlaintextProcess::new(
                424,
                757,
                "sssa-e2e-gap",
                "/usr/bin/sssa-e2e-gap",
                "gap-hash",
            ),
        ),
    )
}

fn write_feed(scenario: &PlaintextFeedCase, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    scenario.write_feed_records(path, feed_records()?)
}

fn request() -> Vec<u8> {
    format!("GET {REQUEST_TARGET} HTTP/1.1\r\nHost: gap.e2e.test\r\n\r\n").into_bytes()
}

fn response_prefix() -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        RESPONSE_BODY_PREFIX.len() + RESPONSE_BODY_REMAINDER.len()
    )
    .into_bytes();
    response.extend_from_slice(RESPONSE_BODY_PREFIX);
    response
}

fn post_gap_response() -> Vec<u8> {
    format!("HTTP/1.1 {POST_GAP_STATUS} No Content\r\nContent-Length: 0\r\n\r\n").into_bytes()
}

fn feed_records() -> Result<Vec<PlaintextFeedRecord>, Box<dyn std::error::Error>> {
    let response = response_prefix();
    let gap_start = u64::try_from(response.len())?;
    let next_offset = gap_start.saturating_add(u64::try_from(RESPONSE_BODY_REMAINDER.len())?);
    Ok(vec![
        PlaintextFeedRecord::connection_opened(),
        PlaintextFeedRecord::bytes(Direction::Outbound, 0, request()),
        PlaintextFeedRecord::bytes(Direction::Inbound, 0, response),
        PlaintextFeedRecord::gap(Direction::Inbound, gap_start, Some(next_offset), GAP_REASON),
        PlaintextFeedRecord::bytes(Direction::Inbound, next_offset, post_gap_response()),
        PlaintextFeedRecord::connection_closed(),
    ])
}

fn assert_spool_outputs(
    spool_path: &Path,
    scenario: &PlaintextFeedCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    if ingress.len() != GAP_FEED_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {GAP_FEED_EVENT_COUNT} gap ingress records, got {}",
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
    if envelopes.len() != GAP_EXPORT_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {GAP_EXPORT_EVENT_COUNT} gap export records, got {}",
            envelopes.len()
        ))
        .into());
    }
    assert_gap_exports(&envelopes, scenario)?;

    println!(
        "e2e gap plaintext feed observed {} ingress records and {} export records",
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

fn assert_gap_exports(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let gap_expected_offset = u64::try_from(response_prefix().len())?;
    let gap_next_offset =
        Some(gap_expected_offset.saturating_add(u64::try_from(RESPONSE_BODY_REMAINDER.len())?));
    let opened_index =
        export_event_position(envelopes, scenario, CONTEXT, "connection opened", |kind| {
            matches!(kind, EventKind::ConnectionOpened)
        })?;
    let request_index =
        export_event_position(envelopes, scenario, CONTEXT, "HTTP request", |kind| {
            matches!(
                kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.direction == Direction::Outbound
                        && headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(REQUEST_TARGET)
            )
        })?;
    let response_index =
        export_event_position(envelopes, scenario, CONTEXT, "HTTP response", |kind| {
            matches!(
                kind,
                EventKind::HttpResponseHeaders(headers)
                    if headers.direction == Direction::Inbound && headers.status == Some(200)
            )
        })?;
    let body_index = export_event_position(envelopes, scenario, CONTEXT, "body prefix", |kind| {
        matches!(
            kind,
            EventKind::HttpBodyChunk(chunk)
                if chunk.direction == Direction::Inbound
                    && chunk.offset == 0
                    && chunk.data.as_ref() == RESPONSE_BODY_PREFIX
                    && !chunk.end_stream
        )
    })?;
    let gap_index = export_event_position(envelopes, scenario, CONTEXT, "gap", |kind| {
        matches!(
            kind,
            EventKind::Gap(gap)
                if gap.direction == Direction::Inbound
                    && gap.reason == GAP_REASON
                    && gap.expected_offset == gap_expected_offset
                    && gap.next_offset == gap_next_offset
        )
    })?;
    let post_gap_response_index =
        export_event_position(envelopes, scenario, CONTEXT, "post-gap response", |kind| {
            matches!(
                kind,
                EventKind::HttpResponseHeaders(headers)
                    if headers.direction == Direction::Inbound
                        && headers.status == Some(POST_GAP_STATUS)
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
            ("HTTP request", request_index),
            ("HTTP response", response_index),
            ("body prefix", body_index),
            ("gap", gap_index),
            ("post-gap response", post_gap_response_index),
            ("connection closed", closed_index),
        ],
    )?;

    let gap_envelope = &envelopes[gap_index];
    if !gap_envelope.degraded() {
        return Err(e2e_error("gap export event was not marked degraded").into());
    }
    assert_no_http_body_chunks_after(envelopes, gap_index, CONTEXT, "gap")?;
    assert_no_protocol_errors(envelopes, CONTEXT)?;
    Ok(())
}

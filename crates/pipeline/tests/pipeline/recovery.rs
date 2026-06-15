use capture::CaptureEvent;
use parsers::Http1ParserFactory;
use pipeline::{
    CapturePipeline, PARSER_INGRESS_CURSOR_OWNER, PipelineError, PipelinePolicy, PipelineSummary,
};
use policy::{PolicyHook, PolicyManifest, PolicyRuntime};
use probe_core::{CaptureSource, Direction, EventKind, Gap, SpoolPayloadSchema, Timestamp};
use storage::SpoolPayload;
use tempfile::tempdir;

use super::fixture::{
    SequenceProvider, captured_bytes, captured_bytes_with_direction, connection_closed,
    demo_flow_with_ports, exported_envelopes,
};

#[test]
fn recover_ingress_journal_replays_capture_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let event = captured_bytes_with_direction(
        demo_flow_with_ports(50_000, 80, 31),
        Direction::Outbound,
        b"GET /recovered HTTP/1.1\r\nHost: recovery.test\r\n\r\n",
    );
    spool.append_ingress(capture_event_payload(&event)?)?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.recover_ingress_journal_until_idle(16)?;

    assert_eq!(summary.capture_events_read, 0);
    assert_eq!(summary.ingress_records_journaled, 0);
    assert_eq!(summary.ingress_records_processed, 1);
    assert_eq!(summary.ingress_records_recovered, 1);
    assert_eq!(summary.export_events_written, 1);
    let envelopes = exported_envelopes(&spool)?;
    assert!(envelopes.iter().any(|envelope| {
        envelope.source == CaptureSource::Replay
            && matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.target.as_deref() == Some("/recovered")
            )
    }));
    let first_id = request_ids_for_target(&spool, "/recovered")?
        .into_iter()
        .next()
        .expect("first recovery should export request");
    let repeated = recover_without_policy(&spool)?;
    assert_eq!(repeated.ingress_records_recovered, 1);
    assert_eq!(repeated.export_events_written, 1);
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 0);
    assert_eq!(count_request_targets(&spool, "/recovered")?, 2);
    assert_eq!(
        request_ids_for_target(&spool, "/recovered")?,
        vec![first_id.clone(), first_id]
    );
    Ok(())
}

#[test]
fn recover_ingress_journal_replays_policy_outputs_with_stable_event_id()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let event = captured_bytes_with_direction(
        demo_flow_with_ports(50_000, 80, 35),
        Direction::Outbound,
        b"GET /policy-recovered HTTP/1.1\r\nHost: recovery.test\r\n\r\n",
    );
    spool.append_ingress(capture_event_payload(&event)?)?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "recovery-policy".to_string(),
            version: "one".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  return probe.emit_alert("recovered " .. event.kind.target)
end
"#,
    )?;

    let first = recover_with_policy(&spool, &policy)?;

    assert_eq!(first.ingress_records_recovered, 1);
    assert_eq!(first.export_events_written, 2);
    let first_id = policy_alert_ids(&spool)?
        .into_iter()
        .next()
        .expect("first recovery should export policy alert");
    let repeated = recover_with_policy(&spool, &policy)?;
    assert_eq!(repeated.ingress_records_recovered, 1);
    assert_eq!(repeated.export_events_written, 2);
    assert_eq!(policy_alert_ids(&spool)?, vec![first_id.clone(), first_id]);
    Ok(())
}

#[test]
fn recover_ingress_journal_replays_persisted_prefix_for_parser_state()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let flow = demo_flow_with_ports(50_000, 80, 32);
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(vec![captured_bytes(
        flow.clone(),
        b"GET /split-recovered HTTP/1.1\r\nHost: recovery",
    )]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    assert_eq!(summary.export_events_written, 0);
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 0);
    let event = captured_bytes_with_direction(flow, Direction::Outbound, b".test\r\n\r\n");
    spool.append_ingress(capture_event_payload(&event)?)?;
    drop(pipeline);
    drop(parser_factory);
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.recover_ingress_journal_until_idle(16)?;

    assert_eq!(summary.ingress_records_journaled, 0);
    assert_eq!(summary.ingress_records_recovered, 2);
    assert_eq!(summary.ingress_records_processed, 2);
    assert_eq!(summary.export_events_written, 1);
    let envelopes = exported_envelopes(&spool)?;
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::HttpRequestHeaders(headers)
                if headers.target.as_deref() == Some("/split-recovered")
        )
    }));
    let repeated = recover_without_policy(&spool)?;
    assert_eq!(repeated.ingress_records_recovered, 2);
    assert_eq!(repeated.export_events_written, 1);
    assert_eq!(count_request_targets(&spool, "/split-recovered")?, 2);
    Ok(())
}

#[test]
fn recover_ingress_journal_advances_cursor_after_recovered_connection_close()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let flow = demo_flow_with_ports(50_000, 80, 33);
    spool.append_ingress(capture_event_payload(&captured_bytes_with_direction(
        flow.clone(),
        Direction::Outbound,
        b"GET /checkpoint HTTP/1.1\r\nHost: recovery.test\r\n\r\n",
    ))?)?;
    spool.append_ingress(capture_event_payload(&captured_bytes_with_direction(
        flow.clone(),
        Direction::Inbound,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    ))?)?;
    spool.append_ingress(capture_event_payload(&connection_closed(flow))?)?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.recover_ingress_journal_until_idle(16)?;

    assert_eq!(summary.ingress_records_recovered, 3);
    assert_eq!(summary.ingress_records_processed, 3);
    assert_eq!(summary.export_events_written, 3);
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 3);
    let repeated = recover_without_policy(&spool)?;
    assert_eq!(repeated.ingress_records_recovered, 0);
    assert_eq!(repeated.export_events_written, 0);
    Ok(())
}

#[test]
fn run_provider_advances_parser_cursor_after_flow_becomes_checkpoint_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let flow = demo_flow_with_ports(50_000, 80, 36);
    let mut provider = SequenceProvider::new(vec![
        captured_bytes_with_direction(
            flow.clone(),
            Direction::Outbound,
            b"GET /live-checkpoint HTTP/1.1\r\nHost: recovery.test\r\n\r\n",
        ),
        captured_bytes_with_direction(
            flow.clone(),
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ),
        connection_closed(flow),
    ]);
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 3);
    assert_eq!(summary.ingress_records_processed, 3);
    assert_eq!(summary.export_events_written, 3);
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 3);
    let repeated = recover_without_policy(&spool)?;
    assert_eq!(repeated.ingress_records_recovered, 0);
    assert_eq!(repeated.export_events_written, 0);
    Ok(())
}

#[test]
fn parser_cursor_waits_until_every_flow_is_checkpoint_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let unsafe_flow = demo_flow_with_ports(50_000, 80, 37);
    let closing_flow = demo_flow_with_ports(50_001, 80, 38);
    let mut first_provider = SequenceProvider::new(vec![
        captured_bytes_with_direction(
            unsafe_flow.clone(),
            Direction::Outbound,
            b"GET /blocked-checkpoint HTTP/1.1\r\nHost: recovery",
        ),
        captured_bytes_with_direction(
            closing_flow.clone(),
            Direction::Outbound,
            b"GET /closed-flow HTTP/1.1\r\nHost: recovery.test\r\n\r\n",
        ),
        captured_bytes_with_direction(
            closing_flow.clone(),
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ),
        connection_closed(closing_flow),
    ]);
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.run_provider(&mut first_provider)?;

    assert_eq!(summary.ingress_records_journaled, 4);
    assert_eq!(summary.ingress_records_processed, 4);
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 0);

    let mut second_provider = SequenceProvider::new(vec![
        captured_bytes_with_direction(unsafe_flow.clone(), Direction::Outbound, b".test\r\n\r\n"),
        connection_closed(unsafe_flow),
    ]);

    let summary = pipeline.run_provider(&mut second_provider)?;

    assert_eq!(summary.ingress_records_journaled, 2);
    assert_eq!(summary.ingress_records_processed, 2);
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 6);
    let repeated = recover_without_policy(&spool)?;
    assert_eq!(repeated.ingress_records_recovered, 0);
    assert_eq!(repeated.export_events_written, 0);
    Ok(())
}

fn captured_gap(
    flow: probe_core::FlowContext,
    direction: Direction,
    expected_offset: u64,
    next_offset: Option<u64>,
    reason: &'static str,
) -> CaptureEvent {
    CaptureEvent::Gap(capture::CapturedGap {
        timestamp: Timestamp {
            monotonic_ns: 2,
            wall_time_unix_ns: 2,
        },
        flow,
        source: CaptureSource::Replay,
        provider: capture::CaptureProviderKind::Replay,
        gap: Gap {
            direction,
            expected_offset,
            next_offset,
            reason: reason.to_string(),
        },
    })
}

fn capture_event_payload(event: &CaptureEvent) -> Result<SpoolPayload, serde_json::Error> {
    Ok(SpoolPayload::new(
        SpoolPayloadSchema::CaptureEventJson,
        serde_json::to_vec(event)?,
    ))
}

fn recover_without_policy(spool: &storage::FjallSpool) -> Result<PipelineSummary, PipelineError> {
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(spool, &mut parser_factory, Vec::new(), "test");
    pipeline.recover_ingress_journal_until_idle(16)
}

fn recover_with_policy(
    spool: &storage::FjallSpool,
    policy: &PolicyRuntime,
) -> Result<PipelineSummary, PipelineError> {
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(
        spool,
        &mut parser_factory,
        vec![PipelinePolicy::unscoped(policy)],
        "test",
    );
    pipeline.recover_ingress_journal_until_idle(16)
}

fn count_request_targets(
    spool: &storage::FjallSpool,
    target: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(exported_envelopes(spool)?
        .iter()
        .filter(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.target.as_deref() == Some(target)
            )
        })
        .count())
}

fn request_ids_for_target(
    spool: &storage::FjallSpool,
    target: &str,
) -> Result<Vec<probe_core::EventId>, Box<dyn std::error::Error>> {
    Ok(exported_envelopes(spool)?
        .into_iter()
        .filter(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.target.as_deref() == Some(target)
            )
        })
        .map(|envelope| envelope.id)
        .collect())
}

fn policy_alert_ids(
    spool: &storage::FjallSpool,
) -> Result<Vec<probe_core::EventId>, Box<dyn std::error::Error>> {
    Ok(exported_envelopes(spool)?
        .into_iter()
        .filter(|envelope| matches!(envelope.kind, EventKind::PolicyAlert(_)))
        .map(|envelope| envelope.id)
        .collect())
}

#[test]
fn recover_ingress_journal_replays_persisted_gap() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let flow = demo_flow_with_ports(50_000, 80, 34);
    spool.append_ingress(capture_event_payload(&captured_gap(
        flow,
        Direction::Outbound,
        12,
        Some(24),
        "dropped packets",
    ))?)?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.recover_ingress_journal_until_idle(16)?;

    assert_eq!(summary.ingress_records_recovered, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    assert_eq!(summary.export_events_written, 1);
    let repeated = recover_without_policy(&spool)?;
    assert_eq!(repeated.ingress_records_recovered, 0);
    assert_eq!(repeated.export_events_written, 0);
    let envelopes = exported_envelopes(&spool)?;
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::Gap(gap)
                if gap.direction == Direction::Outbound
                    && gap.expected_offset == 12
                    && gap.next_offset == Some(24)
                    && gap.reason == "dropped packets"
        )
    }));
    Ok(())
}

#[test]
fn recover_ingress_journal_rejects_unexpected_payload_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    spool.append_ingress(SpoolPayload::new(
        SpoolPayloadSchema::EventEnvelopeJson,
        b"{}",
    ))?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let error = pipeline
        .recover_ingress_journal_until_idle(16)
        .expect_err("unexpected ingress schema must fail recovery");

    assert!(matches!(
        error,
        PipelineError::UnexpectedIngressSchema {
            sequence: 1,
            expected: SpoolPayloadSchema::CAPTURE_EVENT_JSON,
            actual,
        } if actual == SpoolPayloadSchema::EVENT_ENVELOPE_JSON
    ));
    assert!(spool.read_export_batch("sink", 16)?.is_empty());
    Ok(())
}

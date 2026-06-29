use capture::{
    CaptureError, CapturePoll, CaptureProvider, PlaintextChunk, PlaintextEventProvider,
    PlaintextSource, ReplayProvider,
};
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelineRuntimeMetrics};
use probe_core::{
    CapabilityState, CaptureProviderKind, CaptureSource, Direction, EventEmission, EventKind,
    Timestamp,
};
use tempfile::tempdir;

use super::fixture::{
    SequenceProvider, capture_loss, captured_bytes, demo_flow_with_ports, exported_envelopes,
    flow_carried_observation_only_ebpf_syscall_gap,
    observation_only_ebpf_syscall_bytes_with_direction,
};

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
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    assert_eq!(summary.export_events_written, 2);
    assert_eq!(spool.read_ingress_batch_after(0, 10)?.len(), 1);
    let envelopes = exported_envelopes(&spool)?;
    assert_eq!(envelopes.len(), 2);
    assert_eq!(
        envelopes
            .iter()
            .filter_map(|envelope| envelope.provenance())
            .map(|provenance| match provenance.emission {
                EventEmission::Primary { index } => (provenance.ingress_sequence, index),
                EventEmission::Policy { .. } => panic!("expected primary event provenance"),
            })
            .collect::<Vec<_>>(),
        vec![(1, 0), (1, 1)]
    );
    Ok(())
}

fn demo_flow() -> probe_core::FlowContext {
    demo_flow_with_ports(50_000, 80, 1)
}

#[test]
fn plaintext_event_provider_writes_ingress_and_http_export_events()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(50_000, 443, 13);
    let mut provider = PlaintextEventProvider::from_chunks(
        PlaintextSource::ExternalPlaintextFeed,
        [PlaintextChunk::new(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow,
            Direction::Outbound,
            b"GET /plaintext HTTP/1.1\r\nHost: tls.example\r\n\r\n",
        )],
    );
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.capture_events_read, 1);
    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    let envelopes = exported_envelopes(&spool)?;
    assert!(envelopes.iter().any(|envelope| {
        envelope.origin().source() == CaptureSource::ExternalPlaintextFeed
            && envelope.origin().provider() == CaptureProviderKind::Plaintext
            && matches!(
                envelope.kind(),
                EventKind::HttpRequestHeaders(headers)
                    if headers.target.as_deref() == Some("/plaintext")
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
fn runtime_metrics_count_degraded_and_gap_event_envelopes() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(50_000, 80, 41);
    let mut provider = SequenceProvider::new(vec![
        observation_only_ebpf_syscall_bytes_with_direction(
            flow.clone(),
            Direction::Outbound,
            b"GET /degraded HTTP/1.1\r\nHost: example\r\n\r\n",
        ),
        flow_carried_observation_only_ebpf_syscall_gap(flow),
    ]);
    let metrics = PipelineRuntimeMetrics::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test")
        .with_runtime_metrics(metrics.clone());

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.export_events_written, 2);
    let envelopes = exported_envelopes(&spool)?;
    assert_eq!(envelopes.len(), 2);
    assert!(envelopes.iter().any(|envelope| envelope.degraded()
        && matches!(envelope.kind(), EventKind::HttpRequestHeaders(headers)
                    if headers.target.as_deref() == Some("/degraded"))));
    assert!(
        envelopes
            .iter()
            .any(|envelope| envelope.degraded() && matches!(envelope.kind(), EventKind::Gap(_)))
    );
    let events = metrics.snapshot().events;
    assert_eq!(events.total, 2);
    assert_eq!(events.degraded, 2);
    assert_eq!(events.gaps, 1);
    Ok(())
}

#[test]
fn capture_loss_writes_degraded_export_without_parser_events()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(vec![capture_loss(7)]);
    let metrics = PipelineRuntimeMetrics::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test")
        .with_runtime_metrics(metrics.clone());

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.capture_events_read, 1);
    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    assert_eq!(summary.export_events_written, 1);
    let envelopes = exported_envelopes(&spool)?;
    let [loss] = envelopes.as_slice() else {
        panic!("expected one capture loss envelope: {envelopes:?}");
    };
    assert!(loss.degraded());
    assert!(matches!(
        loss.kind(),
        EventKind::CaptureLoss(loss) if loss.lost_events == 7
    ));
    assert_eq!(loss.subject(), &probe_core::EventSubject::Provider);
    assert_eq!(loss.origin().provider(), CaptureProviderKind::Ebpf);
    assert!(
        loss.enforcement_evidence()
            .destructive_enforcement_rejection_reason()
            .is_some_and(|reason| reason.contains("lost observations"))
    );
    let capture_loss = metrics.snapshot().capture_loss;
    assert_eq!(capture_loss.events, 1);
    assert_eq!(capture_loss.lost_events, 7);
    let events = metrics.snapshot().events;
    assert_eq!(events.total, 1);
    assert_eq!(events.degraded, 1);
    assert_eq!(events.gaps, 0);
    Ok(())
}

#[test]
fn runtime_metrics_count_provider_poll_outcomes() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(50_000, 80, 43);
    let mut provider = PollSequenceProvider::new(vec![
        CapturePoll::event(captured_bytes(
            flow,
            b"GET /polls HTTP/1.1\r\nHost: example\r\n\r\n",
        )),
        CapturePoll::Progress,
        CapturePoll::Idle,
        CapturePoll::Finished,
    ]);
    let metrics = PipelineRuntimeMetrics::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test")
        .with_runtime_metrics(metrics.clone());

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.capture_events_read, 1);
    let polls = metrics.snapshot().capture_polls;
    assert_eq!(polls.total, 4);
    assert_eq!(polls.events, 1);
    assert_eq!(polls.progress, 1);
    assert_eq!(polls.idle, 1);
    assert_eq!(polls.finished, 1);
    Ok(())
}

struct PollSequenceProvider {
    polls: std::vec::IntoIter<CapturePoll>,
}

impl PollSequenceProvider {
    fn new(polls: Vec<CapturePoll>) -> Self {
        Self {
            polls: polls.into_iter(),
        }
    }
}

impl CaptureProvider for PollSequenceProvider {
    fn name(&self) -> &'static str {
        "poll-sequence"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        Vec::new()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        Ok(self.polls.next().unwrap_or(CapturePoll::Finished))
    }
}

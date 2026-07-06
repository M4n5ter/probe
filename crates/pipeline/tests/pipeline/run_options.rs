use std::collections::VecDeque;

use capture::{CaptureError, CapturePoll, CaptureProvider};
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelineHandoffDrainOutcome, PipelineRunOptions};
use probe_core::{CancellationToken, CapabilityState};
use tempfile::tempdir;

use super::fixture::{SequenceProvider, captured_bytes, demo_flow_with_ports};

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
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary =
        pipeline.run_provider_with_options(&mut provider, PipelineRunOptions::max_events(1))?;

    assert_eq!(summary.capture_events_read, 1);
    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    assert_eq!(spool.read_ingress_batch_after(0, 10)?.len(), 1);
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
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary =
        pipeline.run_provider_with_options(&mut provider, PipelineRunOptions::max_events(0))?;

    assert_eq!(summary.capture_events_read, 0);
    assert_eq!(summary.ingress_records_journaled, 0);
    assert_eq!(summary.ingress_records_processed, 0);
    assert!(spool.read_ingress_batch_after(0, 10)?.is_empty());
    assert!(spool.read_export_batch("sink", 10)?.is_empty());
    Ok(())
}

#[test]
fn run_provider_stops_when_shutdown_is_requested_before_poll()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = UnreadableProvider;
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");
    let cancellation = CancellationToken::cancelled();

    let summary = pipeline.run_provider_with_options(
        &mut provider,
        PipelineRunOptions::default().with_cancellation_token(cancellation.clone()),
    )?;

    assert!(cancellation.is_cancelled());
    assert_eq!(summary.capture_events_read, 0);
    assert_eq!(summary.ingress_records_journaled, 0);
    assert_eq!(summary.ingress_records_processed, 0);
    Ok(())
}

#[test]
fn run_provider_stops_after_max_idle_polls() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = IdleProvider::default();
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary =
        pipeline.run_provider_with_options(&mut provider, PipelineRunOptions::max_polls(3))?;

    assert_eq!(summary.capture_events_read, 0);
    assert!(!summary.capture_provider_finished);
    assert_eq!(provider.polls, 3);
    assert!(spool.read_ingress_batch_after(0, 10)?.is_empty());
    assert!(spool.read_export_batch("sink", 10)?.is_empty());
    Ok(())
}

#[test]
fn run_provider_summary_reports_provider_finished() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(Vec::new());
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary =
        pipeline.run_provider_with_options(&mut provider, PipelineRunOptions::max_polls(1))?;

    assert_eq!(summary.capture_events_read, 0);
    assert!(summary.capture_provider_finished);
    Ok(())
}

#[test]
fn drain_provider_before_handoff_journals_drain_events_until_idle()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = HandoffDrainProvider::new(vec![
        CapturePoll::event(captured_bytes(
            demo_flow_with_ports(50_000, 80, 10),
            b"GET /handoff HTTP/1.1\r\nHost: handoff.test\r\n\r\n",
        )),
        CapturePoll::Idle,
    ]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary =
        pipeline.drain_provider_before_handoff(&mut provider, PipelineRunOptions::max_polls(8))?;

    assert_eq!(summary.outcome, PipelineHandoffDrainOutcome::Drained);
    assert_eq!(summary.pipeline.capture_events_read, 1);
    assert_eq!(summary.pipeline.ingress_records_journaled, 1);
    assert_eq!(summary.pipeline.ingress_records_processed, 1);
    assert_eq!(provider.polls, 0);
    assert_eq!(provider.handoff_polls, 2);
    assert_eq!(spool.read_ingress_batch_after(0, 10)?.len(), 1);
    assert_eq!(spool.read_export_batch("sink", 10)?.len(), 1);
    Ok(())
}

#[test]
fn drain_provider_before_handoff_reports_progress_before_budget_is_exhausted()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = HandoffDrainProvider::new(vec![CapturePoll::Progress]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary =
        pipeline.drain_provider_before_handoff(&mut provider, PipelineRunOptions::max_polls(8))?;

    assert_eq!(summary.outcome, PipelineHandoffDrainOutcome::Progress);
    assert_eq!(summary.pipeline.capture_events_read, 0);
    assert_eq!(provider.polls, 0);
    assert_eq!(provider.handoff_polls, 1);
    assert!(spool.read_ingress_batch_after(0, 10)?.is_empty());
    assert!(spool.read_export_batch("sink", 10)?.is_empty());
    Ok(())
}

#[test]
fn drain_provider_before_handoff_reports_budget_exhausted_when_poll_budget_runs_out()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = HandoffDrainProvider::new(vec![
        CapturePoll::event(captured_bytes(
            demo_flow_with_ports(50_000, 80, 10),
            b"GET /first HTTP/1.1\r\nHost: first.test\r\n\r\n",
        )),
        CapturePoll::event(captured_bytes(
            demo_flow_with_ports(50_001, 80, 11),
            b"GET /second HTTP/1.1\r\nHost: second.test\r\n\r\n",
        )),
    ]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary =
        pipeline.drain_provider_before_handoff(&mut provider, PipelineRunOptions::max_polls(1))?;

    assert_eq!(
        summary.outcome,
        PipelineHandoffDrainOutcome::BudgetExhausted
    );
    assert_eq!(summary.pipeline.capture_events_read, 1);
    assert_eq!(summary.pipeline.ingress_records_journaled, 1);
    assert_eq!(provider.polls, 0);
    assert_eq!(provider.handoff_polls, 1);
    assert_eq!(spool.read_ingress_batch_after(0, 10)?.len(), 1);
    assert_eq!(spool.read_export_batch("sink", 10)?.len(), 1);
    Ok(())
}

#[test]
fn drain_provider_before_handoff_respects_max_events() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = HandoffDrainProvider::new(vec![
        CapturePoll::event(captured_bytes(
            demo_flow_with_ports(50_000, 80, 10),
            b"GET /first HTTP/1.1\r\nHost: first.test\r\n\r\n",
        )),
        CapturePoll::event(captured_bytes(
            demo_flow_with_ports(50_001, 80, 11),
            b"GET /second HTTP/1.1\r\nHost: second.test\r\n\r\n",
        )),
    ]);
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");

    let summary =
        pipeline.drain_provider_before_handoff(&mut provider, PipelineRunOptions::max_events(1))?;

    assert_eq!(
        summary.outcome,
        PipelineHandoffDrainOutcome::BudgetExhausted
    );
    assert_eq!(summary.pipeline.capture_events_read, 1);
    assert_eq!(summary.pipeline.ingress_records_journaled, 1);
    assert_eq!(provider.polls, 0);
    assert_eq!(provider.handoff_polls, 1);
    assert_eq!(spool.read_ingress_batch_after(0, 10)?.len(), 1);
    assert_eq!(spool.read_export_batch("sink", 10)?.len(), 1);
    Ok(())
}

struct UnreadableProvider;

impl CaptureProvider for UnreadableProvider {
    fn name(&self) -> &'static str {
        "unreadable"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        Vec::new()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        Err(CaptureError::provider(
            "unreadable",
            "provider.poll_next must not be called when max_events is zero",
        ))
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        Err(CaptureError::provider(
            "unreadable",
            "provider.drain_before_handoff must not be called when max_events is zero",
        ))
    }
}

#[derive(Default)]
struct IdleProvider {
    polls: u64,
}

impl CaptureProvider for IdleProvider {
    fn name(&self) -> &'static str {
        "idle"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        Vec::new()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.polls = self.polls.saturating_add(1);
        Ok(CapturePoll::Idle)
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        Ok(CapturePoll::Idle)
    }
}

struct HandoffDrainProvider {
    polls: u64,
    handoff_polls: u64,
    handoff: VecDeque<CapturePoll>,
}

impl HandoffDrainProvider {
    fn new(handoff: Vec<CapturePoll>) -> Self {
        Self {
            polls: 0,
            handoff_polls: 0,
            handoff: handoff.into(),
        }
    }
}

impl CaptureProvider for HandoffDrainProvider {
    fn name(&self) -> &'static str {
        "handoff-drain"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        Vec::new()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.polls = self.polls.saturating_add(1);
        Err(CaptureError::provider(
            "handoff-drain",
            "provider.poll_next must not be called during handoff drain",
        ))
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        self.handoff_polls = self.handoff_polls.saturating_add(1);
        Ok(self.handoff.pop_front().unwrap_or(CapturePoll::Idle))
    }
}

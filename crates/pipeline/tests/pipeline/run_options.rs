use capture::{CaptureError, CapturePoll, CaptureProvider, CaptureProviderKind};
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelineRunOptions};
use probe_core::CapabilityState;
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

struct UnreadableProvider;

impl CaptureProvider for UnreadableProvider {
    fn name(&self) -> &'static str {
        "unreadable"
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Replay
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
}

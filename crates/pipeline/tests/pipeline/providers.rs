use capture::{PlaintextChunk, PlaintextEventProvider, PlaintextSource, ReplayProvider};
use parsers::Http1ParserFactory;
use pipeline::CapturePipeline;
use probe_core::{CaptureSource, Direction, EventKind, Timestamp};
use tempfile::tempdir;

use super::fixture::{demo_flow_with_ports, exported_envelopes};

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

    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    assert_eq!(summary.export_events_written, 2);
    assert_eq!(spool.read_ingress_batch_after(0, 10)?.len(), 1);
    assert_eq!(spool.read_export_batch("sink", 10)?.len(), 2);
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
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, None, "test");

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.capture_events_read, 1);
    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    let envelopes = exported_envelopes(&spool)?;
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

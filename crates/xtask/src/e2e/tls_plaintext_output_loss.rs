use std::{
    fs,
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::{
    CaptureEvent, CapturePoll, CaptureProvider, LibsslUprobeAttachPlan,
    LibsslUprobePlaintextProbeConfig, LibsslUprobePlaintextProvider, LibsslUprobeTargetDiscovery,
};
use probe_core::{CaptureProviderKind, CaptureSource, FlowIdentity, ObservationOnlyReason};

use super::{
    harness::{ChildSupervisor, create_temp_root, e2e_error, ensure_e2e_packages_built},
    loopback::{
        Http1LoopbackFixtureConfig, spawn_tls_http1_loopback_fixture, start_http1_loopback_fixture,
        wait_for_http1_loopback_fixture_exit, wait_for_http1_loopback_fixture_ready,
    },
    tls_plaintext_harness::{
        DIRECT_LOOPBACK_FLOW_CONFIDENCE, DirectLoopbackFlowResolver,
        is_expected_tls_plaintext_request_bytes, provider_event_summary,
    },
};

const REQUESTS: usize = 1;
const REQUEST_BODY_BYTES: usize = 1024 * 1024;
const RESPONSE_BODY_BYTES: usize = 0;
const WRITE_CHUNKS: usize = 1024;
const INITIAL_FLOW_TIMEOUT: Duration = Duration::from_secs(10);
const LOSS_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e TLS plaintext output loss failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["e2e-fixture"])?;
    let tls_object_path = crate::ebpf::ensure_tls_plaintext_artifact_ready().map_err(e2e_error)?;

    let root = create_temp_root("tls-plaintext-output-loss")?;
    match run_at(&root, &tls_object_path) {
        Ok(summary) => {
            fs::remove_dir_all(&root)?;
            println!(
                "e2e TLS plaintext output loss passed with {} lost event(s) and {} provider-loss gap(s)",
                summary.lost_events, summary.provider_loss_gaps
            );
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(
    root: &Path,
    tls_object_path: &Path,
) -> Result<OutputLossSummary, Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");

    let supervisor = ChildSupervisor::new()?;
    let mut fixture = supervisor.watch(
        spawn_tls_http1_loopback_fixture(
            &fixture_ready_path,
            &fixture_start_path,
            fixture_config(),
        )?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;
    let report = LibsslUprobeTargetDiscovery::default().discover_for_pid(fixture_ready.pid)?;
    let process = report.process();
    let attach_plan = LibsslUprobeAttachPlan::from_discovery_report(report);
    let mut provider = LibsslUprobePlaintextProvider::open(
        LibsslUprobePlaintextProbeConfig::new(tls_object_path, attach_plan),
        Box::new(DirectLoopbackFlowResolver::new(
            fixture_ready.pid,
            process.start_time_ticks,
            fixture_ready.listen_port,
        )),
    )?;

    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    let tracked_flow = wait_for_initial_plaintext_flow(
        &mut provider,
        fixture.child_mut(),
        fixture_ready.listen_port,
    )?;

    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    fixture_result?;
    observe_provider_output_loss(&mut provider, fixture_ready.listen_port, &tracked_flow)
}

fn fixture_config() -> Http1LoopbackFixtureConfig {
    Http1LoopbackFixtureConfig {
        listen_port: None,
        requests: REQUESTS,
        request_body_bytes: REQUEST_BODY_BYTES,
        response_body_bytes: RESPONSE_BODY_BYTES,
        write_chunks: WRITE_CHUNKS,
        connect_write_delay_ms: 0,
        post_exchange_delay_ms: 0,
    }
}

fn wait_for_initial_plaintext_flow(
    provider: &mut LibsslUprobePlaintextProvider,
    fixture: &mut Child,
    listen_port: u16,
) -> Result<FlowIdentity, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + INITIAL_FLOW_TIMEOUT;
    let mut observed = Vec::new();
    loop {
        match provider.poll_next()? {
            CapturePoll::Event(event) => {
                let event = *event;
                if is_expected_tls_plaintext_request_bytes(&event, listen_port) {
                    let CaptureEvent::Bytes(bytes) = event else {
                        unreachable!("guard matched a bytes event");
                    };
                    return Ok(bytes.flow.id);
                }
                observed.push(event);
            }
            CapturePoll::Progress => {}
            CapturePoll::Idle => thread::sleep(POLL_INTERVAL),
            CapturePoll::Finished => {
                return Err(e2e_error(
                    "TLS plaintext provider finished before initial tracked flow",
                )
                .into());
            }
        }
        if let Some(status) = fixture.try_wait()? {
            return Err(e2e_error(format!(
                "fixture exited with {status} before TLS plaintext provider observed an initial tracked flow; observed {}",
                provider_event_summary(&observed, listen_port)
            ))
            .into());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for TLS plaintext provider to observe an initial tracked flow; observed {}",
                provider_event_summary(&observed, listen_port)
            ))
            .into());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutputLossSummary {
    lost_events: u64,
    provider_loss_gaps: u64,
}

fn observe_provider_output_loss(
    provider: &mut LibsslUprobePlaintextProvider,
    listen_port: u16,
    tracked_flow: &FlowIdentity,
) -> Result<OutputLossSummary, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + LOSS_TIMEOUT;
    let mut lost_events = 0_u64;
    let mut provider_loss_gaps = 0_u64;
    let mut observed_events = 0_u64;
    let mut observed = Vec::new();
    loop {
        match provider.poll_next()? {
            CapturePoll::Event(event) => {
                observed_events = observed_events.saturating_add(1);
                if let Some(loss) = tls_plaintext_output_loss_events(&event) {
                    lost_events = lost_events.saturating_add(loss);
                }
                if is_tracked_provider_loss_gap(&event, listen_port, tracked_flow) {
                    provider_loss_gaps = provider_loss_gaps.saturating_add(1);
                }
                if lost_events > 0 && provider_loss_gaps > 0 {
                    return Ok(OutputLossSummary {
                        lost_events,
                        provider_loss_gaps,
                    });
                }
                observed.push(*event);
            }
            CapturePoll::Progress => {}
            CapturePoll::Idle => thread::sleep(POLL_INTERVAL),
            CapturePoll::Finished => {
                return Err(e2e_error(
                    "TLS plaintext provider finished before output loss was observed",
                )
                .into());
            }
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for TLS plaintext output loss on port {listen_port}; observed {observed_events} event(s), lost_events={lost_events}, provider_loss_gaps={provider_loss_gaps}; observed {}",
                provider_event_summary(&observed, listen_port)
            ))
            .into());
        }
    }
}

fn tls_plaintext_output_loss_events(event: &CaptureEvent) -> Option<u64> {
    let CaptureEvent::Loss(loss) = event else {
        return None;
    };
    (loss.origin.source() == CaptureSource::LibsslUprobe
        && loss.origin.provider() == CaptureProviderKind::Plaintext
        && matches!(
            &loss.enforcement_evidence,
            probe_core::EnforcementEvidence::ObservationOnly {
                reason: ObservationOnlyReason::ProviderCaptureLoss,
                ..
            }
        ))
    .then_some(loss.loss.lost_events)
}

fn is_tracked_provider_loss_gap(
    event: &CaptureEvent,
    listen_port: u16,
    tracked_flow: &FlowIdentity,
) -> bool {
    let CaptureEvent::Gap(gap) = event else {
        return false;
    };
    gap.origin.source() == CaptureSource::LibsslUprobe
        && gap.origin.provider() == CaptureProviderKind::Plaintext
        && gap.flow.id == *tracked_flow
        && (gap.flow.local.port == listen_port || gap.flow.remote.port == listen_port)
        && gap.flow.attribution_confidence == DIRECT_LOOPBACK_FLOW_CONFIDENCE
        && gap.gap.next_offset.is_none()
        && matches!(
            &gap.enforcement_evidence,
            probe_core::EnforcementEvidence::ObservationOnly {
                reason: ObservationOnlyReason::ProviderCaptureLoss,
                ..
            }
        )
}

use std::{
    fs,
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::{
    CaptureEvent, CapturePoll, CaptureProvider, EbpfProcessObservationProbeConfig,
    EbpfProcessObservationProvider,
};
use probe_core::{
    CaptureProviderKind, CaptureSource, CompiledSelector, Direction, FlowIdentity,
    ObservationOnlyReason, ProcessSelector, Selector, TrafficSelector,
};

use super::{
    ebpf_procfs_resolver::ProcfsEbpfFlowResolver,
    harness::{ChildSupervisor, create_temp_root, e2e_error, ensure_e2e_packages_built},
    loopback::{
        Http1FixtureIoMode, Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig,
        is_fixture_process, spawn_http1_loopback_fixture_with_io_mode,
        start_http1_loopback_fixture, wait_for_http1_loopback_fixture_exit,
        wait_for_http1_loopback_fixture_ready,
    },
};

const REQUESTS: usize = 1;
const REQUEST_BODY_BYTES: usize = 256 * 1024;
const RESPONSE_BODY_BYTES: usize = 0;
const WRITE_CHUNKS: usize = 1024;
const CONNECT_WRITE_DELAY_MS: u64 = 10_000;
const ACCEPT_READ_DELAY_MS: u64 = CONNECT_WRITE_DELAY_MS;
const INITIAL_FLOW_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_FLOW_MARGIN: Duration = Duration::from_secs(2);
const LOSS_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e eBPF process output loss failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["e2e-fixture"])?;
    let ebpf_object_path = crate::ebpf::ensure_process_artifact_ready().map_err(e2e_error)?;
    let root = create_temp_root("ebpf-process-output-loss")?;
    match run_at(&root, &ebpf_object_path) {
        Ok(summary) => {
            fs::remove_dir_all(&root)?;
            println!(
                "e2e eBPF process output loss passed with {} lost event(s) and {} provider-loss gap(s)",
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
    ebpf_object_path: &Path,
) -> Result<OutputLossSummary, Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    validate_timing_invariant()?;
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");

    let supervisor = ChildSupervisor::new()?;
    let mut fixture = supervisor.watch(
        spawn_http1_loopback_fixture_with_io_mode(
            &fixture_ready_path,
            &fixture_start_path,
            fixture_config(),
            Http1FixtureIoMode::ReadWrite,
        )?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;
    let selector = output_loss_selector(fixture_ready.listen_port)?;
    let mut provider = EbpfProcessObservationProvider::open(
        EbpfProcessObservationProbeConfig::new(ebpf_object_path),
        Box::<ProcfsEbpfFlowResolver>::default(),
        Some(selector),
    )?;

    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    let tracked_client_flow = wait_for_initial_tracked_flow(
        &mut provider,
        fixture.child_mut(),
        fixture_ready.listen_port,
    )?;

    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    fixture_result?;
    observe_provider_output_loss(
        &mut provider,
        fixture_ready.listen_port,
        &tracked_client_flow,
    )
}

fn validate_timing_invariant() -> Result<(), Box<dyn std::error::Error>> {
    let write_delay = Duration::from_millis(CONNECT_WRITE_DELAY_MS);
    if write_delay <= INITIAL_FLOW_TIMEOUT.saturating_add(INITIAL_FLOW_MARGIN) {
        return Err(e2e_error(format!(
            "connect write delay {write_delay:?} must exceed initial flow timeout {INITIAL_FLOW_TIMEOUT:?} plus margin {INITIAL_FLOW_MARGIN:?}"
        ))
        .into());
    }
    Ok(())
}

fn fixture_config() -> PlainHttp1LoopbackFixtureConfig {
    PlainHttp1LoopbackFixtureConfig {
        shared: Http1LoopbackFixtureConfig {
            listen_port: None,
            requests: REQUESTS,
            request_body_bytes: REQUEST_BODY_BYTES,
            response_body_bytes: RESPONSE_BODY_BYTES,
            write_chunks: WRITE_CHUNKS,
            connect_write_delay_ms: CONNECT_WRITE_DELAY_MS,
            post_exchange_delay_ms: 0,
        },
        accept_read_delay_ms: ACCEPT_READ_DELAY_MS,
    }
}

fn output_loss_selector(listen_port: u16) -> Result<CompiledSelector, Box<dyn std::error::Error>> {
    Ok(Selector::Any {
        selectors: vec![
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![listen_port],
                    directions: vec![Direction::Outbound, Direction::Inbound],
                    ..TrafficSelector::default()
                },
            ),
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![listen_port],
                    directions: vec![Direction::Outbound, Direction::Inbound],
                    ..TrafficSelector::default()
                },
            ),
        ],
    }
    .compile()?)
}

fn wait_for_initial_tracked_flow(
    provider: &mut EbpfProcessObservationProvider,
    fixture: &mut Child,
    listen_port: u16,
) -> Result<FlowIdentity, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + INITIAL_FLOW_TIMEOUT;
    loop {
        match provider.poll_next()? {
            CapturePoll::Event(event)
                if is_fixture_client_connection_opened(&event, listen_port) =>
            {
                let CaptureEvent::ConnectionOpened { flow, .. } = *event else {
                    unreachable!("guard matched a connection opened event");
                };
                return Ok(flow.id);
            }
            CapturePoll::Event(_) | CapturePoll::Progress => {}
            CapturePoll::Idle => thread::sleep(POLL_INTERVAL),
            CapturePoll::Finished => {
                return Err(e2e_error("eBPF provider finished before fixture flow opened").into());
            }
        }
        if let Some(status) = fixture.try_wait()? {
            return Err(e2e_error(format!(
                "fixture exited with {status} before eBPF provider observed an initial tracked flow"
            ))
            .into());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for eBPF provider to observe a fixture flow on port {listen_port}"
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
    provider: &mut EbpfProcessObservationProvider,
    listen_port: u16,
    tracked_client_flow: &FlowIdentity,
) -> Result<OutputLossSummary, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + LOSS_TIMEOUT;
    let mut lost_events = 0_u64;
    let mut provider_loss_gaps = 0_u64;
    let mut observed_events = 0_u64;
    loop {
        match provider.poll_next()? {
            CapturePoll::Event(event) => {
                observed_events = observed_events.saturating_add(1);
                if let Some(loss) = ebpf_output_loss_events(&event) {
                    lost_events = lost_events.saturating_add(loss);
                }
                if is_fixture_provider_loss_gap(&event, listen_port, tracked_client_flow) {
                    provider_loss_gaps = provider_loss_gaps.saturating_add(1);
                }
                if lost_events > 0 && provider_loss_gaps > 0 {
                    return Ok(OutputLossSummary {
                        lost_events,
                        provider_loss_gaps,
                    });
                }
            }
            CapturePoll::Progress => {}
            CapturePoll::Idle => thread::sleep(POLL_INTERVAL),
            CapturePoll::Finished => {
                return Err(
                    e2e_error("eBPF provider finished before output loss was observed").into(),
                );
            }
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for eBPF output loss on port {listen_port}; observed {observed_events} event(s), lost_events={lost_events}, provider_loss_gaps={provider_loss_gaps}"
            ))
            .into());
        }
    }
}

fn is_fixture_client_connection_opened(event: &CaptureEvent, listen_port: u16) -> bool {
    let CaptureEvent::ConnectionOpened { origin, flow, .. } = event else {
        return false;
    };
    origin.source() == CaptureSource::EbpfSyscall
        && origin.provider() == CaptureProviderKind::Ebpf
        && flow.remote.port == listen_port
        && flow.attribution_confidence > 0
        && is_fixture_process(&flow.process)
}

fn ebpf_output_loss_events(event: &CaptureEvent) -> Option<u64> {
    let CaptureEvent::Loss(loss) = event else {
        return None;
    };
    (loss.origin.source() == CaptureSource::EbpfSyscall
        && loss.origin.provider() == CaptureProviderKind::Ebpf
        && matches!(
            &loss.enforcement_evidence,
            probe_core::EnforcementEvidence::ObservationOnly {
                reason: ObservationOnlyReason::ProviderCaptureLoss,
                ..
            }
        ))
    .then_some(loss.loss.lost_events)
}

fn is_fixture_provider_loss_gap(
    event: &CaptureEvent,
    listen_port: u16,
    tracked_client_flow: &FlowIdentity,
) -> bool {
    let CaptureEvent::Gap(gap) = event else {
        return false;
    };
    gap.origin.source() == CaptureSource::EbpfSyscall
        && gap.origin.provider() == CaptureProviderKind::Ebpf
        && gap.flow.id == *tracked_client_flow
        && (gap.flow.local.port == listen_port || gap.flow.remote.port == listen_port)
        && gap.flow.attribution_confidence > 0
        && is_fixture_process(&gap.flow.process)
        && gap.gap.next_offset.is_none()
        && matches!(
            &gap.enforcement_evidence,
            probe_core::EnforcementEvidence::ObservationOnly {
                reason: ObservationOnlyReason::ProviderCaptureLoss,
                ..
            }
        )
}

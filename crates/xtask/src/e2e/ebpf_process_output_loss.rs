use std::{
    fs,
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::{
    CaptureEvent, CapturePoll, CaptureProvider, CapturedGap, CapturedLoss,
    EbpfProcessObservationProbeConfig, EbpfProcessObservationProvider,
};
use probe_config::{AgentConfig, CaptureSelection};
use probe_core::{
    CaptureProviderKind, CaptureSource, CompiledSelector, Direction, EventEnvelope, EventKind,
    FlowIdentity, ObservationOnlyReason, ProcessSelector, Selector, TrafficSelector,
};
use storage::FjallSpool;

use super::{
    agent_admin::{
        assert_agent_capture_loss_prometheus_metrics, wait_for_agent_capture_loss_metrics_at_least,
        wait_for_agent_pipeline_progress,
    },
    ebpf_procfs_resolver::ProcfsEbpfFlowResolver,
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        Http1FixtureIoMode, Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig,
        is_fixture_process, spawn_agent, spawn_http1_loopback_fixture_with_io_mode,
        start_http1_loopback_fixture, wait_for_agent_ready, wait_for_http1_loopback_fixture_exit,
        wait_for_http1_loopback_fixture_ready,
    },
};

const AGENT_ID: &str = "e2e-ebpf-process-output-loss-agent";
const CONFIG_VERSION: &str = "e2e-ebpf-process-output-loss";
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-ebpf-process-output-loss";
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
    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    let ebpf_object_path = crate::ebpf::ensure_process_artifact_ready().map_err(e2e_error)?;
    let root = create_temp_root("ebpf-process-output-loss")?;
    match run_at(&root, &ebpf_object_path) {
        Ok(summary) => {
            fs::remove_dir_all(&root)?;
            println!(
                "e2e eBPF process output loss passed with {} loss event(s), {} lost event(s), and {} provider-loss gap(s)",
                summary.loss_events, summary.lost_events, summary.provider_loss_gaps
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
    let feed_path = root.join("observed-ebpf-output-loss.jsonl");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let admin_socket_path = root.join("admin.sock");
    let agent_ready_socket_path = root.join("agent.ready.sock");

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
    let observation = observe_provider_output_loss(
        &mut provider,
        fixture_ready.listen_port,
        &tracked_client_flow,
    )?;
    write_observed_capture_event_feed(&feed_path, &observation.replay_events)?;
    write_agent_config(&config_path, &feed_path, &spool_path, &admin_socket_path)?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    let replay_events = u64::try_from(observation.replay_events.len())?;
    let metrics = wait_for_agent_capture_loss_metrics_at_least(
        agent.child_mut(),
        &admin_socket_path,
        observation.summary.loss_events,
        observation.summary.lost_events,
        "observed eBPF output loss",
    )?;
    wait_for_agent_pipeline_progress(
        agent.child_mut(),
        &admin_socket_path,
        0,
        replay_events,
        replay_events,
    )?;
    assert_agent_capture_loss_prometheus_metrics(
        &admin_socket_path,
        observation.summary.loss_events,
        observation.summary.lost_events,
        "observed eBPF output loss",
    )?;
    stop_running_child(agent.child_mut(), "agent")?;
    agent.unwatch();
    assert_agent_spool_outputs(
        &spool_path,
        &observation,
        observation.summary.loss_events,
        observation.summary.lost_events,
    )?;
    Ok(OutputLossSummary {
        loss_events: metrics.events,
        lost_events: metrics.lost_events,
        provider_loss_gaps: observation.summary.provider_loss_gaps,
    })
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
        vector_first_payload_slice_bytes: None,
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
    loss_events: u64,
    lost_events: u64,
    provider_loss_gaps: u64,
}

#[derive(Debug)]
struct OutputLossObservation {
    summary: OutputLossSummary,
    replay_events: Vec<CaptureEvent>,
}

fn observe_provider_output_loss(
    provider: &mut EbpfProcessObservationProvider,
    listen_port: u16,
    tracked_client_flow: &FlowIdentity,
) -> Result<OutputLossObservation, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + LOSS_TIMEOUT;
    let mut loss_events = 0_u64;
    let mut lost_events = 0_u64;
    let mut provider_loss_gaps = 0_u64;
    let mut observed_events = 0_u64;
    let mut replay_events = Vec::new();
    loop {
        match provider.poll_next()? {
            CapturePoll::Event(event) => {
                let event = *event;
                observed_events = observed_events.saturating_add(1);
                if let Some(loss) = ebpf_output_loss_events(&event) {
                    loss_events = loss_events.saturating_add(1);
                    lost_events = lost_events.saturating_add(loss);
                    replay_events.push(event.clone());
                }
                if is_fixture_provider_loss_gap(&event, listen_port, tracked_client_flow) {
                    provider_loss_gaps = provider_loss_gaps.saturating_add(1);
                    if !replay_events
                        .iter()
                        .any(|event| matches!(event, CaptureEvent::Gap(_)))
                    {
                        replay_events.push(event);
                    }
                }
                if lost_events > 0 && provider_loss_gaps > 0 {
                    return Ok(OutputLossObservation {
                        summary: OutputLossSummary {
                            loss_events,
                            lost_events,
                            provider_loss_gaps,
                        },
                        replay_events,
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
                "timed out waiting for eBPF output loss on port {listen_port}; observed {observed_events} event(s), loss_events={loss_events}, lost_events={lost_events}, provider_loss_gaps={provider_loss_gaps}"
            ))
            .into());
        }
    }
}

fn write_observed_capture_event_feed(
    path: &Path,
    events: &[CaptureEvent],
) -> Result<(), Box<dyn std::error::Error>> {
    if !events
        .iter()
        .any(|event| matches!(event, CaptureEvent::Loss(_)))
    {
        return Err(e2e_error("observed eBPF output loss replay feed has no loss event").into());
    }
    if !events
        .iter()
        .any(|event| matches!(event, CaptureEvent::Gap(_)))
    {
        return Err(e2e_error("observed eBPF output loss replay feed has no gap event").into());
    }
    let mut output = String::new();
    for event in events {
        output.push_str(&serde_json::to_string(event)?);
        output.push('\n');
    }
    fs::write(path, output)?;
    Ok(())
}

fn write_agent_config(
    path: &Path,
    feed_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: AGENT_ID.to_string(),
        config_version: CONFIG_VERSION.to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::CaptureEventFeed;
    config.capture.capture_event_feed.path = Some(feed_path.to_path_buf());
    config.capture.capture_event_feed.follow = Some(true);
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_agent_spool_outputs(
    spool_path: &Path,
    observation: &OutputLossObservation,
    expected_loss_events: u64,
    expected_lost_events: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool
        .read_ingress_batch_after(0, 64)?
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    assert_observed_replay_ingress(&ingress, observation)?;
    let (ingress_loss_events, ingress_lost_events) =
        capture_loss_totals(ingress.iter().filter_map(capture_loss_event));
    if ingress_loss_events != expected_loss_events || ingress_lost_events != expected_lost_events {
        return Err(e2e_error(format!(
            "expected replayed eBPF capture loss ingress totals loss_events={expected_loss_events} lost_events={expected_lost_events}, got loss_events={ingress_loss_events} lost_events={ingress_lost_events}"
        ))
        .into());
    }
    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 64)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_observed_replay_exports(&envelopes, observation)?;
    let (export_loss_events, export_lost_events) =
        capture_loss_totals(envelopes.iter().filter_map(capture_loss_envelope));
    if export_loss_events != expected_loss_events || export_lost_events != expected_lost_events {
        return Err(e2e_error(format!(
            "expected eBPF capture_loss export totals loss_events={expected_loss_events} lost_events={expected_lost_events}, got loss_events={export_loss_events} lost_events={export_lost_events}"
        ))
        .into());
    }
    Ok(())
}

fn assert_observed_replay_ingress(
    ingress: &[CaptureEvent],
    observation: &OutputLossObservation,
) -> Result<(), Box<dyn std::error::Error>> {
    if ingress == observation.replay_events.as_slice() {
        return Ok(());
    }
    Err(e2e_error(format!(
        "expected exact observed eBPF replay ingress sequence {:?}, got {ingress:?}",
        observation.replay_events
    ))
    .into())
}

fn assert_observed_replay_exports(
    envelopes: &[EventEnvelope],
    observation: &OutputLossObservation,
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes.len() != observation.replay_events.len() {
        return Err(e2e_error(format!(
            "expected {} observed eBPF replay export envelope(s), got {}: {envelopes:?}",
            observation.replay_events.len(),
            envelopes.len()
        ))
        .into());
    }
    for (index, (envelope, expected)) in envelopes
        .iter()
        .zip(observation.replay_events.iter())
        .enumerate()
    {
        if !export_matches_observed_replay_event(envelope, expected) {
            return Err(e2e_error(format!(
                "expected observed eBPF replay export at index {index} for {expected:?}, got {envelope:?}"
            ))
            .into());
        }
    }
    Ok(())
}

fn export_matches_observed_replay_event(envelope: &EventEnvelope, event: &CaptureEvent) -> bool {
    match event {
        CaptureEvent::Loss(loss) => capture_loss_export_matches(envelope, loss),
        CaptureEvent::Gap(gap) => provider_loss_gap_envelope_matches(envelope, gap),
        CaptureEvent::Bytes(_)
        | CaptureEvent::ConnectionOpened { .. }
        | CaptureEvent::ConnectionClosed { .. } => false,
    }
}

fn capture_loss_export_matches(envelope: &EventEnvelope, expected: &CapturedLoss) -> bool {
    envelope.timestamp() == expected.timestamp
        && envelope.origin() == expected.origin
        && envelope.subject() == &probe_core::EventSubject::Provider
        && envelope.degraded()
        && envelope.enforcement_evidence() == &expected.enforcement_evidence
        && matches!(envelope.kind(), EventKind::CaptureLoss(loss) if loss == &expected.loss)
}

fn capture_loss_event(event: &CaptureEvent) -> Option<u64> {
    let CaptureEvent::Loss(CapturedLoss { loss, .. }) = event else {
        return None;
    };
    ebpf_output_loss_events(event)?;
    Some(loss.lost_events)
}

fn capture_loss_envelope(envelope: &EventEnvelope) -> Option<u64> {
    if envelope.origin().source() != CaptureSource::EbpfSyscall {
        return None;
    }
    if envelope.origin().provider() != CaptureProviderKind::Ebpf
        || envelope.subject() != &probe_core::EventSubject::Provider
        || !envelope.degraded()
        || !matches!(
            envelope.enforcement_evidence(),
            probe_core::EnforcementEvidence::ObservationOnly {
                reason: ObservationOnlyReason::ProviderCaptureLoss,
                ..
            }
        )
    {
        return None;
    }
    let EventKind::CaptureLoss(loss) = envelope.kind() else {
        return None;
    };
    Some(loss.lost_events)
}

fn capture_loss_totals(losses: impl Iterator<Item = u64>) -> (u64, u64) {
    losses.fold((0, 0), |(events, lost_events), loss| {
        (events.saturating_add(1), lost_events.saturating_add(loss))
    })
}

fn provider_loss_gap_envelope_matches(
    envelope: &EventEnvelope,
    observed_gap: &CapturedGap,
) -> bool {
    envelope.timestamp() == observed_gap.timestamp
        && envelope.origin() == observed_gap.origin
        && envelope
            .subject()
            .flow()
            .is_some_and(|flow| flow == &observed_gap.flow)
        && envelope.degraded()
        && envelope.enforcement_evidence() == &observed_gap.enforcement_evidence
        && matches!(envelope.kind(), EventKind::Gap(gap) if gap == &observed_gap.gap)
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

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use capture::{CaptureEvent, CaptureProviderKind};
use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{
    CaptureSource, Direction, EnforcementEvidence, EventEnvelope, EventKind, ObservationOnlyReason,
    ProcessSelector, Selector, TrafficSelector,
};
use storage::{FjallSpool, StoredEvent};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        Http1FixtureIoMode, Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig,
        assert_no_policy_runtime_errors, is_fixture_process, merge_run_results, spawn_agent,
        spawn_http1_loopback_fixture_with_io_mode, start_http1_loopback_fixture,
        wait_for_agent_pipeline_progress, wait_for_agent_ready,
        wait_for_http1_loopback_fixture_exit, wait_for_http1_loopback_fixture_ready,
    },
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-ebpf";
const POLICY_ID: &str = "ebpf-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const EXPECTED_POLICY_VERSION: &str = "ebpf-e2e-policy@e2e";
const REQUESTS: usize = 1;
const REQUEST_BODY_BYTES: usize = 64;
const RESPONSE_BODY_BYTES: usize = 32;
const WRITE_CHUNKS: usize = 1;
const CONNECT_WRITE_DELAY_MS: u64 = 2_000;
const ACCEPT_READ_DELAY_MS: u64 = 2_000;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e eBPF process loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    let ebpf_object_path = crate::ebpf::ensure_process_artifact_ready().map_err(e2e_error)?;

    for io_mode in [
        Http1FixtureIoMode::ReadWrite,
        Http1FixtureIoMode::SendRecv,
        Http1FixtureIoMode::ReadvWritev,
        Http1FixtureIoMode::SendmsgRecvmsg,
    ] {
        let root = create_temp_root(io_mode_temp_name(io_mode))?;
        match run_at(&root, &ebpf_object_path, io_mode) {
            Ok(()) => {
                fs::remove_dir_all(&root)?;
                println!("e2e eBPF process loopback {} passed", io_mode.cli_value());
            }
            Err(error) => {
                eprintln!("e2e artifacts retained at {}", root.display());
                return Err(error);
            }
        }
    }
    println!("e2e eBPF process loopback passed");
    Ok(())
}

fn io_mode_temp_name(io_mode: Http1FixtureIoMode) -> &'static str {
    match io_mode {
        Http1FixtureIoMode::ReadWrite => "ebpf-process-loopback-read-write",
        Http1FixtureIoMode::SendRecv => "ebpf-process-loopback-send-recv",
        Http1FixtureIoMode::ReadvWritev => "ebpf-process-loopback-readv-writev",
        Http1FixtureIoMode::SendmsgRecvmsg => "ebpf-process-loopback-sendmsg-recvmsg",
    }
}

fn run_at(
    root: &Path,
    ebpf_object_path: &Path,
    io_mode: Http1FixtureIoMode,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("ebpf-e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&policy_path)?;
    let mut fixture = supervisor.watch(
        spawn_http1_loopback_fixture_with_io_mode(
            &fixture_ready_path,
            &fixture_start_path,
            fixture_config(),
            io_mode,
        )?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;
    write_agent_config(
        &config_path,
        ebpf_object_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        fixture_ready.listen_port,
    )?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    let progress_result = match &fixture_result {
        Ok(()) => wait_for_agent_pipeline_progress(
            agent.child_mut(),
            &admin_socket_path,
            expected_policy_alert_messages().len() as u64,
            expected_capture_event_floor(io_mode),
            expected_export_event_floor(io_mode),
        ),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&fixture_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&spool_path, fixture_ready.listen_port, io_mode),
        _ => Ok(()),
    };
    merge_run_results(fixture_result, progress_result, agent_result, spool_result)?;

    Ok(())
}

fn expected_capture_event_floor(io_mode: Http1FixtureIoMode) -> u64 {
    match io_mode {
        Http1FixtureIoMode::ReadvWritev | Http1FixtureIoMode::SendmsgRecvmsg => 12,
        Http1FixtureIoMode::ReadWrite | Http1FixtureIoMode::SendRecv => 10,
    }
}

fn expected_export_event_floor(io_mode: Http1FixtureIoMode) -> u64 {
    match io_mode {
        Http1FixtureIoMode::ReadvWritev | Http1FixtureIoMode::SendmsgRecvmsg => 18,
        Http1FixtureIoMode::ReadWrite | Http1FixtureIoMode::SendRecv => 16,
    }
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

fn write_policy_bundle(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)?;
    fs::write(
        path.join("manifest.toml"),
        format!(
            r#"
id = "{POLICY_ID}"
version = "{POLICY_VERSION}"
hooks = ["on_http_request_headers"]
"#
        ),
    )?;
    fs::write(
        path.join("main.lua"),
        r#"
function on_http_request_headers(event)
  local target = event.kind.target or ""
  if string.sub(target, 1, 10) == "/sssa-e2e/" then
    return probe.emit_alert("ebpf policy observed " .. target)
  end
end
"#,
    )
}

fn write_agent_config(
    path: &Path,
    ebpf_object_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-ebpf-agent".to_string(),
        config_version: "e2e-ebpf-process-loopback".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Ebpf;
    config.capture.ebpf.object_path = Some(PathBuf::from(ebpf_object_path));
    config.capture.deep_observe_selector = Some(Selector::Any {
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
    });
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        path: policy_path.to_path_buf(),
        enabled: true,
        selector: None,
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_spool_outputs(
    spool_path: &Path,
    listen_port: u16,
    io_mode: Http1FixtureIoMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 256)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected eBPF ingress records, got none").into());
    }
    assert_ebpf_ingress(&ingress, listen_port, io_mode)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_lifecycle_exports(&envelopes, listen_port)?;
    assert_expected_requests(&envelopes)?;
    assert_expected_responses(&envelopes)?;
    assert_expected_policy_alerts(&envelopes)?;

    println!(
        "e2e eBPF process loopback observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_ebpf_ingress(
    events: &[StoredEvent],
    listen_port: u16,
    io_mode: Http1FixtureIoMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;

    for side in [FlowSide::Client, FlowSide::Server] {
        for lifecycle in [ConnectionLifecycle::Opened, ConnectionLifecycle::Closed] {
            if capture_events
                .iter()
                .any(|event| is_expected_connection_event(event, listen_port, side, lifecycle))
            {
                continue;
            }
            return Err(e2e_error(format!(
                "missing eBPF {side:?} {lifecycle:?} ingress event; observed {}",
                ingress_summary(&capture_events, listen_port)
            ))
            .into());
        }
        for direction in [Direction::Outbound, Direction::Inbound] {
            if capture_events.iter().any(|event| {
                is_expected_degraded_payload_event(event, listen_port, side, direction)
            }) {
                continue;
            }
            return Err(e2e_error(format!(
                "missing selector-authorized eBPF {side:?} {direction:?} syscall payload sample; observed {}",
                ingress_summary(&capture_events, listen_port)
            ))
            .into());
        }
    }
    assert_expected_vector_gaps(&capture_events, listen_port, io_mode)?;

    Ok(())
}

fn assert_expected_vector_gaps(
    events: &[CaptureEvent],
    listen_port: u16,
    io_mode: Http1FixtureIoMode,
) -> Result<(), Box<dyn std::error::Error>> {
    match io_mode {
        Http1FixtureIoMode::ReadvWritev | Http1FixtureIoMode::SendmsgRecvmsg => {}
        Http1FixtureIoMode::ReadWrite | Http1FixtureIoMode::SendRecv => return Ok(()),
    }

    for (side, direction) in [
        (FlowSide::Client, Direction::Outbound),
        (FlowSide::Server, Direction::Inbound),
    ] {
        if events
            .iter()
            .any(|event| is_expected_gap_event(event, listen_port, side, direction))
        {
            continue;
        }
        return Err(e2e_error(format!(
            "missing vector eBPF {side:?} {direction:?} truncated gap; observed {}",
            ingress_summary(events, listen_port)
        ))
        .into());
    }
    Ok(())
}

fn ingress_summary(events: &[CaptureEvent], listen_port: u16) -> String {
    let summaries = events
        .iter()
        .filter_map(|event| event_summary(event, listen_port))
        .take(16)
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        return format!("no eBPF ingress events near port {listen_port}");
    }
    summaries.join("; ")
}

fn event_summary(event: &CaptureEvent, listen_port: u16) -> Option<String> {
    match event {
        CaptureEvent::ConnectionOpened { origin, flow, .. }
        | CaptureEvent::ConnectionClosed { origin, flow, .. }
            if origin.source() == CaptureSource::EbpfSyscall
                && origin.provider() == CaptureProviderKind::Ebpf
                && (flow.local.port == listen_port || flow.remote.port == listen_port) =>
        {
            Some(format!(
                "{} local={}:{} remote={}:{} pid={} name={} confidence={} fixture={}",
                match event {
                    CaptureEvent::ConnectionOpened { .. } => "opened",
                    CaptureEvent::ConnectionClosed { .. } => "closed",
                    _ => unreachable!(),
                },
                flow.local.address,
                flow.local.port,
                flow.remote.address,
                flow.remote.port,
                flow.process.identity.pid,
                flow.process.name,
                flow.attribution_confidence,
                is_fixture_process(&flow.process)
            ))
        }
        CaptureEvent::Bytes(bytes)
            if bytes.origin.source() == CaptureSource::EbpfSyscall
                && bytes.origin.provider() == CaptureProviderKind::Ebpf
                && (bytes.flow.local.port == listen_port
                    || bytes.flow.remote.port == listen_port) =>
        {
            Some(format!(
                "bytes direction={:?} local={}:{} remote={}:{} pid={} name={} confidence={} len={} degraded={} fixture={}",
                bytes.direction,
                bytes.flow.local.address,
                bytes.flow.local.port,
                bytes.flow.remote.address,
                bytes.flow.remote.port,
                bytes.flow.process.identity.pid,
                bytes.flow.process.name,
                bytes.flow.attribution_confidence,
                bytes.bytes.len(),
                bytes.degraded,
                is_fixture_process(&bytes.flow.process)
            ))
        }
        CaptureEvent::Gap(gap)
            if gap.origin.source() == CaptureSource::EbpfSyscall
                && gap.origin.provider() == CaptureProviderKind::Ebpf
                && (gap.flow.local.port == listen_port || gap.flow.remote.port == listen_port) =>
        {
            Some(format!(
                "gap direction={:?} local={}:{} remote={}:{} pid={} name={} confidence={} reason={}",
                gap.gap.direction,
                gap.flow.local.address,
                gap.flow.local.port,
                gap.flow.remote.address,
                gap.flow.remote.port,
                gap.flow.process.identity.pid,
                gap.flow.process.name,
                gap.flow.attribution_confidence,
                gap.gap.reason
            ))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionLifecycle {
    Opened,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowSide {
    Client,
    Server,
}

fn is_expected_connection_event(
    event: &CaptureEvent,
    listen_port: u16,
    side: FlowSide,
    lifecycle: ConnectionLifecycle,
) -> bool {
    match (lifecycle, event) {
        (ConnectionLifecycle::Opened, CaptureEvent::ConnectionOpened { origin, flow, .. })
        | (ConnectionLifecycle::Closed, CaptureEvent::ConnectionClosed { origin, flow, .. }) => {
            origin.source() == CaptureSource::EbpfSyscall
                && origin.provider() == CaptureProviderKind::Ebpf
                && matches_expected_side(flow.local.port, flow.remote.port, listen_port, side)
                && flow.attribution_confidence > 0
                && is_fixture_process(&flow.process)
        }
        _ => false,
    }
}

fn is_expected_degraded_payload_event(
    event: &CaptureEvent,
    listen_port: u16,
    side: FlowSide,
    direction: Direction,
) -> bool {
    let CaptureEvent::Bytes(bytes) = event else {
        return false;
    };
    bytes.origin.source() == CaptureSource::EbpfSyscall
        && bytes.origin.provider() == CaptureProviderKind::Ebpf
        && bytes.direction == direction
        && matches_expected_side(
            bytes.flow.local.port,
            bytes.flow.remote.port,
            listen_port,
            side,
        )
        && bytes.flow.attribution_confidence > 0
        && is_fixture_process(&bytes.flow.process)
        && bytes.degraded
        && bytes
            .degradation_reason
            .as_deref()
            .is_some_and(|reason| expected_payload_reason(reason, direction))
        && matches!(
            &bytes.enforcement_evidence,
            EnforcementEvidence::ObservationOnly {
                reason: ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                ..
            }
        )
}

fn is_expected_gap_event(
    event: &CaptureEvent,
    listen_port: u16,
    side: FlowSide,
    direction: Direction,
) -> bool {
    let CaptureEvent::Gap(gap) = event else {
        return false;
    };
    gap.origin.source() == CaptureSource::EbpfSyscall
        && gap.origin.provider() == CaptureProviderKind::Ebpf
        && gap.gap.direction == direction
        && matches_expected_side(gap.flow.local.port, gap.flow.remote.port, listen_port, side)
        && gap.flow.attribution_confidence > 0
        && is_fixture_process(&gap.flow.process)
        && gap.gap.reason.contains("syscall sample truncated payload")
}

fn matches_expected_side(
    local_port: u16,
    remote_port: u16,
    listen_port: u16,
    side: FlowSide,
) -> bool {
    match side {
        FlowSide::Client => remote_port == listen_port,
        FlowSide::Server => local_port == listen_port,
    }
}

fn expected_payload_reason(reason: &str, direction: Direction) -> bool {
    match direction {
        Direction::Outbound => {
            reason.contains("outbound syscall sample")
                && reason.contains("before the kernel copies bytes")
                && reason.contains("best-effort")
        }
        Direction::Inbound => {
            reason.contains("inbound syscall sample")
                && reason.contains("after the kernel returns")
                && reason.contains("best-effort")
        }
    }
}

fn assert_expected_lifecycle_exports(
    envelopes: &[EventEnvelope],
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    for side in [FlowSide::Client, FlowSide::Server] {
        for lifecycle in [ConnectionLifecycle::Opened, ConnectionLifecycle::Closed] {
            if envelopes.iter().any(|envelope| {
                is_expected_lifecycle_envelope(envelope, listen_port, side, lifecycle)
            }) {
                continue;
            }
            return Err(e2e_error(format!(
                "missing eBPF {side:?} {lifecycle:?} export event for fixture flow"
            ))
            .into());
        }
    }
    Ok(())
}

fn is_expected_lifecycle_envelope(
    envelope: &EventEnvelope,
    listen_port: u16,
    side: FlowSide,
    lifecycle: ConnectionLifecycle,
) -> bool {
    let expected_kind = match lifecycle {
        ConnectionLifecycle::Opened => EventKind::ConnectionOpened,
        ConnectionLifecycle::Closed => EventKind::ConnectionClosed,
    };
    let Some(flow) = envelope.flow() else {
        return false;
    };
    envelope.origin().source() == CaptureSource::EbpfSyscall
        && matches_expected_side(flow.local.port, flow.remote.port, listen_port, side)
        && flow.attribution_confidence > 0
        && is_fixture_process(&flow.process)
        && envelope.kind() == &expected_kind
}

fn assert_expected_requests(envelopes: &[EventEnvelope]) -> Result<(), Box<dyn std::error::Error>> {
    assert_expected_request_direction(envelopes, Direction::Outbound)?;
    assert_expected_request_direction(envelopes, Direction::Inbound)
}

fn assert_expected_request_direction(
    envelopes: &[EventEnvelope],
    direction: Direction,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::HttpRequestHeaders(headers)
                if envelope.origin().source() == CaptureSource::EbpfSyscall
                    && envelope.origin().provider() == CaptureProviderKind::Ebpf
                    && envelope.degraded()
                    && matches!(
                        &envelope.enforcement_evidence(),
                        EnforcementEvidence::ObservationOnly {
                            reason: ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                            ..
                        }
                    )
                    && headers.direction == direction
                    && headers.method.as_deref() == Some("POST") =>
            {
                headers.target.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_targets();
    if observed.is_superset(&expected) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing eBPF {direction:?} HTTP request targets; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn assert_expected_responses(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_expected_response_direction(envelopes, Direction::Inbound)?;
    assert_expected_response_direction(envelopes, Direction::Outbound)
}

fn assert_expected_response_direction(
    envelopes: &[EventEnvelope],
    direction: Direction,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter(|envelope| {
            matches!(
                envelope.kind(),
                EventKind::HttpResponseHeaders(headers)
                if envelope.origin().source() == CaptureSource::EbpfSyscall
                    && envelope.origin().provider() == CaptureProviderKind::Ebpf
                    && envelope.degraded()
                    && matches!(
                        &envelope.enforcement_evidence(),
                        EnforcementEvidence::ObservationOnly {
                            reason: ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                            ..
                        }
                    )
                    && headers.direction == direction
                    && headers.status == Some(200)
            )
        })
        .count();
    if observed >= REQUESTS {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing eBPF {direction:?} HTTP response headers; expected at least {REQUESTS}, observed {observed}",
    ))
    .into())
}

fn assert_expected_policy_alerts(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert)
                if envelope.origin().source() == CaptureSource::EbpfSyscall
                    && envelope.origin().provider() == CaptureProviderKind::Ebpf
                    && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
                    && envelope.degraded()
                    && matches!(
                        &envelope.enforcement_evidence(),
                        EnforcementEvidence::ObservationOnly {
                            reason: ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                            ..
                        }
                    ) =>
            {
                Some(alert.message.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_policy_alert_messages();
    if observed.is_superset(&expected) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing eBPF policy alerts; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn expected_targets() -> BTreeSet<String> {
    (0..REQUESTS)
        .map(|request| format!("/sssa-e2e/{request}"))
        .collect()
}

fn expected_policy_alert_messages() -> BTreeSet<String> {
    expected_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .collect()
}

fn expected_policy_alert_message(target: String) -> String {
    format!("ebpf policy observed {target}")
}

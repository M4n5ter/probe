use std::{fs, path::Path, process::ExitCode};

use capture::{CaptureEvent, CaptureProviderKind, CapturedLoss};
use probe_config::{AgentConfig, CaptureSelection};
use probe_core::{
    CaptureLoss, CaptureOrigin, CaptureSource, EnforcementEvidence, EventEnvelope, EventKind,
    EventSubject, ObservationOnlyReason, Timestamp,
};
use storage::FjallSpool;

use super::{
    agent_admin::{
        assert_agent_capture_loss_prometheus_metrics, wait_for_agent_capture_loss_metrics_at_least,
    },
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{spawn_agent, wait_for_agent_ready},
};

const AGENT_ID: &str = "e2e-capture-loss-event-feed-agent";
const CONFIG_VERSION: &str = "e2e-capture-loss-event-feed";
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-capture-loss";
const LOST_EVENTS: u64 = 11;
const LOSS_REASON: &str = "deterministic provider loss fixture";

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e capture loss event feed failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent"])?;
    let root = create_temp_root("capture-loss-event-feed")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e capture loss event feed passed");
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("capture-events.jsonl");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let admin_socket_path = root.join("admin.sock");
    let agent_ready_socket_path = root.join("agent.ready.sock");

    write_capture_event_feed(&feed_path)?;
    write_agent_config(&config_path, &feed_path, &spool_path, &admin_socket_path)?;

    let supervisor = ChildSupervisor::new()?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    let metrics = wait_for_agent_capture_loss_metrics_at_least(
        agent.child_mut(),
        &admin_socket_path,
        1,
        LOST_EVENTS,
        "deterministic provider loss",
    )?;
    assert_agent_capture_loss_prometheus_metrics(
        &admin_socket_path,
        1,
        LOST_EVENTS,
        "deterministic provider loss",
    )?;
    stop_running_child(agent.child_mut(), "agent")?;
    agent.unwatch();
    assert_spool_outputs(&spool_path)?;

    println!(
        "e2e capture loss event feed observed {} loss event(s) and {} lost event(s)",
        metrics.events, metrics.lost_events
    );
    Ok(())
}

fn write_capture_event_feed(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let event = capture_loss_event();
    let mut line = serde_json::to_string(&event)?;
    line.push('\n');
    fs::write(path, line)?;
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

fn capture_loss_event() -> CaptureEvent {
    CaptureEvent::Loss(CapturedLoss {
        timestamp: loss_timestamp(),
        origin: CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
        enforcement_evidence: EnforcementEvidence::observation_only_with_detail(
            ObservationOnlyReason::ProviderCaptureLoss,
            LOSS_REASON,
        ),
        loss: CaptureLoss {
            lost_events: LOST_EVENTS,
            reason: LOSS_REASON.to_string(),
        },
    })
}

fn loss_timestamp() -> Timestamp {
    Timestamp {
        monotonic_ns: 1,
        wall_time_unix_ns: 2,
    }
}

fn assert_spool_outputs(spool_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    let [ingress_record] = ingress.as_slice() else {
        return Err(e2e_error(format!(
            "expected one capture loss ingress record, got {}",
            ingress.len()
        ))
        .into());
    };
    let ingress_event = decode_capture_event(ingress_record)?;
    assert_capture_loss_event(&ingress_event)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 16)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    let [envelope] = envelopes.as_slice() else {
        return Err(e2e_error(format!(
            "expected one capture loss export record, got {}",
            envelopes.len()
        ))
        .into());
    };
    assert_capture_loss_export(envelope)?;
    Ok(())
}

fn assert_capture_loss_event(event: &CaptureEvent) -> Result<(), Box<dyn std::error::Error>> {
    let CaptureEvent::Loss(loss) = event else {
        return Err(e2e_error(format!(
            "expected capture loss ingress event, got {event:?}"
        ))
        .into());
    };
    if loss.timestamp != loss_timestamp()
        || loss.origin.source() != CaptureSource::EbpfSyscall
        || loss.origin.provider() != CaptureProviderKind::Ebpf
        || loss.loss.lost_events != LOST_EVENTS
        || loss.loss.reason != LOSS_REASON
    {
        return Err(e2e_error(format!("unexpected capture loss ingress event: {loss:?}")).into());
    }
    Ok(())
}

fn assert_capture_loss_export(envelope: &EventEnvelope) -> Result<(), Box<dyn std::error::Error>> {
    if envelope.timestamp() != loss_timestamp()
        || envelope.origin().source() != CaptureSource::EbpfSyscall
        || envelope.origin().provider() != CaptureProviderKind::Ebpf
        || envelope.subject() != &EventSubject::Provider
        || !envelope.degraded()
    {
        return Err(e2e_error(format!("unexpected capture loss envelope: {envelope:?}")).into());
    }
    let EventKind::CaptureLoss(loss) = envelope.kind() else {
        return Err(e2e_error(format!(
            "expected capture_loss export envelope, got {:?}",
            envelope.kind()
        ))
        .into());
    };
    if loss.lost_events != LOST_EVENTS || loss.reason != LOSS_REASON {
        return Err(e2e_error(format!("unexpected capture loss payload: {loss:?}")).into());
    }
    Ok(())
}

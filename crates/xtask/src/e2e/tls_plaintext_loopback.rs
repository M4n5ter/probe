use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::{CaptureEvent, CaptureProviderKind};
use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{
    CaptureSource, Direction, EventEnvelope, EventKind, ProcessSelector, Selector, TrafficSelector,
};
use storage::{FjallSpool, StoredEvent};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, stop_running_child,
    },
    loopback::{
        Http1LoopbackFixtureConfig, assert_no_policy_runtime_errors, is_fixture_process,
        merge_run_results, spawn_agent, spawn_tls_http1_loopback_fixture,
        start_http1_loopback_fixture, wait_for_agent_policy_progress, wait_for_agent_ready,
        wait_for_http1_loopback_fixture_exit, wait_for_http1_loopback_fixture_ready,
    },
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-tls-plaintext";
const INTERFACE: &str = "any";
const POLICY_ID: &str = "tls-plaintext-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const EXPECTED_POLICY_VERSION: &str = "tls-plaintext-e2e-policy@e2e";
const REQUESTS: usize = 1;
const REQUEST_BODY_BYTES: usize = 48;
const RESPONSE_BODY_BYTES: usize = 24;
const WRITE_CHUNKS: usize = 1;
const POST_EXCHANGE_DELAY_MS: u64 = 500;
const TLS_RECONCILE_INTERVAL_MS: u64 = 100;
const TLS_ATTACH_READY_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_ATTACH_READY_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e TLS plaintext loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    let tls_object_path = crate::ebpf::ensure_tls_plaintext_artifact_ready().map_err(e2e_error)?;

    let root = create_temp_root("tls-plaintext-loopback")?;
    match run_at(&root, &tls_object_path) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e TLS plaintext loopback passed");
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path, tls_object_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("tls-plaintext-e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&policy_path)?;
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
    write_agent_config(
        &config_path,
        tls_object_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        fixture_ready.pid,
        fixture_ready.listen_port,
    )?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    wait_for_tls_plaintext_active_target(agent.child_mut(), &admin_socket_path, fixture_ready.pid)?;
    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    let progress_result = match &fixture_result {
        Ok(()) => wait_for_agent_policy_progress(
            agent.child_mut(),
            &admin_socket_path,
            expected_policy_alert_messages().len() as u64,
        ),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&fixture_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&spool_path, fixture_ready.listen_port),
        _ => Ok(()),
    };
    merge_run_results(fixture_result, progress_result, agent_result, spool_result)?;

    Ok(())
}

fn fixture_config() -> Http1LoopbackFixtureConfig {
    Http1LoopbackFixtureConfig {
        requests: REQUESTS,
        request_body_bytes: REQUEST_BODY_BYTES,
        response_body_bytes: RESPONSE_BODY_BYTES,
        write_chunks: WRITE_CHUNKS,
        connect_write_delay_ms: 0,
        post_exchange_delay_ms: POST_EXCHANGE_DELAY_MS,
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
    return probe.emit_alert("tls plaintext policy observed " .. target)
  end
end
"#,
    )
}

fn write_agent_config(
    path: &Path,
    tls_object_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    fixture_pid: u32,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-tls-plaintext-agent".to_string(),
        config_version: "e2e-tls-plaintext-loopback".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {listen_port}");
    config.capture.libpcap.read_timeout_ms = 100;
    config.tls.plaintext.instrumentation.enabled = true;
    config
        .tls
        .plaintext
        .instrumentation
        .libssl_uprobe_object_path = Some(tls_object_path.to_path_buf());
    config.tls.plaintext.instrumentation.reconcile_interval_ms = TLS_RECONCILE_INTERVAL_MS;
    config.tls.plaintext.instrumentation.selector = Some(Selector::term(
        ProcessSelector {
            pids: vec![fixture_pid],
            ..ProcessSelector::default()
        },
        TrafficSelector {
            remote_ports: vec![listen_port],
            directions: vec![Direction::Outbound],
            ..TrafficSelector::default()
        },
    ));
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
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 256)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected TLS plaintext ingress records, got none").into());
    }
    assert_tls_plaintext_ingress(&ingress, listen_port)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_requests(&envelopes)?;
    assert_expected_policy_alerts(&envelopes)?;

    println!(
        "e2e TLS plaintext loopback observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn wait_for_tls_plaintext_active_target(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + TLS_ATTACH_READY_TIMEOUT;
    loop {
        let status = match read_tls_plaintext_status(admin_socket_path) {
            Ok(status) if status.has_active_target(fixture_pid) => return Ok(()),
            Ok(status) => status,
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before TLS plaintext attached to fixture pid {fixture_pid}: {error}"
                    ))
                    .into());
                }
                TlsPlaintextAttachStatus::error(error.to_string())
            }
        };
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for TLS plaintext active target pid {fixture_pid}; last status: {}",
                status.summary()
            ))
            .into());
        }
        thread::sleep(TLS_ATTACH_READY_INTERVAL);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsPlaintextAttachStatus {
    mode: Option<String>,
    reason: Option<String>,
    active: u64,
    active_pids: BTreeSet<u32>,
    error: Option<String>,
}

impl TlsPlaintextAttachStatus {
    fn error(error: String) -> Self {
        Self {
            mode: None,
            reason: None,
            active: 0,
            active_pids: BTreeSet::new(),
            error: Some(error),
        }
    }

    fn has_active_target(&self, fixture_pid: u32) -> bool {
        self.active_pids.contains(&fixture_pid)
    }

    fn summary(&self) -> String {
        if let Some(error) = &self.error {
            return format!("admin error: {error}");
        }
        format!(
            "mode={:?} reason={:?} active={} active_pids={:?}",
            self.mode, self.reason, self.active, self.active_pids
        )
    }
}

fn read_tls_plaintext_status(
    admin_socket_path: &Path,
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(admin_socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"{\"command\":\"status\"}\n")?;

    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    let value = serde_json::from_str::<serde_json::Value>(&line)?;
    let runtime = &value["snapshot"]["tls"]["plaintext"]["instrumentation"]["runtime"];
    let active = runtime["last_reconcile"]["target_counts"]["active"]
        .as_u64()
        .unwrap_or_default();
    let active_pids = runtime["last_reconcile"]["targets"]["active"]["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target["pid"].as_u64())
        .filter_map(|pid| u32::try_from(pid).ok())
        .collect::<BTreeSet<_>>();
    Ok(TlsPlaintextAttachStatus {
        mode: runtime["mode"].as_str().map(ToOwned::to_owned),
        reason: runtime["reason"].as_str().map(ToOwned::to_owned),
        active,
        active_pids,
        error: None,
    })
}

fn assert_tls_plaintext_ingress(
    events: &[StoredEvent],
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    let unresolved = capture_events
        .iter()
        .filter(|event| is_unresolved_tls_plaintext_bytes(event))
        .count();
    if unresolved > 0 {
        return Err(e2e_error(format!(
            "observed {unresolved} unresolved libssl plaintext byte event(s) under a remote-port scoped selector; observed {}",
            ingress_summary(&capture_events, listen_port)
        ))
        .into());
    }

    if capture_events
        .iter()
        .any(|event| is_expected_tls_plaintext_request_bytes(event, listen_port))
    {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing outbound libssl uprobe plaintext request bytes; observed {}",
        ingress_summary(&capture_events, listen_port)
    ))
    .into())
}

fn is_expected_tls_plaintext_request_bytes(event: &CaptureEvent, listen_port: u16) -> bool {
    let CaptureEvent::Bytes(bytes) = event else {
        return false;
    };
    bytes.source == CaptureSource::LibsslUprobe
        && bytes.provider == CaptureProviderKind::Plaintext
        && bytes.direction == Direction::Outbound
        && bytes.flow.remote.port == listen_port
        && bytes.flow.attribution_confidence > 0
        && is_fixture_process(&bytes.flow.process)
        && bytes.degraded
        && bytes
            .degradation_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("libssl uprobe"))
        && bytes
            .bytes
            .as_ref()
            .windows("POST /sssa-e2e/0".len())
            .any(|window| window == b"POST /sssa-e2e/0")
}

fn is_unresolved_tls_plaintext_bytes(event: &CaptureEvent) -> bool {
    let CaptureEvent::Bytes(bytes) = event else {
        return false;
    };
    bytes.source == CaptureSource::LibsslUprobe
        && bytes.provider == CaptureProviderKind::Plaintext
        && bytes.flow.attribution_confidence == 0
        && bytes.flow.local.port == 0
        && bytes.flow.remote.port == 0
}

fn ingress_summary(events: &[CaptureEvent], listen_port: u16) -> String {
    let summaries = events
        .iter()
        .filter_map(|event| event_summary(event, listen_port))
        .take(16)
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        return format!("no TLS plaintext ingress events near port {listen_port}");
    }
    summaries.join("; ")
}

fn event_summary(event: &CaptureEvent, listen_port: u16) -> Option<String> {
    match event {
        CaptureEvent::Bytes(bytes) if is_summary_relevant_bytes(bytes, listen_port) => {
            Some(format!(
                "bytes source={:?} provider={:?} direction={:?} local={}:{} remote={}:{} pid={} name={} confidence={} len={} degraded={} fixture={}",
                bytes.source,
                bytes.provider,
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
        CaptureEvent::Gap(gap) if is_summary_relevant_gap(gap, listen_port) => Some(format!(
            "gap source={:?} provider={:?} direction={:?} local={}:{} remote={}:{} pid={} name={} confidence={} reason={}",
            gap.source,
            gap.provider,
            gap.gap.direction,
            gap.flow.local.address,
            gap.flow.local.port,
            gap.flow.remote.address,
            gap.flow.remote.port,
            gap.flow.process.identity.pid,
            gap.flow.process.name,
            gap.flow.attribution_confidence,
            gap.gap.reason
        )),
        _ => None,
    }
}

fn is_summary_relevant_bytes(bytes: &capture::CapturedBytes, listen_port: u16) -> bool {
    bytes.source == CaptureSource::LibsslUprobe
        || bytes.flow.local.port == listen_port
        || bytes.flow.remote.port == listen_port
}

fn is_summary_relevant_gap(gap: &capture::CapturedGap, listen_port: u16) -> bool {
    gap.source == CaptureSource::LibsslUprobe
        || gap.flow.local.port == listen_port
        || gap.flow.remote.port == listen_port
}

fn assert_expected_requests(envelopes: &[EventEnvelope]) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match &envelope.kind {
            EventKind::HttpRequestHeaders(headers)
                if envelope.source == CaptureSource::LibsslUprobe
                    && envelope.degraded
                    && headers.direction == Direction::Outbound
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
        "missing TLS plaintext HTTP request targets; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn assert_expected_policy_alerts(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match &envelope.kind {
            EventKind::PolicyAlert(alert)
                if envelope.source == CaptureSource::LibsslUprobe
                    && envelope.policy_version.as_deref() == Some(EXPECTED_POLICY_VERSION)
                    && envelope.degraded =>
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
        "missing TLS plaintext policy alerts; expected at least {:?}, observed {:?}",
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
    format!("tls plaintext policy observed {target}")
}

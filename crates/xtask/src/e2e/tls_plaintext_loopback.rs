use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, TcpListener},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
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
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        Http1LoopbackFixtureConfig, assert_no_policy_runtime_errors, is_fixture_process,
        merge_labeled_run_results, merge_run_results, spawn_agent,
        spawn_tls_http1_loopback_fixture, start_http1_loopback_fixture,
        wait_for_agent_policy_progress, wait_for_agent_ready, wait_for_http1_loopback_fixture_exit,
        wait_for_http1_loopback_fixture_ready,
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
const FIXTURE_EXE_GLOB: &str = "**/sssa-e2e-fixture";
const TLS_RECONCILE_INTERVAL_MS: u64 = 100;
const TLS_ATTACH_READY_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_ATTACH_READY_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) fn run() -> ExitCode {
    match run_inner(Scenario::Startup) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e TLS plaintext loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn run_dynamic() -> ExitCode {
    match run_inner(Scenario::Dynamic) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e TLS plaintext dynamic loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Startup,
    Dynamic,
}

impl Scenario {
    fn temp_name(self) -> &'static str {
        match self {
            Self::Startup => "tls-plaintext-loopback",
            Self::Dynamic => "tls-plaintext-dynamic-loopback",
        }
    }

    fn success_message(self) -> &'static str {
        match self {
            Self::Startup => "e2e TLS plaintext loopback passed",
            Self::Dynamic => "e2e TLS plaintext dynamic loopback passed",
        }
    }

    fn agent_id(self) -> &'static str {
        match self {
            Self::Startup => "e2e-tls-plaintext-agent",
            Self::Dynamic => "e2e-tls-plaintext-dynamic-agent",
        }
    }

    fn config_version(self) -> &'static str {
        match self {
            Self::Startup => "e2e-tls-plaintext-loopback",
            Self::Dynamic => "e2e-tls-plaintext-dynamic-loopback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachSelector {
    ProcessId(u32),
    FixtureExecutable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsLoopbackPaths {
    fixture_ready: PathBuf,
    fixture_start: PathBuf,
    agent_ready_socket: PathBuf,
    admin_socket: PathBuf,
    policy: PathBuf,
    config: PathBuf,
    spool: PathBuf,
}

impl TlsLoopbackPaths {
    fn new(root: &Path) -> Self {
        Self {
            fixture_ready: root.join("fixture.ready"),
            fixture_start: root.join("fixture.start"),
            agent_ready_socket: root.join("agent.ready.sock"),
            admin_socket: root.join("admin.sock"),
            policy: root.join("tls-plaintext-e2e-policy.bundle"),
            config: root.join("agent.toml"),
            spool: root.join("spool"),
        }
    }
}

fn run_inner(scenario: Scenario) -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    let tls_object_path = crate::ebpf::ensure_tls_plaintext_artifact_ready().map_err(e2e_error)?;

    let root = create_temp_root(scenario.temp_name())?;
    let result = match scenario {
        Scenario::Startup => run_at(&root, &tls_object_path),
        Scenario::Dynamic => run_dynamic_at(&root, &tls_object_path),
    };
    match result {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("{}", scenario.success_message());
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
    let paths = TlsLoopbackPaths::new(root);

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&paths.policy)?;
    let mut fixture = supervisor.watch(
        spawn_tls_http1_loopback_fixture(
            &paths.fixture_ready,
            &paths.fixture_start,
            fixture_config(),
        )?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &paths.fixture_ready)?;
    write_agent_config(
        &paths,
        tls_object_path,
        fixture_ready.listen_port,
        Scenario::Startup,
        AttachSelector::ProcessId(fixture_ready.pid),
    )?;
    let mut ready_signal = UnixSocketReadySignal::bind(paths.agent_ready_socket.clone())?;
    let mut agent = supervisor.watch(spawn_agent(&paths.config, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    wait_for_tls_plaintext_active_target(
        agent.child_mut(),
        &paths.admin_socket,
        fixture_ready.pid,
    )?;
    start_http1_loopback_fixture(&paths.fixture_start, &fixture_ready.start_nonce)?;
    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    let progress_result = match &fixture_result {
        Ok(()) => wait_for_agent_policy_progress(
            agent.child_mut(),
            &paths.admin_socket,
            expected_policy_alert_messages().len() as u64,
        ),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&fixture_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&paths.spool, fixture_ready.listen_port),
        _ => Ok(()),
    };
    merge_run_results(fixture_result, progress_result, agent_result, spool_result)?;

    Ok(())
}

fn run_dynamic_at(root: &Path, tls_object_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let paths = TlsLoopbackPaths::new(root);
    let listen_port = available_loopback_port()?;

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&paths.policy)?;
    write_agent_config(
        &paths,
        tls_object_path,
        listen_port,
        Scenario::Dynamic,
        AttachSelector::FixtureExecutable,
    )?;
    let mut ready_signal = UnixSocketReadySignal::bind(paths.agent_ready_socket.clone())?;
    let mut agent = supervisor.watch(spawn_agent(&paths.config, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    let mut fixture = supervisor.watch(
        spawn_tls_http1_loopback_fixture(
            &paths.fixture_ready,
            &paths.fixture_start,
            dynamic_fixture_config(listen_port),
        )?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &paths.fixture_ready)?;
    let active_status = wait_for_tls_plaintext_active_target(
        agent.child_mut(),
        &paths.admin_socket,
        fixture_ready.pid,
    )?;
    start_http1_loopback_fixture(&paths.fixture_start, &fixture_ready.start_nonce)?;
    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    let detach_result = match &fixture_result {
        Ok(()) => wait_for_tls_plaintext_detached_target(
            agent.child_mut(),
            &paths.admin_socket,
            fixture_ready.pid,
            active_status.sequence,
        ),
        Err(_) => Ok(()),
    };
    let progress_result = match &fixture_result {
        Ok(()) => wait_for_agent_policy_progress(
            agent.child_mut(),
            &paths.admin_socket,
            expected_policy_alert_messages().len() as u64,
        ),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&fixture_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&paths.spool, fixture_ready.listen_port),
        _ => Ok(()),
    };
    merge_labeled_run_results([
        ("fixture", fixture_result),
        ("TLS plaintext detach", detach_result),
        ("agent policy progress", progress_result),
        ("agent", agent_result),
        ("spool assertion", spool_result),
    ])?;

    Ok(())
}

fn fixture_config() -> Http1LoopbackFixtureConfig {
    Http1LoopbackFixtureConfig {
        listen_port: None,
        requests: REQUESTS,
        request_body_bytes: REQUEST_BODY_BYTES,
        response_body_bytes: RESPONSE_BODY_BYTES,
        write_chunks: WRITE_CHUNKS,
        connect_write_delay_ms: 0,
        post_exchange_delay_ms: POST_EXCHANGE_DELAY_MS,
    }
}

fn dynamic_fixture_config(listen_port: u16) -> Http1LoopbackFixtureConfig {
    Http1LoopbackFixtureConfig {
        listen_port: Some(listen_port),
        ..fixture_config()
    }
}

fn available_loopback_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
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
    paths: &TlsLoopbackPaths,
    tls_object_path: &Path,
    listen_port: u16,
    scenario: Scenario,
    attach_selector: AttachSelector,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: scenario.agent_id().to_string(),
        config_version: scenario.config_version().to_string(),
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
    let process = match attach_selector {
        AttachSelector::ProcessId(pid) => ProcessSelector {
            pids: vec![pid],
            ..ProcessSelector::default()
        },
        AttachSelector::FixtureExecutable => ProcessSelector {
            exe_path_globs: vec![FIXTURE_EXE_GLOB.to_string()],
            ..ProcessSelector::default()
        },
    };
    config.tls.plaintext.instrumentation.selector = Some(Selector::term(
        process,
        TrafficSelector {
            remote_ports: vec![listen_port],
            directions: vec![Direction::Outbound],
            ..TrafficSelector::default()
        },
    ));
    config.storage.path = paths.spool.clone();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = paths.admin_socket.clone();
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        path: paths.policy.clone(),
        enabled: true,
        selector: None,
    });
    fs::write(&paths.config, toml::to_string(&config)?)?;
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
) -> Result<TlsPlaintextAttachStatus, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + TLS_ATTACH_READY_TIMEOUT;
    loop {
        let status = match read_tls_plaintext_status(admin_socket_path) {
            Ok(status) if status.has_active_target(fixture_pid) => return Ok(status),
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

fn wait_for_tls_plaintext_detached_target(
    agent: &mut Child,
    admin_socket_path: &Path,
    fixture_pid: u32,
    active_sequence: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + TLS_ATTACH_READY_TIMEOUT;
    loop {
        let status = match read_tls_plaintext_status(admin_socket_path) {
            Ok(status)
                if status.sequence > active_sequence
                    && (status.has_detached_target(fixture_pid)
                        || (status.active == 0 && !status.has_active_target(fixture_pid))) =>
            {
                return Ok(());
            }
            Ok(status) => status,
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before TLS plaintext detached fixture pid {fixture_pid}: {error}"
                    ))
                    .into());
                }
                TlsPlaintextAttachStatus::error(error.to_string())
            }
        };
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for TLS plaintext detach of fixture pid {fixture_pid}; last status: {}",
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
    sequence: u64,
    active: u64,
    detached: u64,
    active_pids: BTreeSet<u32>,
    detached_pids: BTreeSet<u32>,
    error: Option<String>,
}

impl TlsPlaintextAttachStatus {
    fn error(error: String) -> Self {
        Self {
            mode: None,
            reason: None,
            sequence: 0,
            active: 0,
            detached: 0,
            active_pids: BTreeSet::new(),
            detached_pids: BTreeSet::new(),
            error: Some(error),
        }
    }

    fn has_active_target(&self, fixture_pid: u32) -> bool {
        self.active_pids.contains(&fixture_pid)
    }

    fn has_detached_target(&self, fixture_pid: u32) -> bool {
        self.detached_pids.contains(&fixture_pid)
    }

    fn summary(&self) -> String {
        if let Some(error) = &self.error {
            return format!("admin error: {error}");
        }
        format!(
            "mode={:?} reason={:?} sequence={} active={} detached={} active_pids={:?} detached_pids={:?}",
            self.mode,
            self.reason,
            self.sequence,
            self.active,
            self.detached,
            self.active_pids,
            self.detached_pids
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
    let sequence = runtime["last_reconcile"]["sequence"]
        .as_u64()
        .unwrap_or_default();
    let active = runtime["last_reconcile"]["target_counts"]["active"]
        .as_u64()
        .unwrap_or_default();
    let detached = runtime["last_reconcile"]["target_counts"]["detached"]
        .as_u64()
        .unwrap_or_default();
    let active_pids = runtime["last_reconcile"]["targets"]["active"]["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target["pid"].as_u64())
        .filter_map(|pid| u32::try_from(pid).ok())
        .collect::<BTreeSet<_>>();
    let detached_pids = runtime["last_reconcile"]["targets"]["detached"]["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target["pid"].as_u64())
        .filter_map(|pid| u32::try_from(pid).ok())
        .collect::<BTreeSet<_>>();
    Ok(TlsPlaintextAttachStatus {
        mode: runtime["mode"].as_str().map(ToOwned::to_owned),
        reason: runtime["reason"].as_str().map(ToOwned::to_owned),
        sequence,
        active,
        detached,
        active_pids,
        detached_pids,
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
    bytes.origin.source() == CaptureSource::LibsslUprobe
        && bytes.origin.provider() == CaptureProviderKind::Plaintext
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
    bytes.origin.source() == CaptureSource::LibsslUprobe
        && bytes.origin.provider() == CaptureProviderKind::Plaintext
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
                bytes.origin.source(),
                bytes.origin.provider(),
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
            gap.origin.source(),
            gap.origin.provider(),
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
    bytes.origin.source() == CaptureSource::LibsslUprobe
        || bytes.flow.local.port == listen_port
        || bytes.flow.remote.port == listen_port
}

fn is_summary_relevant_gap(gap: &capture::CapturedGap, listen_port: u16) -> bool {
    gap.origin.source() == CaptureSource::LibsslUprobe
        || gap.flow.local.port == listen_port
        || gap.flow.remote.port == listen_port
}

fn assert_expected_requests(envelopes: &[EventEnvelope]) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::HttpRequestHeaders(headers)
                if envelope.origin().source() == CaptureSource::LibsslUprobe
                    && envelope.origin().provider() == CaptureProviderKind::Plaintext
                    && envelope.degraded()
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
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert)
                if envelope.origin().source() == CaptureSource::LibsslUprobe
                    && envelope.origin().provider() == CaptureProviderKind::Plaintext
                    && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
                    && envelope.degraded() =>
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

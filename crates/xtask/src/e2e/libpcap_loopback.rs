use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

use capture::CaptureEvent;
use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{CaptureSource, Direction, EventEnvelope, EventKind};
use storage::{FjallSpool, StoredEvent};

use super::harness::{
    ChildSupervisor, UnixSocketReadySignal, create_temp_root, debug_binary, decode_capture_event,
    decode_envelope, e2e_error, publish_atomic_file, run_in_own_process_group, stop_running_child,
    wait_for_child_exit, wait_for_file_or_child_exit, wait_for_ready_signal_or_child_exit,
};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);
const AGENT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
const AGENT_PROGRESS_STABLE_POLLS: u8 = 3;
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-libpcap";
const INTERFACE: &str = "any";
const READY_SOCKET_ENV: &str = "SSSA_PROBE_READY_SOCKET";
const POLICY_ID: &str = "libpcap-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const EXPECTED_POLICY_VERSION: &str = "libpcap-e2e-policy@e2e";
const REQUESTS: usize = 2;
const REQUEST_BODY_BYTES: usize = 96;
const RESPONSE_BODY_BYTES: usize = 48;
const WRITE_CHUNKS: usize = 3;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e libpcap loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    let root = create_temp_root("libpcap-loopback")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e libpcap loopback passed");
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
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("libpcap-e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&policy_path)?;
    let mut fixture = supervisor.watch(
        spawn_fixture(&fixture_ready_path, &fixture_start_path)?,
        "fixture",
    );
    let fixture_ready = wait_for_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;
    write_agent_config(
        &config_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        fixture_ready.listen_port,
    )?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), ready_signal.listener_mut())?;
    publish_atomic_file(
        &fixture_start_path,
        format!("start_nonce={}\n", fixture_ready.start_nonce).as_bytes(),
    )?;
    let fixture_result = wait_for_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    let progress_result = match &fixture_result {
        Ok(()) => wait_for_agent_policy_progress(agent.child_mut(), &admin_socket_path),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&fixture_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&spool_path),
        _ => Ok(()),
    };
    merge_run_results(fixture_result, progress_result, agent_result, spool_result)?;

    Ok(())
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
    return probe.emit_alert("libpcap policy observed " .. target)
  end
end
"#,
    )
}

fn write_agent_config(
    path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-libpcap-agent".to_string(),
        config_version: "e2e-libpcap-loopback".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {listen_port}");
    config.capture.libpcap.read_timeout_ms = 100;
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

fn spawn_agent(
    config_path: &Path,
    ready_signal: &UnixSocketReadySignal,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary("agent")?);
    let child = run_in_own_process_group(&mut command)
        .args(["run", "--config"])
        .arg(config_path)
        .env(READY_SOCKET_ENV, ready_signal.path())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

fn spawn_fixture(
    ready_path: &Path,
    start_path: &Path,
) -> Result<Child, Box<dyn std::error::Error>> {
    let requests = REQUESTS.to_string();
    let request_body_bytes = REQUEST_BODY_BYTES.to_string();
    let response_body_bytes = RESPONSE_BODY_BYTES.to_string();
    let write_chunks = WRITE_CHUNKS.to_string();
    let mut command = Command::new(debug_binary("sssa-e2e-fixture")?);
    let child = run_in_own_process_group(&mut command)
        .args([
            "http1-loopback",
            "--requests",
            &requests,
            "--request-body-bytes",
            &request_body_bytes,
            "--response-body-bytes",
            &response_body_bytes,
            "--write-chunks",
            &write_chunks,
        ])
        .args(["--ready-file"])
        .arg(ready_path)
        .args(["--start-file"])
        .arg(start_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

fn wait_for_fixture_ready(
    fixture: &mut Child,
    ready_path: &Path,
) -> Result<FixtureReady, Box<dyn std::error::Error>> {
    wait_for_file_or_child_exit(fixture, ready_path, READY_TIMEOUT, "fixture ready")?;
    parse_fixture_ready(ready_path)
}

fn wait_for_agent_ready(
    agent: &mut Child,
    ready_signal: &mut std::os::unix::net::UnixListener,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_ready_signal_or_child_exit(agent, ready_signal, READY_TIMEOUT, "agent ready")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureReady {
    listen_port: u16,
    start_nonce: String,
}

fn parse_fixture_ready(path: &Path) -> Result<FixtureReady, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let Some(listen_addr) = ready_value(&content, "listen_addr") else {
        return Err(e2e_error(format!(
            "fixture ready file {} did not contain listen_addr",
            path.display()
        ))
        .into());
    };
    let Some(start_nonce) = ready_value(&content, "start_nonce") else {
        return Err(e2e_error(format!(
            "fixture ready file {} did not contain start_nonce",
            path.display()
        ))
        .into());
    };
    let address = listen_addr.parse::<SocketAddr>()?;
    Ok(FixtureReady {
        listen_port: address.port(),
        start_nonce,
    })
}

fn ready_value(content: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    content
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(ToOwned::to_owned)
}

fn wait_for_fixture_exit(fixture: &mut Child) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_child_exit(fixture, FIXTURE_TIMEOUT, "fixture")
}

fn wait_for_agent_policy_progress(
    agent: &mut Child,
    admin_socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + AGENT_PROGRESS_TIMEOUT;
    let mut stable_polls = 0u8;
    let mut last_policy_alerts = None;
    let expected_alert_floor = expected_policy_alert_messages().len() as u64;
    loop {
        match read_agent_policy_metrics(admin_socket_path) {
            Ok(policy) if policy.errors > 0 => {
                return Err(e2e_error(format!(
                    "agent policy metrics reported {} runtime errors before expected alerts",
                    policy.errors
                ))
                .into());
            }
            Ok(policy) if policy.alerts >= expected_alert_floor => {
                stable_polls = match last_policy_alerts {
                    Some(previous) if previous == policy.alerts => stable_polls.saturating_add(1),
                    _ => 1,
                };
                last_policy_alerts = Some(policy.alerts);
                if stable_polls >= AGENT_PROGRESS_STABLE_POLLS {
                    return Ok(());
                }
            }
            Ok(policy) => {
                stable_polls = 0;
                last_policy_alerts = Some(policy.alerts);
            }
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before policy alert progress reached {expected_alert_floor}: {error}"
                    ))
                    .into());
                }
                if Instant::now() >= deadline {
                    return Err(e2e_error(format!(
                        "timed out waiting for agent policy alert progress to reach {expected_alert_floor}: {error}"
                    ))
                    .into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for agent policy alert progress to reach {expected_alert_floor}"
            ))
            .into());
        }
        thread::sleep(AGENT_PROGRESS_INTERVAL);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AgentPolicyMetrics {
    alerts: u64,
    errors: u64,
}

fn read_agent_policy_metrics(
    admin_socket_path: &Path,
) -> Result<AgentPolicyMetrics, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(admin_socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"{\"command\":\"metrics\"}\n")?;

    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    let response = serde_json::from_str::<serde_json::Value>(&line)?;
    let policy = &response["metrics"]["pipeline"]["policy"];
    let alerts = policy["alerts"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted policy alert count: {line}"
        ))
    })?;
    let errors = policy["errors"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted policy error count: {line}"
        ))
    })?;
    Ok(AgentPolicyMetrics { alerts, errors })
}

fn merge_run_results(
    fixture_result: Result<(), Box<dyn std::error::Error>>,
    metrics_result: Result<(), Box<dyn std::error::Error>>,
    agent_result: Result<(), Box<dyn std::error::Error>>,
    spool_result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let errors = [
        ("fixture", fixture_result),
        ("agent policy progress", metrics_result),
        ("agent", agent_result),
        ("spool assertion", spool_result),
    ]
    .into_iter()
    .filter_map(|(label, result)| result.err().map(|error| format!("{label} failed: {error}")))
    .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(e2e_error(errors.join("; ")).into())
    }
}

fn assert_spool_outputs(spool_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 256)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected libpcap ingress records, got none").into());
    }
    assert_libpcap_ingress(&ingress)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_requests(&envelopes)?;
    assert_expected_policy_alerts(&envelopes)?;

    println!(
        "e2e libpcap loopback observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_libpcap_ingress(events: &[StoredEvent]) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    let degraded_bytes = capture_events
        .iter()
        .filter(|event| {
            matches!(
                event,
                CaptureEvent::Bytes(bytes)
                    if bytes.source == CaptureSource::Libpcap
                        && bytes.degraded
                        && bytes
                            .degradation_reason
                            .as_deref()
                            .is_some_and(|reason| reason.contains("libpcap fallback"))
            )
        })
        .count();
    if degraded_bytes == 0 {
        return Err(e2e_error("missing degraded libpcap ingress bytes").into());
    }
    Ok(())
}

fn assert_no_policy_runtime_errors(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime_errors = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind, EventKind::PolicyRuntimeError(_)))
        .count();
    if runtime_errors == 0 {
        return Ok(());
    }

    Err(e2e_error(format!(
        "observed {runtime_errors} policy runtime error event(s)"
    ))
    .into())
}

fn assert_expected_requests(envelopes: &[EventEnvelope]) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match &envelope.kind {
            EventKind::HttpRequestHeaders(headers)
                if envelope.source == CaptureSource::Libpcap
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
        "missing libpcap HTTP request targets; expected at least {:?}, observed {:?}",
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
                if envelope.source == CaptureSource::Libpcap
                    && envelope.policy_version.as_deref() == Some(EXPECTED_POLICY_VERSION) =>
            {
                Some(alert.message.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .collect::<BTreeSet<_>>();
    if observed.is_superset(&expected) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing libpcap policy alerts; expected at least {:?}, observed {:?}",
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
    format!("libpcap policy observed {target}")
}

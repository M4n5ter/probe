use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use super::harness::{
    UnixSocketReadySignal, debug_binary, e2e_error, publish_atomic_file, run_in_own_process_group,
    wait_for_child_exit, wait_for_file_or_child_exit, wait_for_ready_signal_or_child_exit,
};
use probe_core::{EventEnvelope, EventKind, ProcessContext};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);
const AGENT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
const AGENT_PROGRESS_STABLE_POLLS: u8 = 3;
const FIXTURE_PROCESS_NAME_PREFIX: &str = "sssa-e2e";
const FIXTURE_BINARY_NAME: &str = "sssa-e2e-fixture";

pub(crate) const AGENT_READY_SOCKET_ENV: &str = "SSSA_PROBE_READY_SOCKET";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Http1LoopbackFixtureConfig {
    pub(crate) listen_port: Option<u16>,
    pub(crate) requests: usize,
    pub(crate) request_body_bytes: usize,
    pub(crate) response_body_bytes: usize,
    pub(crate) write_chunks: usize,
    pub(crate) connect_write_delay_ms: u64,
    pub(crate) post_exchange_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlainHttp1LoopbackFixtureConfig {
    pub(crate) shared: Http1LoopbackFixtureConfig,
    pub(crate) accept_read_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Http1FixtureIoMode {
    ReadWrite,
    SendRecv,
    ReadvWritev,
    SendmsgRecvmsg,
}

impl Http1FixtureIoMode {
    pub(crate) fn cli_value(self) -> &'static str {
        match self {
            Self::ReadWrite => "read-write",
            Self::SendRecv => "send-recv",
            Self::ReadvWritev => "readv-writev",
            Self::SendmsgRecvmsg => "sendmsg-recvmsg",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Http1LoopbackFixtureReady {
    pub(crate) pid: u32,
    pub(crate) listen_port: u16,
    pub(crate) start_nonce: String,
}

pub(crate) type RunResult = Result<(), Box<dyn std::error::Error>>;
pub(crate) type LabeledRunResult = (&'static str, RunResult);

pub(crate) fn spawn_http1_loopback_fixture(
    ready_path: &Path,
    start_path: &Path,
    config: PlainHttp1LoopbackFixtureConfig,
) -> Result<Child, Box<dyn std::error::Error>> {
    spawn_http1_loopback_fixture_with_io_mode(
        ready_path,
        start_path,
        config,
        Http1FixtureIoMode::ReadWrite,
    )
}

pub(crate) fn spawn_http1_loopback_fixture_with_io_mode(
    ready_path: &Path,
    start_path: &Path,
    config: PlainHttp1LoopbackFixtureConfig,
    io_mode: Http1FixtureIoMode,
) -> Result<Child, Box<dyn std::error::Error>> {
    spawn_loopback_fixture(
        "http1-loopback",
        ready_path,
        start_path,
        config.shared,
        Some(PlainHttp1LoopbackFixtureOptions {
            io_mode,
            accept_read_delay_ms: config.accept_read_delay_ms,
        }),
    )
}

pub(crate) fn spawn_tls_http1_loopback_fixture(
    ready_path: &Path,
    start_path: &Path,
    config: Http1LoopbackFixtureConfig,
) -> Result<Child, Box<dyn std::error::Error>> {
    spawn_loopback_fixture("tls-http1-loopback", ready_path, start_path, config, None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlainHttp1LoopbackFixtureOptions {
    io_mode: Http1FixtureIoMode,
    accept_read_delay_ms: u64,
}

fn spawn_loopback_fixture(
    scenario: &'static str,
    ready_path: &Path,
    start_path: &Path,
    config: Http1LoopbackFixtureConfig,
    plain_options: Option<PlainHttp1LoopbackFixtureOptions>,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary("sssa-e2e-fixture")?);
    let command = run_in_own_process_group(&mut command).arg(scenario);
    if let Some(listen_port) = config.listen_port {
        command.arg("--listen-port").arg(listen_port.to_string());
    }
    command
        .arg("--requests")
        .arg(config.requests.to_string())
        .arg("--request-body-bytes")
        .arg(config.request_body_bytes.to_string())
        .arg("--response-body-bytes")
        .arg(config.response_body_bytes.to_string())
        .arg("--write-chunks")
        .arg(config.write_chunks.to_string());
    if let Some(options) = plain_options {
        command
            .arg("--io-mode")
            .arg(options.io_mode.cli_value())
            .arg("--accept-read-delay-ms")
            .arg(options.accept_read_delay_ms.to_string());
    }
    let child = command
        .arg("--connect-write-delay-ms")
        .arg(config.connect_write_delay_ms.to_string())
        .arg("--post-exchange-delay-ms")
        .arg(config.post_exchange_delay_ms.to_string())
        .arg("--ready-file")
        .arg(ready_path)
        .arg("--start-file")
        .arg(start_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

pub(crate) fn spawn_agent(
    config_path: &Path,
    ready_signal: &UnixSocketReadySignal,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary("agent")?);
    let child = run_in_own_process_group(&mut command)
        .args(["run", "--config"])
        .arg(config_path)
        .env(AGENT_READY_SOCKET_ENV, ready_signal.path())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

pub(crate) fn wait_for_http1_loopback_fixture_ready(
    fixture: &mut Child,
    ready_path: &Path,
) -> Result<Http1LoopbackFixtureReady, Box<dyn std::error::Error>> {
    wait_for_file_or_child_exit(fixture, ready_path, READY_TIMEOUT, "fixture ready")?;
    parse_fixture_ready(ready_path)
}

pub(crate) fn start_http1_loopback_fixture(
    start_path: &Path,
    start_nonce: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    publish_atomic_file(
        start_path,
        format!("start_nonce={start_nonce}\n").as_bytes(),
    )?;
    Ok(())
}

pub(crate) fn wait_for_http1_loopback_fixture_exit(
    fixture: &mut Child,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_child_exit(fixture, FIXTURE_TIMEOUT, "fixture")
}

pub(crate) fn wait_for_agent_ready(
    agent: &mut Child,
    ready_signal: &mut UnixSocketReadySignal,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_ready_signal_or_child_exit(
        agent,
        ready_signal.listener_mut(),
        READY_TIMEOUT,
        "agent ready",
    )
}

pub(crate) fn wait_for_agent_policy_progress(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected_alert_floor: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + AGENT_PROGRESS_TIMEOUT;
    let mut stable_polls = 0u8;
    let mut last_policy_alerts = None;
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

pub(crate) fn merge_run_results(
    fixture_result: Result<(), Box<dyn std::error::Error>>,
    metrics_result: Result<(), Box<dyn std::error::Error>>,
    agent_result: Result<(), Box<dyn std::error::Error>>,
    spool_result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    merge_labeled_run_results([
        ("fixture", fixture_result),
        ("agent policy progress", metrics_result),
        ("agent", agent_result),
        ("spool assertion", spool_result),
    ])
}

pub(crate) fn merge_labeled_run_results<const N: usize>(
    results: [LabeledRunResult; N],
) -> Result<(), Box<dyn std::error::Error>> {
    let errors = results
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|error| format!("{label} failed: {error}")))
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(e2e_error(errors.join("; ")).into())
    }
}

pub(crate) fn assert_no_policy_runtime_errors(
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

pub(crate) fn is_fixture_process(process: &ProcessContext) -> bool {
    process.identity.pid > 0
        && (process.name.starts_with(FIXTURE_PROCESS_NAME_PREFIX)
            || process
                .identity
                .exe_path
                .rsplit('/')
                .next()
                .is_some_and(|name| name == FIXTURE_BINARY_NAME)
            || process
                .cmdline
                .iter()
                .any(|arg| arg.contains(FIXTURE_BINARY_NAME)))
}

fn parse_fixture_ready(
    path: &Path,
) -> Result<Http1LoopbackFixtureReady, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let Some(listen_addr) = ready_value(&content, "listen_addr") else {
        return Err(e2e_error(format!(
            "fixture ready file {} did not contain listen_addr",
            path.display()
        ))
        .into());
    };
    let Some(pid) = ready_value(&content, "pid") else {
        return Err(e2e_error(format!(
            "fixture ready file {} did not contain pid",
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
    let pid = pid.parse::<u32>()?;
    Ok(Http1LoopbackFixtureReady {
        pid,
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

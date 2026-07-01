use std::{
    fs,
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use super::harness::{
    UnixSocketReadySignal, debug_binary, e2e_error, publish_atomic_file, run_in_own_process_group,
    wait_for_child_exit, wait_for_file_or_child_exit, wait_for_ready_signal_or_child_exit,
};
use probe_core::ProcessContext;

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);
const FIXTURE_PROCESS_NAME_PREFIX: &str = "traffic-probe-e2e";
const FIXTURE_PROCESS_TASK_COMM: &str = "traffic-probe-e";
const FIXTURE_BINARY_NAME: &str = "traffic-probe-e2e-fixture";
const DYNSSL_FIXTURE_BINARY_NAME: &str = "traffic-probe-e2e-dynssl-fixture";
const FIXTURE_BINARY_NAMES: [&str; 2] = [FIXTURE_BINARY_NAME, DYNSSL_FIXTURE_BINARY_NAME];

pub(crate) const AGENT_READY_SOCKET_ENV: &str = "TRAFFIC_PROBE_READY_SOCKET";

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
pub(crate) struct WebSocketLoopbackFixtureConfig {
    pub(crate) listen_port: Option<u16>,
    pub(crate) connections: usize,
    pub(crate) frame_payload_bytes: usize,
    pub(crate) write_chunks: usize,
    pub(crate) connect_write_delay_ms: u64,
    pub(crate) post_exchange_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Http1FixtureIoMode {
    ReadWrite,
    SendRecv,
    ReadvWritev,
    SendmsgRecvmsg,
    Sendfile,
}

impl Http1FixtureIoMode {
    pub(crate) fn cli_value(self) -> &'static str {
        match self {
            Self::ReadWrite => "read-write",
            Self::SendRecv => "send-recv",
            Self::ReadvWritev => "readv-writev",
            Self::SendmsgRecvmsg => "sendmsg-recvmsg",
            Self::Sendfile => "sendfile",
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
        config.shared.listen_port,
        config.shared.connect_write_delay_ms,
        config.shared.post_exchange_delay_ms,
        |command| {
            append_http1_loopback_fixture_args(command, config.shared);
            append_plain_http1_loopback_fixture_args(
                command,
                PlainHttp1LoopbackFixtureOptions {
                    io_mode,
                    accept_read_delay_ms: config.accept_read_delay_ms,
                },
            );
        },
    )
}

pub(crate) fn spawn_tls_http1_loopback_fixture(
    ready_path: &Path,
    start_path: &Path,
    config: Http1LoopbackFixtureConfig,
) -> Result<Child, Box<dyn std::error::Error>> {
    spawn_loopback_fixture(
        "tls-http1-loopback",
        ready_path,
        start_path,
        config.listen_port,
        config.connect_write_delay_ms,
        config.post_exchange_delay_ms,
        |command| append_http1_loopback_fixture_args(command, config),
    )
}

pub(crate) fn spawn_websocket_loopback_fixture(
    ready_path: &Path,
    start_path: &Path,
    config: WebSocketLoopbackFixtureConfig,
) -> Result<Child, Box<dyn std::error::Error>> {
    spawn_loopback_fixture(
        "websocket-loopback",
        ready_path,
        start_path,
        config.listen_port,
        config.connect_write_delay_ms,
        config.post_exchange_delay_ms,
        |command| append_websocket_loopback_fixture_args(command, config),
    )
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
    listen_port: Option<u16>,
    connect_write_delay_ms: u64,
    post_exchange_delay_ms: u64,
    append_scenario_args: impl FnOnce(&mut Command),
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary(FIXTURE_BINARY_NAME)?);
    let command = run_in_own_process_group(&mut command).arg(scenario);
    if let Some(listen_port) = listen_port {
        command.arg("--listen-port").arg(listen_port.to_string());
    }
    append_scenario_args(command);
    let child = command
        .arg("--connect-write-delay-ms")
        .arg(connect_write_delay_ms.to_string())
        .arg("--post-exchange-delay-ms")
        .arg(post_exchange_delay_ms.to_string())
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

fn append_http1_loopback_fixture_args(command: &mut Command, config: Http1LoopbackFixtureConfig) {
    command
        .arg("--requests")
        .arg(config.requests.to_string())
        .arg("--request-body-bytes")
        .arg(config.request_body_bytes.to_string())
        .arg("--response-body-bytes")
        .arg(config.response_body_bytes.to_string())
        .arg("--write-chunks")
        .arg(config.write_chunks.to_string());
}

fn append_plain_http1_loopback_fixture_args(
    command: &mut Command,
    options: PlainHttp1LoopbackFixtureOptions,
) {
    command
        .arg("--io-mode")
        .arg(options.io_mode.cli_value())
        .arg("--accept-read-delay-ms")
        .arg(options.accept_read_delay_ms.to_string());
}

fn append_websocket_loopback_fixture_args(
    command: &mut Command,
    config: WebSocketLoopbackFixtureConfig,
) {
    command
        .arg("--connections")
        .arg(config.connections.to_string())
        .arg("--frame-payload-bytes")
        .arg(config.frame_payload_bytes.to_string())
        .arg("--write-chunks")
        .arg(config.write_chunks.to_string());
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

pub(crate) fn is_fixture_process(process: &ProcessContext) -> bool {
    process.identity.pid > 0
        && (is_fixture_process_name(&process.name)
            || process
                .identity
                .exe_path
                .rsplit('/')
                .next()
                .is_some_and(is_fixture_binary_name)
            || process
                .cmdline
                .iter()
                .any(|arg| FIXTURE_BINARY_NAMES.iter().any(|name| arg.contains(name))))
}

fn is_fixture_process_name(name: &str) -> bool {
    name.starts_with(FIXTURE_PROCESS_NAME_PREFIX) || name == FIXTURE_PROCESS_TASK_COMM
}

fn is_fixture_binary_name(name: &str) -> bool {
    FIXTURE_BINARY_NAMES.contains(&name)
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

#[cfg(test)]
mod tests {
    use probe_core::ProcessIdentity;

    use super::*;

    #[test]
    fn fixture_process_matcher_accepts_linux_task_comm_truncation() {
        assert!(is_fixture_process(&process_context(
            42,
            "traffic-probe-e",
            "",
            []
        )));
    }

    #[test]
    fn fixture_process_matcher_accepts_dynamic_fixture_cmdline() {
        assert!(is_fixture_process(&process_context(
            42,
            "openssl",
            "",
            ["/workspace/traffic-probe-e2e-dynssl-fixture"]
        )));
    }

    #[test]
    fn fixture_process_matcher_accepts_dynamic_fixture_exe_path() {
        assert!(is_fixture_process(&process_context(
            42,
            "openssl",
            "/tmp/e2e/traffic-probe-e2e-dynssl-fixture",
            []
        )));
    }

    #[test]
    fn fixture_process_matcher_rejects_unknown_or_synthetic_processes() {
        assert!(!is_fixture_process(&process_context(
            0,
            "traffic-probe-e",
            "",
            []
        )));
        assert!(!is_fixture_process(&process_context(
            42,
            "traffic-probe",
            "",
            []
        )));
    }

    fn process_context<const N: usize>(
        pid: u32,
        name: &str,
        exe_path: &str,
        cmdline: [&str; N],
    ) -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid,
                tgid: pid,
                start_time_ticks: 1,
                boot_id: "boot".to_string(),
                exe_path: exe_path.to_string(),
                cmdline_hash: "cmdline".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: name.to_string(),
            cmdline: cmdline.into_iter().map(ToOwned::to_owned).collect(),
        }
    }
}

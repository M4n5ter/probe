use std::{
    io::Read,
    net::TcpListener,
    path::Path,
    process::{Child, Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

use super::support::{
    CLIENT_ADDR, HOST_ADDR, IsolatedClientNamespace, PROCESS_SCOPED_LISTENER_NAME,
    TransparentTproxyCase, UPSTREAM_SCENARIOS, UpstreamReport, UpstreamServer,
    assert_transparent_interception_cleanup, merge_run_results, process_name_selector, run_client,
    run_transparent_tproxy_case, write_agent_config,
};
use crate::e2e::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, debug_binary, e2e_error, run_in_own_process_group,
        stop_running_child,
    },
    loopback::{spawn_agent, wait_for_agent_ready},
};

const MISMATCHING_PROCESS_SCOPED_LISTENER_NAME: &str = "not-xtask";
const AGENT_FAIL_CLOSED_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn run() -> ExitCode {
    run_mode(TproxyE2eMode::HostRules)
}

pub(crate) fn run_process_scoped() -> ExitCode {
    run_mode(TproxyE2eMode::ProcessScoped)
}

pub(crate) fn run_process_derived() -> ExitCode {
    run_mode(TproxyE2eMode::ProcessDerived)
}

fn run_mode(mode: TproxyE2eMode) -> ExitCode {
    run_transparent_tproxy_case(mode.case(), |root| run_at(root, mode))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TproxyE2eMode {
    HostRules,
    ProcessScoped,
    ProcessDerived,
}

impl TproxyE2eMode {
    fn case(self) -> TransparentTproxyCase {
        TransparentTproxyCase {
            case_name: self.case_name(),
            agent_id: self.agent_id(),
            config_version: self.config_version(),
            temp_root: self.temp_root(),
            label: self.label(),
        }
    }

    fn case_name(self) -> &'static str {
        match self {
            Self::HostRules => "e2e-transparent-tproxy-loopback",
            Self::ProcessScoped => "e2e-transparent-tproxy-process-loopback",
            Self::ProcessDerived => "e2e-transparent-tproxy-process-derived-loopback",
        }
    }

    fn agent_id(self) -> &'static str {
        match self {
            Self::HostRules => "e2e-transparent-tproxy-agent",
            Self::ProcessScoped => "e2e-transparent-tproxy-process-agent",
            Self::ProcessDerived => "e2e-transparent-tproxy-process-derived-agent",
        }
    }

    fn config_version(self) -> &'static str {
        self.case_name()
    }

    fn temp_root(self) -> &'static str {
        match self {
            Self::HostRules => "transparent-tproxy-loopback",
            Self::ProcessScoped => "transparent-tproxy-process-loopback",
            Self::ProcessDerived => "tproxy-process-derived",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::HostRules => "e2e transparent TPROXY loopback",
            Self::ProcessScoped => "e2e transparent TPROXY process-scoped loopback",
            Self::ProcessDerived => "e2e transparent TPROXY process-derived listener loopback",
        }
    }

    fn process_selector(self) -> ProcessSelector {
        match self {
            Self::HostRules => ProcessSelector::default(),
            Self::ProcessScoped | Self::ProcessDerived => {
                process_name_selector(PROCESS_SCOPED_LISTENER_NAME)
            }
        }
    }

    fn traffic_selector(self) -> TrafficSelector {
        let mut traffic = TrafficSelector {
            directions: vec![Direction::Inbound],
            ..TrafficSelector::default()
        };
        match self {
            Self::HostRules | Self::ProcessScoped => {
                traffic.local_ports = UPSTREAM_SCENARIOS
                    .iter()
                    .map(|scenario| scenario.port)
                    .collect();
                traffic.remote_addresses = vec![CLIENT_ADDR.to_string()];
            }
            Self::ProcessDerived => {}
        }
        traffic
    }

    fn requires_fail_closed_probe(self) -> bool {
        matches!(self, Self::ProcessScoped | Self::ProcessDerived)
    }

    fn mismatched_process_failure(self) -> &'static str {
        match self {
            Self::HostRules => "",
            Self::ProcessScoped => "does not match the process selector",
            Self::ProcessDerived => "no attributed TCP listeners matching the process selector",
        }
    }

    fn selector(self) -> Selector {
        Selector::term(self.process_selector(), self.traffic_selector())
    }
}

fn run_at(root: &Path, mode: TproxyE2eMode) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = root.join("agent.toml");
    let enforcement_manifest_path = root.join("enforcement.toml");
    let spool_path = root.join("spool");
    let ready_socket_path = root.join("agent.ready.sock");

    write_agent_config(
        &config_path,
        &spool_path,
        &enforcement_manifest_path,
        mode.case(),
        mode.selector(),
    )?;
    let supervisor = ChildSupervisor::new()?;
    let mut client_namespace = IsolatedClientNamespace::start(&supervisor, mode.case())?;
    let client_pid = client_namespace.pid();
    if mode.requires_fail_closed_probe() {
        assert_mismatched_process_selector_fails_closed(root, &supervisor, mode)?;
    }

    let upstreams = UPSTREAM_SCENARIOS
        .iter()
        .copied()
        .map(UpstreamServer::spawn)
        .collect::<Result<Vec<_>, _>>()?;
    let mut ready_signal = UnixSocketReadySignal::bind(ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    let client_responses = UPSTREAM_SCENARIOS
        .iter()
        .map(|scenario| run_client(client_pid, scenario))
        .collect::<Vec<_>>();
    let upstream_reports = upstreams
        .into_iter()
        .map(UpstreamServer::join)
        .collect::<Vec<Result<UpstreamReport, Box<dyn std::error::Error>>>>();
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let client_namespace_result = client_namespace.stop();
    let cleanup_result = assert_transparent_interception_cleanup();

    merge_run_results(
        client_responses,
        upstream_reports,
        agent_result,
        client_namespace_result,
        cleanup_result,
    )
}

fn assert_mismatched_process_selector_fails_closed(
    root: &Path,
    supervisor: &ChildSupervisor,
    mode: TproxyE2eMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = root.join("mismatch.toml");
    let enforcement_manifest_path = root.join("mismatch-enforcement.toml");
    let spool_path = root.join("spool-mismatch");
    let ready_socket_path = root.join("mismatch.sock");
    write_agent_config(
        &config_path,
        &spool_path,
        &enforcement_manifest_path,
        mode.case(),
        Selector::term(
            process_name_selector(MISMATCHING_PROCESS_SCOPED_LISTENER_NAME),
            mode.traffic_selector(),
        ),
    )?;
    let listeners = bind_listener_probe_ports()?;
    let mut ready_signal = UnixSocketReadySignal::bind(ready_socket_path)?;
    let mut agent = supervisor.watch(
        spawn_agent_for_expected_failure(&config_path, &ready_signal)?,
        "mismatched process agent",
    );
    assert_agent_fails_before_ready(
        agent.child_mut(),
        &mut ready_signal,
        mode.mismatched_process_failure(),
    )?;
    agent.unwatch();
    drop(listeners);
    assert_transparent_interception_cleanup()?;
    Ok(())
}

fn bind_listener_probe_ports() -> Result<Vec<TcpListener>, Box<dyn std::error::Error>> {
    UPSTREAM_SCENARIOS
        .iter()
        .map(|scenario| TcpListener::bind((HOST_ADDR, scenario.port)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn spawn_agent_for_expected_failure(
    config_path: &Path,
    ready_signal: &UnixSocketReadySignal,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary("agent")?);
    let child = run_in_own_process_group(&mut command)
        .args(["run", "--config"])
        .arg(config_path)
        .env(
            crate::e2e::loopback::AGENT_READY_SOCKET_ENV,
            ready_signal.path(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok(child)
}

fn assert_agent_fails_before_ready(
    child: &mut Child,
    ready_signal: &mut UnixSocketReadySignal,
    expected_stderr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| e2e_error("expected failure agent stderr pipe is missing"))?;
    ready_signal.listener_mut().set_nonblocking(true)?;
    let deadline = Instant::now() + AGENT_FAIL_CLOSED_TIMEOUT;
    let status = loop {
        match ready_signal.listener_mut().accept() {
            Ok(_) => {
                return Err(e2e_error(
                    "mismatched process-scoped transparent TPROXY agent unexpectedly became ready",
                )
                .into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "mismatched process-scoped transparent TPROXY agent did not fail within {}ms",
                AGENT_FAIL_CLOSED_TIMEOUT.as_millis()
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text)?;
    if status.success() {
        return Err(e2e_error(format!(
            "mismatched process-scoped transparent TPROXY agent exited successfully; stderr: {stderr_text}"
        ))
        .into());
    }
    if !stderr_text.contains(expected_stderr) {
        return Err(e2e_error(format!(
            "mismatched process-scoped transparent TPROXY agent failed for the wrong reason; expected stderr to contain {expected_stderr:?}, got {stderr_text:?}"
        ))
        .into());
    }
    Ok(())
}

use std::{
    env,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, debug_binary, e2e_error,
        ensure_e2e_packages_built, reexec_current_case_in_fresh_network_namespace,
        run_in_own_process_group, stop_running_child, trusted_system_command,
        verify_fresh_network_namespace,
    },
    loopback::{spawn_agent, wait_for_agent_ready},
};
use probe_config::{
    AgentConfig, CaptureSelection, EnforcementPolicyManifest, EnforcementPolicySourceConfig,
    TransparentInterceptionProxyConfig, TransparentInterceptionProxyModeConfig,
    TransparentInterceptionStrategyConfig,
};
use probe_core::{
    Action, Direction, EnforcementMode, ProcessSelector, ProtectiveActionProfile, Selector,
    TrafficSelector,
};
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

const IN_NETNS_ENV: &str = "TRAFFIC_PROBE_E2E_TRANSPARENT_TPROXY_NETNS";
const CLIENT_OWNER_ENV: &str = "TRAFFIC_PROBE_E2E_TRANSPARENT_TPROXY_CLIENT_OWNER";
const HOST_IFACE: &str = "tprobe0h";
const CLIENT_IFACE: &str = "tprobe0c";
const HOST_ADDR: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
const PROXY_PORT: u16 = 15001;
const TPROXY_MARK: &str = "0x54500101";
const TPROXY_ROUTE_TABLE: &str = "45100";
const ENFORCEMENT_MANIFEST_ID: &str = "e2e-transparent-tproxy-enforcement";
const ENFORCEMENT_MANIFEST_VERSION: &str = "e2e";
const PROCESS_SCOPED_LISTENER_NAME: &str = "xtask";
const MISMATCHING_PROCESS_SCOPED_LISTENER_NAME: &str = "not-xtask";
const UPSTREAM_SCENARIOS: [UpstreamScenario; 2] = [
    UpstreamScenario {
        port: 18080,
        client_payload: b"GET /transparent-tproxy-e2e-a HTTP/1.1\r\nHost: tproxy-a.test\r\n\r\n",
        server_response: b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ntproxy-a\n",
    },
    UpstreamScenario {
        port: 18081,
        client_payload: b"GET /transparent-tproxy-e2e-b HTTP/1.1\r\nHost: tproxy-b.test\r\n\r\n",
        server_response: b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ntproxy-b\n",
    },
];
const CLIENT_NAMESPACE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const AGENT_FAIL_CLOSED_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpstreamScenario {
    port: u16,
    client_payload: &'static [u8],
    server_response: &'static [u8],
}

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
    match run_outer(mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} failed: {error}", mode.label());
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TproxyE2eMode {
    HostRules,
    ProcessScoped,
    ProcessDerived,
}

impl TproxyE2eMode {
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
}

fn run_outer(mode: TproxyE2eMode) -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(CLIENT_OWNER_ENV).is_some() {
        require_root()?;
        return run_client_namespace_owner();
    }
    if env::var_os(IN_NETNS_ENV).is_some() {
        require_root()?;
        verify_fresh_network_namespace(IN_NETNS_ENV)?;
        run_inner(mode)
    } else {
        ensure_e2e_packages_built(["agent"])?;
        require_root()?;
        reexec_current_case_in_fresh_network_namespace(
            IN_NETNS_ENV,
            mode.case_name(),
            "network-namespace transparent TPROXY e2e",
        )
    }
}

fn run_inner(mode: TproxyE2eMode) -> Result<(), Box<dyn std::error::Error>> {
    let root = create_temp_root(mode.temp_root())?;
    match run_at(&root, mode) {
        Ok(()) => {
            std::fs::remove_dir_all(&root)?;
            println!("{} passed", mode.label());
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
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
        mode,
        mode.process_selector(),
    )?;
    let supervisor = ChildSupervisor::new()?;
    let mut client_namespace =
        supervisor.watch(spawn_client_namespace_owner(mode)?, "client namespace");
    let client_pid = client_namespace.child_mut().id();
    wait_for_client_namespace_ready(client_namespace.child_mut())?;
    let _network = IsolatedNetwork::setup(client_pid)?;
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
        .collect::<Vec<_>>();
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let client_namespace_result =
        stop_running_child(client_namespace.child_mut(), "client namespace");
    client_namespace.unwatch();
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
        mode,
        process_name_selector(MISMATCHING_PROCESS_SCOPED_LISTENER_NAME),
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

fn write_agent_config(
    path: &Path,
    spool_path: &Path,
    enforcement_manifest_path: &Path,
    mode: TproxyE2eMode,
    process_selector: ProcessSelector,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: mode.agent_id().to_string(),
        config_version: mode.config_version().to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(HOST_IFACE.to_string());
    let bpf_ports = UPSTREAM_SCENARIOS
        .iter()
        .map(|scenario| format!("port {}", scenario.port))
        .collect::<Vec<_>>()
        .join(" or ");
    config.capture.libpcap.bpf_filter = format!("tcp and ({bpf_ports})");
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.enforcement.mode = EnforcementMode::Enforce;
    let selector = Selector::term(process_selector, mode.traffic_selector());
    super::enforcement_manifest::write_enforcement_policy_manifest(
        enforcement_manifest_path,
        &EnforcementPolicyManifest {
            id: ENFORCEMENT_MANIFEST_ID.to_string(),
            version: ENFORCEMENT_MANIFEST_VERSION.to_string(),
            selectors: Default::default(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        },
    )?;
    config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
        path: enforcement_manifest_path.to_path_buf(),
    };
    config.enforcement.interception.strategy = TransparentInterceptionStrategyConfig::InboundTproxy;
    config.enforcement.interception.proxy = TransparentInterceptionProxyConfig {
        mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
        listen_port: Some(PROXY_PORT),
        ..TransparentInterceptionProxyConfig::default()
    };
    config.enforcement.interception.selector = Some(selector);
    std::fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn process_name_selector(name: &str) -> ProcessSelector {
    ProcessSelector {
        names: vec![name.to_string()],
        ..ProcessSelector::default()
    }
}

fn spawn_agent_for_expected_failure(
    config_path: &Path,
    ready_signal: &UnixSocketReadySignal,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary("agent")?);
    let child = run_in_own_process_group(&mut command)
        .args(["run", "--config"])
        .arg(config_path)
        .env(super::loopback::AGENT_READY_SOCKET_ENV, ready_signal.path())
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

fn spawn_client_namespace_owner(mode: TproxyE2eMode) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(unshare_command()?);
    let child = run_in_own_process_group(&mut command)
        .arg("-n")
        .arg("--")
        .arg(env::current_exe()?)
        .arg(mode.case_name())
        .env(CLIENT_OWNER_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

fn run_client_namespace_owner() -> Result<(), Box<dyn std::error::Error>> {
    ip(["link", "set", "lo", "up"])?;
    let mut signals = Signals::new([SIGINT, SIGTERM])?;
    let _ = signals.forever().next();
    Ok(())
}

fn wait_for_client_namespace_ready(child: &mut Child) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + CLIENT_NAMESPACE_READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(e2e_error(format!(
                "client namespace owner exited before readiness with {status}"
            ))
            .into());
        }
        match ip_in_client_netns(child.id(), ["link", "show", "lo"]) {
            Ok(()) => return Ok(()),
            Err(_error) if Instant::now() < deadline => {}
            Err(error) => {
                return Err(e2e_error(format!(
                    "timed out waiting for client namespace readiness: {error}"
                ))
                .into());
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct IsolatedNetwork;

impl IsolatedNetwork {
    fn setup(client_pid: u32) -> Result<Self, Box<dyn std::error::Error>> {
        ip(["link", "set", "lo", "up"])?;
        let network = Self;
        network.configure_links(client_pid)?;
        Ok(network)
    }

    fn configure_links(&self, client_pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        ip([
            "link",
            "add",
            HOST_IFACE,
            "type",
            "veth",
            "peer",
            "name",
            CLIENT_IFACE,
        ])?;
        ip(["addr", "add", &format!("{HOST_ADDR}/24"), "dev", HOST_IFACE])?;
        ip(["link", "set", HOST_IFACE, "up"])?;
        let client_pid_arg = client_pid.to_string();
        ip(["link", "set", CLIENT_IFACE, "netns", &client_pid_arg])?;
        ip_in_client_netns(client_pid, ["link", "set", "lo", "up"])?;
        ip_in_client_netns(
            client_pid,
            [
                "addr",
                "add",
                &format!("{CLIENT_ADDR}/24"),
                "dev",
                CLIENT_IFACE,
            ],
        )?;
        ip_in_client_netns(client_pid, ["link", "set", CLIENT_IFACE, "up"])?;
        Ok(())
    }
}

impl Drop for IsolatedNetwork {
    fn drop(&mut self) {
        let _ = ip(["link", "del", HOST_IFACE]);
    }
}

struct UpstreamServer {
    report: mpsc::Receiver<Result<UpstreamReport, String>>,
    thread: thread::JoinHandle<()>,
}

impl UpstreamServer {
    fn spawn(scenario: UpstreamScenario) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((HOST_ADDR, scenario.port))?;
        listener.set_nonblocking(true)?;
        let (sender, report) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = run_upstream_server(listener, scenario).map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Ok(Self { report, thread })
    }

    fn join(self) -> Result<UpstreamReport, Box<dyn std::error::Error>> {
        let result = self
            .report
            .recv_timeout(SERVER_ACCEPT_TIMEOUT + Duration::from_secs(1))
            .map_err(|error| e2e_error(format!("upstream server did not report: {error}")))?;
        self.thread
            .join()
            .map_err(|_| e2e_error("upstream server thread panicked"))?;
        result.map_err(|error| e2e_error(error).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpstreamReport {
    port: u16,
    peer_addr: SocketAddr,
    request: Vec<u8>,
}

fn run_upstream_server(
    listener: TcpListener,
    scenario: UpstreamScenario,
) -> Result<UpstreamReport, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + SERVER_ACCEPT_TIMEOUT;
    let (mut stream, peer_addr) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(e2e_error("upstream server timed out waiting for relayed client").into());
        }
        thread::sleep(Duration::from_millis(20));
    };
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let read = stream.read(&mut buffer)?;
    request.extend_from_slice(&buffer[..read]);
    stream.write_all(scenario.server_response)?;
    Ok(UpstreamReport {
        port: scenario.port,
        peer_addr,
        request,
    })
}

fn run_client(
    client_pid: u32,
    scenario: &UpstreamScenario,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let host = HOST_ADDR.to_string();
    let port = scenario.port.to_string();
    let mut child = Command::new(nsenter_command()?)
        .args(["--target", &client_pid.to_string(), "--net", "--"])
        .arg(nc_command()?)
        .args(["-w", "2", &host, &port])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| e2e_error("failed to open nc stdin"))?
        .write_all(scenario.client_payload)?;
    let output = wait_with_timeout(child, CLIENT_TIMEOUT)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(e2e_error(format!(
            "client nc failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

fn assert_upstream_observed_relayed_request(
    report: &UpstreamReport,
    scenario: &UpstreamScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    if report.port != scenario.port {
        return Err(e2e_error(format!(
            "upstream report port mismatch: expected {}, got {}",
            scenario.port, report.port
        ))
        .into());
    }
    if report.peer_addr.ip() != HOST_ADDR {
        return Err(e2e_error(format!(
            "upstream server on port {} peer mismatch: expected relay host address {HOST_ADDR}, got {}",
            scenario.port, report.peer_addr
        ))
        .into());
    }
    if !report.request.starts_with(scenario.client_payload) {
        return Err(e2e_error(format!(
            "upstream server on port {} received unexpected payload: {:?}",
            scenario.port,
            String::from_utf8_lossy(&report.request)
        ))
        .into());
    }
    println!(
        "upstream server on port {} accepted relayed request from peer={}",
        scenario.port, report.peer_addr
    );
    Ok(())
}

fn assert_client_received_server_response(
    response: &[u8],
    scenario: &UpstreamScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    if response == scenario.server_response {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "client did not receive server response for port {} through managed relay: {:?}",
            scenario.port,
            String::from_utf8_lossy(response)
        ))
        .into())
    }
}

fn assert_transparent_interception_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    assert_tproxy_table_removed()?;
    assert_policy_routing_removed()?;
    Ok(())
}

fn merge_run_results(
    client_responses: Vec<Result<Vec<u8>, Box<dyn std::error::Error>>>,
    upstream_reports: Vec<Result<UpstreamReport, Box<dyn std::error::Error>>>,
    agent_result: Result<(), Box<dyn std::error::Error>>,
    client_namespace_result: Result<(), Box<dyn std::error::Error>>,
    cleanup_result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut errors = Vec::new();
    record_result_count("client responses", client_responses.len(), &mut errors);
    record_result_count("upstream reports", upstream_reports.len(), &mut errors);
    for (scenario, client_response) in UPSTREAM_SCENARIOS.iter().zip(client_responses) {
        if let Some(response) = collect_result(
            format!("client for port {}", scenario.port),
            client_response,
            &mut errors,
        ) {
            record_result(
                format!("client response assertion for port {}", scenario.port),
                assert_client_received_server_response(&response, scenario),
                &mut errors,
            );
        }
    }
    for (scenario, upstream_report) in UPSTREAM_SCENARIOS.iter().zip(upstream_reports) {
        if let Some(report) = collect_result(
            format!("upstream server for port {}", scenario.port),
            upstream_report,
            &mut errors,
        ) {
            record_result(
                format!("upstream server assertion for port {}", scenario.port),
                assert_upstream_observed_relayed_request(&report, scenario),
                &mut errors,
            );
        }
    }
    record_result("agent shutdown", agent_result, &mut errors);
    record_result(
        "client namespace shutdown",
        client_namespace_result,
        &mut errors,
    );
    record_result(
        "transparent interception cleanup",
        cleanup_result,
        &mut errors,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(e2e_error(errors.join("; ")).into())
    }
}

fn record_result_count(label: &'static str, actual: usize, errors: &mut Vec<String>) {
    if actual != UPSTREAM_SCENARIOS.len() {
        errors.push(format!(
            "{label} count mismatch: expected {}, got {actual}",
            UPSTREAM_SCENARIOS.len()
        ));
    }
}

fn collect_result<T>(
    label: impl Into<String>,
    result: Result<T, Box<dyn std::error::Error>>,
    errors: &mut Vec<String>,
) -> Option<T> {
    let label = label.into();
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(format!("{label} failed: {error}"));
            None
        }
    }
}

fn record_result(
    label: impl Into<String>,
    result: Result<(), Box<dyn std::error::Error>>,
    errors: &mut Vec<String>,
) {
    let label = label.into();
    if let Err(error) = result {
        errors.push(format!("{label} failed: {error}"));
    }
}

fn assert_tproxy_table_removed() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(nft_command()?)
        .args(["list", "table", "inet", "traffic_probe"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if output.status.success() {
        return Err(e2e_error(format!(
            "transparent interception nft table still exists after agent shutdown: {}",
            String::from_utf8_lossy(&output.stdout)
        ))
        .into());
    }
    Ok(())
}

fn assert_policy_routing_removed() -> Result<(), Box<dyn std::error::Error>> {
    for family in ["-4", "-6"] {
        let rules = ip_output([family, "rule", "show"], "ip rule show")?;
        if rules.contains(TPROXY_MARK) {
            return Err(e2e_error(format!(
                "transparent interception policy rule still references {TPROXY_MARK}: {rules:?}"
            ))
            .into());
        }

        let routes = ip_route_table_output(family)?;
        if !routes.trim().is_empty() {
            return Err(e2e_error(format!(
                "transparent interception route table {TPROXY_ROUTE_TABLE} still has routes: {routes:?}"
            ))
            .into());
        }
    }
    Ok(())
}

fn ip_route_table_output(family: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(ip_command()?)
        .args([family, "route", "show", "table", TPROXY_ROUTE_TABLE])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("FIB table does not exist") {
        return Ok(String::new());
    }
    Err(e2e_error(format!(
        "ip route show table failed with {}: {stderr}",
        output.status
    ))
    .into())
}

fn ip_output<const N: usize>(
    args: [&str; N],
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(ip_command()?)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    ensure_command_success(&output, name)?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn ip<const N: usize>(args: [&str; N]) -> Result<(), Box<dyn std::error::Error>> {
    command_success(Command::new(ip_command()?).args(args).output()?, "ip")
}

fn ip_in_client_netns<const N: usize>(
    client_pid: u32,
    args: [&str; N],
) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(nsenter_command()?)
        .args(["--target", &client_pid.to_string(), "--net", "--"])
        .arg(ip_command()?)
        .args(args)
        .output()?;
    command_success(output, "nsenter --net ip")
}

fn command_success(
    output: std::process::Output,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_command_success(&output, name)
}

fn ensure_command_success(
    output: &std::process::Output,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if output.status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "{name} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

fn wait_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e2e_error(format!(
                "client command timed out after {}ms",
                timeout.as_millis()
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(e2e_error("transparent TPROXY e2e must run as root").into())
    }
}

fn unshare_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/bin/unshare", "/bin/unshare"],
        "unshare",
    )?)
}

fn nsenter_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/bin/nsenter", "/bin/nsenter"],
        "nsenter",
    )?)
}

fn ip_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"],
        "ip",
    )?)
}

fn nft_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"],
        "nft",
    )?)
}

fn nc_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/bin/nc", "/bin/nc", "/usr/bin/netcat", "/bin/netcat"],
        "nc",
    )?)
}

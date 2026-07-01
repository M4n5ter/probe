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

use crate::e2e::{
    enforcement_manifest,
    harness::{
        ChildGuard, ChildSupervisor, create_temp_root, e2e_error, ensure_e2e_packages_built,
        reexec_current_case_in_fresh_network_namespace, run_in_own_process_group,
        stop_running_child, trusted_system_command, verify_fresh_network_namespace,
    },
};
use probe_config::{
    AgentConfig, CaptureSelection, EnforcementPolicyManifest, EnforcementPolicySourceConfig,
    TransparentInterceptionProxyConfig, TransparentInterceptionProxyModeConfig,
    TransparentInterceptionStrategyConfig,
};
use probe_core::{Action, EnforcementMode, ProcessSelector, ProtectiveActionProfile, Selector};
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

const IN_NETNS_ENV: &str = "TRAFFIC_PROBE_E2E_TRANSPARENT_TPROXY_NETNS";
const CLIENT_OWNER_ENV: &str = "TRAFFIC_PROBE_E2E_TRANSPARENT_TPROXY_CLIENT_OWNER";
pub(super) const HOST_IFACE: &str = "tprobe0h";
const CLIENT_IFACE: &str = "tprobe0c";
pub(super) const HOST_ADDR: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
pub(super) const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
pub(super) const PROXY_PORT: u16 = 15001;
const TPROXY_MARK: &str = "0x54500101";
const TPROXY_ROUTE_TABLE: &str = "45100";
const ENFORCEMENT_MANIFEST_ID: &str = "e2e-transparent-tproxy-enforcement";
const ENFORCEMENT_MANIFEST_VERSION: &str = "e2e";
pub(super) const PROCESS_SCOPED_LISTENER_NAME: &str = "xtask";
pub(super) const UPSTREAM_SCENARIOS: [UpstreamScenario; 2] = [
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
pub(super) const REJECTED_UPSTREAM_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UpstreamScenario {
    pub(super) port: u16,
    pub(super) client_payload: &'static [u8],
    pub(super) server_response: &'static [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TransparentTproxyCase {
    pub(super) case_name: &'static str,
    pub(super) agent_id: &'static str,
    pub(super) config_version: &'static str,
    pub(super) temp_root: &'static str,
    pub(super) label: &'static str,
}

pub(super) fn run_transparent_tproxy_case(
    case: TransparentTproxyCase,
    run_at: impl FnOnce(&Path) -> Result<(), Box<dyn std::error::Error>>,
) -> ExitCode {
    match run_outer(case, run_at) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} failed: {error}", case.label);
            ExitCode::FAILURE
        }
    }
}

fn run_outer(
    case: TransparentTproxyCase,
    run_at: impl FnOnce(&Path) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(CLIENT_OWNER_ENV).is_some() {
        require_root()?;
        return run_client_namespace_owner();
    }
    if env::var_os(IN_NETNS_ENV).is_some() {
        require_root()?;
        verify_fresh_network_namespace(IN_NETNS_ENV)?;
        run_inner(case, run_at)
    } else {
        ensure_e2e_packages_built(["agent"])?;
        require_root()?;
        reexec_current_case_in_fresh_network_namespace(
            IN_NETNS_ENV,
            case.case_name,
            "network-namespace transparent TPROXY e2e",
        )
    }
}

fn run_inner(
    case: TransparentTproxyCase,
    run_at: impl FnOnce(&Path) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = create_temp_root(case.temp_root)?;
    match run_at(&root) {
        Ok(()) => {
            std::fs::remove_dir_all(&root)?;
            println!("{} passed", case.label);
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

pub(super) fn write_agent_config(
    path: &Path,
    spool_path: &Path,
    enforcement_manifest_path: &Path,
    case: TransparentTproxyCase,
    selector: Selector,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: case.agent_id.to_string(),
        config_version: case.config_version.to_string(),
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
    enforcement_manifest::write_enforcement_policy_manifest(
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

pub(super) fn process_name_selector(name: &str) -> ProcessSelector {
    ProcessSelector {
        names: vec![name.to_string()],
        ..ProcessSelector::default()
    }
}

fn spawn_client_namespace_owner(case_name: &str) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(unshare_command()?);
    let child = run_in_own_process_group(&mut command)
        .arg("-n")
        .arg("--")
        .arg(env::current_exe()?)
        .arg(case_name)
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

pub(super) struct IsolatedClientNamespace {
    guard: ChildGuard,
    _network: IsolatedNetwork,
}

impl IsolatedClientNamespace {
    pub(super) fn start(
        supervisor: &ChildSupervisor,
        case: TransparentTproxyCase,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut guard = supervisor.watch(
            spawn_client_namespace_owner(case.case_name)?,
            "client namespace",
        );
        wait_for_client_namespace_ready(guard.child_mut())?;
        let network = IsolatedNetwork::setup(guard.child_mut().id())?;
        Ok(Self {
            guard,
            _network: network,
        })
    }

    pub(super) fn pid(&mut self) -> u32 {
        self.guard.child_mut().id()
    }

    pub(super) fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let result = stop_running_child(self.guard.child_mut(), "client namespace");
        self.guard.unwatch();
        result
    }
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

pub(super) struct UpstreamServer {
    report: mpsc::Receiver<Result<UpstreamReport, String>>,
    thread: thread::JoinHandle<()>,
}

impl UpstreamServer {
    pub(super) fn spawn(scenario: UpstreamScenario) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((HOST_ADDR, scenario.port))?;
        listener.set_nonblocking(true)?;
        let (sender, report) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = run_upstream_server(listener, scenario).map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Ok(Self { report, thread })
    }

    pub(super) fn join(self) -> Result<UpstreamReport, Box<dyn std::error::Error>> {
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
pub(super) struct UpstreamReport {
    pub(super) port: u16,
    pub(super) peer_addr: SocketAddr,
    pub(super) request: Vec<u8>,
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

pub(super) fn run_client(
    client_pid: u32,
    scenario: &UpstreamScenario,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let output = run_client_output(client_pid, scenario)?;
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

pub(super) fn run_client_output(
    client_pid: u32,
    scenario: &UpstreamScenario,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
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
    wait_with_timeout(child, CLIENT_TIMEOUT)
}

pub(super) fn assert_upstream_observed_relayed_request(
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

pub(super) fn assert_client_received_server_response(
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

pub(super) fn assert_transparent_interception_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    assert_tproxy_table_removed()?;
    assert_policy_routing_removed()?;
    Ok(())
}

pub(super) fn merge_run_results(
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

pub(super) fn collect_result<T>(
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

pub(super) fn record_result(
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

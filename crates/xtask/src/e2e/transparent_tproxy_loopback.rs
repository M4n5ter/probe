use std::{
    env,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use probe_config::{
    AgentConfig, CaptureSelection, TransparentInterceptionProxyConfig,
    TransparentInterceptionStrategyConfig,
};
use probe_core::{Direction, EnforcementMode, ProcessSelector, Selector, TrafficSelector};
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, e2e_error,
        ensure_e2e_packages_built, run_in_own_process_group, stop_running_child,
    },
    loopback::{spawn_agent, wait_for_agent_ready},
};

const IN_NETNS_ENV: &str = "SSSA_PROBE_E2E_TRANSPARENT_TPROXY_NETNS";
const CLIENT_OWNER_ENV: &str = "SSSA_PROBE_E2E_TRANSPARENT_TPROXY_CLIENT_OWNER";
const HOST_IFACE: &str = "sssa0h";
const CLIENT_IFACE: &str = "sssa0c";
const HOST_ADDR: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
const SERVER_PORT: u16 = 18080;
const PROXY_PORT: u16 = 15001;
const TPROXY_MARK: &str = "0x53534101";
const TPROXY_ROUTE_TABLE: &str = "53534";
const CLIENT_PAYLOAD: &[u8] = b"GET /transparent-tproxy-e2e HTTP/1.1\r\nHost: tproxy.test\r\n\r\n";
const PROXY_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ntproxy\n";
const CLIENT_NAMESPACE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const PROXY_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn run() -> ExitCode {
    match run_outer() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e transparent TPROXY loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_outer() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(CLIENT_OWNER_ENV).is_some() {
        require_root()?;
        return run_client_namespace_owner();
    }
    if env::var_os(IN_NETNS_ENV).is_some() {
        require_root()?;
        run_inner()
    } else {
        ensure_e2e_packages_built(["agent"])?;
        require_root()?;
        reexec_in_network_namespace()
    }
}

fn reexec_in_network_namespace() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let status = Command::new(unshare_command()?)
        .arg("-n")
        .arg("--")
        .arg(current_exe)
        .arg("e2e-transparent-tproxy-loopback")
        .env(IN_NETNS_ENV, "1")
        .stdin(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "network-namespace transparent TPROXY e2e exited with {status}"
        ))
        .into())
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    let root = create_temp_root("transparent-tproxy-loopback")?;
    match run_at(&root) {
        Ok(()) => {
            std::fs::remove_dir_all(&root)?;
            println!("e2e transparent TPROXY loopback passed");
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let ready_socket_path = root.join("agent.ready.sock");

    write_agent_config(&config_path, &spool_path)?;
    let supervisor = ChildSupervisor::new()?;
    let mut client_namespace =
        supervisor.watch(spawn_client_namespace_owner()?, "client namespace");
    let client_pid = client_namespace.child_mut().id();
    wait_for_client_namespace_ready(client_namespace.child_mut())?;
    let _network = IsolatedNetwork::setup(client_pid)?;
    let proxy = TransparentProxy::spawn(PROXY_PORT)?;
    let mut ready_signal = UnixSocketReadySignal::bind(ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    let client_response = run_client(client_pid);
    let proxy_report = proxy.join();
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let client_namespace_result =
        stop_running_child(client_namespace.child_mut(), "client namespace");
    client_namespace.unwatch();
    let cleanup_result = assert_transparent_interception_cleanup();

    merge_run_results(
        client_response,
        proxy_report,
        agent_result,
        client_namespace_result,
        cleanup_result,
    )
}

fn write_agent_config(path: &Path, spool_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-transparent-tproxy-agent".to_string(),
        config_version: "e2e-transparent-tproxy-loopback".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(HOST_IFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {SERVER_PORT}");
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.enforcement.mode = EnforcementMode::Enforce;
    config.enforcement.interception.strategy = TransparentInterceptionStrategyConfig::InboundTproxy;
    config.enforcement.interception.proxy = TransparentInterceptionProxyConfig {
        listen_port: Some(PROXY_PORT),
    };
    config.enforcement.interception.selector = Some(Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            local_ports: vec![SERVER_PORT],
            directions: vec![Direction::Inbound],
            remote_addresses: vec![CLIENT_ADDR.to_string()],
            ..TrafficSelector::default()
        },
    ));
    std::fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn spawn_client_namespace_owner() -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(unshare_command()?);
    let child = run_in_own_process_group(&mut command)
        .arg("-n")
        .arg("--")
        .arg(env::current_exe()?)
        .arg("e2e-transparent-tproxy-loopback")
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

struct TransparentProxy {
    report: mpsc::Receiver<Result<ProxyReport, String>>,
    thread: thread::JoinHandle<()>,
}

impl TransparentProxy {
    fn spawn(port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = transparent_listener(port)?;
        let (sender, report) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = run_proxy(listener).map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Ok(Self { report, thread })
    }

    fn join(self) -> Result<ProxyReport, Box<dyn std::error::Error>> {
        let result = self
            .report
            .recv_timeout(PROXY_ACCEPT_TIMEOUT + Duration::from_secs(1))
            .map_err(|error| e2e_error(format!("transparent proxy did not report: {error}")))?;
        self.thread
            .join()
            .map_err(|_| e2e_error("transparent proxy thread panicked"))?;
        result.map_err(|error| e2e_error(error).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyReport {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    original_dst: Option<SocketAddr>,
    request: Vec<u8>,
}

fn transparent_listener(port: u16) -> Result<Socket, Box<dyn std::error::Error>> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_ip_transparent_v4(true)?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        port,
    )))?;
    socket.listen(16)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn run_proxy(listener: Socket) -> Result<ProxyReport, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + PROXY_ACCEPT_TIMEOUT;
    let (accepted, peer) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(
                e2e_error("transparent proxy timed out waiting for intercepted client").into(),
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    accepted.set_read_timeout(Some(Duration::from_secs(2)))?;
    accepted.set_write_timeout(Some(Duration::from_secs(2)))?;
    let original_dst = accepted
        .original_dst_v4()
        .ok()
        .and_then(|address| address.as_socket());
    let mut stream = TcpStream::from(accepted);
    let peer_addr = peer
        .as_socket()
        .ok_or_else(|| e2e_error("transparent proxy accepted non-IP peer address"))?;
    let local_addr = stream.local_addr()?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let read = stream.read(&mut buffer)?;
    request.extend_from_slice(&buffer[..read]);
    stream.write_all(PROXY_RESPONSE)?;
    Ok(ProxyReport {
        peer_addr,
        local_addr,
        original_dst,
        request,
    })
}

fn run_client(client_pid: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut child = Command::new(nsenter_command()?)
        .args(["--target", &client_pid.to_string(), "--net", "--"])
        .arg(nc_command()?)
        .args(["-w", "2", &HOST_ADDR.to_string(), &SERVER_PORT.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| e2e_error("failed to open nc stdin"))?
        .write_all(CLIENT_PAYLOAD)?;
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

fn assert_proxy_observed_intercepted_request(
    report: &ProxyReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_local = SocketAddr::V4(SocketAddrV4::new(HOST_ADDR, SERVER_PORT));
    if report.peer_addr.ip() != CLIENT_ADDR {
        return Err(e2e_error(format!(
            "transparent proxy peer mismatch: expected {CLIENT_ADDR}, got {}",
            report.peer_addr
        ))
        .into());
    }
    if report.local_addr != expected_local {
        return Err(e2e_error(format!(
            "transparent proxy local destination mismatch: expected {expected_local}, got {}",
            report.local_addr
        ))
        .into());
    }
    if !report.request.starts_with(CLIENT_PAYLOAD) {
        return Err(e2e_error(format!(
            "transparent proxy received unexpected payload: {:?}",
            String::from_utf8_lossy(&report.request)
        ))
        .into());
    }
    println!(
        "transparent proxy accepted peer={} local={} original_dst={:?}",
        report.peer_addr, report.local_addr, report.original_dst
    );
    Ok(())
}

fn assert_client_received_proxy_response(
    response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if response == PROXY_RESPONSE {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "client did not receive proxy response: {:?}",
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
    client_response: Result<Vec<u8>, Box<dyn std::error::Error>>,
    proxy_report: Result<ProxyReport, Box<dyn std::error::Error>>,
    agent_result: Result<(), Box<dyn std::error::Error>>,
    client_namespace_result: Result<(), Box<dyn std::error::Error>>,
    cleanup_result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut errors = Vec::new();
    let client_response = collect_result("client", client_response, &mut errors);
    let proxy_report = collect_result("transparent proxy", proxy_report, &mut errors);
    if let Some(report) = proxy_report.as_ref() {
        record_result(
            "transparent proxy assertion",
            assert_proxy_observed_intercepted_request(report),
            &mut errors,
        );
    }
    if let Some(response) = client_response.as_ref() {
        record_result(
            "client response assertion",
            assert_client_received_proxy_response(response),
            &mut errors,
        );
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

fn collect_result<T>(
    label: &'static str,
    result: Result<T, Box<dyn std::error::Error>>,
    errors: &mut Vec<String>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(format!("{label} failed: {error}"));
            None
        }
    }
}

fn record_result(
    label: &'static str,
    result: Result<(), Box<dyn std::error::Error>>,
    errors: &mut Vec<String>,
) {
    if let Err(error) = result {
        errors.push(format!("{label} failed: {error}"));
    }
}

fn assert_tproxy_table_removed() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(nft_command()?)
        .args(["list", "table", "inet", "sssa_probe"])
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
    first_existing_system_command(["/usr/bin/unshare", "/bin/unshare"], "unshare")
}

fn nsenter_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    first_existing_system_command(["/usr/bin/nsenter", "/bin/nsenter"], "nsenter")
}

fn ip_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    first_existing_system_command(["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"], "ip")
}

fn nft_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    first_existing_system_command(
        ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"],
        "nft",
    )
}

fn nc_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    first_existing_system_command(
        ["/usr/bin/nc", "/bin/nc", "/usr/bin/netcat", "/bin/netcat"],
        "nc",
    )
}

fn first_existing_system_command<const N: usize>(
    candidates: [&str; N],
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    candidates
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| e2e_error(format!("missing trusted system command {name}")).into())
}

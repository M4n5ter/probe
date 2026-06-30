use std::{
    fs,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

use e2e_support::mitm_bridge;

use super::{
    backend::{MitmBackendConfig, PreparedMitmBackend, ProductProxyUpstream},
    case::{MitmBridgeCase, MitmBridgeDirection},
    data_plane::{self, MitmDataPlaneProtocol},
    feed::product_proxy_deny_response_bytes,
    tls::MitmCaMaterial,
    websocket,
    websocket_upstream::ProductProxyTlsWebSocketUpstreamServer,
};
use crate::e2e::harness::{
    ChildSupervisor, e2e_error, run_in_own_process_group, stop_running_child,
    trusted_system_command,
};

pub(super) const CLIENT_OWNER_ENV: &str = "TRAFFIC_PROBE_E2E_MITM_TRANSPARENT_TLS_CLIENT_OWNER";

const HOST_IFACE: &str = "mitm0h";
const CLIENT_IFACE: &str = "mitm0c";
const HOST_ADDR: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 1);
const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 2);
const CLIENT_NAMESPACE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_READY_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn run_client_namespace_owner() -> Result<(), Box<dyn std::error::Error>> {
    ip(["link", "set", "lo", "up"])?;
    let mut signals = Signals::new([SIGINT, SIGTERM])?;
    let _ = signals.forever().next();
    Ok(())
}

pub(super) fn exercise_product_proxy_transparent_tls_path(
    case: MitmBridgeCase,
    supervisor: &ChildSupervisor,
    intercept_port: u16,
    mitm_ca: &MitmCaMaterial,
    mitm_backend: &PreparedMitmBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    match case.direction() {
        MitmBridgeDirection::Inbound => exercise_inbound_product_proxy_transparent_tls_path(
            case,
            supervisor,
            intercept_port,
            mitm_ca,
            mitm_backend,
        ),
        MitmBridgeDirection::Outbound => exercise_outbound_product_proxy_transparent_tls_path(
            case,
            intercept_port,
            mitm_ca,
            mitm_backend,
        ),
    }
}

fn exercise_inbound_product_proxy_transparent_tls_path(
    case: MitmBridgeCase,
    supervisor: &ChildSupervisor,
    intercept_port: u16,
    mitm_ca: &MitmCaMaterial,
    mitm_backend: &PreparedMitmBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_namespace = supervisor.watch(
        spawn_client_namespace_owner(case)?,
        "MITM transparent TLS client namespace",
    );
    let client_pid = client_namespace.child_mut().id();
    wait_for_client_namespace_ready(client_namespace.child_mut())?;
    let _network = IsolatedClientNetwork::setup(client_pid)?;
    let upstream = product_proxy_upstream(mitm_backend)?;
    let exchange_result = exercise_product_proxy_tls_exchange(case, upstream, |request| {
        run_client_netns_tls_client(
            client_pid,
            intercept_port,
            mitm_ca,
            &upstream.server_name,
            request,
        )
    });
    let client_namespace_result = stop_running_child(
        client_namespace.child_mut(),
        "MITM transparent TLS client namespace",
    );
    client_namespace.unwatch();
    exchange_result.and(client_namespace_result)
}

fn exercise_outbound_product_proxy_transparent_tls_path(
    case: MitmBridgeCase,
    intercept_port: u16,
    mitm_ca: &MitmCaMaterial,
    mitm_backend: &PreparedMitmBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream = product_proxy_upstream(mitm_backend)?;
    exercise_product_proxy_tls_exchange(case, upstream, |request| {
        run_local_tls_client(intercept_port, mitm_ca, &upstream.server_name, request)
    })
}

fn exercise_product_proxy_tls_exchange(
    case: MitmBridgeCase,
    upstream: &ProductProxyUpstream,
    run_client: impl FnMut(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario = data_plane::scenario(case);
    if !scenario.uses_product_proxy_transparent_tls() {
        return Err(e2e_error(format!(
            "{} is not a product proxy transparent TLS data-plane case",
            case.case_name()
        ))
        .into());
    }
    match scenario.protocol() {
        MitmDataPlaneProtocol::BridgeHttp => {
            exercise_product_proxy_http_tls_exchange(case, upstream, run_client)
        }
        MitmDataPlaneProtocol::WebSocket => {
            exercise_product_proxy_websocket_tls_exchange(case, upstream, run_client)
        }
    }
}

fn exercise_product_proxy_http_tls_exchange(
    case: MitmBridgeCase,
    upstream: &ProductProxyUpstream,
    mut run_client: impl FnMut(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario = data_plane::scenario(case);
    let upstream_server = ProductProxyTlsUpstreamServer::start(upstream)?;
    let response = run_client(scenario.allow_request_bytes().as_ref());
    let upstream_result = upstream_server.wait();
    let response = response?;
    assert_tls_client_received_allow_response(&response)?;
    upstream_result?;
    let response = run_client(scenario.request_bytes().as_ref())?;
    assert_tls_client_received_deny_response(&response)
}

fn exercise_product_proxy_websocket_tls_exchange(
    case: MitmBridgeCase,
    upstream: &ProductProxyUpstream,
    mut run_client: impl FnMut(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_server = ProductProxyTlsWebSocketUpstreamServer::start(upstream)?;
    let request = data_plane::scenario(case).request_bytes();
    let response = run_client(request.as_ref());
    let upstream_result = upstream_server.wait();
    let response = response?;
    assert_tls_client_received_websocket_response(&response)?;
    upstream_result
}

fn product_proxy_upstream(
    mitm_backend: &PreparedMitmBackend,
) -> Result<&ProductProxyUpstream, Box<dyn std::error::Error>> {
    match &mitm_backend.config {
        MitmBackendConfig::ProductProxy { upstream, .. } => Ok(upstream),
        config => Err(e2e_error(format!(
            "product proxy transparent TLS exercise received non-product backend {config:?}"
        ))
        .into()),
    }
}

fn spawn_client_namespace_owner(case: MitmBridgeCase) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(unshare_command()?);
    let child = run_in_own_process_group(&mut command)
        .arg("-n")
        .arg("--")
        .arg(std::env::current_exe()?)
        .arg(case.case_name())
        .env(CLIENT_OWNER_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

fn wait_for_client_namespace_ready(child: &mut Child) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + CLIENT_NAMESPACE_READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(e2e_error(format!(
                "MITM transparent TLS client namespace exited before readiness with {status}"
            ))
            .into());
        }
        match ip_in_client_netns(child.id(), ["link", "show", "lo"]) {
            Ok(()) => return Ok(()),
            Err(_error) if Instant::now() < deadline => {}
            Err(error) => {
                return Err(e2e_error(format!(
                    "timed out waiting for MITM transparent TLS client namespace readiness: {error}"
                ))
                .into());
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct IsolatedClientNetwork;

impl IsolatedClientNetwork {
    fn setup(client_pid: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let _ = ip(["link", "del", HOST_IFACE]);
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

impl Drop for IsolatedClientNetwork {
    fn drop(&mut self) {
        let _ = ip(["link", "del", HOST_IFACE]);
    }
}

fn run_client_netns_tls_client(
    client_pid: u32,
    intercept_port: u16,
    mitm_ca: &MitmCaMaterial,
    server_name: &str,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let connect = format!("{HOST_ADDR}:{intercept_port}");
    let mut command = Command::new(nsenter_command()?);
    command
        .args(["--target", &client_pid.to_string(), "--net", "--"])
        .arg(openssl_command()?)
        .args([
            "s_client",
            "-connect",
            &connect,
            "-servername",
            server_name,
            "-CAfile",
        ])
        .arg(&mitm_ca.certificate_path)
        .args(["-quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_tls_client_command(&mut command, request)
}

fn run_local_tls_client(
    intercept_port: u16,
    mitm_ca: &MitmCaMaterial,
    server_name: &str,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let connect = SocketAddr::from((Ipv4Addr::LOCALHOST, intercept_port)).to_string();
    let mut command = Command::new(openssl_command()?);
    command
        .args([
            "s_client",
            "-connect",
            &connect,
            "-servername",
            server_name,
            "-CAfile",
        ])
        .arg(&mitm_ca.certificate_path)
        .args(["-quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_tls_client_command(&mut command, request)
}

fn run_tls_client_command(
    command: &mut Command,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| e2e_error("failed to open openssl s_client stdin"))?
        .write_all(request)?;
    let output = wait_child_with_timeout(child, CLIENT_TIMEOUT, "MITM transparent TLS client")?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(e2e_error(format!(
            "MITM transparent TLS client failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

struct ProductProxyTlsUpstreamServer {
    child: Option<Child>,
}

impl ProductProxyTlsUpstreamServer {
    fn start(upstream: &ProductProxyUpstream) -> Result<Self, Box<dyn std::error::Error>> {
        let target = upstream.target.to_string();
        let mut child = Command::new(openssl_command()?)
            .args(["s_server", "-accept", &target])
            .arg("-cert")
            .arg(&upstream.certificate_path)
            .arg("-key")
            .arg(&upstream.private_key_path)
            .args(["-HTTP", "-quiet", "-naccept", "1"])
            .current_dir(&upstream.document_root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        wait_for_upstream_tls_server_ready(&mut child, upstream.target)?;
        Ok(Self { child: Some(child) })
    }

    fn wait(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let output = wait_child_with_timeout(
            self.child
                .take()
                .ok_or_else(|| e2e_error("product proxy upstream TLS fixture already waited"))?,
            CLIENT_TIMEOUT,
            "product proxy upstream TLS fixture",
        )?;
        if output.status.success() {
            return Ok(());
        }
        Err(e2e_error(format!(
            "product proxy upstream TLS fixture failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

impl Drop for ProductProxyTlsUpstreamServer {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn assert_tls_client_received_allow_response(
    response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if response == mitm_bridge::ALLOW_RESPONSE_BYTES {
        return Ok(());
    }
    Err(e2e_error(format!(
        "MITM transparent TLS allow response mismatch: expected {:?}, got {:?}",
        String::from_utf8_lossy(mitm_bridge::ALLOW_RESPONSE_BYTES),
        String::from_utf8_lossy(response)
    ))
    .into())
}

fn assert_tls_client_received_websocket_response(
    response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = websocket::response_with_frame_bytes();
    if response == expected {
        return Ok(());
    }
    Err(e2e_error(format!(
        "MITM transparent TLS WebSocket response mismatch: expected {:?}, got {:?}",
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(response)
    ))
    .into())
}

fn assert_tls_client_received_deny_response(
    response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = product_proxy_deny_response_bytes();
    if response == expected {
        return Ok(());
    }
    Err(e2e_error(format!(
        "MITM transparent TLS client response mismatch: expected {:?}, got {:?}",
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(response)
    ))
    .into())
}

fn wait_for_upstream_tls_server_ready(
    child: &mut Child,
    target: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + UPSTREAM_READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(e2e_error(format!(
                "product proxy upstream TLS fixture exited before readiness with {status}"
            ))
            .into());
        }
        if tcp_listen_port_is_ready(target.port())? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for product proxy upstream TLS fixture to listen on {target}"
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn tcp_listen_port_is_ready(port: u16) -> io::Result<bool> {
    Ok(proc_tcp_has_listen_port("/proc/net/tcp", port)?
        || proc_tcp_has_listen_port("/proc/net/tcp6", port)?)
}

fn proc_tcp_has_listen_port(path: &str, port: u16) -> io::Result<bool> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let port_suffix = format!(":{port:04X}");
    Ok(content.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        let _slot = fields.next();
        let Some(local_address) = fields.next() else {
            return false;
        };
        let _remote_address = fields.next();
        let Some(state) = fields.next() else {
            return false;
        };
        state == "0A" && local_address.ends_with(&port_suffix)
    }))
}

fn wait_child_with_timeout(
    mut child: Child,
    timeout: Duration,
    label: &str,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                e2e_error(format!("{label} timed out after {}ms", timeout.as_millis())).into(),
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn ip<const N: usize>(args: [&str; N]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(ip_command()?).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "ip failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
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
    if output.status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "nsenter --net ip failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

fn unshare_command() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/bin/unshare", "/bin/unshare"],
        "unshare",
    )?)
}

fn nsenter_command() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/bin/nsenter", "/bin/nsenter"],
        "nsenter",
    )?)
}

fn ip_command() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"],
        "ip",
    )?)
}

fn openssl_command() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/bin/openssl", "/bin/openssl"],
        "openssl",
    )?)
}

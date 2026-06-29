use std::{
    io::Write,
    net::Ipv4Addr,
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
    backend::MitmBridgeCase,
    feed::product_proxy_deny_response_bytes,
    tls::{MitmCaMaterial, SERVER_NAME},
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
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_namespace = supervisor.watch(
        spawn_client_namespace_owner(case)?,
        "MITM transparent TLS client namespace",
    );
    let client_pid = client_namespace.child_mut().id();
    wait_for_client_namespace_ready(client_namespace.child_mut())?;
    let _network = IsolatedClientNetwork::setup(client_pid)?;
    let response = run_tls_client(client_pid, intercept_port, mitm_ca)?;
    assert_tls_client_received_deny_response(&response)?;
    let client_namespace_result = stop_running_child(
        client_namespace.child_mut(),
        "MITM transparent TLS client namespace",
    );
    client_namespace.unwatch();
    client_namespace_result
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

fn run_tls_client(
    client_pid: u32,
    intercept_port: u16,
    mitm_ca: &MitmCaMaterial,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let connect = format!("{HOST_ADDR}:{intercept_port}");
    let mut child = Command::new(nsenter_command()?)
        .args(["--target", &client_pid.to_string(), "--net", "--"])
        .arg(openssl_command()?)
        .args([
            "s_client",
            "-connect",
            &connect,
            "-servername",
            SERVER_NAME,
            "-CAfile",
        ])
        .arg(&mitm_ca.certificate_path)
        .args(["-quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| e2e_error("failed to open openssl s_client stdin"))?
        .write_all(mitm_bridge::REQUEST_BYTES)?;
    let output = wait_with_timeout(child, CLIENT_TIMEOUT)?;
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
                "MITM transparent TLS client timed out after {}ms",
                timeout.as_millis()
            ))
            .into());
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

use std::{
    collections::BTreeSet,
    fs, io,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use rustix::{
    io::Errno,
    process::{Pid, Signal, kill_process_group},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use e2e_support::mitm_bridge;

use super::super::harness::{debug_binary, e2e_error};
use super::tls;

pub(super) const EXTERNAL_INBOUND_CASE_NAME: &str = "e2e-mitm-plaintext-bridge-live-sidecar";
pub(super) const POLICY_HOOK_INBOUND_CASE_NAME: &str =
    "e2e-mitm-policy-hook-plaintext-bridge-live-sidecar";
pub(super) const MANAGED_INBOUND_CASE_NAME: &str = "e2e-managed-mitm-plaintext-bridge-live-sidecar";
pub(super) const MANAGED_POLICY_HOOK_INBOUND_CASE_NAME: &str =
    "e2e-managed-mitm-policy-hook-plaintext-bridge-live-sidecar";
pub(super) const PRODUCT_PROXY_TRANSPARENT_HTTPS_POLICY_HOOK_CASE_NAME: &str =
    "e2e-product-mitm-proxy-transparent-https-policy-hook";
pub(super) const EXTERNAL_OUTBOUND_CASE_NAME: &str =
    "e2e-outbound-mitm-plaintext-bridge-live-sidecar";
pub(super) const MANAGED_OUTBOUND_CASE_NAME: &str =
    "e2e-managed-outbound-mitm-plaintext-bridge-live-sidecar";
pub(super) const EXTERNAL_INBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MITM_PLAINTEXT_BRIDGE_NETNS";
pub(super) const POLICY_HOOK_INBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MITM_POLICY_HOOK_PLAINTEXT_BRIDGE_NETNS";
pub(super) const MANAGED_INBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MANAGED_MITM_PLAINTEXT_BRIDGE_NETNS";
pub(super) const MANAGED_POLICY_HOOK_INBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MANAGED_MITM_POLICY_HOOK_PLAINTEXT_BRIDGE_NETNS";
pub(super) const EXTERNAL_OUTBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_OUTBOUND_MITM_PLAINTEXT_BRIDGE_NETNS";
pub(super) const MANAGED_OUTBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MANAGED_OUTBOUND_MITM_PLAINTEXT_BRIDGE_NETNS";

const DEFAULT_INTERCEPT_PORT: u16 = 65_529;
const DEFAULT_MANAGED_BACKEND_PORT: u16 = 65_521;
const DEFAULT_MANAGED_POLICY_HOOK_PORT: u16 = 65_518;
const MANAGED_BACKEND_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const EXTERNAL_BACKEND_REBIND_TIMEOUT: Duration = Duration::from_secs(2);
const EXTERNAL_BACKEND_LISTEN_BACKLOG: i32 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmBridgeCase {
    ExternalInbound,
    ExternalInboundPolicyHook,
    ManagedInbound,
    ManagedInboundPolicyHook,
    ProductProxyTransparentHttpsPolicyHook,
    ExternalOutbound,
    ManagedOutbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmBridgeDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmBackendKind {
    External,
    ManagedProcess,
    ProductProxy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmPolicyHookOwner {
    None,
    ExternalServer,
    ManagedFixture,
    ProductProxy,
}

impl MitmPolicyHookOwner {
    pub(super) const fn enabled(self) -> bool {
        !matches!(self, Self::None)
    }

    pub(super) const fn execution_reason(self) -> &'static str {
        match self {
            Self::ProductProxy => super::feed::POLICY_HOOK_PRODUCT_PROXY_RESPONSE_REASON,
            Self::None | Self::ExternalServer | Self::ManagedFixture => {
                super::feed::POLICY_HOOK_RESPONSE_REASON
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmDataPlaneExercise {
    None,
    ManagedPlaintext,
    ProductProxyTransparentTls,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MitmBridgeCaseSpec {
    pub(super) backend: MitmBackendKind,
    pub(super) direction: MitmBridgeDirection,
    pub(super) policy_hook: MitmPolicyHookOwner,
    pub(super) data_plane: MitmDataPlaneExercise,
}

impl MitmBridgeCase {
    pub(super) const fn spec(self) -> MitmBridgeCaseSpec {
        match self {
            Self::ExternalInbound => MitmBridgeCaseSpec {
                backend: MitmBackendKind::External,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookOwner::None,
                data_plane: MitmDataPlaneExercise::None,
            },
            Self::ExternalInboundPolicyHook => MitmBridgeCaseSpec {
                backend: MitmBackendKind::External,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookOwner::ExternalServer,
                data_plane: MitmDataPlaneExercise::None,
            },
            Self::ManagedInbound => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ManagedProcess,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookOwner::None,
                data_plane: MitmDataPlaneExercise::ManagedPlaintext,
            },
            Self::ManagedInboundPolicyHook => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ManagedProcess,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookOwner::ManagedFixture,
                data_plane: MitmDataPlaneExercise::ManagedPlaintext,
            },
            Self::ProductProxyTransparentHttpsPolicyHook => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ProductProxy,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookOwner::ProductProxy,
                data_plane: MitmDataPlaneExercise::ProductProxyTransparentTls,
            },
            Self::ExternalOutbound => MitmBridgeCaseSpec {
                backend: MitmBackendKind::External,
                direction: MitmBridgeDirection::Outbound,
                policy_hook: MitmPolicyHookOwner::None,
                data_plane: MitmDataPlaneExercise::None,
            },
            Self::ManagedOutbound => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ManagedProcess,
                direction: MitmBridgeDirection::Outbound,
                policy_hook: MitmPolicyHookOwner::None,
                data_plane: MitmDataPlaneExercise::ManagedPlaintext,
            },
        }
    }

    pub(super) const fn case_name(self) -> &'static str {
        match self {
            Self::ExternalInbound => EXTERNAL_INBOUND_CASE_NAME,
            Self::ExternalInboundPolicyHook => POLICY_HOOK_INBOUND_CASE_NAME,
            Self::ManagedInbound => MANAGED_INBOUND_CASE_NAME,
            Self::ManagedInboundPolicyHook => MANAGED_POLICY_HOOK_INBOUND_CASE_NAME,
            Self::ProductProxyTransparentHttpsPolicyHook => {
                PRODUCT_PROXY_TRANSPARENT_HTTPS_POLICY_HOOK_CASE_NAME
            }
            Self::ExternalOutbound => EXTERNAL_OUTBOUND_CASE_NAME,
            Self::ManagedOutbound => MANAGED_OUTBOUND_CASE_NAME,
        }
    }

    pub(super) const fn netns_env(self) -> &'static str {
        match self {
            Self::ExternalInbound => EXTERNAL_INBOUND_IN_NETNS_ENV,
            Self::ExternalInboundPolicyHook => POLICY_HOOK_INBOUND_IN_NETNS_ENV,
            Self::ManagedInbound => MANAGED_INBOUND_IN_NETNS_ENV,
            Self::ManagedInboundPolicyHook => MANAGED_POLICY_HOOK_INBOUND_IN_NETNS_ENV,
            Self::ProductProxyTransparentHttpsPolicyHook => {
                "TRAFFIC_PROBE_E2E_PRODUCT_MITM_PROXY_TRANSPARENT_HTTPS_POLICY_HOOK_NETNS"
            }
            Self::ExternalOutbound => EXTERNAL_OUTBOUND_IN_NETNS_ENV,
            Self::ManagedOutbound => MANAGED_OUTBOUND_IN_NETNS_ENV,
        }
    }

    pub(super) const fn temp_root_name(self) -> &'static str {
        match self {
            Self::ExternalInbound => "mitm-bridge",
            Self::ExternalInboundPolicyHook => "mitm-policy-hook-bridge",
            Self::ManagedInbound => "managed-mitm-bridge",
            Self::ManagedInboundPolicyHook => "managed-mitm-policy-hook-bridge",
            Self::ProductProxyTransparentHttpsPolicyHook => "product-mitm-https",
            Self::ExternalOutbound => "outbound-mitm-bridge",
            Self::ManagedOutbound => "managed-outbound-mitm-bridge",
        }
    }

    pub(super) const fn failure_label(self) -> &'static str {
        match self {
            Self::ExternalInbound => "e2e MITM plaintext bridge live sidecar",
            Self::ExternalInboundPolicyHook => "e2e MITM policy hook plaintext bridge live sidecar",
            Self::ManagedInbound => "e2e managed MITM plaintext bridge live sidecar",
            Self::ManagedInboundPolicyHook => {
                "e2e managed MITM policy hook plaintext bridge live sidecar"
            }
            Self::ProductProxyTransparentHttpsPolicyHook => {
                "e2e product MITM proxy transparent HTTPS policy hook"
            }
            Self::ExternalOutbound => "e2e outbound MITM plaintext bridge live sidecar",
            Self::ManagedOutbound => "e2e managed outbound MITM plaintext bridge live sidecar",
        }
    }

    pub(super) const fn success_label(self) -> &'static str {
        match self {
            Self::ExternalInbound => "e2e MITM plaintext bridge live sidecar passed",
            Self::ExternalInboundPolicyHook => {
                "e2e MITM policy hook plaintext bridge live sidecar passed"
            }
            Self::ManagedInbound => "e2e managed MITM plaintext bridge live sidecar passed",
            Self::ManagedInboundPolicyHook => {
                "e2e managed MITM policy hook plaintext bridge live sidecar passed"
            }
            Self::ProductProxyTransparentHttpsPolicyHook => {
                "e2e product MITM proxy transparent HTTPS policy hook passed"
            }
            Self::ExternalOutbound => "e2e outbound MITM plaintext bridge live sidecar passed",
            Self::ManagedOutbound => {
                "e2e managed outbound MITM plaintext bridge live sidecar passed"
            }
        }
    }

    pub(super) const fn backend(self) -> MitmBackendKind {
        self.spec().backend
    }

    pub(super) const fn direction(self) -> MitmBridgeDirection {
        self.spec().direction
    }

    pub(super) const fn policy_hook_execution_reason(self) -> &'static str {
        self.spec().policy_hook.execution_reason()
    }
}

pub(super) struct PreparedMitmBackend {
    pub(super) config: MitmBackendConfig,
    pub(super) proxy_port: u16,
    pub(super) policy_hook_endpoint: Option<String>,
    pub(super) action_report_file: Option<PathBuf>,
    external_backend: Option<ExternalMitmBackend>,
}

impl PreparedMitmBackend {
    pub(super) fn managed_pid_file(&self) -> Option<&Path> {
        match &self.config {
            MitmBackendConfig::ManagedProcess { pid_file, .. } => Some(pid_file),
            MitmBackendConfig::External { .. } | MitmBackendConfig::ProductProxy { .. } => None,
        }
    }

    pub(super) fn pause_external_listener(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.external_backend.as_mut() {
            Some(backend) => backend.pause(),
            None => {
                Err(e2e_error("cannot pause managed MITM backend as an external listener").into())
            }
        }
    }

    pub(super) fn resume_external_listener(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.external_backend.as_mut() {
            Some(backend) => backend.resume(),
            None => {
                Err(e2e_error("cannot resume managed MITM backend as an external listener").into())
            }
        }
    }
}

struct ExternalMitmBackend {
    target: SocketAddr,
    listener: Option<ExternalMitmListener>,
}

impl ExternalMitmBackend {
    fn start(listener: TcpListener) -> Result<Self, Box<dyn std::error::Error>> {
        let target = listener.local_addr()?;
        Ok(Self {
            target,
            listener: Some(ExternalMitmListener::start(listener)?),
        })
    }

    fn target(&self) -> SocketAddr {
        self.target
    }

    fn pause(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(listener) = self.listener.take() {
            listener.stop()?;
        }
        Ok(())
    }

    fn resume(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.listener.is_none() {
            let listener = bind_external_listener_with_retry(self.target)?;
            self.listener = Some(ExternalMitmListener::start(listener)?);
        }
        Ok(())
    }
}

struct ExternalMitmListener {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl ExternalMitmListener {
    fn start(listener: TcpListener) -> Result<Self, Box<dyn std::error::Error>> {
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread =
            thread::spawn(move || accept_external_backend_connections(listener, thread_stop));
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop.store(true, Ordering::Relaxed);
        match self
            .thread
            .take()
            .expect("external backend thread already joined")
            .join()
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(e2e_error("external MITM backend accept thread panicked").into()),
        }
    }
}

impl Drop for ExternalMitmListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Debug)]
pub(super) enum MitmBackendConfig {
    External {
        target: String,
    },
    ManagedProcess {
        target: String,
        program: PathBuf,
        args: Vec<String>,
        pid_file: PathBuf,
    },
    ProductProxy {
        target: String,
        program: PathBuf,
        upstream_route: ProductProxyUpstreamRoute,
    },
}

#[derive(Debug)]
pub(super) struct ProductProxyUpstreamRoute {
    pub(super) host: String,
    pub(super) target: SocketAddr,
    pub(super) certificate_path: PathBuf,
    pub(super) private_key_path: PathBuf,
    pub(super) document_root: PathBuf,
}

pub(super) fn prepare_mitm_backend(
    case: MitmBridgeCase,
    root: &Path,
    bridge_feed_path: &Path,
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<PreparedMitmBackend, Box<dyn std::error::Error>> {
    match case.backend() {
        MitmBackendKind::External => prepare_external_backend(),
        MitmBackendKind::ManagedProcess => {
            prepare_managed_process_backend(case, root, bridge_feed_path, used_ports)
        }
        MitmBackendKind::ProductProxy => prepare_product_proxy_backend(root, used_ports),
    }
}

pub(super) fn unused_intercept_port(used_ports: impl IntoIterator<Item = u16>) -> u16 {
    let used_ports = used_ports.into_iter().collect::<BTreeSet<_>>();
    for port in [DEFAULT_INTERCEPT_PORT, DEFAULT_INTERCEPT_PORT - 1] {
        if !used_ports.contains(&port) {
            return port;
        }
    }
    DEFAULT_INTERCEPT_PORT - 2
}

pub(super) fn wait_for_managed_backend_pid(
    pid_file: &Path,
) -> Result<u32, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + MANAGED_BACKEND_CLEANUP_TIMEOUT;
    loop {
        if pid_file.try_exists()? {
            return parse_managed_backend_pid(pid_file);
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for managed MITM backend pid file {}",
                pid_file.display()
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn cleanup_managed_backend(
    pid_file: Option<&Path>,
    expect_agent_cleanup: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pid_file) = pid_file else {
        return Ok(());
    };
    if !pid_file.try_exists()? {
        return Ok(());
    }
    let pid = parse_managed_backend_pid(pid_file)?;
    if wait_until_process_exits(pid, Duration::from_millis(200))? {
        return Ok(());
    }

    let agent_cleanup_error = expect_agent_cleanup.then(|| {
        e2e_error(format!(
            "managed MITM backend pid {pid} remained alive after agent shutdown"
        ))
    });

    signal_process_group(pid, Signal::TERM)?;
    if wait_until_process_exits(pid, MANAGED_BACKEND_CLEANUP_TIMEOUT)? {
        return agent_cleanup_error.map_or(Ok(()), |error| Err(error.into()));
    }
    signal_process_group(pid, Signal::KILL)?;
    if wait_until_process_exits(pid, MANAGED_BACKEND_CLEANUP_TIMEOUT)? {
        return agent_cleanup_error.map_or(Ok(()), |error| Err(error.into()));
    }
    Err(e2e_error(format!(
        "managed MITM backend pid {pid} remained alive after forced cleanup"
    ))
    .into())
}

fn prepare_external_backend() -> Result<PreparedMitmBackend, Box<dyn std::error::Error>> {
    let listener = bind_reusable_tcp_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let backend = ExternalMitmBackend::start(listener)?;
    let target = backend.target();
    Ok(PreparedMitmBackend {
        config: MitmBackendConfig::External {
            target: target.to_string(),
        },
        proxy_port: target.port(),
        policy_hook_endpoint: None,
        action_report_file: None,
        external_backend: Some(backend),
    })
}

fn prepare_managed_process_backend(
    case: MitmBridgeCase,
    root: &Path,
    bridge_feed_path: &Path,
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<PreparedMitmBackend, Box<dyn std::error::Error>> {
    let used_ports = used_ports.into_iter().collect::<BTreeSet<_>>();
    let spec = case.spec();
    let target = managed_backend_target(used_ports.iter().copied())?;
    let pid_file = root.join("managed-mitm-backend.pid");
    let action_report_file = matches!(spec.policy_hook, MitmPolicyHookOwner::ManagedFixture)
        .then(|| root.join("managed-mitm-actions.json"));
    let policy_hook_target = (spec.policy_hook == MitmPolicyHookOwner::ManagedFixture)
        .then(|| managed_policy_hook_target(used_ports.iter().copied().chain([target.port()])))
        .transpose()?;
    let (program, args) = managed_fixture_backend_args(
        target,
        &pid_file,
        bridge_feed_path,
        policy_hook_target,
        action_report_file.as_ref(),
    )?;
    Ok(PreparedMitmBackend {
        proxy_port: target.port(),
        policy_hook_endpoint: policy_hook_target
            .map(|target| format!("http://{target}{}", mitm_bridge::POLICY_HOOK_PATH)),
        action_report_file,
        config: MitmBackendConfig::ManagedProcess {
            target: target.to_string(),
            program,
            args,
            pid_file,
        },
        external_backend: None,
    })
}

fn prepare_product_proxy_backend(
    root: &Path,
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<PreparedMitmBackend, Box<dyn std::error::Error>> {
    let used_ports = used_ports.into_iter().collect::<BTreeSet<_>>();
    let target = managed_backend_target(used_ports.iter().copied())?;
    let policy_hook_target =
        managed_policy_hook_target(used_ports.iter().copied().chain([target.port()]))?;
    let upstream_target = product_proxy_upstream_target(
        used_ports
            .iter()
            .copied()
            .chain([target.port(), policy_hook_target.port()]),
    )?;
    let upstream_route = prepare_product_proxy_upstream_route(root, upstream_target)?;
    Ok(PreparedMitmBackend {
        proxy_port: target.port(),
        policy_hook_endpoint: Some(format!(
            "http://{policy_hook_target}{}",
            mitm_bridge::POLICY_HOOK_PATH
        )),
        action_report_file: None,
        config: MitmBackendConfig::ProductProxy {
            target: target.to_string(),
            program: debug_binary("traffic-probe-mitm-proxy")?,
            upstream_route,
        },
        external_backend: None,
    })
}

fn product_proxy_upstream_target(
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    deterministic_loopback_target(
        DEFAULT_MANAGED_BACKEND_PORT - 10,
        used_ports,
        "product proxy upstream",
    )
}

fn prepare_product_proxy_upstream_route(
    root: &Path,
    target: SocketAddr,
) -> Result<ProductProxyUpstreamRoute, Box<dyn std::error::Error>> {
    let material = tls::write_upstream_server_certificate(root)?;
    let document_root = root.join("product-proxy-upstream");
    let response_path = document_root.join("mitm-bridge").join("allow");
    fs::create_dir_all(
        response_path
            .parent()
            .ok_or_else(|| e2e_error("product proxy upstream response path has no parent"))?,
    )?;
    fs::write(&response_path, mitm_bridge::ALLOW_RESPONSE_BYTES)?;
    Ok(ProductProxyUpstreamRoute {
        host: tls::SERVER_NAME.to_string(),
        target,
        certificate_path: material.certificate_path.clone(),
        private_key_path: material.private_key_path,
        document_root,
    })
}

fn managed_fixture_backend_args(
    target: SocketAddr,
    pid_file: &Path,
    bridge_feed_path: &Path,
    policy_hook_target: Option<SocketAddr>,
    action_report_file: Option<&PathBuf>,
) -> Result<(PathBuf, Vec<String>), Box<dyn std::error::Error>> {
    let mut args = vec![
        "managed-mitm-backend".to_string(),
        "--listen-addr".to_string(),
        target.to_string(),
        "--pid-file".to_string(),
        pid_file.display().to_string(),
        "--bridge-feed-file".to_string(),
        bridge_feed_path.display().to_string(),
    ];
    if let (Some(policy_hook_target), Some(action_report_file)) =
        (policy_hook_target, action_report_file)
    {
        args.extend([
            "--policy-hook-listen-addr".to_string(),
            policy_hook_target.to_string(),
            "--action-report-file".to_string(),
            action_report_file.display().to_string(),
        ]);
    }
    Ok((debug_binary("traffic-probe-e2e-fixture")?, args))
}

fn managed_backend_target(
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    deterministic_loopback_target(
        DEFAULT_MANAGED_BACKEND_PORT,
        used_ports,
        "managed MITM backend",
    )
}

fn managed_policy_hook_target(
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    deterministic_loopback_target(
        DEFAULT_MANAGED_POLICY_HOOK_PORT,
        used_ports,
        "managed MITM policy hook",
    )
}

fn deterministic_loopback_target(
    default_port: u16,
    used_ports: impl IntoIterator<Item = u16>,
    label: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let used_ports = used_ports.into_iter().collect::<BTreeSet<_>>();
    for port in [default_port, default_port - 1, default_port - 2] {
        if used_ports.contains(&port) {
            continue;
        }
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        match TcpListener::bind(target) {
            Ok(listener) => {
                drop(listener);
                return Ok(target);
            }
            Err(error) if is_address_in_use(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(e2e_error(format!("failed to find a free deterministic {label} port")).into())
}

fn bind_external_listener_with_retry(
    target: SocketAddr,
) -> Result<TcpListener, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + EXTERNAL_BACKEND_REBIND_TIMEOUT;
    loop {
        match bind_reusable_tcp_listener(target) {
            Ok(listener) => return Ok(listener),
            Err(error) if is_address_in_use(&error) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn bind_reusable_tcp_listener(target: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(target))?;
    socket.listen(EXTERNAL_BACKEND_LISTEN_BACKLOG)?;
    Ok(TcpListener::from(socket))
}

fn accept_external_backend_connections(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => drop(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn is_address_in_use(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::AddrInUse)
}

fn parse_managed_backend_pid(pid_file: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(pid_file)?;
    raw.trim().parse::<u32>().map_err(|error| {
        e2e_error(format!(
            "managed MITM backend pid file {} did not contain a pid: {error}",
            pid_file.display()
        ))
        .into()
    })
}

fn wait_until_process_exits(
    pid: u32,
    timeout: Duration,
) -> Result<bool, Box<dyn std::error::Error>> {
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let deadline = Instant::now() + timeout;
    loop {
        if !proc_path.try_exists()? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn signal_process_group(pid: u32, signal: Signal) -> Result<(), Box<dyn std::error::Error>> {
    let raw_pid = i32::try_from(pid).map_err(|_| {
        e2e_error(format!(
            "managed MITM backend pid {pid} does not fit Linux pid_t"
        ))
    })?;
    let process_group = Pid::from_raw(raw_pid).ok_or_else(|| {
        e2e_error(format!(
            "managed MITM backend pid {pid} is not a valid process group id"
        ))
    })?;
    match kill_process_group(process_group, signal) {
        Ok(()) => Ok(()),
        Err(error) if error == Errno::SRCH => Ok(()),
        Err(error) => Err(e2e_error(format!(
            "failed to send {signal:?} to managed MITM backend process group {pid}: {error}"
        ))
        .into()),
    }
}

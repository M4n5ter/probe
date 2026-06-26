use std::{
    collections::BTreeSet,
    fs, io,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    io::Errno,
    process::{Pid, Signal, kill_process_group},
};

use super::super::harness::{debug_binary, e2e_error};

pub(super) const EXTERNAL_CASE_NAME: &str = "e2e-mitm-plaintext-bridge-live-sidecar";
pub(super) const MANAGED_CASE_NAME: &str = "e2e-managed-mitm-plaintext-bridge-live-sidecar";
pub(super) const EXTERNAL_IN_NETNS_ENV: &str = "SSSA_PROBE_E2E_MITM_PLAINTEXT_BRIDGE_NETNS";
pub(super) const MANAGED_IN_NETNS_ENV: &str = "SSSA_PROBE_E2E_MANAGED_MITM_PLAINTEXT_BRIDGE_NETNS";

const DEFAULT_INTERCEPT_PORT: u16 = 65_529;
const DEFAULT_MANAGED_BACKEND_PORT: u16 = 65_521;
const MANAGED_BACKEND_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmBackendCase {
    External,
    ManagedProcess,
}

impl MitmBackendCase {
    pub(super) const fn case_name(self) -> &'static str {
        match self {
            Self::External => EXTERNAL_CASE_NAME,
            Self::ManagedProcess => MANAGED_CASE_NAME,
        }
    }

    pub(super) const fn netns_env(self) -> &'static str {
        match self {
            Self::External => EXTERNAL_IN_NETNS_ENV,
            Self::ManagedProcess => MANAGED_IN_NETNS_ENV,
        }
    }

    pub(super) const fn temp_root_name(self) -> &'static str {
        match self {
            Self::External => "mitm-bridge",
            Self::ManagedProcess => "managed-mitm-bridge",
        }
    }

    pub(super) const fn failure_label(self) -> &'static str {
        match self {
            Self::External => "e2e MITM plaintext bridge live sidecar",
            Self::ManagedProcess => "e2e managed MITM plaintext bridge live sidecar",
        }
    }

    pub(super) const fn success_label(self) -> &'static str {
        match self {
            Self::External => "e2e MITM plaintext bridge live sidecar passed",
            Self::ManagedProcess => "e2e managed MITM plaintext bridge live sidecar passed",
        }
    }
}

pub(super) struct PreparedMitmBackend {
    pub(super) config: MitmBackendConfig,
    pub(super) proxy_port: u16,
    _external_listener: Option<TcpListener>,
}

impl PreparedMitmBackend {
    pub(super) fn managed_pid_file(&self) -> Option<&Path> {
        match &self.config {
            MitmBackendConfig::ManagedProcess { pid_file, .. } => Some(pid_file),
            MitmBackendConfig::External { .. } => None,
        }
    }
}

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
}

pub(super) fn prepare_mitm_backend(
    case: MitmBackendCase,
    root: &Path,
    bridge_feed_path: &Path,
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<PreparedMitmBackend, Box<dyn std::error::Error>> {
    match case {
        MitmBackendCase::External => prepare_external_backend(),
        MitmBackendCase::ManagedProcess => {
            prepare_managed_backend(root, bridge_feed_path, used_ports)
        }
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
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    Ok(PreparedMitmBackend {
        config: MitmBackendConfig::External {
            target: target.to_string(),
        },
        proxy_port: target.port(),
        _external_listener: Some(listener),
    })
}

fn prepare_managed_backend(
    root: &Path,
    bridge_feed_path: &Path,
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<PreparedMitmBackend, Box<dyn std::error::Error>> {
    let target = managed_backend_target(used_ports)?;
    let pid_file = root.join("managed-mitm-backend.pid");
    Ok(PreparedMitmBackend {
        proxy_port: target.port(),
        config: MitmBackendConfig::ManagedProcess {
            target: target.to_string(),
            program: debug_binary("sssa-e2e-fixture")?,
            args: vec![
                "managed-mitm-backend".to_string(),
                "--listen-addr".to_string(),
                target.to_string(),
                "--pid-file".to_string(),
                pid_file.display().to_string(),
                "--bridge-feed-file".to_string(),
                bridge_feed_path.display().to_string(),
            ],
            pid_file,
        },
        _external_listener: None,
    })
}

fn managed_backend_target(
    used_ports: impl IntoIterator<Item = u16>,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let used_ports = used_ports.into_iter().collect::<BTreeSet<_>>();
    for port in [
        DEFAULT_MANAGED_BACKEND_PORT,
        DEFAULT_MANAGED_BACKEND_PORT - 1,
        DEFAULT_MANAGED_BACKEND_PORT - 2,
    ] {
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
    Err(e2e_error("failed to find a free deterministic managed MITM backend port").into())
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

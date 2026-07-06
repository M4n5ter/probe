use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::{fs::OpenOptionsExt, net::UnixListener as StdUnixListener},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use probe_config::{AgentConfig, probe_home_path};
use probe_core::CancellationToken;
use rustix::{
    fs::OFlags,
    process::{Pid, Signal, kill_process, kill_process_group},
};
use tokio::{process::Command, time::Instant};

use super::{
    config_edit::TuiError, generated_resources::ensure_private_directory,
    runtime_attachment::RuntimeAttachment,
};
use crate::admin::{AdminRequest, send_admin_json_request_with_timeout};

const ADMIN_PROBE_TIMEOUT: Duration = Duration::from_millis(200);
const ADMIN_SHUTDOWN_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const ADMIN_SHUTDOWN_GRACE_TIMEOUT: Duration = Duration::from_secs(5);
const MANAGED_AGENT_STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const MANAGED_AGENT_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const LOG_TAIL_BYTES: u64 = 8 * 1024;
const DATA_READY_SOCKET_ENV: &str = "TRAFFIC_PROBE_READY_SOCKET";
const CONTROL_READY_SOCKET_ENV: &str = "TRAFFIC_PROBE_CONTROL_READY_SOCKET";

#[derive(Debug)]
pub(crate) struct TuiAgentSupervisor {
    mode: TuiAgentMode,
}

#[derive(Debug)]
enum TuiAgentMode {
    Existing(ExistingAgent),
    Managed(Box<ManagedAgent>),
}

#[derive(Debug)]
struct ExistingAgent {
    runtime_dir: PathBuf,
    runtime_config_path: PathBuf,
}

impl Drop for ExistingAgent {
    fn drop(&mut self) {
        cleanup_existing_agent_files(self);
    }
}

#[derive(Debug)]
struct ManagedAgent {
    child: ManagedChild,
    runtime_dir: PathBuf,
    runtime_config_path: PathBuf,
    socket_path: PathBuf,
    readiness_path: PathBuf,
    log_path: PathBuf,
}

impl Drop for ManagedAgent {
    fn drop(&mut self) {
        cleanup_managed_runtime_files(self);
    }
}

#[derive(Debug)]
struct ManagedChild {
    child: tokio::process::Child,
}

impl ManagedChild {
    fn new(child: tokio::process::Child) -> Self {
        Self { child }
    }

    fn id(&self) -> Option<u32> {
        self.child.id()
    }

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, std::io::Error> {
        self.child.try_wait()
    }

    async fn wait_for_exit(&mut self, timeout: Duration) -> bool {
        matches!(
            tokio::time::timeout(timeout, self.child.wait()).await,
            Ok(Ok(_))
        )
    }

    async fn terminate(&mut self) {
        if matches!(self.try_wait(), Ok(Some(_))) {
            return;
        }
        if !self.signal(Signal::TERM) {
            let _ = self.child.start_kill();
        }
        if !self.wait_for_exit(MANAGED_AGENT_STOP_TIMEOUT).await {
            let _ = self.signal(Signal::KILL);
            let _ = self.child.start_kill();
            let _ = self.child.wait().await;
        }
    }

    fn signal(&mut self, signal: Signal) -> bool {
        if matches!(self.try_wait(), Ok(Some(_))) {
            return false;
        }
        let Some(pid) = self.id().and_then(|pid| Pid::from_raw(pid as i32)) else {
            return false;
        };
        if let Err(error) = kill_process(pid, signal) {
            eprintln!("failed to signal TUI managed agent process {pid}: {error}");
        }
        if signal == Signal::KILL
            && let Err(error) = kill_process_group(pid, signal)
        {
            eprintln!("failed to signal TUI managed agent process group {pid}: {error}");
        }
        true
    }

    fn kill_on_drop(&mut self) {
        if matches!(self.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.signal(Signal::TERM);
        let _ = self.signal(Signal::KILL);
        let _ = self.child.start_kill();
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.kill_on_drop();
    }
}

impl TuiAgentSupervisor {
    pub(crate) async fn attach_or_spawn(config: &AgentConfig) -> Result<Self, TuiError> {
        Self::attach_or_spawn_with_cancellation(config, CancellationToken::default()).await
    }

    pub(crate) async fn attach_or_spawn_with_cancellation(
        config: &AgentConfig,
        cancellation: CancellationToken,
    ) -> Result<Self, TuiError> {
        let configured_socket_path = config.admin.socket_path.clone();
        if admin_socket_responds(&configured_socket_path).await {
            return Ok(Self {
                mode: TuiAgentMode::Existing(ExistingAgent::create()?),
            });
        }
        spawn_managed_agent_with_cancellation(config, cancellation).await
    }

    pub(crate) fn attachment(&self, config: &AgentConfig) -> RuntimeAttachment {
        match &self.mode {
            TuiAgentMode::Existing(_) => {
                RuntimeAttachment::existing(config.admin.socket_path.clone())
            }
            TuiAgentMode::Managed(agent) => RuntimeAttachment::managed(
                agent.socket_path.clone(),
                agent.child.id(),
                agent.log_path.clone(),
            ),
        }
    }

    pub(crate) fn is_managed(&self) -> bool {
        matches!(self.mode, TuiAgentMode::Managed(_))
    }

    pub(crate) fn prepare_config_reload_candidate(
        &self,
        config: &AgentConfig,
    ) -> Result<PathBuf, TuiError> {
        match &self.mode {
            TuiAgentMode::Existing(agent) => {
                replace_runtime_config(config, &agent.runtime_config_path)?;
                Ok(agent.runtime_config_path.clone())
            }
            TuiAgentMode::Managed(agent) => {
                let runtime_config = managed_runtime_config(config, &agent.socket_path);
                replace_runtime_config(&runtime_config, &agent.runtime_config_path)?;
                Ok(agent.runtime_config_path.clone())
            }
        }
    }

    pub(crate) async fn restart_with_cancellation(
        self,
        config: &AgentConfig,
        cancellation: CancellationToken,
    ) -> Result<Self, TuiError> {
        match self.mode {
            TuiAgentMode::Existing(agent) => Ok(Self {
                mode: TuiAgentMode::Existing(agent),
            }),
            TuiAgentMode::Managed(agent) => {
                stop_managed_agent(*agent).await;
                spawn_managed_agent_with_cancellation(config, cancellation).await
            }
        }
    }

    pub(crate) async fn poll_exit(&mut self) -> Result<Option<String>, TuiError> {
        let TuiAgentMode::Managed(agent) = &mut self.mode else {
            return Ok(None);
        };
        match agent
            .child
            .try_wait()
            .map_err(|source| TuiError::AgentSupervisor {
                action: "poll TUI managed agent",
                source,
            })? {
            Some(status) => Ok(Some(managed_agent_exit_message(status, &agent.log_path))),
            None => Ok(None),
        }
    }

    pub(crate) async fn stop(self) {
        match self.mode {
            TuiAgentMode::Existing(agent) => cleanup_existing_agent(agent),
            TuiAgentMode::Managed(agent) => stop_managed_agent(*agent).await,
        }
    }
}

impl ExistingAgent {
    fn create() -> Result<Self, TuiError> {
        let runtime_dir = probe_home_path(
            PathBuf::from("run")
                .join("tui")
                .join("existing")
                .join(runtime_config_suffix()),
        );
        ensure_private_directory(&runtime_dir)?;
        Ok(Self {
            runtime_config_path: runtime_dir.join("reload-candidate.toml"),
            runtime_dir,
        })
    }
}

fn cleanup_existing_agent(agent: ExistingAgent) {
    cleanup_existing_agent_files(&agent);
}

fn cleanup_existing_agent_files(agent: &ExistingAgent) {
    remove_runtime_file(
        &agent.runtime_config_path,
        "TUI existing agent reload candidate",
    );
    if let Err(error) = fs::remove_dir(&agent.runtime_dir)
        && error.kind() != std::io::ErrorKind::NotFound
        && error.kind() != std::io::ErrorKind::DirectoryNotEmpty
    {
        eprintln!(
            "failed to remove TUI existing agent runtime directory {}: {error}",
            agent.runtime_dir.display()
        );
    }
}

async fn stop_managed_agent(mut agent: ManagedAgent) {
    if !request_admin_shutdown_and_wait(&mut agent).await {
        agent.child.terminate().await;
    }
    cleanup_managed_runtime_files(&agent);
}

fn cleanup_managed_runtime_files(agent: &ManagedAgent) {
    remove_runtime_file(&agent.runtime_config_path, "TUI runtime config");
    remove_runtime_file(&agent.socket_path, "TUI managed agent admin socket");
    remove_runtime_file(&agent.readiness_path, "TUI managed agent readiness socket");
    remove_runtime_file(&agent.log_path, "TUI managed agent log");
    if let Err(error) = fs::remove_dir(&agent.runtime_dir)
        && error.kind() != std::io::ErrorKind::NotFound
        && error.kind() != std::io::ErrorKind::DirectoryNotEmpty
    {
        eprintln!(
            "failed to remove TUI runtime directory {}: {error}",
            agent.runtime_dir.display()
        );
    }
}

async fn request_admin_shutdown_and_wait(agent: &mut ManagedAgent) -> bool {
    if send_admin_json_request_with_timeout(
        &agent.socket_path,
        AdminRequest::Shutdown,
        ADMIN_SHUTDOWN_REQUEST_TIMEOUT,
    )
    .await
    .is_err()
    {
        return false;
    }
    agent
        .child
        .wait_for_exit(ADMIN_SHUTDOWN_GRACE_TIMEOUT)
        .await
}

async fn spawn_managed_agent_with_cancellation(
    config: &AgentConfig,
    cancellation: CancellationToken,
) -> Result<TuiAgentSupervisor, TuiError> {
    let layout = ManagedRuntimeLayout::create()?;
    let mut startup_guard = ManagedStartupGuard::new(&layout);
    let runtime_config = managed_runtime_config(config, &layout.socket_path);
    write_runtime_config(&runtime_config, &layout.config_path)?;
    let readiness_listener = bind_readiness_socket(&layout.readiness_path)?;
    let log = open_log_file(&layout.log_path)?;
    let mut command = Command::new(current_exe()?);
    command
        .arg("run")
        .arg("--config")
        .arg(&layout.config_path)
        .env(CONTROL_READY_SOCKET_ENV, &layout.readiness_path)
        .env_remove(DATA_READY_SOCKET_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().map_err(|source| {
            TuiError::AgentSupervisor {
                action: "clone TUI managed agent log handle",
                source,
            }
        })?))
        .stderr(Stdio::from(log))
        .process_group(0);
    let child = command
        .spawn()
        .map_err(|source| TuiError::AgentSupervisor {
            action: "spawn TUI managed agent",
            source,
        })?;
    let mut child = ManagedChild::new(child);
    if let Err(error) = wait_for_managed_agent(
        &mut child,
        &readiness_listener,
        &layout.socket_path,
        &layout.log_path,
        &cancellation,
    )
    .await
    {
        child.terminate().await;
        if !matches!(error, TuiError::ManagedAgentStartupCancelled) {
            startup_guard.keep_log();
        }
        return Err(error);
    }
    startup_guard.disarm();
    Ok(TuiAgentSupervisor {
        mode: TuiAgentMode::Managed(Box::new(ManagedAgent {
            child,
            runtime_dir: layout.runtime_dir,
            runtime_config_path: layout.config_path,
            socket_path: layout.socket_path,
            readiness_path: layout.readiness_path,
            log_path: layout.log_path,
        })),
    })
}

#[derive(Debug)]
struct ManagedRuntimeLayout {
    runtime_dir: PathBuf,
    config_path: PathBuf,
    socket_path: PathBuf,
    readiness_path: PathBuf,
    log_path: PathBuf,
}

impl ManagedRuntimeLayout {
    fn create() -> Result<Self, TuiError> {
        let runtime_dir = probe_home_path(
            PathBuf::from("run")
                .join("tui")
                .join(runtime_config_suffix()),
        );
        ensure_private_directory(&runtime_dir)?;
        Ok(Self {
            config_path: runtime_dir.join("agent.toml"),
            socket_path: runtime_dir.join("admin.sock"),
            readiness_path: runtime_dir.join("ready.sock"),
            log_path: runtime_dir.join("agent.log"),
            runtime_dir,
        })
    }
}

#[derive(Debug)]
struct ManagedStartupGuard {
    runtime_dir: PathBuf,
    config_path: PathBuf,
    socket_path: PathBuf,
    readiness_path: PathBuf,
    log_path: PathBuf,
    keep_log: bool,
    armed: bool,
}

impl ManagedStartupGuard {
    fn new(layout: &ManagedRuntimeLayout) -> Self {
        Self {
            runtime_dir: layout.runtime_dir.clone(),
            config_path: layout.config_path.clone(),
            socket_path: layout.socket_path.clone(),
            readiness_path: layout.readiness_path.clone(),
            log_path: layout.log_path.clone(),
            keep_log: false,
            armed: true,
        }
    }

    fn keep_log(&mut self) {
        self.keep_log = true;
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for ManagedStartupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        remove_runtime_file(&self.config_path, "TUI runtime config");
        remove_runtime_file(&self.socket_path, "TUI managed agent admin socket");
        remove_runtime_file(&self.readiness_path, "TUI managed agent readiness socket");
        if !self.keep_log {
            remove_runtime_file(&self.log_path, "TUI managed agent log");
        }
        if let Err(error) = fs::remove_dir(&self.runtime_dir)
            && error.kind() != std::io::ErrorKind::NotFound
            && error.kind() != std::io::ErrorKind::DirectoryNotEmpty
        {
            eprintln!(
                "failed to remove TUI runtime directory {}: {error}",
                self.runtime_dir.display()
            );
        }
    }
}

fn remove_runtime_file(path: &Path, label: &str) {
    if let Err(error) = fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("failed to remove {label} {}: {error}", path.display());
    }
}

fn managed_runtime_config(config: &AgentConfig, socket_path: &Path) -> AgentConfig {
    let mut runtime_config = config.clone();
    runtime_config.admin.enabled = true;
    runtime_config.admin.socket_path = socket_path.to_path_buf();
    runtime_config.runtime_reload.watch_config = false;
    runtime_config
}

fn current_exe() -> Result<PathBuf, TuiError> {
    std::env::current_exe().map_err(|source| TuiError::AgentSupervisor {
        action: "resolve current executable",
        source,
    })
}

fn write_runtime_config(config: &AgentConfig, path: &Path) -> Result<(), TuiError> {
    write_runtime_config_file(config, path, RuntimeConfigWriteMode::CreateNew)
}

fn replace_runtime_config(config: &AgentConfig, path: &Path) -> Result<(), TuiError> {
    write_runtime_config_file(config, path, RuntimeConfigWriteMode::Replace)
}

#[derive(Debug, Clone, Copy)]
enum RuntimeConfigWriteMode {
    CreateNew,
    Replace,
}

impl RuntimeConfigWriteMode {
    fn configure(self, options: &mut OpenOptions) {
        options.write(true).mode(0o600);
        match self {
            Self::CreateNew => {
                options.create_new(true);
            }
            Self::Replace => {
                options.create(true).truncate(true);
            }
        };
        options.custom_flags(OFlags::NOFOLLOW.bits() as i32);
    }

    fn open_action(self) -> &'static str {
        match self {
            Self::CreateNew => "create TUI runtime config",
            Self::Replace => "replace TUI runtime config",
        }
    }
}

fn write_runtime_config_file(
    config: &AgentConfig,
    path: &Path,
    mode: RuntimeConfigWriteMode,
) -> Result<(), TuiError> {
    let body = toml::to_string(config)?;
    let mut options = OpenOptions::new();
    mode.configure(&mut options);
    let mut file = options
        .open(path)
        .map_err(|source| TuiError::AgentSupervisor {
            action: mode.open_action(),
            source,
        })?;
    use std::io::Write as _;
    file.write_all(body.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| TuiError::AgentSupervisor {
            action: "write TUI runtime config",
            source,
        })
}

fn open_log_file(path: &Path) -> Result<File, TuiError> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| TuiError::AgentSupervisor {
            action: "create TUI managed agent log",
            source,
        })
}

fn bind_readiness_socket(path: &Path) -> Result<StdUnixListener, TuiError> {
    let listener = StdUnixListener::bind(path).map_err(|source| TuiError::AgentSupervisor {
        action: "bind TUI managed agent readiness socket",
        source,
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| TuiError::AgentSupervisor {
            action: "configure TUI managed agent readiness socket",
            source,
        })?;
    Ok(listener)
}

fn runtime_config_suffix() -> String {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{pid}-{nanos}")
}

async fn wait_for_managed_agent(
    child: &mut ManagedChild,
    readiness_listener: &StdUnixListener,
    admin_socket_path: &Path,
    log_path: &Path,
    cancellation: &CancellationToken,
) -> Result<(), TuiError> {
    let deadline = Instant::now() + MANAGED_AGENT_STARTUP_TIMEOUT;
    loop {
        if cancellation.is_cancelled() {
            return Err(TuiError::ManagedAgentStartupCancelled);
        }
        match readiness_listener.accept() {
            Ok((_stream, _address)) => {
                wait_for_admin_socket_after_readiness(
                    child,
                    admin_socket_path,
                    log_path,
                    deadline,
                    cancellation,
                )
                .await?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(source) => {
                return Err(TuiError::AgentSupervisor {
                    action: "accept TUI managed agent readiness signal",
                    source,
                });
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|source| TuiError::AgentSupervisor {
                action: "poll TUI managed agent startup",
                source,
            })?
        {
            return Err(TuiError::ManagedAgentExited {
                status,
                log_path: log_path.to_path_buf(),
                log_tail: managed_startup_log_tail(log_path),
            });
        }
        if Instant::now() >= deadline {
            return Err(TuiError::ManagedAgentStartupTimeout {
                socket_path: admin_socket_path.display().to_string(),
                log_path: log_path.to_path_buf(),
                log_tail: managed_startup_log_tail(log_path),
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_admin_socket_after_readiness(
    child: &mut ManagedChild,
    admin_socket_path: &Path,
    log_path: &Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), TuiError> {
    loop {
        if cancellation.is_cancelled() {
            return Err(TuiError::ManagedAgentStartupCancelled);
        }
        if admin_socket_responds(admin_socket_path).await {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|source| TuiError::AgentSupervisor {
                action: "poll TUI managed agent startup",
                source,
            })?
        {
            return Err(TuiError::ManagedAgentExited {
                status,
                log_path: log_path.to_path_buf(),
                log_tail: managed_startup_log_tail(log_path),
            });
        }
        if Instant::now() >= deadline {
            return Err(TuiError::ManagedAgentStartupTimeout {
                socket_path: admin_socket_path.display().to_string(),
                log_path: log_path.to_path_buf(),
                log_tail: managed_startup_log_tail(log_path),
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn admin_socket_responds(socket_path: &Path) -> bool {
    send_admin_json_request_with_timeout(socket_path, AdminRequest::Ping, ADMIN_PROBE_TIMEOUT)
        .await
        .is_ok_and(|response| {
            response.get("kind").and_then(serde_json::Value::as_str) == Some("pong")
        })
}

fn managed_agent_exit_message(status: std::process::ExitStatus, log_path: &Path) -> String {
    let log_tail = read_log_tail(log_path);
    if log_tail.is_empty() {
        format!(
            "TUI managed agent exited: {status}; log {}",
            log_path.display()
        )
    } else {
        format!(
            "TUI managed agent exited: {status}; log {}; tail: {}",
            log_path.display(),
            one_line_log_tail(&log_tail)
        )
    }
}

fn managed_startup_log_tail(log_path: &Path) -> String {
    one_line_log_tail(&read_log_tail(log_path))
}

fn read_log_tail(path: &Path) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let Ok(len) = file.metadata().map(|metadata| metadata.len()) else {
        return String::new();
    };
    let start = len.saturating_sub(LOG_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes).trim().to_string()
}

fn one_line_log_tail(log_tail: &str) -> String {
    log_tail
        .lines()
        .rev()
        .filter(|line| !line.trim().is_empty())
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    #[test]
    fn managed_runtime_config_uses_tui_owned_socket_without_mutating_input() {
        let mut config = AgentConfig::default();
        config.admin.enabled = false;
        config.admin.socket_path = PathBuf::from("/tmp/probe.sock");
        config.runtime_reload.watch_config = true;
        let socket_path =
            PathBuf::from("/home/operator/.local/state/traffic-probe/run/tui/x/admin.sock");

        let runtime_config = managed_runtime_config(&config, &socket_path);

        assert!(!config.admin.enabled);
        assert_eq!(config.admin.socket_path, PathBuf::from("/tmp/probe.sock"));
        assert!(config.runtime_reload.watch_config);
        assert!(runtime_config.admin.enabled);
        assert_eq!(runtime_config.admin.socket_path, socket_path);
        assert!(!runtime_config.runtime_reload.watch_config);
    }

    #[test]
    fn existing_config_reload_candidate_uses_tui_owned_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let runtime_config_path = temp.path().join("reload-candidate.toml");
        let user_config_path = temp.path().join("user-agent.toml");
        let user_config = AgentConfig {
            config_version: "external".to_string(),
            ..AgentConfig::default()
        };
        fs::write(&user_config_path, toml::to_string(&user_config)?)?;
        let supervisor = TuiAgentSupervisor {
            mode: TuiAgentMode::Existing(ExistingAgent {
                runtime_dir: temp.path().to_path_buf(),
                runtime_config_path: runtime_config_path.clone(),
            }),
        };
        let snapshot_config = AgentConfig {
            config_version: "snapshot".to_string(),
            ..AgentConfig::default()
        };

        let candidate_path = supervisor.prepare_config_reload_candidate(&snapshot_config)?;

        assert_eq!(candidate_path, runtime_config_path);
        assert_ne!(candidate_path, user_config_path);
        let written = AgentConfig::from_toml_str(&fs::read_to_string(&candidate_path)?)?;
        assert_eq!(written, snapshot_config);
        let user_written = AgentConfig::from_toml_str(&fs::read_to_string(&user_config_path)?)?;
        assert_eq!(user_written, user_config);
        Ok(())
    }

    #[tokio::test]
    async fn managed_config_reload_candidate_uses_projected_runtime_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let runtime_config_path = temp.path().join("agent.toml");
        let socket_path = temp.path().join("admin.sock");
        fs::write(&runtime_config_path, "stale")?;
        let child = tokio::process::Command::new("/bin/true").spawn()?;
        let mut supervisor = TuiAgentSupervisor {
            mode: TuiAgentMode::Managed(Box::new(ManagedAgent {
                child: ManagedChild::new(child),
                runtime_dir: temp.path().to_path_buf(),
                runtime_config_path: runtime_config_path.clone(),
                socket_path: socket_path.clone(),
                readiness_path: temp.path().join("ready.sock"),
                log_path: temp.path().join("agent.log"),
            })),
        };
        let mut config = AgentConfig::default();
        config.admin.enabled = false;
        config.admin.socket_path = PathBuf::from("/tmp/user-admin.sock");
        config.runtime_reload.watch_config = true;

        let candidate_path = supervisor.prepare_config_reload_candidate(&config)?;

        assert_eq!(candidate_path, runtime_config_path);
        assert!(config.runtime_reload.watch_config);
        assert_eq!(
            config.admin.socket_path,
            PathBuf::from("/tmp/user-admin.sock")
        );
        let written = AgentConfig::from_toml_str(&fs::read_to_string(&candidate_path)?)?;
        assert!(written.admin.enabled);
        assert_eq!(written.admin.socket_path, socket_path);
        assert!(!written.runtime_reload.watch_config);
        if let TuiAgentMode::Managed(agent) = &mut supervisor.mode {
            let _ = agent.child.wait_for_exit(Duration::from_secs(1)).await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_probe_uses_lightweight_ping() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept admin probe");
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let mut request = String::new();
            {
                let mut reader = BufReader::new(&mut stream);
                reader
                    .read_line(&mut request)
                    .await
                    .expect("read admin probe");
            }
            let request: serde_json::Value =
                serde_json::from_str(&request).expect("admin probe should be JSON");
            assert_eq!(request["command"], "ping");
            stream
                .write_all(b"{\"kind\":\"pong\"}\n")
                .await
                .expect("write pong");
        });

        assert!(admin_socket_responds(&socket_path).await);
        server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_probe_rejects_non_pong_response() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept admin probe");
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let mut request = String::new();
            {
                let mut reader = BufReader::new(&mut stream);
                reader
                    .read_line(&mut request)
                    .await
                    .expect("read admin probe");
            }
            stream
                .write_all(b"{\"kind\":\"status\"}\n")
                .await
                .expect("write non-pong response");
        });

        assert!(!admin_socket_responds(&socket_path).await);
        server.await?;
        Ok(())
    }

    #[test]
    fn one_line_log_tail_keeps_recent_lines() {
        assert_eq!(
            one_line_log_tail("one\ntwo\nthree\nfour\nfive\n"),
            "two | three | four | five"
        );
    }

    #[test]
    fn managed_startup_log_tail_is_single_line() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let log_path = temp.path().join("agent.log");
        fs::write(&log_path, "one\ntwo\nthree\nfour\nfive\n")?;

        assert_eq!(
            managed_startup_log_tail(&log_path),
            "two | three | four | five"
        );
        Ok(())
    }

    #[test]
    fn startup_guard_removes_unclaimed_runtime_files() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let layout = test_layout(temp.path().join("session"));
        fs::create_dir_all(&layout.runtime_dir)?;
        fs::write(&layout.config_path, "config")?;
        fs::write(&layout.socket_path, "socket")?;
        fs::write(&layout.log_path, "log")?;

        drop(ManagedStartupGuard::new(&layout));

        assert!(!layout.config_path.exists());
        assert!(!layout.socket_path.exists());
        assert!(!layout.log_path.exists());
        assert!(!layout.runtime_dir.exists());
        Ok(())
    }

    #[test]
    fn startup_guard_keeps_log_after_child_startup_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let layout = test_layout(temp.path().join("session"));
        fs::create_dir_all(&layout.runtime_dir)?;
        fs::write(&layout.config_path, "config")?;
        fs::write(&layout.socket_path, "socket")?;
        fs::write(&layout.log_path, "startup failed")?;

        let mut guard = ManagedStartupGuard::new(&layout);
        guard.keep_log();
        drop(guard);

        assert!(!layout.config_path.exists());
        assert!(!layout.socket_path.exists());
        assert!(layout.log_path.exists());
        assert!(layout.runtime_dir.exists());
        Ok(())
    }

    #[test]
    fn managed_agent_exit_message_includes_log_path_and_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let log_path = temp.path().join("agent.log");
        fs::write(&log_path, "first\nstartup failed\n")?;

        let message = managed_agent_exit_message(ExitStatusExt::from_raw(1 << 8), &log_path);

        assert!(message.contains("TUI managed agent exited"));
        assert!(message.contains(&log_path.display().to_string()));
        assert!(message.contains("startup failed"));
        Ok(())
    }

    fn test_layout(runtime_dir: PathBuf) -> ManagedRuntimeLayout {
        ManagedRuntimeLayout {
            config_path: runtime_dir.join("agent.toml"),
            socket_path: runtime_dir.join("admin.sock"),
            readiness_path: runtime_dir.join("ready.sock"),
            log_path: runtime_dir.join("agent.log"),
            runtime_dir,
        }
    }
}

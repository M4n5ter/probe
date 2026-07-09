use std::{
    fs::{self, File, OpenOptions},
    os::unix::{fs::OpenOptionsExt, net::UnixListener as StdUnixListener},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use probe_config::{
    AgentConfig, TransparentInterceptionMitmBackendConfig,
    TransparentInterceptionMitmBackendReadinessProbeConfig, probe_home_path,
};
use probe_core::CancellationToken;
use rustix::{
    fs::{FlockOperation, OFlags, flock},
    process::{Pid, Signal, kill_process, kill_process_group},
};
use tokio::{process::Command, time::Instant};

use super::{
    config_edit::TuiError,
    generated_resources::ensure_private_directory,
    log_tail::{DEFAULT_TAIL_BYTES, one_line_tail, read_text_tail},
    runtime_attachment::RuntimeAttachment,
};
use crate::admin::{AdminClientError, AdminRequest, send_admin_json_request_with_timeout};

const ADMIN_PROBE_TIMEOUT: Duration = Duration::from_millis(200);
const ADMIN_ATTACH_PROBE_ATTEMPTS: usize = 3;
const ADMIN_ATTACH_PROBE_DELAY: Duration = Duration::from_millis(200);
const ADMIN_SHUTDOWN_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const ADMIN_SHUTDOWN_GRACE_TIMEOUT: Duration = Duration::from_secs(5);
const SHARED_MANAGED_HEALTH_PROBE_INTERVAL: Duration = Duration::from_secs(1);
const MANAGED_AGENT_BASE_STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const MANAGED_AGENT_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const DATA_READY_SOCKET_ENV: &str = "TRAFFIC_PROBE_READY_SOCKET";
const CONTROL_READY_SOCKET_ENV: &str = "TRAFFIC_PROBE_CONTROL_READY_SOCKET";

#[derive(Debug)]
pub(crate) struct TuiAgentSupervisor {
    mode: TuiAgentMode,
}

#[derive(Debug)]
enum TuiAgentMode {
    Existing(ExistingAgent),
    SharedManaged(SharedManagedAgent),
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
struct SharedManagedAgent {
    boot_config_path: PathBuf,
    config_apply_lock_path: PathBuf,
    reload_dir: PathBuf,
    reload_candidate_path: PathBuf,
    socket_path: PathBuf,
    log_path: PathBuf,
    shutdown_on_stop: bool,
    last_probe: Option<Instant>,
}

impl Drop for SharedManagedAgent {
    fn drop(&mut self) {
        cleanup_shared_managed_agent_files(self);
    }
}

#[derive(Debug)]
struct ManagedChild {
    child: tokio::process::Child,
    terminate_on_drop: bool,
}

impl ManagedChild {
    fn new(child: tokio::process::Child) -> Self {
        Self {
            child,
            terminate_on_drop: true,
        }
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
        if !self.terminate_on_drop {
            return;
        }
        if matches!(self.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.signal(Signal::TERM);
        let _ = self.signal(Signal::KILL);
        let _ = self.child.start_kill();
    }

    fn detach(mut self) {
        self.terminate_on_drop = false;
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
        if matches!(
            probe_admin_socket_with_retries(&configured_socket_path).await,
            AdminSocketProbe::Responding
        ) {
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
            TuiAgentMode::SharedManaged(agent) => {
                RuntimeAttachment::managed(agent.socket_path.clone(), None, agent.log_path.clone())
            }
        }
    }

    pub(crate) fn is_managed(&self) -> bool {
        matches!(self.mode, TuiAgentMode::SharedManaged(_))
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
            TuiAgentMode::SharedManaged(agent) => {
                let runtime_config = managed_runtime_config(config, &agent.socket_path);
                replace_runtime_config(&runtime_config, &agent.reload_candidate_path)?;
                Ok(agent.reload_candidate_path.clone())
            }
        }
    }

    pub(crate) fn promote_config_reload_candidate(
        &self,
        candidate_path: &Path,
    ) -> Result<bool, TuiError> {
        match &self.mode {
            TuiAgentMode::Existing(_) => Ok(false),
            TuiAgentMode::SharedManaged(agent) => {
                if candidate_path != agent.reload_candidate_path {
                    return Err(TuiError::AgentSupervisor {
                        action: "promote TUI shared runtime config",
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "candidate path is not owned by this TUI session",
                        ),
                    });
                }
                promote_runtime_config_file(candidate_path, &agent.boot_config_path)?;
                Ok(true)
            }
        }
    }

    pub(crate) async fn acquire_config_apply_lock(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<TuiManagedConfigApplyLock>, TuiError> {
        match &self.mode {
            TuiAgentMode::Existing(_) => Ok(None),
            TuiAgentMode::SharedManaged(agent) => {
                TuiManagedConfigApplyLock::acquire(&agent.config_apply_lock_path, cancellation)
                    .await
                    .map(Some)
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
            TuiAgentMode::SharedManaged(agent) => {
                let layout = ManagedRuntimeLayout::create()?;
                let config_apply_lock = TuiManagedConfigApplyLock::acquire(
                    &layout.config_apply_lock_path,
                    &cancellation,
                )
                .await?;
                request_shared_managed_shutdown(&agent).await?;
                spawn_managed_agent_with_locked_config(
                    config,
                    cancellation,
                    layout,
                    &config_apply_lock,
                )
                .await
            }
        }
    }

    pub(crate) async fn poll_exit(&mut self) -> Result<Option<String>, TuiError> {
        match &mut self.mode {
            TuiAgentMode::SharedManaged(agent) => agent.poll_unavailable().await,
            TuiAgentMode::Existing(_) => Ok(None),
        }
    }

    pub(crate) async fn stop(self) -> Result<(), TuiError> {
        match self.mode {
            TuiAgentMode::Existing(agent) => {
                cleanup_existing_agent(agent);
                Ok(())
            }
            TuiAgentMode::SharedManaged(agent) => {
                if agent.shutdown_on_stop {
                    request_shared_managed_shutdown(&agent).await?;
                }
                Ok(())
            }
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

impl SharedManagedAgent {
    fn from_layout(
        layout: &ManagedRuntimeLayout,
        shutdown_on_stop: bool,
    ) -> Result<Self, TuiError> {
        let reload_dir = layout
            .runtime_dir
            .join("reload")
            .join(runtime_config_suffix());
        ensure_private_directory(&reload_dir)?;
        Ok(Self {
            boot_config_path: layout.config_path.clone(),
            config_apply_lock_path: layout.config_apply_lock_path.clone(),
            reload_candidate_path: reload_dir.join("agent.toml"),
            reload_dir,
            socket_path: layout.socket_path.clone(),
            log_path: layout.log_path.clone(),
            shutdown_on_stop,
            last_probe: None,
        })
    }

    async fn poll_unavailable(&mut self) -> Result<Option<String>, TuiError> {
        let now = Instant::now();
        if self.last_probe.is_some_and(|last_probe| {
            now.duration_since(last_probe) < SHARED_MANAGED_HEALTH_PROBE_INTERVAL
        }) {
            return Ok(None);
        }
        self.last_probe = Some(now);
        if admin_socket_responds(&self.socket_path).await {
            Ok(None)
        } else {
            Ok(Some(format!(
                "TUI managed agent admin socket {} stopped responding; log {}",
                self.socket_path.display(),
                self.log_path.display()
            )))
        }
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

fn cleanup_shared_managed_agent_files(agent: &SharedManagedAgent) {
    remove_runtime_file(&agent.reload_candidate_path, "TUI shared reload candidate");
    if let Err(error) = fs::remove_dir(&agent.reload_dir)
        && error.kind() != std::io::ErrorKind::NotFound
        && error.kind() != std::io::ErrorKind::DirectoryNotEmpty
    {
        eprintln!(
            "failed to remove TUI shared reload directory {}: {error}",
            agent.reload_dir.display()
        );
    }
}

async fn request_shared_managed_shutdown(agent: &SharedManagedAgent) -> Result<(), TuiError> {
    request_shared_managed_shutdown_path(&agent.socket_path).await
}

async fn request_shared_managed_shutdown_path(socket_path: &Path) -> Result<(), TuiError> {
    request_shared_managed_shutdown_path_with_grace(socket_path, ADMIN_SHUTDOWN_GRACE_TIMEOUT).await
}

async fn request_shared_managed_shutdown_path_with_grace(
    socket_path: &Path,
    grace_timeout: Duration,
) -> Result<(), TuiError> {
    let _ = send_admin_json_request_with_timeout(
        socket_path,
        AdminRequest::Shutdown,
        ADMIN_SHUTDOWN_REQUEST_TIMEOUT,
    )
    .await;
    let deadline = Instant::now() + grace_timeout;
    while Instant::now() < deadline {
        match probe_admin_socket_once(socket_path).await {
            AdminSocketProbe::Missing | AdminSocketProbe::Stale => return Ok(()),
            AdminSocketProbe::Responding | AdminSocketProbe::Unresponsive => {}
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(TuiError::ManagedAgentShutdownTimeout {
        socket_path: socket_path.display().to_string(),
    })
}

async fn spawn_managed_agent_with_cancellation(
    config: &AgentConfig,
    cancellation: CancellationToken,
) -> Result<TuiAgentSupervisor, TuiError> {
    let layout = ManagedRuntimeLayout::create()?;
    let config_apply_lock =
        TuiManagedConfigApplyLock::acquire(&layout.config_apply_lock_path, &cancellation).await?;
    spawn_managed_agent_with_locked_config(config, cancellation, layout, &config_apply_lock).await
}

async fn spawn_managed_agent_with_locked_config(
    config: &AgentConfig,
    cancellation: CancellationToken,
    layout: ManagedRuntimeLayout,
    _config_apply_lock: &TuiManagedConfigApplyLock,
) -> Result<TuiAgentSupervisor, TuiError> {
    let _startup_lock = ManagedStartupLock::acquire(&layout, &cancellation).await?;
    let startup_timeout = managed_agent_startup_timeout(config);
    match probe_admin_socket_with_retries(&layout.socket_path).await {
        AdminSocketProbe::Responding => {
            if shared_managed_runtime_matches(config, &layout)? {
                return Ok(TuiAgentSupervisor {
                    mode: TuiAgentMode::SharedManaged(SharedManagedAgent::from_layout(
                        &layout, false,
                    )?),
                });
            }
            request_shared_managed_shutdown_path(&layout.socket_path).await?;
        }
        AdminSocketProbe::Missing => {}
        AdminSocketProbe::Stale => {
            remove_runtime_file(&layout.socket_path, "stale TUI managed agent admin socket");
        }
        AdminSocketProbe::Unresponsive => {
            return Err(TuiError::ManagedAgentAdminUnresponsive {
                socket_path: layout.socket_path.display().to_string(),
            });
        }
    }
    let mut startup_guard = ManagedStartupGuard::new(&layout);
    let runtime_config = managed_runtime_config(config, &layout.socket_path);
    replace_runtime_config(&runtime_config, &layout.config_path)?;
    write_executable_fingerprint(&layout.fingerprint_path)?;
    let readiness_listener = bind_readiness_socket(&layout.readiness_path)?;
    let log = open_log_file(&layout.log_path)?;
    let mut command = Command::new(current_exe()?);
    command
        .arg("run")
        .arg("--config")
        .arg(&layout.config_path)
        .env(DATA_READY_SOCKET_ENV, &layout.readiness_path)
        .env_remove(CONTROL_READY_SOCKET_ENV)
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
        startup_timeout,
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
    child.detach();
    Ok(TuiAgentSupervisor {
        mode: TuiAgentMode::SharedManaged(SharedManagedAgent::from_layout(&layout, true)?),
    })
}

#[derive(Debug)]
struct ManagedRuntimeLayout {
    runtime_dir: PathBuf,
    config_path: PathBuf,
    fingerprint_path: PathBuf,
    config_apply_lock_path: PathBuf,
    socket_path: PathBuf,
    readiness_path: PathBuf,
    log_path: PathBuf,
}

impl ManagedRuntimeLayout {
    fn create() -> Result<Self, TuiError> {
        let runtime_dir = probe_home_path(PathBuf::from("run").join("tui").join("managed"));
        ensure_private_directory(&runtime_dir)?;
        Ok(Self {
            config_path: runtime_dir.join("agent.toml"),
            fingerprint_path: runtime_dir.join("executable.fingerprint"),
            config_apply_lock_path: runtime_dir.join("config-apply.lock"),
            socket_path: runtime_dir.join("admin.sock"),
            readiness_path: runtime_dir.join("ready.sock"),
            log_path: runtime_dir.join("agent.log"),
            runtime_dir,
        })
    }
}

struct ManagedStartupLock {
    file: File,
}

impl ManagedStartupLock {
    async fn acquire(
        layout: &ManagedRuntimeLayout,
        cancellation: &CancellationToken,
    ) -> Result<Self, TuiError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(TuiError::ManagedAgentStartupCancelled);
            }
            if let Some(lock) = Self::try_acquire(layout)? {
                return Ok(lock);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn try_acquire(layout: &ManagedRuntimeLayout) -> Result<Option<Self>, TuiError> {
        let lock_path = layout.runtime_dir.join("startup.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&lock_path)
            .map_err(|source| TuiError::AgentSupervisor {
                action: "open TUI managed agent startup lock",
                source,
            })?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(Self { file })),
            Err(source) => {
                let source = std::io::Error::from(source);
                if source.kind() == std::io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(TuiError::AgentSupervisor {
                        action: "lock TUI managed agent startup",
                        source,
                    })
                }
            }
        }
    }
}

impl Drop for ManagedStartupLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

pub(crate) struct TuiManagedConfigApplyLock {
    file: File,
}

impl TuiManagedConfigApplyLock {
    async fn acquire(path: &Path, cancellation: &CancellationToken) -> Result<Self, TuiError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(TuiError::ManagedAgentStartupCancelled);
            }
            if let Some(lock) = Self::try_acquire(path)? {
                return Ok(lock);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn try_acquire(path: &Path) -> Result<Option<Self>, TuiError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|source| TuiError::AgentSupervisor {
                action: "open TUI managed agent config apply lock",
                source,
            })?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(Self { file })),
            Err(source) => {
                let source = std::io::Error::from(source);
                if source.kind() == std::io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(TuiError::AgentSupervisor {
                        action: "lock TUI managed agent config apply",
                        source,
                    })
                }
            }
        }
    }
}

impl Drop for TuiManagedConfigApplyLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

#[derive(Debug)]
struct ManagedStartupGuard {
    runtime_dir: PathBuf,
    config_path: PathBuf,
    fingerprint_path: PathBuf,
    socket_path: PathBuf,
    remove_socket_on_drop: bool,
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
            fingerprint_path: layout.fingerprint_path.clone(),
            socket_path: layout.socket_path.clone(),
            remove_socket_on_drop: !layout.socket_path.exists(),
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
        remove_runtime_file(
            &self.fingerprint_path,
            "TUI managed agent executable fingerprint",
        );
        if self.remove_socket_on_drop {
            remove_runtime_file(&self.socket_path, "TUI managed agent admin socket");
        }
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

fn shared_managed_runtime_matches(
    config: &AgentConfig,
    layout: &ManagedRuntimeLayout,
) -> Result<bool, TuiError> {
    Ok(runtime_config_matches(config, layout)? && executable_fingerprint_matches(layout)?)
}

fn runtime_config_matches(
    config: &AgentConfig,
    layout: &ManagedRuntimeLayout,
) -> Result<bool, TuiError> {
    let expected = toml::to_string(&managed_runtime_config(config, &layout.socket_path))?;
    let actual =
        match fs::read_to_string(&layout.config_path).map_err(|source| TuiError::AgentSupervisor {
            action: "read TUI managed agent runtime config",
            source,
        }) {
            Ok(actual) => actual,
            Err(TuiError::AgentSupervisor { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
    Ok(actual == expected)
}

fn executable_fingerprint_matches(layout: &ManagedRuntimeLayout) -> Result<bool, TuiError> {
    let expected = current_executable_fingerprint()?;
    let actual = match fs::read_to_string(&layout.fingerprint_path).map_err(|source| {
        TuiError::AgentSupervisor {
            action: "read TUI managed agent executable fingerprint",
            source,
        }
    }) {
        Ok(actual) => actual,
        Err(TuiError::AgentSupervisor { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    Ok(actual == expected)
}

fn current_exe() -> Result<PathBuf, TuiError> {
    std::env::current_exe().map_err(|source| TuiError::AgentSupervisor {
        action: "resolve current executable",
        source,
    })
}

fn current_executable_fingerprint() -> Result<String, TuiError> {
    let path = current_exe()?;
    let metadata = fs::metadata(&path).map_err(|source| TuiError::AgentSupervisor {
        action: "read current executable metadata",
        source,
    })?;
    let modified_unix_ns = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|| "-".to_string());
    Ok(format!(
        "path={}\nlen={}\nmodified_unix_ns={modified_unix_ns}\n",
        path.display(),
        metadata.len()
    ))
}

fn write_executable_fingerprint(path: &Path) -> Result<(), TuiError> {
    write_private_text_file(
        path,
        &current_executable_fingerprint()?,
        "write TUI managed agent executable fingerprint",
    )
}

fn replace_runtime_config(config: &AgentConfig, path: &Path) -> Result<(), TuiError> {
    let body = toml::to_string(config)?;
    write_private_text_file(path, &body, "replace TUI runtime config")
}

fn promote_runtime_config_file(
    candidate_path: &Path,
    boot_config_path: &Path,
) -> Result<(), TuiError> {
    let body = fs::read_to_string(candidate_path).map_err(|source| TuiError::AgentSupervisor {
        action: "read TUI shared runtime reload candidate",
        source,
    })?;
    write_private_text_file(boot_config_path, &body, "promote TUI shared runtime config")
}

fn write_private_text_file(path: &Path, body: &str, action: &'static str) -> Result<(), TuiError> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|source| TuiError::AgentSupervisor { action, source })?;
    use std::io::Write as _;
    file.write_all(body.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| TuiError::AgentSupervisor { action, source })
}

fn open_log_file(path: &Path) -> Result<File, TuiError> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| TuiError::AgentSupervisor {
            action: "create TUI managed agent log",
            source,
        })
}

fn bind_readiness_socket(path: &Path) -> Result<StdUnixListener, TuiError> {
    remove_runtime_file(path, "stale TUI managed agent readiness socket");
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

fn managed_agent_startup_timeout(config: &AgentConfig) -> Duration {
    MANAGED_AGENT_BASE_STARTUP_TIMEOUT
        .saturating_add(managed_mitm_backend_readiness_budget(config).unwrap_or(Duration::ZERO))
}

fn managed_mitm_backend_readiness_budget(config: &AgentConfig) -> Option<Duration> {
    match &config.enforcement.interception.mitm.backend {
        TransparentInterceptionMitmBackendConfig::ManagedProcess {
            readiness_probe, ..
        }
        | TransparentInterceptionMitmBackendConfig::ProductProxy {
            readiness_probe, ..
        } => Some(readiness_probe_budget(readiness_probe)),
        TransparentInterceptionMitmBackendConfig::Disabled
        | TransparentInterceptionMitmBackendConfig::External { .. } => None,
    }
}

fn readiness_probe_budget(
    readiness_probe: &TransparentInterceptionMitmBackendReadinessProbeConfig,
) -> Duration {
    let attempts = readiness_probe.failure_threshold;
    let attempt_timeouts =
        Duration::from_millis(readiness_probe.timeout_ms).saturating_mul(attempts);
    let sleeps = Duration::from_millis(readiness_probe.interval_ms)
        .saturating_mul(attempts.saturating_sub(1));
    attempt_timeouts.saturating_add(sleeps)
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
    startup_timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<(), TuiError> {
    let deadline = Instant::now() + startup_timeout;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminSocketProbe {
    Responding,
    Missing,
    Stale,
    Unresponsive,
}

async fn probe_admin_socket_with_retries(socket_path: &Path) -> AdminSocketProbe {
    let mut last = AdminSocketProbe::Missing;
    for attempt in 0..ADMIN_ATTACH_PROBE_ATTEMPTS {
        let state = probe_admin_socket_once(socket_path).await;
        match state {
            AdminSocketProbe::Responding | AdminSocketProbe::Missing | AdminSocketProbe::Stale => {
                return state;
            }
            AdminSocketProbe::Unresponsive => {
                last = state;
                if attempt + 1 < ADMIN_ATTACH_PROBE_ATTEMPTS {
                    tokio::time::sleep(ADMIN_ATTACH_PROBE_DELAY).await;
                }
            }
        }
    }
    last
}

async fn admin_socket_responds(socket_path: &Path) -> bool {
    probe_admin_socket_once(socket_path).await == AdminSocketProbe::Responding
}

async fn probe_admin_socket_once(socket_path: &Path) -> AdminSocketProbe {
    match send_admin_json_request_with_timeout(socket_path, AdminRequest::Ping, ADMIN_PROBE_TIMEOUT)
        .await
    {
        Ok(response)
            if response.get("kind").and_then(serde_json::Value::as_str) == Some("pong") =>
        {
            AdminSocketProbe::Responding
        }
        Ok(_) => AdminSocketProbe::Unresponsive,
        Err(AdminClientError::Connect { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            AdminSocketProbe::Missing
        }
        Err(AdminClientError::Connect { source, .. })
            if source.kind() == std::io::ErrorKind::ConnectionRefused =>
        {
            AdminSocketProbe::Stale
        }
        Err(_) => AdminSocketProbe::Unresponsive,
    }
}

fn managed_startup_log_tail(log_path: &Path) -> String {
    read_text_tail(log_path, DEFAULT_TAIL_BYTES)
        .map(|tail| one_line_tail(&tail, 4))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn shared_managed_config_reload_candidate_uses_projected_runtime_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let runtime_config_path = temp.path().join("boot-agent.toml");
        let reload_dir = temp.path().join("reload");
        fs::create_dir_all(&reload_dir)?;
        let reload_candidate_path = reload_dir.join("agent.toml");
        let socket_path = temp.path().join("admin.sock");
        fs::write(&runtime_config_path, "stale")?;
        let supervisor = TuiAgentSupervisor {
            mode: TuiAgentMode::SharedManaged(SharedManagedAgent {
                boot_config_path: runtime_config_path.clone(),
                config_apply_lock_path: temp.path().join("config-apply.lock"),
                reload_dir: reload_dir.clone(),
                reload_candidate_path: reload_candidate_path.clone(),
                socket_path: socket_path.clone(),
                log_path: temp.path().join("agent.log"),
                shutdown_on_stop: false,
                last_probe: None,
            }),
        };
        let mut config = AgentConfig::default();
        config.admin.enabled = false;
        config.admin.socket_path = PathBuf::from("/tmp/user-admin.sock");
        config.runtime_reload.watch_config = true;

        let candidate_path = supervisor.prepare_config_reload_candidate(&config)?;

        assert_eq!(candidate_path, reload_candidate_path);
        assert_ne!(candidate_path, runtime_config_path);
        assert_eq!(fs::read_to_string(&runtime_config_path)?, "stale");
        assert!(config.runtime_reload.watch_config);
        assert_eq!(
            config.admin.socket_path,
            PathBuf::from("/tmp/user-admin.sock")
        );
        let written = AgentConfig::from_toml_str(&fs::read_to_string(&candidate_path)?)?;
        assert!(written.admin.enabled);
        assert_eq!(written.admin.socket_path, socket_path);
        assert!(!written.runtime_reload.watch_config);
        assert!(supervisor.promote_config_reload_candidate(&candidate_path)?);
        let promoted = AgentConfig::from_toml_str(&fs::read_to_string(&runtime_config_path)?)?;
        assert_eq!(promoted, written);
        Ok(())
    }

    #[test]
    fn shared_managed_attachment_uses_shared_socket_without_owned_pid() {
        let temp = tempfile::tempdir().expect("temp dir");
        let reload_dir = temp.path().join("reload");
        let socket_path = temp.path().join("admin.sock");
        let log_path = temp.path().join("agent.log");
        let supervisor = TuiAgentSupervisor {
            mode: TuiAgentMode::SharedManaged(SharedManagedAgent {
                boot_config_path: temp.path().join("agent.toml"),
                config_apply_lock_path: temp.path().join("config-apply.lock"),
                reload_dir: reload_dir.clone(),
                reload_candidate_path: reload_dir.join("agent.toml"),
                socket_path: socket_path.clone(),
                log_path: log_path.clone(),
                shutdown_on_stop: false,
                last_probe: None,
            }),
        };

        let attachment = supervisor.attachment(&AgentConfig::default());

        assert_eq!(
            attachment,
            RuntimeAttachment::managed(socket_path, None, log_path)
        );
    }

    #[test]
    fn managed_agent_startup_timeout_honors_managed_mitm_readiness_budget() {
        let mut config = AgentConfig::default();
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::managed_process(
                slow_readiness_probe(),
                Default::default(),
            );

        assert_eq!(
            managed_agent_startup_timeout(&config),
            MANAGED_AGENT_BASE_STARTUP_TIMEOUT.saturating_add(slow_readiness_budget())
        );
    }

    #[test]
    fn managed_agent_startup_timeout_honors_product_proxy_readiness_budget() {
        let mut config = AgentConfig::default();
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::product_proxy(
                slow_readiness_probe(),
                Default::default(),
            );

        assert_eq!(
            managed_agent_startup_timeout(&config),
            MANAGED_AGENT_BASE_STARTUP_TIMEOUT.saturating_add(slow_readiness_budget())
        );
    }

    #[test]
    fn managed_agent_startup_timeout_does_not_wait_for_external_mitm_health_probe() {
        let mut config = AgentConfig::default();
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(slow_readiness_probe());

        assert_eq!(
            managed_agent_startup_timeout(&config),
            MANAGED_AGENT_BASE_STARTUP_TIMEOUT
        );
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

    #[tokio::test]
    async fn admin_socket_probe_distinguishes_missing_stale_and_unresponsive()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let missing_path = temp.path().join("missing.sock");
        assert_eq!(
            probe_admin_socket_once(&missing_path).await,
            AdminSocketProbe::Missing
        );

        let stale_path = temp.path().join("stale.sock");
        drop(tokio::net::UnixListener::bind(&stale_path)?);
        assert_eq!(
            probe_admin_socket_once(&stale_path).await,
            AdminSocketProbe::Stale
        );

        let unresponsive_path = temp.path().join("unresponsive.sock");
        let listener = tokio::net::UnixListener::bind(&unresponsive_path)?;
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept admin probe");
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert_eq!(
            probe_admin_socket_once(&unresponsive_path).await,
            AdminSocketProbe::Unresponsive
        );
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn shared_shutdown_times_out_while_socket_keeps_responding()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let server = spawn_persistent_admin_test_server(socket_path.clone())?;

        let error = request_shared_managed_shutdown_path_with_grace(
            &socket_path,
            Duration::from_millis(50),
        )
        .await
        .expect_err("responding admin socket should time out shutdown wait");

        assert!(matches!(
            error,
            TuiError::ManagedAgentShutdownTimeout { socket_path: _ }
        ));
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn stop_requests_shared_managed_shutdown_and_cleans_session_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept shutdown request");
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let mut request = String::new();
            {
                let mut reader = BufReader::new(&mut stream);
                reader
                    .read_line(&mut request)
                    .await
                    .expect("read shutdown request");
            }
            let request: serde_json::Value =
                serde_json::from_str(&request).expect("shutdown request should be JSON");
            assert_eq!(request["command"], "shutdown");
            stream
                .write_all(b"{\"kind\":\"shutdown\",\"requested\":true}\n")
                .await
                .expect("write shutdown response");
        });
        let reload_dir = temp.path().join("reload");
        fs::create_dir_all(&reload_dir)?;
        let reload_candidate_path = reload_dir.join("agent.toml");
        fs::write(&reload_candidate_path, "reload")?;
        let supervisor = TuiAgentSupervisor {
            mode: TuiAgentMode::SharedManaged(SharedManagedAgent {
                boot_config_path: temp.path().join("boot-agent.toml"),
                config_apply_lock_path: temp.path().join("config-apply.lock"),
                reload_dir: reload_dir.clone(),
                reload_candidate_path: reload_candidate_path.clone(),
                socket_path,
                log_path: temp.path().join("agent.log"),
                shutdown_on_stop: true,
                last_probe: None,
            }),
        };

        supervisor.stop().await?;
        server.await?;

        assert!(!reload_candidate_path.exists());
        assert!(!reload_dir.exists());
        Ok(())
    }

    #[tokio::test]
    async fn stop_keeps_attached_shared_managed_runtime_running()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let server = spawn_persistent_admin_test_server(socket_path.clone())?;
        let reload_dir = temp.path().join("reload");
        fs::create_dir_all(&reload_dir)?;
        let reload_candidate_path = reload_dir.join("agent.toml");
        fs::write(&reload_candidate_path, "reload")?;
        let supervisor = TuiAgentSupervisor {
            mode: TuiAgentMode::SharedManaged(SharedManagedAgent {
                boot_config_path: temp.path().join("boot-agent.toml"),
                config_apply_lock_path: temp.path().join("config-apply.lock"),
                reload_dir: reload_dir.clone(),
                reload_candidate_path: reload_candidate_path.clone(),
                socket_path: socket_path.clone(),
                log_path: temp.path().join("agent.log"),
                shutdown_on_stop: false,
                last_probe: None,
            }),
        };

        supervisor.stop().await?;

        assert!(admin_socket_responds(&socket_path).await);
        assert!(!reload_candidate_path.exists());
        assert!(!reload_dir.exists());
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn startup_lock_acquire_observes_cancellation() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let layout = test_layout(temp.path().join("managed"));
        fs::create_dir_all(&layout.runtime_dir)?;
        let _held = ManagedStartupLock::try_acquire(&layout)?.expect("first lock should be held");
        let cancellation = CancellationToken::new();
        let task_layout = test_layout(layout.runtime_dir.clone());
        let task_cancellation = cancellation.clone();
        let acquire = tokio::spawn(async move {
            ManagedStartupLock::acquire(&task_layout, &task_cancellation).await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        cancellation.cancel();
        let result = acquire.await?;

        assert!(matches!(
            result,
            Err(TuiError::ManagedAgentStartupCancelled)
        ));
        Ok(())
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
        let guard = ManagedStartupGuard::new(&layout);
        fs::write(&layout.config_path, "config")?;
        fs::write(&layout.fingerprint_path, "fingerprint")?;
        fs::write(&layout.socket_path, "socket")?;
        fs::write(&layout.log_path, "log")?;

        drop(guard);

        assert!(!layout.config_path.exists());
        assert!(!layout.fingerprint_path.exists());
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
        let mut guard = ManagedStartupGuard::new(&layout);
        fs::write(&layout.config_path, "config")?;
        fs::write(&layout.fingerprint_path, "fingerprint")?;
        fs::write(&layout.socket_path, "socket")?;
        fs::write(&layout.log_path, "startup failed")?;

        guard.keep_log();
        drop(guard);

        assert!(!layout.config_path.exists());
        assert!(!layout.fingerprint_path.exists());
        assert!(!layout.socket_path.exists());
        assert!(layout.log_path.exists());
        assert!(layout.runtime_dir.exists());
        Ok(())
    }

    #[test]
    fn startup_guard_preserves_preexisting_admin_socket() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let layout = test_layout(temp.path().join("session"));
        fs::create_dir_all(&layout.runtime_dir)?;
        fs::write(&layout.socket_path, "preexisting socket")?;

        drop(ManagedStartupGuard::new(&layout));

        assert!(layout.socket_path.exists());
        Ok(())
    }

    #[test]
    fn shared_runtime_match_requires_boot_config_and_current_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let layout = test_layout(temp.path().join("managed"));
        fs::create_dir_all(&layout.runtime_dir)?;
        let mut config = AgentConfig::default();
        config.admin.enabled = false;
        config.admin.socket_path = PathBuf::from("/tmp/user-admin.sock");
        config.runtime_reload.watch_config = true;

        replace_runtime_config(
            &managed_runtime_config(&config, &layout.socket_path),
            &layout.config_path,
        )?;
        write_executable_fingerprint(&layout.fingerprint_path)?;

        assert!(shared_managed_runtime_matches(&config, &layout)?);
        fs::write(&layout.config_path, "stale")?;
        assert!(!shared_managed_runtime_matches(&config, &layout)?);
        replace_runtime_config(
            &managed_runtime_config(&config, &layout.socket_path),
            &layout.config_path,
        )?;
        fs::write(&layout.fingerprint_path, "stale")?;
        assert!(!shared_managed_runtime_matches(&config, &layout)?);
        Ok(())
    }

    fn spawn_persistent_admin_test_server(
        socket_path: PathBuf,
    ) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        Ok(tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                    let mut request = String::new();
                    {
                        let mut reader = BufReader::new(&mut stream);
                        if reader.read_line(&mut request).await.is_err() {
                            return;
                        }
                    }
                    let Ok(request) = serde_json::from_str::<serde_json::Value>(&request) else {
                        return;
                    };
                    let response = if request.get("command").and_then(serde_json::Value::as_str)
                        == Some("ping")
                    {
                        b"{\"kind\":\"pong\"}\n".as_slice()
                    } else {
                        b"{\"kind\":\"ok\"}\n".as_slice()
                    };
                    let _ = stream.write_all(response).await;
                });
            }
        }))
    }

    fn test_layout(runtime_dir: PathBuf) -> ManagedRuntimeLayout {
        ManagedRuntimeLayout {
            config_path: runtime_dir.join("agent.toml"),
            fingerprint_path: runtime_dir.join("executable.fingerprint"),
            config_apply_lock_path: runtime_dir.join("config-apply.lock"),
            socket_path: runtime_dir.join("admin.sock"),
            readiness_path: runtime_dir.join("ready.sock"),
            log_path: runtime_dir.join("agent.log"),
            runtime_dir,
        }
    }

    fn slow_readiness_probe() -> TransparentInterceptionMitmBackendReadinessProbeConfig {
        TransparentInterceptionMitmBackendReadinessProbeConfig {
            target: Some("127.0.0.1:15002".to_string()),
            interval_ms: 60_000,
            timeout_ms: 5_000,
            failure_threshold: 3,
        }
    }

    fn slow_readiness_budget() -> Duration {
        Duration::from_millis((5_000 * 3) + (60_000 * 2))
    }
}

use std::{
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use runtime::{
    TransparentInterceptionMitmBackendPlan, TransparentInterceptionMitmManagedProcessPlan,
};
use rustix::{
    io::Errno,
    process::{Pid, Signal, kill_process_group},
};

use super::{
    L7MitmBackendHealthProbeGuard,
    backend::{L7MitmBackendHealthProbe, backend_health_probe, connect_tcp},
    listener_owner::require_listener_owned_by_process_group,
    state::L7MitmRuntimeHandle,
};
use crate::{
    shutdown,
    tcp_health::{start_tcp_health_probe, tcp_connect_failure_reason},
};

const MANAGED_BACKEND_STOP_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct L7MitmBackendLifecycleGuard {
    health_probe: Option<L7MitmBackendHealthProbeGuard>,
    managed_process: Option<L7MitmManagedProcessGuard>,
}

pub(crate) fn start_backend_lifecycle(
    backend: &TransparentInterceptionMitmBackendPlan,
    runtime: L7MitmRuntimeHandle,
    shutdown_requested: &shutdown::ShutdownFlag,
) -> Result<Option<L7MitmBackendLifecycleGuard>, String> {
    match backend {
        TransparentInterceptionMitmBackendPlan::External { .. } => Ok(external(
            runtime,
            backend_health_probe(backend).expect("external MITM backend should have health probe"),
        )),
        TransparentInterceptionMitmBackendPlan::ManagedProcess { process, .. } => managed_process(
            process.clone(),
            backend_health_probe(backend)
                .expect("managed MITM backend should have readiness probe"),
            runtime,
            shutdown_requested,
        )
        .map(Some),
        TransparentInterceptionMitmBackendPlan::Disabled => Ok(None),
    }
}

impl L7MitmBackendLifecycleGuard {
    pub(crate) fn stop(mut self) -> Result<(), String> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), String> {
        let health_result = match self.health_probe.take() {
            Some(health_probe) => health_probe.stop(),
            None => Ok(()),
        };
        let managed_result = match self.managed_process.take() {
            Some(managed_process) => managed_process.stop(),
            None => Ok(()),
        };
        health_result.and(managed_result)
    }
}

impl Drop for L7MitmBackendLifecycleGuard {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

fn external(
    runtime: L7MitmRuntimeHandle,
    health_probe_plan: L7MitmBackendHealthProbe,
) -> Option<L7MitmBackendLifecycleGuard> {
    let health_probe = start_tcp_health_probe(
        Some(health_probe_plan.into_plan()),
        runtime,
        || Ok(()),
        "L7 MITM backend health probe thread panicked",
    );
    health_probe.map(|health_probe| L7MitmBackendLifecycleGuard {
        health_probe: Some(health_probe),
        managed_process: None,
    })
}

fn managed_process(
    process: TransparentInterceptionMitmManagedProcessPlan,
    readiness_probe: L7MitmBackendHealthProbe,
    runtime: L7MitmRuntimeHandle,
    shutdown_requested: &shutdown::ShutdownFlag,
) -> Result<L7MitmBackendLifecycleGuard, String> {
    let managed_process = L7MitmManagedProcessGuard::spawn(process)?;
    if let Err(error) = wait_for_managed_process_readiness(
        &managed_process.child,
        managed_process.process_group,
        &readiness_probe,
        &runtime,
        shutdown_requested,
    ) {
        let cleanup_result = managed_process.stop_after_start_failure();
        return match cleanup_result {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!("{error}; cleanup failed: {cleanup_error}")),
        };
    }

    let child = Arc::clone(&managed_process.child);
    let process_group = managed_process.process_group;
    let target = readiness_probe.target;
    let health_probe = start_tcp_health_probe(
        Some(readiness_probe.into_plan()),
        runtime,
        move || ensure_managed_process_owns_readiness_listener(&child, process_group, target),
        "L7 MITM managed backend health probe thread panicked",
    );
    Ok(L7MitmBackendLifecycleGuard {
        health_probe,
        managed_process: Some(managed_process),
    })
}

struct L7MitmManagedProcessGuard {
    child: Arc<Mutex<Child>>,
    process_group: Pid,
    cleanup_complete: bool,
}

impl L7MitmManagedProcessGuard {
    fn spawn(process: TransparentInterceptionMitmManagedProcessPlan) -> Result<Self, String> {
        let mut command = Command::new(&process.program);
        command
            .args(&process.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        if let Some(working_dir) = &process.working_dir {
            command.current_dir(working_dir);
        }
        let child = command.spawn().map_err(|error| {
            format!(
                "failed to spawn managed L7 MITM backend {}: {error}",
                process.program.display()
            )
        })?;
        let process_group = Pid::from_child(&child);
        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            process_group,
            cleanup_complete: false,
        })
    }

    fn stop(mut self) -> Result<(), String> {
        let result = self.stop_for_shutdown();
        if result.is_ok() {
            self.cleanup_complete = true;
        }
        result
    }

    fn stop_after_start_failure(mut self) -> Result<(), String> {
        let result = self.force_stop();
        if result.is_ok() {
            self.cleanup_complete = true;
        }
        result
    }

    fn stop_for_shutdown(&mut self) -> Result<(), String> {
        let mut child = lock_managed_child(&self.child)?;
        if let Some(status) = poll_managed_child(&mut child)? {
            let cleanup_result =
                terminate_process_group_allow_missing(self.process_group, Signal::KILL);
            return match cleanup_result {
                Ok(()) => Err(format!(
                    "managed L7 MITM backend exited before agent shutdown: {status}"
                )),
                Err(cleanup_error) => Err(format!(
                    "managed L7 MITM backend exited before agent shutdown: {status}; cleanup failed: {cleanup_error}"
                )),
            };
        }

        terminate_process_group_allow_missing(self.process_group, Signal::TERM)?;
        match wait_for_managed_process_exit(&mut child, MANAGED_BACKEND_STOP_TIMEOUT)? {
            Some(_status) => Ok(()),
            None => {
                terminate_process_group_allow_missing(self.process_group, Signal::KILL)?;
                child
                    .wait()
                    .map_err(|error| format!("failed to reap managed L7 MITM backend: {error}"))?;
                Ok(())
            }
        }
    }

    fn force_stop(&mut self) -> Result<(), String> {
        let mut child = lock_managed_child(&self.child)?;
        let already_exited = poll_managed_child(&mut child)?.is_some();
        terminate_process_group_allow_missing(self.process_group, Signal::KILL)?;
        if !already_exited {
            child
                .wait()
                .map_err(|error| format!("failed to reap managed L7 MITM backend: {error}"))?;
        }
        Ok(())
    }
}

impl Drop for L7MitmManagedProcessGuard {
    fn drop(&mut self) {
        if !self.cleanup_complete {
            let _ = self.force_stop();
            self.cleanup_complete = true;
        }
    }
}

fn wait_for_managed_process_readiness(
    child: &Arc<Mutex<Child>>,
    process_group: Pid,
    readiness_probe: &L7MitmBackendHealthProbe,
    runtime: &L7MitmRuntimeHandle,
    shutdown_requested: &shutdown::ShutdownFlag,
) -> Result<(), String> {
    let mut last_failure = "readiness probe was not attempted".to_string();
    for attempt in 0..readiness_probe.failure_threshold {
        if shutdown::requested(shutdown_requested) {
            return Err(
                "managed L7 MITM backend readiness cancelled by shutdown request".to_string(),
            );
        }
        if let Err(error) = ensure_managed_process_owns_readiness_listener(
            child,
            process_group,
            readiness_probe.target,
        ) {
            last_failure = error;
            runtime.record_backend_health_failure(last_failure.clone());
        } else {
            match connect_tcp(readiness_probe.target, readiness_probe.timeout) {
                Ok(()) => {
                    runtime.record_backend_health_success();
                    return Ok(());
                }
                Err(error) => {
                    last_failure = tcp_connect_failure_reason(&error);
                    runtime.record_backend_health_failure(last_failure.clone());
                }
            }
        }
        if attempt + 1 < readiness_probe.failure_threshold {
            sleep_until_next_readiness_attempt(readiness_probe.interval, shutdown_requested)?;
        }
    }
    Err(format!(
        "managed L7 MITM backend readiness probe failed for {} after {} attempt(s): {}",
        readiness_probe.target, readiness_probe.failure_threshold, last_failure
    ))
}

fn sleep_until_next_readiness_attempt(
    interval: Duration,
    shutdown_requested: &shutdown::ShutdownFlag,
) -> Result<(), String> {
    let mut remaining = interval;
    while !remaining.is_zero() {
        if shutdown::requested(shutdown_requested) {
            return Err(
                "managed L7 MITM backend readiness cancelled by shutdown request".to_string(),
            );
        }
        let sleep_for = remaining.min(Duration::from_millis(20));
        thread::sleep(sleep_for);
        remaining = remaining.saturating_sub(sleep_for);
    }
    Ok(())
}

fn ensure_managed_process_is_running(child: &Arc<Mutex<Child>>) -> Result<(), String> {
    let mut child = lock_managed_child(child)?;
    match poll_managed_child(&mut child)? {
        Some(status) => Err(format!("managed L7 MITM backend exited: {status}")),
        None => Ok(()),
    }
}

fn ensure_managed_process_owns_readiness_listener(
    child: &Arc<Mutex<Child>>,
    process_group: Pid,
    target: std::net::SocketAddr,
) -> Result<(), String> {
    ensure_managed_process_is_running(child)?;
    require_listener_owned_by_process_group(target, process_group)
}

fn poll_managed_child(child: &mut Child) -> Result<Option<ExitStatus>, String> {
    child
        .try_wait()
        .map_err(|error| format!("failed to poll managed L7 MITM backend: {error}"))
}

fn wait_for_managed_process_exit(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<ExitStatus>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = poll_managed_child(child)? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn terminate_process_group_allow_missing(process_group: Pid, signal: Signal) -> Result<(), String> {
    match kill_process_group(process_group, signal) {
        Ok(()) => Ok(()),
        Err(error) if error == Errno::SRCH => Ok(()),
        Err(error) => Err(format!(
            "failed to send {signal:?} to managed L7 MITM backend process group {}: {error}",
            process_group.as_raw_pid()
        )),
    }
}

fn lock_managed_child(
    child: &Arc<Mutex<Child>>,
) -> Result<std::sync::MutexGuard<'_, Child>, String> {
    child
        .lock()
        .map_err(|_| "managed L7 MITM backend child state is poisoned".to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        fs, io,
        net::TcpListener,
        path::{Path, PathBuf},
        process::Command,
    };

    use probe_config::{
        AgentConfig, TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmManagedProcessConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};
    use runtime::{
        TransparentInterceptionMitmBackendPlan,
        TransparentInterceptionMitmBackendReadinessProbePlan, TransparentInterceptionMitmPlan,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::l7_mitm::{
        L7MitmBackendHealthMode, L7MitmBackendHealthSnapshot, L7MitmPlaintextBridgeSnapshot,
        L7MitmRuntime, backend::resolve_with_probe,
    };

    #[test]
    fn managed_process_backend_starts_waits_for_readiness_and_stops()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture_dir = tempdir()?;
        let backend_fixture = compile_managed_mitm_backend_fixture(fixture_dir.path())?;
        let target = closed_loopback_target()?;
        let mut config =
            managed_mitm_config(target.to_string(), &backend_fixture, [target.to_string()]);
        let readiness_probe = managed_backend_readiness(&mut config);
        readiness_probe.interval_ms = 100;
        readiness_probe.timeout_ms = 10;
        readiness_probe.failure_threshold = 20;

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            panic!("managed backend readiness must run after the process is spawned")
        });
        let shutdown = crate::shutdown::new_flag();
        let guard = start_configured_backend_lifecycle(&runtime, &config, &shutdown)
            .map_err(io::Error::other)?
            .expect("managed backend lifecycle should start");

        let health = runtime.handle().snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Healthy);
        assert_eq!(health.check_successes, 1);
        guard.stop().map_err(io::Error::other)?;
        Ok(())
    }

    #[test]
    fn managed_process_backend_fails_closed_when_backend_never_becomes_ready() {
        let mut config = managed_mitm_config(
            "127.0.0.1:15002",
            Path::new("/bin/true"),
            std::iter::empty::<String>(),
        );
        managed_backend_readiness(&mut config).failure_threshold = 1;

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            panic!("managed backend readiness must run after the process is spawned")
        });
        let shutdown = crate::shutdown::new_flag();
        let error = match start_configured_backend_lifecycle(&runtime, &config, &shutdown) {
            Ok(_) => panic!("exited managed backend must not start"),
            Err(error) => error,
        };

        assert!(
            error.contains("readiness probe failed")
                || error.contains("managed L7 MITM backend exited"),
            "{error}"
        );
    }

    #[test]
    fn managed_process_backend_rejects_unrelated_readiness_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let target = listener.local_addr()?;
        let sleep = fs::canonicalize("/bin/sleep")?;
        let mut config = managed_mitm_config(target.to_string(), sleep, ["30".to_string()]);
        managed_backend_readiness(&mut config).failure_threshold = 1;

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            panic!("managed backend readiness must run after the process is spawned")
        });
        let shutdown = crate::shutdown::new_flag();
        let error = match start_configured_backend_lifecycle(&runtime, &config, &shutdown) {
            Ok(_) => panic!("unrelated readiness listener must not satisfy managed backend"),
            Err(error) => error,
        };

        assert!(error.contains("not exclusively owned"), "{error}");
        drop(listener);
        Ok(())
    }

    #[test]
    fn managed_process_readiness_stops_when_shutdown_is_requested() {
        let mut config = managed_mitm_config(
            "127.0.0.1:15002",
            Path::new("/bin/sleep"),
            ["30".to_string()],
        );
        let readiness_probe = managed_backend_readiness(&mut config);
        readiness_probe.interval_ms = 60_000;
        readiness_probe.failure_threshold = 100;

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            panic!("managed backend readiness must run after the process is spawned")
        });
        let shutdown = crate::shutdown::new_flag();
        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

        let error = match start_configured_backend_lifecycle(&runtime, &config, &shutdown) {
            Ok(_) => panic!("shutdown should cancel managed backend readiness"),
            Err(error) => error,
        };
        assert!(error.contains("cancelled by shutdown request"), "{error}");
    }

    #[test]
    fn managed_process_start_failure_cleans_forked_descendants()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = closed_loopback_target()?;
        let readiness_target = std::net::SocketAddr::new("127.0.0.2".parse()?, target.port());
        let dir = tempdir()?;
        let pid_file = dir.path().join("forked.pid");
        let command = format!(
            "sleep 30 & echo $! > {}; exit 0",
            shell_quote(&pid_file.display().to_string())
        );
        let shell = fs::canonicalize("/bin/sh")?;
        let mut config = managed_mitm_config(
            readiness_target.to_string(),
            &shell,
            ["-c".to_string(), command],
        );
        let readiness_probe = managed_backend_readiness(&mut config);
        readiness_probe.interval_ms = 100;
        readiness_probe.timeout_ms = 10;
        readiness_probe.failure_threshold = 2;

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            panic!("managed backend readiness must run after the process is spawned")
        });
        let shutdown = crate::shutdown::new_flag();
        let error = match start_configured_backend_lifecycle(&runtime, &config, &shutdown) {
            Ok(_) => panic!("forking backend without readiness must not start"),
            Err(error) => error,
        };
        assert!(
            error.contains("readiness probe failed")
                || error.contains("managed L7 MITM backend exited"),
            "{error}"
        );

        let forked_pid = fs::read_to_string(&pid_file)?
            .trim()
            .parse::<u32>()
            .expect("forked test process pid should parse");
        wait_until(Duration::from_secs(2), || {
            !PathBuf::from(format!("/proc/{forked_pid}")).exists()
        })?;
        Ok(())
    }

    #[test]
    fn backend_health_probe_thread_records_checks_and_stops()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = closed_loopback_target()?;
        let handle = L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            1,
        );
        let backend = TransparentInterceptionMitmBackendPlan::External {
            readiness_probe: TransparentInterceptionMitmBackendReadinessProbePlan::TcpConnect {
                target,
                interval_ms: 5,
                timeout_ms: 10,
                failure_threshold: 1,
            },
        };
        let runtime = L7MitmRuntime {
            capability: CapabilityState {
                kind: CapabilityKind::L7Mitm,
                mode: RuntimeMode::Available,
                reason: None,
            },
            handle: handle.clone(),
        };
        let shutdown = crate::shutdown::new_flag();
        let guard = start_backend_lifecycle(&backend, runtime.handle(), &shutdown)?
            .expect("configured backend health probe should start");

        wait_until(Duration::from_secs(1), || {
            handle.snapshot().backend_health.check_failures > 0
        })?;
        guard.stop()?;

        let health = handle.snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Unhealthy);
        assert!(health.check_failures > 0);
        assert!(health.consecutive_failures > 0);
        Ok(())
    }

    fn managed_mitm_config(
        target: impl ToString,
        program: impl AsRef<Path>,
        args: impl IntoIterator<Item = String>,
    ) -> AgentConfig {
        let mut config = AgentConfig::default();
        let target: std::net::SocketAddr = target
            .to_string()
            .parse()
            .expect("test MITM readiness target should parse");
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(target.port());
        let readiness_probe = TransparentInterceptionMitmBackendReadinessProbeConfig {
            target: Some(target.to_string()),
            ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
        };
        let process = TransparentInterceptionMitmManagedProcessConfig {
            program: Some(program.as_ref().into()),
            args: args.into_iter().collect(),
            working_dir: None,
        };
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::managed_process(readiness_probe, process);
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/sssa/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/sssa/mitm-ca.key".into(),
            },
        ];
        config
    }

    fn managed_backend_readiness(
        config: &mut AgentConfig,
    ) -> &mut TransparentInterceptionMitmBackendReadinessProbeConfig {
        match &mut config.enforcement.interception.mitm.backend {
            TransparentInterceptionMitmBackendConfig::ManagedProcess {
                readiness_probe, ..
            } => readiness_probe,
            _ => panic!("test config should use a managed-process MITM backend"),
        }
    }

    fn start_configured_backend_lifecycle(
        runtime: &L7MitmRuntime,
        config: &AgentConfig,
        shutdown: &crate::shutdown::ShutdownFlag,
    ) -> Result<Option<L7MitmBackendLifecycleGuard>, String> {
        let mitm = TransparentInterceptionMitmPlan::try_from_config(config)
            .expect("test MITM plan should resolve");
        start_backend_lifecycle(&mitm.backend, runtime.handle(), shutdown)
    }

    fn compile_managed_mitm_backend_fixture(
        output_dir: &Path,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("managed_mitm_backend.rs");
        let output = output_dir.join("managed-mitm-backend");
        let status = Command::new("rustc")
            .arg("--edition=2024")
            .arg(&source)
            .arg("-o")
            .arg(&output)
            .status()?;
        if !status.success() {
            return Err(format!(
                "failed to compile managed MITM backend test fixture {}: {status}",
                source.display()
            )
            .into());
        }
        Ok(output)
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn closed_loopback_target() -> Result<std::net::SocketAddr, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let target = listener.local_addr()?;
        drop(listener);
        Ok(target)
    }

    fn wait_until(
        timeout: Duration,
        mut condition: impl FnMut() -> bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err("condition did not become true before timeout".into())
    }
}

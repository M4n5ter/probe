use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde::{Deserialize, Serialize};

const STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, Copy)]
pub(crate) struct TcpHealthProbePlan {
    target: SocketAddr,
    interval: Duration,
    timeout: Duration,
    initial_delay: Duration,
}

impl TcpHealthProbePlan {
    pub(crate) fn new(target: SocketAddr, interval: Duration, timeout: Duration) -> Self {
        Self {
            target,
            interval,
            timeout,
            initial_delay: Duration::ZERO,
        }
    }

    pub(crate) fn with_initial_delay(mut self, initial_delay: Duration) -> Self {
        self.initial_delay = initial_delay;
        self
    }

    #[cfg(test)]
    pub(crate) fn target(&self) -> SocketAddr {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TcpHealthMode {
    Disabled,
    Pending,
    Healthy,
    Unhealthy,
}

impl TcpHealthMode {
    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Pending => "pending",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TcpHealthSnapshot {
    pub mode: TcpHealthMode,
    pub check_successes: u64,
    pub check_failures: u64,
    pub consecutive_failures: u64,
    pub last_failure_reason: Option<String>,
}

impl TcpHealthSnapshot {
    pub(crate) fn disabled() -> Self {
        Self {
            mode: TcpHealthMode::Disabled,
            check_successes: 0,
            check_failures: 0,
            consecutive_failures: 0,
            last_failure_reason: None,
        }
    }

    pub(crate) fn pending() -> Self {
        Self {
            mode: TcpHealthMode::Pending,
            ..Self::disabled()
        }
    }

    pub(crate) fn initial_success() -> Self {
        Self {
            mode: TcpHealthMode::Healthy,
            check_successes: 1,
            ..Self::disabled()
        }
    }

    pub(crate) fn record_success(&mut self) {
        if self.mode == TcpHealthMode::Disabled {
            return;
        }
        self.check_successes = self.check_successes.saturating_add(1);
        self.consecutive_failures = 0;
        self.last_failure_reason = None;
        self.mode = TcpHealthMode::Healthy;
    }

    pub(crate) fn record_failure(&mut self, threshold: u32, reason: impl Into<String>) {
        if self.mode == TcpHealthMode::Disabled {
            return;
        }
        self.check_failures = self.check_failures.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure_reason = Some(reason.into());
        if self.consecutive_failures >= u64::from(threshold) {
            self.mode = TcpHealthMode::Unhealthy;
        }
    }
}

pub(crate) trait TcpHealthProbeObserver: Clone + Send + 'static {
    fn record_tcp_health_success(&self);
    fn record_tcp_health_failure(&self, reason: String);
}

pub(crate) struct TcpHealthProbeGuard {
    shutdown_requested: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    panic_message: &'static str,
}

pub(crate) fn start_tcp_health_probe<O, F>(
    plan: Option<TcpHealthProbePlan>,
    observer: O,
    pre_connect_check: F,
    panic_message: &'static str,
) -> Option<TcpHealthProbeGuard>
where
    O: TcpHealthProbeObserver,
    F: Fn() -> Result<(), String> + Send + 'static,
{
    let plan = plan?;
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::clone(&shutdown_requested);
    let thread =
        thread::spawn(move || run_tcp_health_probe(plan, shutdown, observer, pre_connect_check));
    Some(TcpHealthProbeGuard {
        shutdown_requested,
        thread: Some(thread),
        panic_message,
    })
}

impl TcpHealthProbeGuard {
    pub(crate) fn stop(mut self) -> Result<(), String> {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| self.panic_message.to_string())?;
        }
        Ok(())
    }
}

impl Drop for TcpHealthProbeGuard {
    fn drop(&mut self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }
}

fn run_tcp_health_probe<O, F>(
    plan: TcpHealthProbePlan,
    shutdown_requested: Arc<AtomicBool>,
    observer: O,
    pre_connect_check: F,
) where
    O: TcpHealthProbeObserver,
    F: Fn() -> Result<(), String>,
{
    sleep_until_next_probe(plan.initial_delay, &shutdown_requested);
    while !shutdown_requested.load(Ordering::SeqCst) {
        run_tcp_health_probe_check(&plan, &observer, &pre_connect_check);
        sleep_until_next_probe(plan.interval, &shutdown_requested);
    }
}

fn run_tcp_health_probe_check<O, F>(plan: &TcpHealthProbePlan, observer: &O, pre_connect_check: &F)
where
    O: TcpHealthProbeObserver,
    F: Fn() -> Result<(), String>,
{
    if let Err(reason) = pre_connect_check() {
        observer.record_tcp_health_failure(reason);
        return;
    }
    match TcpStream::connect_timeout(&plan.target, plan.timeout) {
        Ok(stream) => {
            drop(stream);
            observer.record_tcp_health_success();
        }
        Err(error) => observer.record_tcp_health_failure(tcp_connect_failure_reason(&error)),
    }
}

#[cfg(test)]
pub(crate) fn run_tcp_health_probe_check_for_test<O, F>(
    plan: &TcpHealthProbePlan,
    observer: &O,
    pre_connect_check: &F,
) where
    O: TcpHealthProbeObserver,
    F: Fn() -> Result<(), String>,
{
    run_tcp_health_probe_check(plan, observer, pre_connect_check);
}

fn sleep_until_next_probe(interval: Duration, shutdown_requested: &AtomicBool) {
    let mut remaining = interval;
    while !remaining.is_zero() && !shutdown_requested.load(Ordering::SeqCst) {
        let sleep_for = remaining.min(STOP_POLL_INTERVAL);
        thread::sleep(sleep_for);
        remaining = remaining.saturating_sub(sleep_for);
    }
}

pub(crate) fn tcp_connect_failure_reason(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
        io::ErrorKind::TimedOut => "timed out".to_string(),
        io::ErrorKind::NetworkUnreachable => "network unreachable".to_string(),
        io::ErrorKind::HostUnreachable => "host unreachable".to_string(),
        io::ErrorKind::AddrNotAvailable => "address not available".to_string(),
        io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        kind => format!("{kind:?}").to_ascii_lowercase(),
    }
}

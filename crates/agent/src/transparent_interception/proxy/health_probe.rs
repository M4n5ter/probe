use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use probe_config::{
    EnforcementInterceptionConfig, MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
    MAX_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
    MIN_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
    MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, MIN_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
};

use super::{connect::tcp_connect_failure_reason, proxy_error, state::TransparentProxyRuntime};
use crate::transparent_interception::TransparentInterceptionError;

const HEALTH_PROBE_STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub(in crate::transparent_interception) struct TransparentProxyHealthProbePlan {
    target: SocketAddr,
    interval: Duration,
    timeout: Duration,
}

pub(in crate::transparent_interception) struct TransparentProxyHealthProbeGuard {
    shutdown_requested: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

pub(super) fn prepare_health_probe(
    config: &EnforcementInterceptionConfig,
) -> Result<Option<TransparentProxyHealthProbePlan>, TransparentInterceptionError> {
    let health_probe = &config.proxy.health_probe;
    let Some(target) = &health_probe.target else {
        return Ok(None);
    };
    if config.strategy != TransparentInterceptionStrategyConfig::InboundTproxy {
        return Err(proxy_error(
            "transparent proxy health probe is currently executable for inbound TPROXY only",
        ));
    }
    let target = target
        .parse::<SocketAddr>()
        .map_err(|_| proxy_error("transparent proxy health probe target is invalid"))?;
    if target.port() == 0 {
        return Err(proxy_error(
            "transparent proxy health probe target must use a non-zero port",
        ));
    }
    if config.proxy.mode == TransparentInterceptionProxyModeConfig::ManagedTcpRelay
        && config.proxy.listen_port.is_some_and(|listen_port| {
            health_probe_target_matches_managed_relay_listener(target, listen_port)
        })
    {
        return Err(proxy_error(
            "managed TCP relay health probe target must not point at the local relay listener",
        ));
    }
    validate_timing_range(
        health_probe.interval_ms,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS,
        "transparent proxy health probe interval",
    )?;
    validate_timing_range(
        health_probe.timeout_ms,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        "transparent proxy health probe timeout",
    )?;
    validate_timing_range(
        u64::from(health_probe.failure_threshold),
        u64::from(MIN_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD),
        u64::from(MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD),
        "transparent proxy health probe failure threshold",
    )?;
    if health_probe.timeout_ms > health_probe.interval_ms {
        return Err(proxy_error(
            "transparent proxy health probe timeout must not exceed interval",
        ));
    }
    Ok(Some(TransparentProxyHealthProbePlan {
        target,
        interval: Duration::from_millis(health_probe.interval_ms),
        timeout: Duration::from_millis(health_probe.timeout_ms),
    }))
}

fn validate_timing_range(
    value: u64,
    min: u64,
    max: u64,
    label: &str,
) -> Result<(), TransparentInterceptionError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(proxy_error(format!(
            "{label} must be between {min} and {max}"
        )))
    }
}

fn health_probe_target_matches_managed_relay_listener(
    target: SocketAddr,
    listen_port: u16,
) -> bool {
    target.port() == listen_port && is_local_listener_address(target.ip())
}

fn is_local_listener_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_unspecified(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unspecified(),
    }
}

pub(super) fn start_health_probe(
    plan: Option<TransparentProxyHealthProbePlan>,
    runtime: TransparentProxyRuntime,
) -> Option<TransparentProxyHealthProbeGuard> {
    let plan = plan?;
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::clone(&shutdown_requested);
    let thread = thread::spawn(move || {
        run_health_probe(plan.target, plan.interval, plan.timeout, shutdown, runtime)
    });
    Some(TransparentProxyHealthProbeGuard {
        shutdown_requested,
        thread: Some(thread),
    })
}

impl TransparentProxyHealthProbeGuard {
    pub(in crate::transparent_interception) fn stop(
        mut self,
    ) -> Result<(), TransparentInterceptionError> {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| proxy_error("transparent proxy health probe thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for TransparentProxyHealthProbeGuard {
    fn drop(&mut self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }
}

fn run_health_probe(
    target: SocketAddr,
    interval: Duration,
    timeout: Duration,
    shutdown_requested: Arc<AtomicBool>,
    runtime: TransparentProxyRuntime,
) {
    while !shutdown_requested.load(Ordering::SeqCst) {
        run_health_probe_check(target, timeout, &runtime);
        sleep_until_next_probe(interval, &shutdown_requested);
    }
}

fn run_health_probe_check(
    target: SocketAddr,
    timeout: Duration,
    runtime: &TransparentProxyRuntime,
) {
    match TcpStream::connect_timeout(&target, timeout) {
        Ok(stream) => {
            drop(stream);
            runtime.record_health_probe_success();
        }
        Err(error) => runtime.record_health_probe_failure(tcp_connect_failure_reason(&error)),
    }
}

fn sleep_until_next_probe(interval: Duration, shutdown_requested: &AtomicBool) {
    let mut remaining = interval;
    while !remaining.is_zero() && !shutdown_requested.load(Ordering::SeqCst) {
        let sleep_for = remaining.min(HEALTH_PROBE_STOP_POLL_INTERVAL);
        thread::sleep(sleep_for);
        remaining = remaining.saturating_sub(sleep_for);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyHealthProbeConfig, TransparentInterceptionProxyModeConfig,
        TransparentInterceptionStrategyConfig,
    };

    use crate::transparent_interception::proxy::state::TransparentProxyHealthProbeMode;

    use super::*;

    #[test]
    fn health_probe_check_records_success() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let runtime = TransparentProxyRuntime::for_config(&config(listener.local_addr()?));
        let handle = runtime.handle();

        run_health_probe_check(listener.local_addr()?, Duration::from_millis(200), &runtime);
        let (_accepted, _) = listener.accept()?;

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.health_probe.mode,
            TransparentProxyHealthProbeMode::Healthy
        );
        assert_eq!(snapshot.health_probe.check_successes, 1);
        assert_eq!(snapshot.health_probe.check_failures, 0);
        Ok(())
    }

    #[test]
    fn health_probe_check_records_failure() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let target = listener.local_addr()?;
        drop(listener);
        let runtime = TransparentProxyRuntime::for_config(&config(target));
        let handle = runtime.handle();

        run_health_probe_check(target, Duration::from_millis(200), &runtime);

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.health_probe.mode,
            TransparentProxyHealthProbeMode::Unhealthy
        );
        assert_eq!(snapshot.health_probe.check_successes, 0);
        assert_eq!(snapshot.health_probe.check_failures, 1);
        assert_eq!(
            snapshot.health_probe.last_failure_reason.as_deref(),
            Some("connection refused")
        );
        Ok(())
    }

    #[test]
    fn prepare_health_probe_rejects_invalid_runtime_config() {
        let error = prepare_health_probe(&config_with_health_probe("127.0.0.1:0", 500, 100, 1))
            .expect_err("zero target port should be rejected");
        assert!(error.to_string().contains("non-zero port"));

        let error = prepare_health_probe(&config_with_health_probe("127.0.0.1:18080", 0, 100, 1))
            .expect_err("zero timing values should be rejected");
        assert!(error.to_string().contains("must be between"));
    }

    #[test]
    fn prepare_health_probe_rejects_managed_relay_self_target() {
        let error = prepare_health_probe(&config_with_health_probe("127.0.0.1:15001", 500, 100, 1))
            .expect_err("managed relay target should not point at its listen port");

        assert!(error.to_string().contains("local relay listener"));
    }

    #[test]
    fn prepare_health_probe_allows_remote_target_on_relay_port() {
        let plan =
            prepare_health_probe(&config_with_health_probe("203.0.113.10:15001", 500, 100, 1))
                .expect("remote endpoint on the relay port should be valid");

        assert!(plan.is_some());
    }

    #[test]
    fn prepare_health_probe_is_currently_inbound_tproxy_only() {
        let mut config = config_with_health_probe("127.0.0.1:18080", 500, 100, 1);
        config.strategy = TransparentInterceptionStrategyConfig::OutboundMitm;

        let error = prepare_health_probe(&config)
            .expect_err("outbound MITM health probe is not executable");

        assert!(error.to_string().contains("inbound TPROXY only"));
    }

    fn config(target: SocketAddr) -> EnforcementInterceptionConfig {
        config_with_health_probe(&target.to_string(), 500, 100, 1)
    }

    fn config_with_health_probe(
        target: &str,
        interval_ms: u64,
        timeout_ms: u64,
        failure_threshold: u32,
    ) -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            proxy: TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                health_probe: TransparentInterceptionProxyHealthProbeConfig {
                    target: Some(target.to_string()),
                    interval_ms,
                    timeout_ms,
                    failure_threshold,
                },
            },
            ..EnforcementInterceptionConfig::default()
        }
    }
}

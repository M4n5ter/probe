use std::{
    fmt,
    net::{IpAddr, SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use ::runtime::TransparentInterceptionProxyHealthProbePlan;

use super::{
    LocalAddressInventory, ManagedTransparentProxyPlan, connect::tcp_connect_failure_reason,
    proxy_error, state::TransparentProxyRuntime,
};
use crate::transparent_interception::{
    TransparentInterceptionError, TransparentInterceptionIpFamily,
};

const HEALTH_PROBE_STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub(in crate::transparent_interception) struct TransparentProxyHealthProbePlan {
    target: SocketAddr,
    interval: Duration,
    timeout: Duration,
    self_target_guard: Option<ManagedRelaySelfTargetGuard>,
}

struct ManagedRelaySelfTargetGuard {
    target: SocketAddr,
    load_local_addresses: LocalAddressInventory,
}

impl fmt::Debug for ManagedRelaySelfTargetGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedRelaySelfTargetGuard")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

pub(in crate::transparent_interception) struct TransparentProxyHealthProbeGuard {
    shutdown_requested: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

pub(super) fn prepare_health_probe(
    health_probe: &TransparentInterceptionProxyHealthProbePlan,
    managed: Option<&ManagedTransparentProxyPlan>,
    load_local_addresses: LocalAddressInventory,
) -> Result<Option<TransparentProxyHealthProbePlan>, TransparentInterceptionError> {
    let TransparentInterceptionProxyHealthProbePlan::Enabled {
        target,
        interval_ms,
        timeout_ms,
        failure_threshold: _,
    } = health_probe
    else {
        return Ok(None);
    };
    let self_target_guard =
        prepare_managed_relay_self_target_guard(managed, *target, load_local_addresses)?;
    Ok(Some(TransparentProxyHealthProbePlan {
        target: *target,
        interval: Duration::from_millis(*interval_ms),
        timeout: Duration::from_millis(*timeout_ms),
        self_target_guard,
    }))
}

fn prepare_managed_relay_self_target_guard(
    managed: Option<&ManagedTransparentProxyPlan>,
    target: SocketAddr,
    load_local_addresses: LocalAddressInventory,
) -> Result<Option<ManagedRelaySelfTargetGuard>, TransparentInterceptionError> {
    let Some(managed) = managed else {
        return Ok(None);
    };
    if target.port() != managed.listen_port
        || !target_family_has_listener(target.ip(), &managed.families)
    {
        return Ok(None);
    }
    let guard = ManagedRelaySelfTargetGuard {
        target,
        load_local_addresses,
    };
    guard.ensure_target_is_not_local()?;
    Ok(Some(guard))
}

impl ManagedRelaySelfTargetGuard {
    fn ensure_target_is_not_local(&self) -> Result<(), TransparentInterceptionError> {
        let target_address = normalized_ip_address(self.target.ip());
        if is_builtin_local_address(target_address) {
            return Err(local_relay_target_error(self.target));
        }
        if is_local_relay_target_address(target_address, &(self.load_local_addresses)()?) {
            return Err(local_relay_target_error(self.target));
        }
        Ok(())
    }
}

fn local_relay_target_error(target: SocketAddr) -> TransparentInterceptionError {
    proxy_error(format!(
        "managed TCP relay health probe target {target} points at the local relay listener"
    ))
}

fn target_family_has_listener(
    address: IpAddr,
    listener_families: &[TransparentInterceptionIpFamily],
) -> bool {
    let target_family = normalized_target_family(address);
    listener_families.contains(&target_family)
}

fn normalized_target_family(address: IpAddr) -> TransparentInterceptionIpFamily {
    match normalized_ip_address(address) {
        IpAddr::V4(_) => TransparentInterceptionIpFamily::Ipv4,
        IpAddr::V6(_) => TransparentInterceptionIpFamily::Ipv6,
    }
}

fn is_local_relay_target_address(address: IpAddr, local_addresses: &[IpAddr]) -> bool {
    local_addresses
        .iter()
        .copied()
        .any(|local_address| address == normalized_ip_address(local_address))
}

fn is_builtin_local_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_unspecified(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unspecified(),
    }
}

fn normalized_ip_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
    }
}

pub(super) fn start_health_probe(
    plan: Option<TransparentProxyHealthProbePlan>,
    runtime: TransparentProxyRuntime,
) -> Option<TransparentProxyHealthProbeGuard> {
    let plan = plan?;
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::clone(&shutdown_requested);
    let thread = thread::spawn(move || run_health_probe(plan, shutdown, runtime));
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
    plan: TransparentProxyHealthProbePlan,
    shutdown_requested: Arc<AtomicBool>,
    runtime: TransparentProxyRuntime,
) {
    while !shutdown_requested.load(Ordering::SeqCst) {
        run_health_probe_check(&plan, &runtime);
        sleep_until_next_probe(plan.interval, &shutdown_requested);
    }
}

fn run_health_probe_check(
    plan: &TransparentProxyHealthProbePlan,
    runtime: &TransparentProxyRuntime,
) {
    if let Some(guard) = &plan.self_target_guard
        && let Err(error) = guard.ensure_target_is_not_local()
    {
        runtime.record_health_probe_failure(error.to_string());
        return;
    }
    match TcpStream::connect_timeout(&plan.target, plan.timeout) {
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
    use std::{
        net::{Ipv4Addr, TcpListener},
        sync::Arc,
    };

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
        let runtime = TransparentProxyRuntime::for_test_config(&config(listener.local_addr()?));
        let handle = runtime.handle();
        let plan = health_probe_plan(listener.local_addr()?, Duration::from_millis(200), None);

        run_health_probe_check(&plan, &runtime);
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
        let runtime = TransparentProxyRuntime::for_test_config(&config(target));
        let handle = runtime.handle();
        let plan = health_probe_plan(target, Duration::from_millis(200), None);

        run_health_probe_check(&plan, &runtime);

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
    fn disabled_health_probe_has_no_runtime_plan() {
        assert!(
            prepare_health_probe(
                disabled_inbound_plan().health_probe(),
                None,
                local_address_inventory(Vec::new())
            )
            .expect("disabled health probe preparation should succeed")
            .is_none()
        );
    }

    #[test]
    fn managed_health_probe_rejects_local_interface_target() {
        let inbound_plan = inbound_plan(config_with_health_probe("192.0.2.10:15001", 500, 100, 1));

        let error = prepare_health_probe(
            inbound_plan.health_probe(),
            Some(&managed_ipv4_proxy()),
            local_address_inventory(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
        )
        .expect_err("local interface target on relay port must fail closed");

        assert!(error.to_string().contains("local relay listener"));
    }

    #[test]
    fn managed_health_probe_allows_remote_target_on_relay_port()
    -> Result<(), Box<dyn std::error::Error>> {
        let inbound_plan = inbound_plan(config_with_health_probe("192.0.2.10:15001", 500, 100, 1));

        let plan = prepare_health_probe(
            inbound_plan.health_probe(),
            Some(&managed_ipv4_proxy()),
            local_address_inventory(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]),
        )
        .expect("remote target on relay port should be a valid probe")
        .expect("health probe should be enabled");

        assert_eq!(plan.target, "192.0.2.10:15001".parse()?);
        Ok(())
    }

    #[test]
    fn managed_health_probe_matches_ipv4_mapped_local_address() {
        let inbound_plan = inbound_plan(config_with_health_probe(
            "[::ffff:192.0.2.10]:15001",
            500,
            100,
            1,
        ));

        let error = prepare_health_probe(
            inbound_plan.health_probe(),
            Some(&managed_ipv4_proxy()),
            local_address_inventory(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
        )
        .expect_err("IPv4-mapped local target on relay port must fail closed");

        assert!(error.to_string().contains("local relay listener"));
    }

    #[test]
    fn managed_health_probe_rejects_ipv4_mapped_builtin_local_addresses() {
        for target in ["[::ffff:0.0.0.0]:15001", "[::ffff:127.0.0.1]:15001"] {
            let health_probe = enabled_health_probe(target);

            let error = prepare_health_probe(
                &health_probe,
                Some(&managed_ipv4_proxy()),
                Arc::new(|| {
                    panic!("IPv4-mapped builtin local target must not need local address inventory")
                }),
            )
            .expect_err("IPv4-mapped builtin local target must fail closed");

            assert!(error.to_string().contains("local relay listener"));
        }
    }

    #[test]
    fn managed_health_probe_does_not_load_inventory_for_other_listener_family()
    -> Result<(), Box<dyn std::error::Error>> {
        let inbound_plan = inbound_plan(config_with_health_probe(
            "[2001:db8::10]:15001",
            500,
            100,
            1,
        ));

        let plan = prepare_health_probe(
            inbound_plan.health_probe(),
            Some(&managed_ipv4_proxy()),
            Arc::new(|| panic!("opposite-family target must not need local address inventory")),
        )?
        .expect("health probe should be enabled");

        assert_eq!(plan.target, "[2001:db8::10]:15001".parse()?);
        Ok(())
    }

    #[test]
    fn health_probe_check_revalidates_managed_local_target_before_connect() {
        let target = "192.0.2.10:15001"
            .parse()
            .expect("test target should parse");
        let runtime = TransparentProxyRuntime::for_test_config(&config_with_health_probe(
            "192.0.2.10:15001",
            500,
            100,
            1,
        ));
        let handle = runtime.handle();
        let guard = ManagedRelaySelfTargetGuard {
            target,
            load_local_addresses: local_address_inventory(vec![IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 10,
            ))]),
        };
        let plan = health_probe_plan(target, Duration::from_millis(100), Some(guard));

        run_health_probe_check(&plan, &runtime);

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.health_probe.mode,
            TransparentProxyHealthProbeMode::Unhealthy
        );
        assert_eq!(snapshot.health_probe.check_successes, 0);
        assert_eq!(snapshot.health_probe.check_failures, 1);
        assert!(
            snapshot
                .health_probe
                .last_failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("local relay listener"))
        );
    }

    fn config(target: SocketAddr) -> EnforcementInterceptionConfig {
        config_with_health_probe(&target.to_string(), 500, 100, 1)
    }

    fn health_probe_plan(
        target: SocketAddr,
        timeout: Duration,
        self_target_guard: Option<ManagedRelaySelfTargetGuard>,
    ) -> TransparentProxyHealthProbePlan {
        TransparentProxyHealthProbePlan {
            target,
            interval: Duration::from_millis(500),
            timeout,
            self_target_guard,
        }
    }

    fn managed_ipv4_proxy() -> ManagedTransparentProxyPlan {
        ManagedTransparentProxyPlan {
            listen_port: 15001,
            families: vec![TransparentInterceptionIpFamily::Ipv4],
            relay_plan: crate::transparent_interception::proxy::relay::TransparentProxyRelayPlan::inbound_tproxy(15001),
        }
    }

    fn enabled_health_probe(target: &str) -> TransparentInterceptionProxyHealthProbePlan {
        TransparentInterceptionProxyHealthProbePlan::Enabled {
            target: target
                .parse()
                .expect("test health probe target should parse"),
            interval_ms: 500,
            timeout_ms: 100,
            failure_threshold: 1,
        }
    }

    fn local_address_inventory(addresses: Vec<IpAddr>) -> LocalAddressInventory {
        Arc::new(move || Ok(addresses.clone()))
    }

    fn disabled_inbound_plan() -> ::runtime::TransparentInterceptionInboundTproxyPlan {
        inbound_plan(EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            proxy: TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                health_probe: TransparentInterceptionProxyHealthProbeConfig::default(),
            },
            ..EnforcementInterceptionConfig::default()
        })
    }

    fn inbound_plan(
        config: EnforcementInterceptionConfig,
    ) -> ::runtime::TransparentInterceptionInboundTproxyPlan {
        let execution_plan =
            ::runtime::TransparentInterceptionExecutionPlan::try_from_config(&config)
                .expect("test transparent interception config should be valid");
        let ::runtime::TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) =
            execution_plan
        else {
            panic!("test config should produce an inbound TPROXY plan");
        };
        inbound_plan
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

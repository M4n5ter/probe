use super::{
    command::{CommandResult, IpCommand, NftCommand},
    owner_lock::{NftablesOwnerLock, NftablesOwnerLockGuard, SystemNftablesOwnerLock},
    plan::InboundTproxyLifecyclePlan,
};
use crate::transparent_interception::{
    TransparentInterceptionError,
    proxy::{
        TransparentProxyGuard, TransparentProxyRuntime, prepare_proxy_lifecycle,
        start_proxy_lifecycle,
    },
};
#[cfg(test)]
use ::runtime::TransparentInterceptionExecutionPlan;
use ::runtime::TransparentInterceptionInboundTproxyPlan;
use interception::TransparentInterceptionHostRuleScope;
#[cfg(test)]
use probe_config::EnforcementInterceptionConfig;

pub(in crate::transparent_interception) struct NftablesTransparentInterception {
    inbound_plan: TransparentInterceptionInboundTproxyPlan,
    nft: Box<dyn NftCommand + Send>,
    ip: Option<Box<dyn IpCommand + Send>>,
    owner_lock: Box<dyn NftablesOwnerLock>,
    proxy_runtime: TransparentProxyRuntime,
}

impl NftablesTransparentInterception {
    pub(super) fn new<N, I>(
        inbound_plan: TransparentInterceptionInboundTproxyPlan,
        nft: N,
        ip: Option<I>,
        proxy_runtime: TransparentProxyRuntime,
    ) -> Self
    where
        N: NftCommand + Send + 'static,
        I: IpCommand + Send + 'static,
    {
        Self::with_owner_lock(
            inbound_plan,
            nft,
            ip,
            SystemNftablesOwnerLock::default(),
            proxy_runtime,
        )
    }

    fn with_owner_lock<N, I, L>(
        inbound_plan: TransparentInterceptionInboundTproxyPlan,
        nft: N,
        ip: Option<I>,
        owner_lock: L,
        proxy_runtime: TransparentProxyRuntime,
    ) -> Self
    where
        N: NftCommand + Send + 'static,
        I: IpCommand + Send + 'static,
        L: NftablesOwnerLock + 'static,
    {
        Self {
            inbound_plan,
            nft: Box::new(nft),
            ip: ip.map(|ip| Box::new(ip) as Box<dyn IpCommand + Send>),
            owner_lock: Box::new(owner_lock),
            proxy_runtime,
        }
    }

    #[cfg(test)]
    fn new_for_test<N, I>(config: EnforcementInterceptionConfig, nft: N, ip: Option<I>) -> Self
    where
        N: NftCommand + Send + 'static,
        I: IpCommand + Send + 'static,
    {
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");
        let proxy_runtime = TransparentProxyRuntime::for_execution_plan(&execution_plan);
        let TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) = execution_plan
        else {
            panic!("test transparent interception config should use inbound TPROXY");
        };
        Self::with_owner_lock(
            inbound_plan,
            nft,
            ip,
            super::owner_lock::NoopNftablesOwnerLock,
            proxy_runtime,
        )
    }

    pub(in crate::transparent_interception) fn activate(
        mut self,
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<NftablesTransparentInterceptionGuard, TransparentInterceptionError> {
        let plan = InboundTproxyLifecyclePlan::from_inbound_plan_and_scope(
            &self.inbound_plan,
            setup_scope,
        )
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
        let proxy_plan = prepare_proxy_lifecycle(&self.inbound_plan, plan.listener_families())?;
        let setup_script = plan.setup_nft_script();
        check_nft_script(self.nft.as_mut(), &setup_script)?;
        let owner_lock = self.owner_lock.acquire(plan.owner_name())?;
        self.cleanup_previous_owned_state_best_effort(&plan);
        let proxy = start_proxy_lifecycle(proxy_plan, self.proxy_runtime.clone())?;
        if let Err(error) = self.install_policy_routes(&plan) {
            self.cleanup_active_plan_best_effort(&plan);
            let _ = stop_proxy_best_effort(proxy);
            return Err(error);
        }
        if let Err(error) = apply_nft_script(self.nft.as_mut(), &setup_script, "nft setup") {
            self.cleanup_active_plan_best_effort(&plan);
            let _ = stop_proxy_best_effort(proxy);
            return Err(error);
        }
        Ok(NftablesTransparentInterceptionGuard {
            inner: Some(self),
            plan,
            proxy,
            owner_lock: Some(owner_lock),
        })
    }

    fn install_policy_routes(
        &mut self,
        plan: &InboundTproxyLifecyclePlan,
    ) -> Result<(), TransparentInterceptionError> {
        if plan.setup_ip_commands().is_empty() {
            return Ok(());
        }
        let Some(ip) = self.ip.as_mut() else {
            return Err(TransparentInterceptionError::Nftables(
                "policy routing command is unavailable".to_string(),
            ));
        };
        for command in plan.setup_ip_commands() {
            apply_ip_command(ip.as_mut(), &command, "ip setup")?;
        }
        Ok(())
    }

    fn cleanup_previous_owned_state_best_effort(&mut self, plan: &InboundTproxyLifecyclePlan) {
        let _ = apply_nft_script(self.nft.as_mut(), &plan.cleanup_nft_script(), "nft cleanup");
        self.cleanup_ip_commands_best_effort(plan.cleanup_all_ip_commands());
    }

    fn cleanup_active_plan_best_effort(&mut self, plan: &InboundTproxyLifecyclePlan) {
        let _ = apply_nft_script(self.nft.as_mut(), &plan.cleanup_nft_script(), "nft cleanup");
        self.cleanup_ip_commands_best_effort(plan.cleanup_ip_commands());
    }

    fn cleanup_ip_commands_best_effort(&mut self, commands: Vec<Vec<String>>) {
        let Some(ip) = self.ip.as_mut() else {
            return;
        };
        for command in commands {
            let _ = apply_ip_command(ip.as_mut(), &command, "ip cleanup");
        }
    }
}

pub(in crate::transparent_interception) struct NftablesTransparentInterceptionGuard {
    inner: Option<NftablesTransparentInterception>,
    plan: InboundTproxyLifecyclePlan,
    proxy: Option<TransparentProxyGuard>,
    owner_lock: Option<NftablesOwnerLockGuard>,
}

impl NftablesTransparentInterceptionGuard {
    pub(crate) fn deactivate(mut self) -> Result<(), TransparentInterceptionError> {
        self.deactivate_inner()
    }

    fn deactivate_inner(&mut self) -> Result<(), TransparentInterceptionError> {
        let Some(inner) = self.inner.as_mut() else {
            return Ok(());
        };
        let nft_result = apply_nft_script(
            inner.nft.as_mut(),
            &self.plan.cleanup_nft_script(),
            "nft cleanup",
        );
        let mut route_result = Ok(());
        if let Some(ip) = inner.ip.as_mut() {
            for command in self.plan.cleanup_ip_commands() {
                if let Err(error) = apply_ip_command(ip.as_mut(), &command, "ip cleanup") {
                    route_result = Err(error);
                }
            }
        }
        self.inner = None;
        let proxy_result = stop_proxy_best_effort(self.proxy.take());
        self.owner_lock = None;
        nft_result.and(route_result).and(proxy_result)
    }
}

impl Drop for NftablesTransparentInterceptionGuard {
    fn drop(&mut self) {
        if self.inner.is_some()
            && let Err(error) = self.deactivate_inner()
        {
            eprintln!("transparent interception cleanup failed during drop: {error}");
        }
    }
}

fn apply_nft_script(
    nft: &mut dyn NftCommand,
    script: &str,
    command_name: &str,
) -> Result<(), TransparentInterceptionError> {
    let result = nft
        .apply(script)
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    command_success(result, command_name)
}

fn stop_proxy_best_effort(
    proxy: Option<TransparentProxyGuard>,
) -> Result<(), TransparentInterceptionError> {
    match proxy {
        Some(proxy) => proxy.stop(),
        None => Ok(()),
    }
}

fn check_nft_script(
    nft: &mut dyn NftCommand,
    script: &str,
) -> Result<(), TransparentInterceptionError> {
    let result = nft
        .check(script)
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    command_success(result, "nft --check")
}

fn apply_ip_command(
    ip: &mut dyn IpCommand,
    args: &[String],
    command_name: &str,
) -> Result<(), TransparentInterceptionError> {
    let result = ip
        .run(args)
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    command_success(result, command_name)
}

fn command_success(
    result: CommandResult,
    command_name: &str,
) -> Result<(), TransparentInterceptionError> {
    if result.success {
        Ok(())
    } else {
        Err(TransparentInterceptionError::Nftables(
            result.failure_reason(command_name),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        net::{Ipv4Addr, TcpListener},
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyHealthProbeConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};
    use runtime::TransparentInterceptionExecutionPlan;

    use crate::transparent_interception::{
        TransparentProxyRuntimeHandle, nftables::owner_lock::NoopNftablesOwnerLock,
    };

    use super::*;

    #[test]
    fn activation_installs_routes_before_nft_and_cleanup_reverses_owned_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let nft = FakeNft::succeeding();
        let ip = FakeIp::succeeding();
        let config = inbound_config();
        let selector = setup_selector();

        let guard =
            NftablesTransparentInterception::new_for_test(config, nft.clone(), Some(ip.clone()))
                .activate(setup_scope(&selector))?;
        guard.deactivate()?;

        let nft_scripts = nft.scripts();
        assert_eq!(nft_scripts.len(), 3);
        assert!(nft_scripts[0].contains("destroy table inet sssa_probe"));
        assert!(nft_scripts[1].contains("add table inet sssa_probe"));
        assert!(nft_scripts[2].contains("destroy table inet sssa_probe"));
        let ip_args = ip.args();
        assert_eq!(
            ip_args[0],
            string_args(["rule", "del", "fwmark", "0x53534101", "lookup", "53534"])
        );
        assert_eq!(
            ip_args[1],
            string_args([
                "route",
                "del",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                "53534"
            ])
        );
        assert_eq!(
            ip_args[2],
            string_args([
                "-6",
                "rule",
                "del",
                "fwmark",
                "0x53534101",
                "lookup",
                "53534"
            ])
        );
        assert_eq!(
            ip_args[3],
            string_args([
                "-6", "route", "del", "local", "::/0", "dev", "lo", "table", "53534"
            ])
        );
        assert_eq!(
            ip_args[4],
            string_args(["rule", "add", "fwmark", "0x53534101", "lookup", "53534"])
        );
        Ok(())
    }

    #[test]
    fn guard_drop_attempts_cleanup_when_deactivate_is_not_called()
    -> Result<(), Box<dyn std::error::Error>> {
        let nft = FakeNft::succeeding();
        let ip = FakeIp::succeeding();
        let selector = setup_selector();

        let guard = NftablesTransparentInterception::new_for_test(
            inbound_config(),
            nft.clone(),
            Some(ip.clone()),
        )
        .activate(setup_scope(&selector))?;
        drop(guard);

        let nft_scripts = nft.scripts();
        assert_eq!(nft_scripts.len(), 3);
        assert!(nft_scripts[2].contains("destroy table inet sssa_probe"));
        assert!(ip.args().len() >= 8);
        Ok(())
    }

    #[test]
    fn failed_nft_setup_attempts_cleanup() {
        let nft = FakeNft::with_results([
            Ok(success()),
            Ok(CommandResult {
                success: false,
                stdout: Vec::new(),
                stderr: b"bad rule".to_vec(),
            }),
            Ok(success()),
        ]);
        let ip = FakeIp::succeeding();

        let error = match NftablesTransparentInterception::new_for_test(
            inbound_config(),
            nft.clone(),
            Some(ip),
        )
        .activate(setup_scope(&setup_selector()))
        {
            Ok(_) => panic!("failed nft setup must fail activation"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("bad rule"));
        assert_eq!(nft.scripts().len(), 3);
    }

    #[test]
    fn failed_final_nft_check_does_not_mutate_host_state() {
        let nft = FakeNft::with_check_results([Ok(CommandResult {
            success: false,
            stdout: Vec::new(),
            stderr: b"syntax rejected".to_vec(),
        })]);
        let ip = FakeIp::succeeding();

        let error = match NftablesTransparentInterception::new_for_test(
            inbound_config(),
            nft.clone(),
            Some(ip.clone()),
        )
        .activate(setup_scope(&setup_selector()))
        {
            Ok(_) => panic!("failed nft check must fail activation"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("syntax rejected"));
        assert_eq!(nft.checked_scripts().len(), 1);
        assert!(nft.scripts().is_empty());
        assert!(ip.args().is_empty());
    }

    #[test]
    fn activation_starts_configured_health_probe() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let nft = FakeNft::succeeding();
        let ip = FakeIp::succeeding();
        let mut config = inbound_config();
        config.proxy.health_probe = TransparentInterceptionProxyHealthProbeConfig {
            target: Some(listener.local_addr()?.to_string()),
            interval_ms: 100,
            timeout_ms: 10,
            failure_threshold: 1,
        };
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");
        let runtime = TransparentProxyRuntime::for_execution_plan(&execution_plan);
        let handle = runtime.handle();
        let TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) = execution_plan
        else {
            panic!("test transparent interception config should use inbound TPROXY");
        };
        let lifecycle = NftablesTransparentInterception::with_owner_lock(
            inbound_plan,
            nft,
            Some(ip),
            NoopNftablesOwnerLock,
            runtime,
        );

        let guard = lifecycle.activate(setup_scope(&setup_selector()))?;
        wait_for_health_probe_success(&handle)?;
        guard.deactivate()?;

        assert!(handle.snapshot().health_probe.check_successes > 0);
        Ok(())
    }

    #[test]
    fn startup_cleanup_removes_all_owned_route_families_before_projected_install()
    -> Result<(), Box<dyn std::error::Error>> {
        let nft = FakeNft::succeeding();
        let ip = FakeIp::succeeding();
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                remote_addresses: vec!["203.0.113.10".to_string()],
                ..TrafficSelector::default()
            },
        );

        let guard =
            NftablesTransparentInterception::new_for_test(inbound_config(), nft, Some(ip.clone()))
                .activate(setup_scope(&selector))?;
        guard.deactivate()?;

        let ip_args = ip.args();
        assert_eq!(
            ip_args[0],
            string_args(["rule", "del", "fwmark", "0x53534101", "lookup", "53534"])
        );
        assert_eq!(
            ip_args[1],
            string_args([
                "route",
                "del",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                "53534"
            ])
        );
        assert_eq!(
            ip_args[2],
            string_args([
                "-6",
                "rule",
                "del",
                "fwmark",
                "0x53534101",
                "lookup",
                "53534"
            ])
        );
        assert_eq!(
            ip_args[3],
            string_args([
                "-6", "route", "del", "local", "::/0", "dev", "lo", "table", "53534"
            ])
        );
        assert_eq!(
            ip_args[4],
            string_args(["rule", "add", "fwmark", "0x53534101", "lookup", "53534"])
        );
        assert_eq!(
            ip_args[5],
            string_args([
                "route",
                "replace",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                "53534"
            ])
        );
        Ok(())
    }

    fn inbound_config() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
        }
    }

    fn setup_selector() -> Selector {
        Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )
    }

    fn setup_scope(selector: &Selector) -> TransparentInterceptionHostRuleScope {
        TransparentInterceptionHostRuleScope::from_inbound_tproxy_selector(Some(selector))
            .expect("test selector should project to host rules")
    }

    fn string_args<const N: usize>(args: [&str; N]) -> Vec<String> {
        args.into_iter().map(ToString::to_string).collect()
    }

    fn success() -> CommandResult {
        CommandResult {
            success: true,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn wait_for_health_probe_success(
        handle: &TransparentProxyRuntimeHandle,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if handle.snapshot().health_probe.check_successes > 0 {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "health probe did not record a successful check",
        )
        .into())
    }

    #[derive(Clone)]
    struct FakeNft {
        state: Arc<Mutex<FakeNftState>>,
    }

    struct FakeNftState {
        scripts: Vec<String>,
        checked_scripts: Vec<String>,
        results: VecDeque<io::Result<CommandResult>>,
        check_results: VecDeque<io::Result<CommandResult>>,
    }

    impl FakeNft {
        fn succeeding() -> Self {
            Self::with_results(std::iter::repeat_with(|| Ok(success())).take(16))
        }

        fn with_results(results: impl IntoIterator<Item = io::Result<CommandResult>>) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeNftState {
                    scripts: Vec::new(),
                    checked_scripts: Vec::new(),
                    results: results.into_iter().collect(),
                    check_results: VecDeque::new(),
                })),
            }
        }

        fn with_check_results(
            results: impl IntoIterator<Item = io::Result<CommandResult>>,
        ) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeNftState {
                    scripts: Vec::new(),
                    checked_scripts: Vec::new(),
                    results: VecDeque::new(),
                    check_results: results.into_iter().collect(),
                })),
            }
        }

        fn scripts(&self) -> Vec<String> {
            self.state.lock().expect("fake nft lock").scripts.clone()
        }

        fn checked_scripts(&self) -> Vec<String> {
            self.state
                .lock()
                .expect("fake nft lock")
                .checked_scripts
                .clone()
        }
    }

    impl NftCommand for FakeNft {
        fn apply(&mut self, script: &str) -> io::Result<CommandResult> {
            let mut state = self.state.lock().expect("fake nft lock");
            state.scripts.push(script.to_string());
            state.results.pop_front().unwrap_or_else(|| Ok(success()))
        }

        fn check(&mut self, script: &str) -> io::Result<CommandResult> {
            let mut state = self.state.lock().expect("fake nft lock");
            state.checked_scripts.push(script.to_string());
            state
                .check_results
                .pop_front()
                .unwrap_or_else(|| Ok(success()))
        }
    }

    #[derive(Clone)]
    struct FakeIp {
        state: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl FakeIp {
        fn succeeding() -> Self {
            Self {
                state: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn args(&self) -> Vec<Vec<String>> {
            self.state.lock().expect("fake ip lock").clone()
        }
    }

    impl IpCommand for FakeIp {
        fn run(&mut self, args: &[String]) -> io::Result<CommandResult> {
            self.state.lock().expect("fake ip lock").push(args.to_vec());
            Ok(success())
        }
    }
}

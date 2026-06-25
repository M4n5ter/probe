use ::runtime::TransparentInterceptionOutboundProxyPlan;
use interception::TransparentInterceptionHostRuleSet;
use transparent_linux::{
    OutboundRedirectLifecyclePlan, TransparentLinuxResources, cleanup_all_policy_route_ip_commands,
};

use super::{
    activation::{
        SharedIpCommand, apply_ip_command, apply_nft_script, checked_nft_setup_owner,
        local_address_inventory, lock_ip_command, stop_proxy_best_effort,
    },
    command::{NftCommand, SystemNft},
    owner_lock::{NftablesOwnerLock, NftablesOwnerLockGuard, SystemNftablesOwnerLock},
};
use crate::transparent_interception::{
    TransparentInterceptionError, TransparentInterceptionIpFamily,
    proxy::{
        TransparentProxyGuard, TransparentProxyRuntime, prepare_outbound_proxy_lifecycle,
        start_proxy_lifecycle,
    },
};

pub(in crate::transparent_interception) struct NftablesOutboundTransparentProxy {
    outbound_plan: TransparentInterceptionOutboundProxyPlan,
    nft: Box<dyn NftCommand + Send>,
    ip: Option<SharedIpCommand>,
    owner_lock: Box<dyn NftablesOwnerLock>,
    proxy_runtime: TransparentProxyRuntime,
}

impl NftablesOutboundTransparentProxy {
    pub(super) fn new(
        outbound_plan: TransparentInterceptionOutboundProxyPlan,
        nft: SystemNft,
        ip: Option<super::command::SystemIp>,
        proxy_runtime: TransparentProxyRuntime,
    ) -> Self {
        Self::with_owner_lock(
            outbound_plan,
            nft,
            ip,
            SystemNftablesOwnerLock::default(),
            proxy_runtime,
        )
    }

    fn with_owner_lock<N, I, L>(
        outbound_plan: TransparentInterceptionOutboundProxyPlan,
        nft: N,
        ip: Option<I>,
        owner_lock: L,
        proxy_runtime: TransparentProxyRuntime,
    ) -> Self
    where
        N: NftCommand + Send + 'static,
        I: super::command::IpCommand + Send + 'static,
        L: NftablesOwnerLock + 'static,
    {
        Self {
            outbound_plan,
            nft: Box::new(nft),
            ip: ip.map(|ip| {
                std::sync::Arc::new(std::sync::Mutex::new(
                    Box::new(ip) as Box<dyn super::command::IpCommand + Send>
                ))
            }),
            owner_lock: Box::new(owner_lock),
            proxy_runtime,
        }
    }

    pub(in crate::transparent_interception) fn activate(
        mut self,
        setup_scope: TransparentInterceptionHostRuleSet,
    ) -> Result<NftablesOutboundTransparentProxyGuard, TransparentInterceptionError> {
        let plan = outbound_lifecycle_plan(&self.outbound_plan, setup_scope)?;
        let proxy_plan = prepare_outbound_proxy_lifecycle(
            &self.outbound_plan,
            plan.listener_families()
                .into_iter()
                .map(TransparentInterceptionIpFamily::from)
                .collect(),
            plan.proxy_bypass_mark(),
            local_address_inventory(self.ip.clone()),
        )?;
        let setup_script = plan.setup_nft_script();
        let owner_lock = checked_nft_setup_owner(
            self.nft.as_mut(),
            self.owner_lock.as_mut(),
            &setup_script,
            plan.owner_name(),
        )?;
        self.cleanup_previous_owned_state_best_effort(&plan);
        let proxy = start_proxy_lifecycle(proxy_plan, self.proxy_runtime.clone())?;
        if let Err(error) = apply_nft_script(self.nft.as_mut(), &setup_script, "nft setup") {
            self.cleanup_active_plan_best_effort(&plan);
            let _ = stop_proxy_best_effort(proxy);
            return Err(error);
        }
        Ok(NftablesOutboundTransparentProxyGuard {
            inner: Some(self),
            plan,
            proxy,
            owner_lock: Some(owner_lock),
        })
    }

    fn cleanup_previous_owned_state_best_effort(&mut self, plan: &OutboundRedirectLifecyclePlan) {
        let _ = apply_nft_script(self.nft.as_mut(), &plan.cleanup_nft_script(), "nft cleanup");
        self.cleanup_reserved_policy_routes_best_effort();
    }

    fn cleanup_active_plan_best_effort(&mut self, plan: &OutboundRedirectLifecyclePlan) {
        let _ = apply_nft_script(self.nft.as_mut(), &plan.cleanup_nft_script(), "nft cleanup");
    }

    fn cleanup_reserved_policy_routes_best_effort(&mut self) {
        let Some(ip) = self.ip.as_ref() else {
            return;
        };
        let Ok(mut ip) = lock_ip_command(ip) else {
            return;
        };
        let resources = TransparentLinuxResources::reserved();
        for command in cleanup_all_policy_route_ip_commands(
            resources.inbound_tproxy_mark,
            resources.inbound_tproxy_route_table,
        ) {
            let _ = apply_ip_command(ip.as_mut(), &command, "ip cleanup");
        }
    }
}

pub(in crate::transparent_interception) struct NftablesOutboundTransparentProxyGuard {
    inner: Option<NftablesOutboundTransparentProxy>,
    plan: OutboundRedirectLifecyclePlan,
    proxy: Option<TransparentProxyGuard>,
    owner_lock: Option<NftablesOwnerLockGuard>,
}

impl NftablesOutboundTransparentProxyGuard {
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
        self.inner = None;
        let proxy_result = stop_proxy_best_effort(self.proxy.take());
        self.owner_lock = None;
        nft_result.and(proxy_result)
    }
}

impl Drop for NftablesOutboundTransparentProxyGuard {
    fn drop(&mut self) {
        if self.inner.is_some()
            && let Err(error) = self.deactivate_inner()
        {
            eprintln!("outbound transparent proxy cleanup failed during drop: {error}");
        }
    }
}

fn outbound_lifecycle_plan(
    outbound_plan: &TransparentInterceptionOutboundProxyPlan,
    setup_scope: TransparentInterceptionHostRuleSet,
) -> Result<OutboundRedirectLifecyclePlan, TransparentInterceptionError> {
    OutboundRedirectLifecyclePlan::from_spec_and_rule_set(
        outbound_plan.outbound_redirect_artifact().clone(),
        setup_scope,
    )
    .map_err(|error| TransparentInterceptionError::Setup(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::{Arc, Mutex},
    };

    use super::{
        super::{
            command::{CommandResult, IpCommand},
            owner_lock::NoopNftablesOwnerLock,
        },
        *,
    };
    use ::runtime::{
        TransparentInterceptionExecutionPlan, TransparentInterceptionOutboundProxyPlan,
    };
    use interception::{TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan};
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

    #[test]
    fn failed_nft_check_does_not_install_or_start_proxy() {
        let (outbound_plan, proxy_runtime) = managed_outbound_parts();
        let nft = FakeNft::with_check_results([Ok(CommandResult {
            success: false,
            stdout: Vec::new(),
            stderr: b"bad outbound redirect".to_vec(),
        })]);
        let ip = FakeIp::with_results([Ok(CommandResult {
            success: true,
            stdout: br#"[{"addr_info":[{"local":"192.0.2.10"}]}]"#.to_vec(),
            stderr: Vec::new(),
        })]);
        let lifecycle = NftablesOutboundTransparentProxy::with_owner_lock(
            outbound_plan,
            nft.clone(),
            Some(ip.clone()),
            NoopNftablesOwnerLock,
            proxy_runtime,
        );

        let error = match lifecycle.activate(setup_scope()) {
            Ok(_) => panic!("failed nft check must reject activation"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("bad outbound redirect"));
        assert_eq!(nft.checked_scripts().len(), 1);
        assert!(nft.scripts().is_empty());
    }

    #[test]
    fn startup_cleanup_clears_shared_reserved_state() -> Result<(), Box<dyn std::error::Error>> {
        let (outbound_plan, proxy_runtime) = managed_outbound_parts();
        let nft = FakeNft::new();
        let ip = FakeIp::new();
        let mut lifecycle = NftablesOutboundTransparentProxy::with_owner_lock(
            outbound_plan,
            nft.clone(),
            Some(ip.clone()),
            NoopNftablesOwnerLock,
            proxy_runtime,
        );

        let plan = outbound_lifecycle_plan(&lifecycle.outbound_plan, setup_scope())?;
        lifecycle.cleanup_previous_owned_state_best_effort(&plan);

        let nft_scripts = nft.scripts();
        assert_eq!(nft_scripts.len(), 1);
        assert!(nft_scripts[0].contains("destroy table inet sssa_probe"));
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
        Ok(())
    }

    fn managed_outbound_parts() -> (
        TransparentInterceptionOutboundProxyPlan,
        TransparentProxyRuntime,
    ) {
        let config = outbound_config();
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test outbound transparent proxy config should be valid");
        let proxy_runtime = TransparentProxyRuntime::for_execution_plan(&execution_plan);
        let TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound_plan) =
            execution_plan
        else {
            panic!("test config should produce outbound transparent proxy plan");
        };
        (outbound_plan, proxy_runtime)
    }

    fn outbound_config() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::OutboundTransparentProxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        }
    }

    fn setup_scope() -> TransparentInterceptionHostRuleSet {
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                remote_addresses: vec!["203.0.113.10".to_string()],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        );
        match TransparentInterceptionSetupPlan::from_selector(
            Some(&selector),
            TransparentInterceptionSetupDirection::Outbound,
        )
        .expect("test selector should project")
        {
            TransparentInterceptionSetupPlan::HostRules(rules) => rules,
            _ => panic!("test selector should project to host rules"),
        }
    }

    fn success() -> CommandResult {
        CommandResult {
            success: true,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn string_args<const N: usize>(args: [&str; N]) -> Vec<String> {
        args.into_iter().map(ToString::to_string).collect()
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
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeNftState {
                    scripts: Vec::new(),
                    checked_scripts: Vec::new(),
                    results: VecDeque::new(),
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
        state: Arc<Mutex<FakeIpState>>,
    }

    struct FakeIpState {
        args: Vec<Vec<String>>,
        results: VecDeque<io::Result<CommandResult>>,
    }

    impl FakeIp {
        fn new() -> Self {
            Self::with_results(Vec::<io::Result<CommandResult>>::new())
        }

        fn with_results(results: impl IntoIterator<Item = io::Result<CommandResult>>) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeIpState {
                    args: Vec::new(),
                    results: results.into_iter().collect(),
                })),
            }
        }

        fn args(&self) -> Vec<Vec<String>> {
            self.state.lock().expect("fake ip lock").args.clone()
        }
    }

    impl IpCommand for FakeIp {
        fn run(&mut self, args: &[String]) -> io::Result<CommandResult> {
            let mut state = self.state.lock().expect("fake ip lock");
            state.args.push(args.to_vec());
            state.results.pop_front().unwrap_or_else(|| Ok(success()))
        }
    }
}

use super::{
    activation::{
        apply_nft_script, apply_policy_route_operation, checked_nft_setup_owner,
        local_address_inventory, stop_proxy_best_effort,
    },
    command::NftCommand,
    host_routing::{HostRouting, SharedHostRouting},
    owner_lock::{NftablesOwnerLock, NftablesOwnerLockGuard, SystemNftablesOwnerLock},
};
use crate::transparent_interception::{
    TransparentInterceptionActivationScope, TransparentInterceptionError,
    TransparentInterceptionIpFamily,
    proxy::{
        TransparentProxyGuard, TransparentProxyRuntime, prepare_proxy_lifecycle,
        start_proxy_lifecycle,
    },
};
#[cfg(test)]
use ::runtime::TransparentInterceptionExecutionPlan;
use ::runtime::TransparentInterceptionInboundTproxyPlan;
#[cfg(test)]
use interception::TransparentInterceptionHostRuleSet;
#[cfg(test)]
use interception::{TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan};
#[cfg(test)]
use probe_config::EnforcementInterceptionConfig;
use std::sync::Arc;
use transparent_linux::{
    InboundTproxyArtifactSpec, InboundTproxyLifecyclePlan, PolicyRouteOperation,
};

pub(in crate::transparent_interception) struct NftablesTransparentInterception {
    inbound_plan: TransparentInterceptionInboundTproxyPlan,
    nft: Box<dyn NftCommand + Send>,
    host_routing: SharedHostRouting,
    owner_lock: Box<dyn NftablesOwnerLock>,
    proxy_runtime: TransparentProxyRuntime,
}

impl NftablesTransparentInterception {
    pub(super) fn new<N, I>(
        inbound_plan: TransparentInterceptionInboundTproxyPlan,
        nft: N,
        host_routing: I,
        proxy_runtime: TransparentProxyRuntime,
    ) -> Self
    where
        N: NftCommand + Send + 'static,
        I: HostRouting + Send + Sync + 'static,
    {
        Self::with_owner_lock(
            inbound_plan,
            nft,
            host_routing,
            SystemNftablesOwnerLock::default(),
            proxy_runtime,
        )
    }

    fn with_owner_lock<N, I, L>(
        inbound_plan: TransparentInterceptionInboundTproxyPlan,
        nft: N,
        host_routing: I,
        owner_lock: L,
        proxy_runtime: TransparentProxyRuntime,
    ) -> Self
    where
        N: NftCommand + Send + 'static,
        I: HostRouting + Send + Sync + 'static,
        L: NftablesOwnerLock + 'static,
    {
        Self {
            inbound_plan,
            nft: Box::new(nft),
            host_routing: Arc::new(host_routing),
            owner_lock: Box::new(owner_lock),
            proxy_runtime,
        }
    }

    #[cfg(test)]
    fn new_for_test<N, I>(config: EnforcementInterceptionConfig, nft: N, host_routing: I) -> Self
    where
        N: NftCommand + Send + 'static,
        I: HostRouting + Send + Sync + 'static,
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
            host_routing,
            super::owner_lock::NoopNftablesOwnerLock,
            proxy_runtime,
        )
    }

    pub(in crate::transparent_interception) fn activate(
        mut self,
        activation_scope: TransparentInterceptionActivationScope,
    ) -> Result<NftablesTransparentInterceptionGuard, TransparentInterceptionError> {
        let (setup_scope, flow_classifier) = activation_scope.into_parts();
        let plan = InboundTproxyLifecyclePlan::from_spec_and_rule_set(
            InboundTproxyArtifactSpec::new(
                ::runtime::TransparentInterceptionNftablesPlan::reserved(),
                self.inbound_plan.listen_port().get(),
            ),
            setup_scope,
        )
        .map_err(|error| TransparentInterceptionError::Setup(error.to_string()))?;
        let proxy_plan = prepare_proxy_lifecycle(
            &self.inbound_plan,
            plan.listener_families()
                .into_iter()
                .map(TransparentInterceptionIpFamily::from)
                .collect(),
            plan.proxy_bypass_mark(),
            flow_classifier,
            local_address_inventory(self.host_routing.clone()),
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
        if plan.setup_policy_route_operations().is_empty() {
            return Ok(());
        }
        for operation in plan.setup_policy_route_operations() {
            apply_policy_route_operation(&self.host_routing, operation)?;
        }
        Ok(())
    }

    fn cleanup_previous_owned_state_best_effort(&mut self, plan: &InboundTproxyLifecyclePlan) {
        let _ = apply_nft_script(self.nft.as_mut(), &plan.cleanup_nft_script(), "nft cleanup");
        self.cleanup_policy_route_operations_best_effort(
            plan.cleanup_all_policy_route_operations(),
        );
    }

    fn cleanup_active_plan_best_effort(&mut self, plan: &InboundTproxyLifecyclePlan) {
        let _ = apply_nft_script(self.nft.as_mut(), &plan.cleanup_nft_script(), "nft cleanup");
        self.cleanup_policy_route_operations_best_effort(plan.cleanup_policy_route_operations());
    }

    fn cleanup_policy_route_operations_best_effort(
        &mut self,
        operations: Vec<PolicyRouteOperation>,
    ) {
        for operation in operations {
            let _ = apply_policy_route_operation(&self.host_routing, operation);
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
        for operation in self.plan.cleanup_policy_route_operations() {
            if let Err(error) = apply_policy_route_operation(&inner.host_routing, operation) {
                route_result = Err(error);
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

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        net::{IpAddr, Ipv4Addr, TcpListener},
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
    use transparent_linux::TransparentLinuxIpFamily;

    use crate::transparent_interception::{
        TransparentProxyRuntimeHandle, nftables::owner_lock::NoopNftablesOwnerLock,
    };

    use super::super::command::CommandResult;
    use super::*;

    #[test]
    fn activation_installs_routes_before_nft_and_cleanup_reverses_owned_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let nft = FakeNft::succeeding();
        let host_routing = FakeHostRouting::new();
        let config = inbound_config();
        let selector = setup_selector();

        let guard = NftablesTransparentInterception::new_for_test(
            config,
            nft.clone(),
            host_routing.clone(),
        )
        .activate(TransparentInterceptionActivationScope::host_rules(
            setup_scope(&selector),
        ))?;
        guard.deactivate()?;

        let nft_scripts = nft.scripts();
        assert_eq!(nft_scripts.len(), 3);
        assert!(nft_scripts[0].contains("destroy table inet traffic_probe"));
        assert!(nft_scripts[1].contains("add table inet traffic_probe"));
        assert!(nft_scripts[2].contains("destroy table inet traffic_probe"));
        let operations = host_routing.operations();
        assert_eq!(
            operations[0],
            PolicyRouteOperation::delete_fwmark_rule(
                TransparentLinuxIpFamily::Ipv4,
                0x54500101,
                45100
            )
        );
        assert_eq!(
            operations[1],
            PolicyRouteOperation::delete_local_route(TransparentLinuxIpFamily::Ipv4, 45100)
        );
        assert_eq!(
            operations[2],
            PolicyRouteOperation::delete_fwmark_rule(
                TransparentLinuxIpFamily::Ipv6,
                0x54500101,
                45100
            )
        );
        assert_eq!(
            operations[3],
            PolicyRouteOperation::delete_local_route(TransparentLinuxIpFamily::Ipv6, 45100)
        );
        assert_eq!(
            operations[4],
            PolicyRouteOperation::add_fwmark_rule(
                TransparentLinuxIpFamily::Ipv4,
                0x54500101,
                45100
            )
        );
        Ok(())
    }

    #[test]
    fn guard_drop_attempts_cleanup_when_deactivate_is_not_called()
    -> Result<(), Box<dyn std::error::Error>> {
        let nft = FakeNft::succeeding();
        let host_routing = FakeHostRouting::new();
        let selector = setup_selector();

        let guard = NftablesTransparentInterception::new_for_test(
            inbound_config(),
            nft.clone(),
            host_routing.clone(),
        )
        .activate(TransparentInterceptionActivationScope::host_rules(
            setup_scope(&selector),
        ))?;
        drop(guard);

        let nft_scripts = nft.scripts();
        assert_eq!(nft_scripts.len(), 3);
        assert!(nft_scripts[2].contains("destroy table inet traffic_probe"));
        assert!(host_routing.operations().len() >= 8);
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
        let host_routing = FakeHostRouting::new();

        let error = match NftablesTransparentInterception::new_for_test(
            inbound_config(),
            nft.clone(),
            host_routing,
        )
        .activate(TransparentInterceptionActivationScope::host_rules(
            setup_scope(&setup_selector()),
        )) {
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
        let host_routing = FakeHostRouting::new();

        let error = match NftablesTransparentInterception::new_for_test(
            inbound_config(),
            nft.clone(),
            host_routing.clone(),
        )
        .activate(TransparentInterceptionActivationScope::host_rules(
            setup_scope(&setup_selector()),
        )) {
            Ok(_) => panic!("failed nft check must fail activation"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("syntax rejected"));
        assert_eq!(nft.checked_scripts().len(), 1);
        assert!(nft.scripts().is_empty());
        assert!(host_routing.operations().is_empty());
    }

    #[test]
    fn activation_starts_configured_health_probe() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let nft = FakeNft::succeeding();
        let host_routing = FakeHostRouting::new();
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
            host_routing,
            NoopNftablesOwnerLock,
            runtime,
        );

        let guard = lifecycle.activate(TransparentInterceptionActivationScope::host_rules(
            setup_scope(&setup_selector()),
        ))?;
        wait_for_health_probe_success(&handle)?;
        guard.deactivate()?;

        assert!(handle.snapshot().health_probe.check_successes > 0);
        Ok(())
    }

    #[test]
    fn activation_rejects_health_probe_target_on_local_relay_listener_before_host_mutation() {
        let nft = FakeNft::succeeding();
        let host_routing =
            FakeHostRouting::with_local_addresses([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let mut config = inbound_config();
        config.proxy.mode = probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay;
        config.proxy.health_probe = TransparentInterceptionProxyHealthProbeConfig {
            target: Some("192.0.2.10:15001".to_string()),
            interval_ms: 100,
            timeout_ms: 10,
            failure_threshold: 1,
        };

        let error = match NftablesTransparentInterception::new_for_test(
            config,
            nft.clone(),
            host_routing.clone(),
        )
        .activate(TransparentInterceptionActivationScope::host_rules(
            setup_scope(&setup_selector()),
        )) {
            Ok(_) => panic!("local relay listener health probe target must fail activation"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("local relay listener"));
        assert!(nft.scripts().is_empty());
        assert!(host_routing.operations().is_empty());
    }

    #[test]
    fn startup_cleanup_removes_all_owned_route_families_before_projected_install()
    -> Result<(), Box<dyn std::error::Error>> {
        let nft = FakeNft::succeeding();
        let host_routing = FakeHostRouting::new();
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                remote_addresses: vec!["203.0.113.10".to_string()],
                ..TrafficSelector::default()
            },
        );

        let guard = NftablesTransparentInterception::new_for_test(
            inbound_config(),
            nft,
            host_routing.clone(),
        )
        .activate(TransparentInterceptionActivationScope::host_rules(
            setup_scope(&selector),
        ))?;
        guard.deactivate()?;

        let operations = host_routing.operations();
        assert_eq!(
            operations[0],
            PolicyRouteOperation::delete_fwmark_rule(
                TransparentLinuxIpFamily::Ipv4,
                0x54500101,
                45100
            )
        );
        assert_eq!(
            operations[1],
            PolicyRouteOperation::delete_local_route(TransparentLinuxIpFamily::Ipv4, 45100)
        );
        assert_eq!(
            operations[2],
            PolicyRouteOperation::delete_fwmark_rule(
                TransparentLinuxIpFamily::Ipv6,
                0x54500101,
                45100
            )
        );
        assert_eq!(
            operations[3],
            PolicyRouteOperation::delete_local_route(TransparentLinuxIpFamily::Ipv6, 45100)
        );
        assert_eq!(
            operations[4],
            PolicyRouteOperation::add_fwmark_rule(
                TransparentLinuxIpFamily::Ipv4,
                0x54500101,
                45100
            )
        );
        assert_eq!(
            operations[5],
            PolicyRouteOperation::replace_local_route(TransparentLinuxIpFamily::Ipv4, 45100)
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
            ..EnforcementInterceptionConfig::default()
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

    fn setup_scope(selector: &Selector) -> TransparentInterceptionHostRuleSet {
        match TransparentInterceptionSetupPlan::from_selector(
            Some(selector),
            TransparentInterceptionSetupDirection::Inbound,
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
    struct FakeHostRouting {
        state: Arc<Mutex<FakeHostRoutingState>>,
    }

    struct FakeHostRoutingState {
        local_addresses: Vec<IpAddr>,
        operations: Vec<PolicyRouteOperation>,
    }

    impl FakeHostRouting {
        fn new() -> Self {
            Self::with_local_addresses([])
        }

        fn with_local_addresses(addresses: impl IntoIterator<Item = IpAddr>) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeHostRoutingState {
                    local_addresses: addresses.into_iter().collect(),
                    operations: Vec::new(),
                })),
            }
        }

        fn operations(&self) -> Vec<PolicyRouteOperation> {
            self.state
                .lock()
                .expect("fake host routing lock")
                .operations
                .clone()
        }
    }

    impl HostRouting for FakeHostRouting {
        fn local_addresses(&self) -> Result<Vec<IpAddr>, TransparentInterceptionError> {
            Ok(self
                .state
                .lock()
                .expect("fake host routing lock")
                .local_addresses
                .clone())
        }

        fn apply_policy_route_operation(
            &self,
            operation: PolicyRouteOperation,
        ) -> Result<(), TransparentInterceptionError> {
            self.state
                .lock()
                .expect("fake host routing lock")
                .operations
                .push(operation);
            Ok(())
        }
    }
}

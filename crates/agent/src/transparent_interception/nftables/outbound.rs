use ::runtime::TransparentInterceptionOutboundProxyPlan;
use transparent_linux::{
    OutboundRedirectLifecyclePlan, TransparentLinuxResources, cleanup_all_policy_route_operations,
};

use super::{
    activation::{
        apply_nft_script, apply_policy_route_operation, checked_nft_setup_owner,
        local_address_inventory, stop_proxy_best_effort,
    },
    command::{NftCommand, SystemNft},
    host_routing::{HostRouting, SharedHostRouting},
    owner_lock::{NftablesOwnerLock, NftablesOwnerLockGuard, SystemNftablesOwnerLock},
};
use crate::transparent_interception::{
    TransparentInterceptionActivationScope, TransparentInterceptionError,
    TransparentInterceptionIpFamily,
    proxy::{
        TransparentProxyGuard, TransparentProxyRuntime, prepare_outbound_proxy_lifecycle,
        start_proxy_lifecycle,
    },
};

pub(in crate::transparent_interception) struct NftablesOutboundTransparentProxy {
    outbound_plan: TransparentInterceptionOutboundProxyPlan,
    nft: Box<dyn NftCommand + Send>,
    host_routing: SharedHostRouting,
    owner_lock: Box<dyn NftablesOwnerLock>,
    proxy_runtime: TransparentProxyRuntime,
}

impl NftablesOutboundTransparentProxy {
    pub(super) fn new(
        outbound_plan: TransparentInterceptionOutboundProxyPlan,
        nft: SystemNft,
        host_routing: impl HostRouting + Send + Sync + 'static,
        proxy_runtime: TransparentProxyRuntime,
    ) -> Self {
        Self::with_owner_lock(
            outbound_plan,
            nft,
            host_routing,
            SystemNftablesOwnerLock::default(),
            proxy_runtime,
        )
    }

    fn with_owner_lock<N, I, L>(
        outbound_plan: TransparentInterceptionOutboundProxyPlan,
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
            outbound_plan,
            nft: Box::new(nft),
            host_routing: std::sync::Arc::new(host_routing),
            owner_lock: Box::new(owner_lock),
            proxy_runtime,
        }
    }

    pub(in crate::transparent_interception) fn activate(
        mut self,
        activation_scope: TransparentInterceptionActivationScope,
    ) -> Result<NftablesOutboundTransparentProxyGuard, TransparentInterceptionError> {
        let (setup_scope, flow_classifier) = activation_scope.into_parts();
        let plan = outbound_lifecycle_plan(&self.outbound_plan, setup_scope)?;
        let proxy_plan = prepare_outbound_proxy_lifecycle(
            &self.outbound_plan,
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
        let resources = TransparentLinuxResources::reserved();
        for operation in cleanup_all_policy_route_operations(
            resources.inbound_tproxy_mark,
            resources.inbound_tproxy_route_table,
        ) {
            let _ = apply_policy_route_operation(&self.host_routing, operation);
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
    setup_scope: interception::TransparentInterceptionHostRuleSet,
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
        super::{command::CommandResult, owner_lock::NoopNftablesOwnerLock},
        *,
    };
    use ::runtime::{
        TransparentInterceptionExecutionPlan, TransparentInterceptionOutboundProxyPlan,
    };
    use interception::{
        TransparentInterceptionHostRuleSet, TransparentInterceptionSetupDirection,
        TransparentInterceptionSetupPlan,
    };
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};
    use transparent_linux::{PolicyRouteOperation, TransparentLinuxIpFamily};

    #[test]
    fn failed_nft_check_does_not_install_or_start_proxy() {
        let (outbound_plan, proxy_runtime) = managed_outbound_parts();
        let nft = FakeNft::with_check_results([Ok(CommandResult {
            success: false,
            stdout: Vec::new(),
            stderr: b"bad outbound redirect".to_vec(),
        })]);
        let host_routing = FakeHostRouting::new();
        let lifecycle = NftablesOutboundTransparentProxy::with_owner_lock(
            outbound_plan,
            nft.clone(),
            host_routing,
            NoopNftablesOwnerLock,
            proxy_runtime,
        );

        let error = match lifecycle.activate(TransparentInterceptionActivationScope::host_rules(
            setup_scope(),
        )) {
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
        let host_routing = FakeHostRouting::new();
        let mut lifecycle = NftablesOutboundTransparentProxy::with_owner_lock(
            outbound_plan,
            nft.clone(),
            host_routing.clone(),
            NoopNftablesOwnerLock,
            proxy_runtime,
        );

        let plan = outbound_lifecycle_plan(&lifecycle.outbound_plan, setup_scope())?;
        lifecycle.cleanup_previous_owned_state_best_effort(&plan);

        let nft_scripts = nft.scripts();
        assert_eq!(nft_scripts.len(), 1);
        assert!(nft_scripts[0].contains("destroy table inet traffic_probe"));
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
    struct FakeHostRouting {
        operations: Arc<Mutex<Vec<PolicyRouteOperation>>>,
    }

    impl FakeHostRouting {
        fn new() -> Self {
            Self {
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn operations(&self) -> Vec<PolicyRouteOperation> {
            self.operations
                .lock()
                .expect("fake host routing lock")
                .clone()
        }
    }

    impl HostRouting for FakeHostRouting {
        fn local_addresses(&self) -> Result<Vec<std::net::IpAddr>, TransparentInterceptionError> {
            Ok(Vec::new())
        }

        fn apply_policy_route_operation(
            &self,
            operation: PolicyRouteOperation,
        ) -> Result<(), TransparentInterceptionError> {
            self.operations
                .lock()
                .expect("fake host routing lock")
                .push(operation);
            Ok(())
        }
    }
}

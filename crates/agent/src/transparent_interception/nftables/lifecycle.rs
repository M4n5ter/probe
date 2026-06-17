use super::{
    command::{CommandResult, IpCommand, NftCommand},
    owner_lock::{NftablesOwnerLock, NftablesOwnerLockGuard, SystemNftablesOwnerLock},
    plan::InboundTproxyLifecyclePlan,
};
use crate::transparent_interception::TransparentInterceptionError;
use probe_config::EnforcementInterceptionConfig;
use probe_core::Selector;

pub(in crate::transparent_interception) struct NftablesTransparentInterception {
    config: EnforcementInterceptionConfig,
    nft: Box<dyn NftCommand + Send>,
    ip: Option<Box<dyn IpCommand + Send>>,
    owner_lock: Box<dyn NftablesOwnerLock>,
}

impl NftablesTransparentInterception {
    pub(super) fn new<N, I>(config: EnforcementInterceptionConfig, nft: N, ip: Option<I>) -> Self
    where
        N: NftCommand + Send + 'static,
        I: IpCommand + Send + 'static,
    {
        Self::with_owner_lock(config, nft, ip, SystemNftablesOwnerLock::default())
    }

    fn with_owner_lock<N, I, L>(
        config: EnforcementInterceptionConfig,
        nft: N,
        ip: Option<I>,
        owner_lock: L,
    ) -> Self
    where
        N: NftCommand + Send + 'static,
        I: IpCommand + Send + 'static,
        L: NftablesOwnerLock + 'static,
    {
        Self {
            config,
            nft: Box::new(nft),
            ip: ip.map(|ip| Box::new(ip) as Box<dyn IpCommand + Send>),
            owner_lock: Box::new(owner_lock),
        }
    }

    #[cfg(test)]
    fn new_for_test<N, I>(config: EnforcementInterceptionConfig, nft: N, ip: Option<I>) -> Self
    where
        N: NftCommand + Send + 'static,
        I: IpCommand + Send + 'static,
    {
        Self::with_owner_lock(config, nft, ip, super::owner_lock::NoopNftablesOwnerLock)
    }

    pub(in crate::transparent_interception) fn activate(
        mut self,
        effective_enforcement_selector: Option<&Selector>,
    ) -> Result<NftablesTransparentInterceptionGuard, TransparentInterceptionError> {
        let setup_selector = super::super::effective_setup_selector(
            effective_enforcement_selector,
            self.config.selector.as_ref(),
        );
        let plan = InboundTproxyLifecyclePlan::from_config_and_scope(
            &self.config,
            setup_selector.as_ref(),
        )
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
        let setup_script = plan.setup_nft_script();
        check_nft_script(self.nft.as_mut(), &setup_script)?;
        let owner_lock = self.owner_lock.acquire(plan.owner_name())?;
        self.cleanup_previous_owned_state_best_effort(&plan);
        if let Err(error) = self.install_policy_routes(&plan) {
            self.cleanup_active_plan_best_effort(&plan);
            return Err(error);
        }
        if let Err(error) = apply_nft_script(self.nft.as_mut(), &setup_script, "nft setup") {
            self.cleanup_active_plan_best_effort(&plan);
            return Err(error);
        }
        Ok(NftablesTransparentInterceptionGuard {
            inner: Some(self),
            plan,
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
        let Some(ip) = inner.ip.as_mut() else {
            self.inner = None;
            self.owner_lock = None;
            return nft_result;
        };
        for command in self.plan.cleanup_ip_commands() {
            if let Err(error) = apply_ip_command(ip.as_mut(), &command, "ip cleanup") {
                route_result = Err(error);
            }
        }
        self.inner = None;
        self.owner_lock = None;
        nft_result.and(route_result)
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
        sync::{Arc, Mutex},
    };

    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

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
                .activate(Some(&selector))?;
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
    fn outbound_mitm_activation_fails_before_host_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let nft = FakeNft::succeeding();
        let ip = FakeIp::succeeding();
        let config = outbound_config();
        let selector = outbound_selector();

        let error = match NftablesTransparentInterception::new_for_test(
            config,
            nft.clone(),
            Some(ip.clone()),
        )
        .activate(Some(&selector))
        {
            Ok(_) => panic!("outbound MITM lifecycle must fail closed before host mutation"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("supports inbound TPROXY only"));
        assert!(nft.checked_scripts().is_empty());
        assert!(nft.scripts().is_empty());
        assert!(ip.args().is_empty());
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
        .activate(Some(&selector))?;
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
        .activate(Some(&setup_selector()))
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
        .activate(Some(&setup_selector()))
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
                .activate(Some(&selector))?;
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
            },
        }
    }

    fn outbound_config() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::OutboundMitm,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
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

    fn outbound_selector() -> Selector {
        Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
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

use interception::TransparentInterceptionHostRuleScope;
use runtime::TransparentInterceptionOutboundRedirectPlan;

use super::{
    NftablesPlanError, hex_mark,
    projection::{NftRule, NftSelectorProjection},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::transparent_interception::nftables) struct OutboundRedirectLifecyclePlan {
    table_name: String,
    chain_name: String,
    hook: String,
    priority: String,
    proxy_port: u16,
    proxy_bypass_mark: u32,
    rules: Vec<NftRule>,
}

impl OutboundRedirectLifecyclePlan {
    pub(in crate::transparent_interception::nftables) fn from_redirect_plan_and_scope(
        redirect: &TransparentInterceptionOutboundRedirectPlan,
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<Self, NftablesPlanError> {
        let TransparentInterceptionOutboundRedirectPlan::Planned {
            table_name,
            chain_name,
            hook,
            priority,
            proxy_port,
            proxy_bypass_mark,
            ..
        } = redirect
        else {
            return Err(NftablesPlanError::OutboundRedirectNotPlanned);
        };
        if setup_scope.remote_ports().is_any() {
            return Err(NftablesPlanError::OutboundRedirectRequiresRemotePorts {
                proxy_port: *proxy_port,
            });
        }
        Ok(Self {
            table_name: table_name.clone(),
            chain_name: chain_name.clone(),
            hook: hook.clone(),
            priority: priority.clone(),
            proxy_port: *proxy_port,
            proxy_bypass_mark: *proxy_bypass_mark,
            rules: NftSelectorProjection::outbound_redirect(setup_scope).into_rules(),
        })
    }

    pub(in crate::transparent_interception::nftables) fn setup_nft_script(&self) -> String {
        let mut lines = vec![
            format!("destroy table inet {}", self.table_name),
            format!("add table inet {}", self.table_name),
            self.add_chain_command(),
            self.add_proxy_bypass_rule_command(),
        ];
        lines.extend(self.rules.iter().map(|rule| self.add_rule_command(rule)));
        lines.join("\n") + "\n"
    }

    fn add_chain_command(&self) -> String {
        format!(
            "add chain inet {} {} {{ type nat hook {} priority {}; policy accept; }}",
            self.table_name, self.chain_name, self.hook, self.priority
        )
    }

    fn add_proxy_bypass_rule_command(&self) -> String {
        format!(
            "add rule inet {} {} meta mark {} return",
            self.table_name,
            self.chain_name,
            hex_mark(self.proxy_bypass_mark)
        )
    }

    fn add_rule_command(&self, rule: &NftRule) -> String {
        format!(
            "add rule inet {} {} {} redirect to :{}",
            self.table_name,
            self.chain_name,
            rule.match_expression(),
            self.proxy_port
        )
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};
    use runtime::{
        TransparentInterceptionNftablesPlan, TransparentInterceptionOutboundRedirectInstallPlan,
    };

    use super::*;

    #[test]
    fn outbound_redirect_plan_projects_remote_selector_to_output_redirect() {
        let config = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                remote_addresses: vec!["203.0.113.10".to_string()],
                ..TrafficSelector::default()
            },
        )));
        let plan = lifecycle_plan(
            &config,
            setup_scope(config.selector.as_ref().expect("selector should be set")),
        )
        .expect("selector should be projectable");

        let script = plan.setup_nft_script();
        let lines = script.lines().collect::<Vec<_>>();

        assert_eq!(
            lines,
            vec![
                "destroy table inet sssa_probe",
                "add table inet sssa_probe",
                "add chain inet sssa_probe outbound_mitm { type nat hook output priority dstnat; policy accept; }",
                "add rule inet sssa_probe outbound_mitm meta mark 0x53534102 return",
                "add rule inet sssa_probe outbound_mitm meta l4proto tcp meta nfproto ipv4 tcp dport 443 ip daddr 203.0.113.10 redirect to :15001",
            ]
        );
    }

    #[test]
    fn outbound_redirect_requires_explicit_remote_ports() {
        let config = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                directions: vec![Direction::Outbound],
                remote_addresses: vec!["203.0.113.10".to_string()],
                ..TrafficSelector::default()
            },
        )));

        let error = lifecycle_plan(
            &config,
            setup_scope(config.selector.as_ref().expect("selector should be set")),
        )
        .expect_err("wildcard remote ports would redirect too much outbound traffic");

        assert!(matches!(
            error,
            NftablesPlanError::OutboundRedirectRequiresRemotePorts { proxy_port: 15001 }
        ));
    }

    #[test]
    fn outbound_redirect_allows_original_destination_port_equal_to_proxy_port() {
        let config = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![15001],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )));

        let plan = lifecycle_plan(
            &config,
            setup_scope(config.selector.as_ref().expect("selector should be set")),
        )
        .expect("remote port equal to proxy listen port is a valid original destination");

        assert!(
            plan.setup_nft_script()
                .contains("tcp dport 15001 redirect to :15001")
        );
    }

    fn interception_config(selector: Option<Selector>) -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::OutboundMitm,
            selector,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
        }
    }

    fn setup_scope(selector: &Selector) -> TransparentInterceptionHostRuleScope {
        match interception::TransparentInterceptionSetupPlan::from_outbound_mitm_selector(Some(
            selector,
        ))
        .expect("test selector should project")
        {
            interception::TransparentInterceptionSetupPlan::HostRules(scope) => scope,
            _ => panic!("test selector should project to host rules"),
        }
    }

    fn lifecycle_plan(
        config: &EnforcementInterceptionConfig,
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<OutboundRedirectLifecyclePlan, NftablesPlanError> {
        let host_resources = TransparentInterceptionNftablesPlan::reserved();
        let redirect = TransparentInterceptionOutboundRedirectPlan::Planned {
            table_name: host_resources.table_name,
            chain_name: "outbound_mitm".to_string(),
            hook: "output".to_string(),
            priority: "dstnat".to_string(),
            proxy_port: config
                .proxy
                .listen_port
                .expect("test config should have proxy listen port"),
            proxy_bypass_mark: host_resources.outbound_proxy_bypass_mark,
            install: TransparentInterceptionOutboundRedirectInstallPlan::Blocked {
                reason: "test blocked".to_string(),
            },
        };
        OutboundRedirectLifecyclePlan::from_redirect_plan_and_scope(&redirect, setup_scope)
    }
}

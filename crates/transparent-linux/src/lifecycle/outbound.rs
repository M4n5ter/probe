use interception::TransparentInterceptionHostRuleScope;
#[cfg(test)]
use interception::TransparentInterceptionSetupDirection;

use super::{
    OutboundRedirectArtifactSpec, TransparentLinuxIpFamily, TransparentLinuxPlanError, hex_mark,
    projection::{NftFamily, NftRule, NftSelectorProjection},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRedirectLifecyclePlan {
    table_name: String,
    chain_name: String,
    hook: String,
    priority: String,
    proxy_port: u16,
    proxy_bypass_mark: u32,
    rules: Vec<NftRule>,
}

impl OutboundRedirectLifecyclePlan {
    pub fn from_spec_and_scope(
        spec: OutboundRedirectArtifactSpec,
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<Self, TransparentLinuxPlanError> {
        if setup_scope.remote_ports().is_any() {
            return Err(
                TransparentLinuxPlanError::OutboundRedirectRequiresRemotePorts {
                    proxy_port: spec.proxy_port,
                },
            );
        }
        Ok(Self {
            table_name: spec.table_name,
            chain_name: spec.chain_name,
            hook: spec.hook,
            priority: spec.priority,
            proxy_port: spec.proxy_port,
            proxy_bypass_mark: spec.proxy_bypass_mark,
            rules: NftSelectorProjection::outbound_redirect(setup_scope).into_rules(),
        })
    }

    pub fn setup_nft_script(&self) -> String {
        let mut lines = vec![
            format!("destroy table inet {}", self.table_name),
            format!("add table inet {}", self.table_name),
            self.add_chain_command(),
            self.add_proxy_bypass_rule_command(),
        ];
        lines.extend(self.rules.iter().map(|rule| self.add_rule_command(rule)));
        lines.join("\n") + "\n"
    }

    pub fn cleanup_nft_script(&self) -> String {
        format!("destroy table inet {}\n", self.table_name)
    }

    pub fn owner_name(&self) -> &str {
        &self.table_name
    }

    pub fn listener_families(&self) -> Vec<TransparentLinuxIpFamily> {
        let mut families = Vec::new();
        if self
            .rules
            .iter()
            .any(|rule| rule.family() == NftFamily::Ipv4)
        {
            families.push(TransparentLinuxIpFamily::Ipv4);
        }
        if self
            .rules
            .iter()
            .any(|rule| rule.family() == NftFamily::Ipv6)
        {
            families.push(TransparentLinuxIpFamily::Ipv6);
        }
        families
    }

    pub fn proxy_bypass_mark(&self) -> u32 {
        self.proxy_bypass_mark
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
                "add chain inet sssa_probe outbound_transparent_proxy { type nat hook output priority dstnat; policy accept; }",
                "add rule inet sssa_probe outbound_transparent_proxy meta mark 0x53534102 return",
                "add rule inet sssa_probe outbound_transparent_proxy meta l4proto tcp meta nfproto ipv4 tcp dport 443 ip daddr 203.0.113.10 redirect to :15001",
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
            TransparentLinuxPlanError::OutboundRedirectRequiresRemotePorts { proxy_port: 15001 }
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
            strategy: TransparentInterceptionStrategyConfig::OutboundTransparentProxy,
            selector,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
        }
    }

    fn setup_scope(selector: &Selector) -> TransparentInterceptionHostRuleScope {
        match interception::TransparentInterceptionSetupPlan::from_selector(
            Some(selector),
            TransparentInterceptionSetupDirection::Outbound,
        )
        .expect("test selector should project")
        {
            interception::TransparentInterceptionSetupPlan::HostRules(scope) => scope,
            _ => panic!("test selector should project to host rules"),
        }
    }

    fn lifecycle_plan(
        config: &EnforcementInterceptionConfig,
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<OutboundRedirectLifecyclePlan, TransparentLinuxPlanError> {
        OutboundRedirectLifecyclePlan::from_spec_and_scope(
            OutboundRedirectArtifactSpec::outbound_transparent_proxy(
                crate::TransparentLinuxResources::reserved(),
                config
                    .proxy
                    .listen_port
                    .expect("test config should have proxy listen port"),
            ),
            setup_scope,
        )
    }
}

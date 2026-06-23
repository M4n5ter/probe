use interception::TransparentInterceptionHostRuleScope;
#[cfg(test)]
use interception::TransparentInterceptionSetupPlan;
use runtime::{TransparentInterceptionInboundTproxyPlan, TransparentInterceptionNftablesPlan};

use super::{
    INBOUND_TPROXY_OWNER_LOCK, NftablesPlanError, hex_mark,
    projection::{NftFamily, NftRule, NftSelectorProjection},
};
use crate::transparent_interception::TransparentInterceptionIpFamily;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::transparent_interception::nftables) struct InboundTproxyLifecyclePlan {
    table_name: String,
    proxy_port: u16,
    mark: u32,
    route_table: u32,
    rules: Vec<NftRule>,
}

impl InboundTproxyLifecyclePlan {
    pub(in crate::transparent_interception::nftables) fn from_inbound_plan_and_scope(
        plan: &TransparentInterceptionInboundTproxyPlan,
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<Self, NftablesPlanError> {
        let proxy_port = plan.listen_port().get();
        if setup_scope.local_ports().is_any() {
            return Err(NftablesPlanError::WildcardLocalPortsRequireProxyBypass { proxy_port });
        }
        if setup_scope.local_ports().contains(proxy_port) {
            return Err(NftablesPlanError::ProxyPortInInterceptedLocalPorts { proxy_port });
        }
        let projection = NftSelectorProjection::inbound_tproxy(setup_scope);
        let host_resources = TransparentInterceptionNftablesPlan::reserved();
        Ok(Self {
            table_name: host_resources.table_name,
            proxy_port,
            mark: host_resources.inbound_tproxy_mark,
            route_table: host_resources.inbound_tproxy_route_table,
            rules: projection.into_rules(),
        })
    }

    pub(in crate::transparent_interception::nftables) fn setup_nft_script(&self) -> String {
        let mut lines = vec![
            format!("destroy table inet {}", self.table_name),
            format!("add table inet {}", self.table_name),
            self.add_chain_command(),
        ];
        lines.extend(self.rules.iter().map(|rule| self.add_rule_command(rule)));
        lines.join("\n") + "\n"
    }

    pub(in crate::transparent_interception::nftables) fn cleanup_nft_script(&self) -> String {
        format!("destroy table inet {}\n", self.table_name)
    }

    pub(in crate::transparent_interception::nftables) fn setup_ip_commands(
        &self,
    ) -> Vec<Vec<String>> {
        self.policy_route_families()
            .into_iter()
            .flat_map(|family| {
                [
                    family.rule_command("add", self.mark, self.route_table),
                    family.route_command("replace", self.route_table),
                ]
            })
            .collect()
    }

    pub(in crate::transparent_interception::nftables) fn cleanup_ip_commands(
        &self,
    ) -> Vec<Vec<String>> {
        self.policy_route_families()
            .into_iter()
            .flat_map(|family| {
                [
                    family.rule_command("del", self.mark, self.route_table),
                    family.route_command("del", self.route_table),
                ]
            })
            .collect()
    }

    pub(in crate::transparent_interception::nftables) fn cleanup_all_ip_commands(
        &self,
    ) -> Vec<Vec<String>> {
        TransparentInterceptionIpFamily::all()
            .into_iter()
            .flat_map(|family| {
                [
                    family.rule_command("del", self.mark, self.route_table),
                    family.route_command("del", self.route_table),
                ]
            })
            .collect()
    }

    pub(in crate::transparent_interception::nftables) fn owner_name(&self) -> &'static str {
        INBOUND_TPROXY_OWNER_LOCK
    }

    pub(in crate::transparent_interception) fn listener_families(
        &self,
    ) -> Vec<TransparentInterceptionIpFamily> {
        self.policy_route_families()
    }

    fn policy_route_families(&self) -> Vec<TransparentInterceptionIpFamily> {
        let mut families = Vec::new();
        if self
            .rules
            .iter()
            .any(|rule| rule.family() == NftFamily::Ipv4)
        {
            families.push(TransparentInterceptionIpFamily::Ipv4);
        }
        if self
            .rules
            .iter()
            .any(|rule| rule.family() == NftFamily::Ipv6)
        {
            families.push(TransparentInterceptionIpFamily::Ipv6);
        }
        families
    }

    fn add_chain_command(&self) -> String {
        format!(
            "add chain inet {} inbound_tproxy {{ type filter hook prerouting priority mangle; policy accept; }}",
            self.table_name
        )
    }

    fn add_rule_command(&self, rule: &NftRule) -> String {
        format!(
            "add rule inet {} inbound_tproxy {} tproxy {} to :{} meta mark set {}",
            self.table_name,
            rule.match_expression(),
            rule.family().nft_address_family(),
            self.proxy_port,
            hex_mark(self.mark),
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
    use runtime::TransparentInterceptionExecutionPlan;

    use super::*;

    #[test]
    fn inbound_tproxy_plan_projects_traffic_selector_to_nft_and_policy_routing() {
        let config = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                remote_ports: Vec::new(),
                directions: vec![Direction::Inbound],
                remote_addresses: vec!["203.0.113.10".to_string()],
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
                "add chain inet sssa_probe inbound_tproxy { type filter hook prerouting priority mangle; policy accept; }",
                "add rule inet sssa_probe inbound_tproxy meta l4proto tcp meta nfproto ipv4 tcp dport 8443 ip saddr 203.0.113.10 tproxy ip to :15001 meta mark set 0x53534101",
            ]
        );
        assert_eq!(
            plan.setup_ip_commands(),
            vec![
                vec!["rule", "add", "fwmark", "0x53534101", "lookup", "53534"],
                vec![
                    "route",
                    "replace",
                    "local",
                    "0.0.0.0/0",
                    "dev",
                    "lo",
                    "table",
                    "53534"
                ],
            ]
        );
    }

    #[test]
    fn unconstrained_remote_address_projects_both_policy_route_families() {
        let config = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )));
        let plan = lifecycle_plan(
            &config,
            setup_scope(config.selector.as_ref().expect("selector should be set")),
        )
        .expect("selector should be projectable");

        assert_eq!(
            plan.setup_ip_commands(),
            vec![
                vec!["rule", "add", "fwmark", "0x53534101", "lookup", "53534"],
                vec![
                    "route",
                    "replace",
                    "local",
                    "0.0.0.0/0",
                    "dev",
                    "lo",
                    "table",
                    "53534"
                ],
                vec![
                    "-6",
                    "rule",
                    "add",
                    "fwmark",
                    "0x53534101",
                    "lookup",
                    "53534"
                ],
                vec![
                    "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", "53534"
                ],
            ]
        );
    }

    #[test]
    fn executable_owner_lock_stays_on_the_inbound_tproxy_lifecycle() {
        let first = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )));
        let second = first.clone();

        let first_scope = setup_scope(first.selector.as_ref().expect("selector should be set"));
        let first_plan =
            lifecycle_plan(&first, first_scope.clone()).expect("first plan should be valid");
        let second_plan =
            lifecycle_plan(&second, first_scope).expect("second plan should be valid");

        assert_eq!(first_plan.owner_name(), "inbound_tproxy");
        assert_eq!(second_plan.owner_name(), "inbound_tproxy");
    }

    #[test]
    fn proxy_port_cannot_be_in_intercepted_local_ports() {
        let config = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![15001],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )));

        let error = lifecycle_plan(
            &config,
            setup_scope(config.selector.as_ref().expect("selector should be set")),
        )
        .expect_err("proxy port should not be intercepted by its own TPROXY plan");

        assert!(matches!(
            error,
            NftablesPlanError::ProxyPortInInterceptedLocalPorts { proxy_port: 15001 }
        ));
    }

    #[test]
    fn wildcard_local_ports_require_proxy_bypass() {
        let config = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )));

        let error = lifecycle_plan(
            &config,
            setup_scope(config.selector.as_ref().expect("selector should be set")),
        )
        .expect_err("wildcard local ports would intercept the proxy itself");

        assert!(matches!(
            error,
            NftablesPlanError::WildcardLocalPortsRequireProxyBypass { proxy_port: 15001 }
        ));
    }

    fn interception_config(selector: Option<Selector>) -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            selector,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
        }
    }

    fn setup_scope(selector: &Selector) -> TransparentInterceptionHostRuleScope {
        match TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(selector))
            .expect("test selector should project")
        {
            TransparentInterceptionSetupPlan::HostRules(scope) => scope,
            _ => panic!("test selector should project to host rules"),
        }
    }

    fn lifecycle_plan(
        config: &EnforcementInterceptionConfig,
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<InboundTproxyLifecyclePlan, NftablesPlanError> {
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(config)
            .expect("test transparent interception config should be valid");
        let TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) = execution_plan
        else {
            panic!("test transparent interception config should use inbound TPROXY");
        };
        InboundTproxyLifecyclePlan::from_inbound_plan_and_scope(&inbound_plan, setup_scope)
    }
}

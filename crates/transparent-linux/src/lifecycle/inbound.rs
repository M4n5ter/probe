use interception::TransparentInterceptionHostRuleSet;
#[cfg(test)]
use interception::{TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan};

use super::{
    InboundTproxyArtifactSpec, TransparentLinuxIpFamily, TransparentLinuxPlanError,
    cleanup_all_policy_route_ip_commands, hex_mark,
    projection::{NftFamily, NftRule, NftSelectorProjection},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundTproxyLifecyclePlan {
    table_name: String,
    proxy_port: u16,
    mark: u32,
    route_table: u32,
    rules: Vec<NftRule>,
}

impl InboundTproxyLifecyclePlan {
    pub fn from_spec_and_rule_set(
        spec: InboundTproxyArtifactSpec,
        setup_rules: TransparentInterceptionHostRuleSet,
    ) -> Result<Self, TransparentLinuxPlanError> {
        let proxy_port = spec.proxy_port;
        let mut rules = Vec::new();
        for setup_scope in setup_rules.scopes() {
            if setup_scope.local_ports().is_any() {
                return Err(
                    TransparentLinuxPlanError::WildcardLocalPortsRequireProxyBypass { proxy_port },
                );
            }
            if setup_scope.local_ports().contains(proxy_port) {
                return Err(
                    TransparentLinuxPlanError::ProxyPortInInterceptedLocalPorts { proxy_port },
                );
            }
            rules.extend(NftSelectorProjection::inbound_tproxy(setup_scope.clone()).into_rules());
        }
        Ok(Self {
            table_name: spec.resources.table_name,
            proxy_port,
            mark: spec.resources.inbound_tproxy_mark,
            route_table: spec.resources.inbound_tproxy_route_table,
            rules,
        })
    }

    pub fn setup_nft_script(&self) -> String {
        let mut lines = vec![
            format!("destroy table inet {}", self.table_name),
            format!("add table inet {}", self.table_name),
            self.add_chain_command(),
        ];
        lines.extend(self.rules.iter().map(|rule| self.add_rule_command(rule)));
        lines.join("\n") + "\n"
    }

    pub fn cleanup_nft_script(&self) -> String {
        format!("destroy table inet {}\n", self.table_name)
    }

    pub fn setup_ip_commands(&self) -> Vec<Vec<String>> {
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

    pub fn cleanup_ip_commands(&self) -> Vec<Vec<String>> {
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

    pub fn cleanup_all_ip_commands(&self) -> Vec<Vec<String>> {
        cleanup_all_policy_route_ip_commands(self.mark, self.route_table)
    }

    pub fn owner_name(&self) -> &str {
        &self.table_name
    }

    pub fn listener_families(&self) -> Vec<TransparentLinuxIpFamily> {
        self.policy_route_families()
    }

    fn policy_route_families(&self) -> Vec<TransparentLinuxIpFamily> {
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
    use crate::{
        OutboundRedirectArtifactSpec, OutboundRedirectLifecyclePlan, TransparentLinuxResources,
    };
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

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
            setup_rule_set(config.selector.as_ref().expect("selector should be set")),
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
    fn inbound_tproxy_plan_projects_disjoint_host_rule_set_to_tproxy_rules() {
        let config = interception_config(Some(Selector::Any {
            selectors: vec![
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![8443],
                        directions: vec![Direction::Inbound],
                        remote_addresses: vec!["203.0.113.10".to_string()],
                        ..TrafficSelector::default()
                    },
                ),
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![9443],
                        directions: vec![Direction::Inbound],
                        remote_addresses: vec!["203.0.113.20".to_string()],
                        ..TrafficSelector::default()
                    },
                ),
            ],
        }));
        let plan = lifecycle_plan_for_rule_set(
            &config,
            setup_rule_set(config.selector.as_ref().expect("selector should be set")),
        )
        .expect("disjoint selector should project to executable tproxy rules");

        let script = plan.setup_nft_script();
        let lines = script.lines().collect::<Vec<_>>();

        assert_eq!(
            lines,
            vec![
                "destroy table inet sssa_probe",
                "add table inet sssa_probe",
                "add chain inet sssa_probe inbound_tproxy { type filter hook prerouting priority mangle; policy accept; }",
                "add rule inet sssa_probe inbound_tproxy meta l4proto tcp meta nfproto ipv4 tcp dport 8443 ip saddr 203.0.113.10 tproxy ip to :15001 meta mark set 0x53534101",
                "add rule inet sssa_probe inbound_tproxy meta l4proto tcp meta nfproto ipv4 tcp dport 9443 ip saddr 203.0.113.20 tproxy ip to :15001 meta mark set 0x53534101",
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
            setup_rule_set(config.selector.as_ref().expect("selector should be set")),
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
    fn owner_lock_is_scoped_to_the_shared_nft_table() {
        let inbound = interception_config(Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )));
        let outbound_selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        );

        let inbound_plan = lifecycle_plan(
            &inbound,
            setup_rule_set(inbound.selector.as_ref().expect("selector should be set")),
        )
        .expect("inbound plan should be valid");
        let outbound_plan = OutboundRedirectLifecyclePlan::from_spec_and_rule_set(
            OutboundRedirectArtifactSpec::outbound_transparent_proxy(
                TransparentLinuxResources::reserved(),
                15001,
            ),
            outbound_setup_rule_set(&outbound_selector),
        )
        .expect("outbound plan should be valid");

        assert_eq!(inbound_plan.owner_name(), "sssa_probe");
        assert_eq!(outbound_plan.owner_name(), inbound_plan.owner_name());
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
            setup_rule_set(config.selector.as_ref().expect("selector should be set")),
        )
        .expect_err("proxy port should not be intercepted by its own TPROXY plan");

        assert!(matches!(
            error,
            TransparentLinuxPlanError::ProxyPortInInterceptedLocalPorts { proxy_port: 15001 }
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
            setup_rule_set(config.selector.as_ref().expect("selector should be set")),
        )
        .expect_err("wildcard local ports would intercept the proxy itself");

        assert!(matches!(
            error,
            TransparentLinuxPlanError::WildcardLocalPortsRequireProxyBypass { proxy_port: 15001 }
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

    fn setup_rule_set(selector: &Selector) -> TransparentInterceptionHostRuleSet {
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

    fn outbound_setup_rule_set(selector: &Selector) -> TransparentInterceptionHostRuleSet {
        match TransparentInterceptionSetupPlan::from_selector(
            Some(selector),
            TransparentInterceptionSetupDirection::Outbound,
        )
        .expect("test selector should project")
        {
            TransparentInterceptionSetupPlan::HostRules(rules) => rules,
            _ => panic!("test selector should project to host rules"),
        }
    }

    fn lifecycle_plan(
        config: &EnforcementInterceptionConfig,
        setup_rules: TransparentInterceptionHostRuleSet,
    ) -> Result<InboundTproxyLifecyclePlan, TransparentLinuxPlanError> {
        InboundTproxyLifecyclePlan::from_spec_and_rule_set(
            InboundTproxyArtifactSpec::new(
                crate::TransparentLinuxResources::reserved(),
                config
                    .proxy
                    .listen_port
                    .expect("test config should have proxy listen port"),
            ),
            setup_rules,
        )
    }

    fn lifecycle_plan_for_rule_set(
        config: &EnforcementInterceptionConfig,
        setup_rules: TransparentInterceptionHostRuleSet,
    ) -> Result<InboundTproxyLifecyclePlan, TransparentLinuxPlanError> {
        InboundTproxyLifecyclePlan::from_spec_and_rule_set(
            InboundTproxyArtifactSpec::new(
                crate::TransparentLinuxResources::reserved(),
                config
                    .proxy
                    .listen_port
                    .expect("test config should have proxy listen port"),
            ),
            setup_rules,
        )
    }
}

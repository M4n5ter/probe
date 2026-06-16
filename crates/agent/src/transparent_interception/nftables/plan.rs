use std::net::IpAddr;

use probe_config::{EnforcementInterceptionConfig, TransparentInterceptionStrategyConfig};
use probe_core::{Direction, ProcessSelector, Selector, SelectorTerm, TrafficSelector};
use runtime::TransparentInterceptionNftablesPlan;
use thiserror::Error;

const INBOUND_TPROXY_OWNER_LOCK: &str = "inbound_tproxy";

#[derive(Debug, Error)]
pub(super) enum NftablesPlanError {
    #[error("transparent interception requires a proxy listen port")]
    MissingProxyPort,
    #[error("transparent interception nftables lifecycle currently supports inbound TPROXY only")]
    UnsupportedStrategy,
    #[error("transparent interception requires an explicit selector for setup-time rules")]
    MissingSelector,
    #[error(
        "transparent interception selector must include at least one port or remote address constraint"
    )]
    UnconstrainedSelector,
    #[error("transparent interception selector cannot be projected to nftables rules: {0}")]
    UnsupportedSelector(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NftablesInterceptionPlan {
    table_name: String,
    proxy_port: u16,
    mark: u32,
    route_table: u32,
    rules: Vec<NftRule>,
}

impl NftablesInterceptionPlan {
    pub(super) fn from_config_and_scope(
        config: &EnforcementInterceptionConfig,
        setup_selector: Option<&Selector>,
    ) -> Result<Self, NftablesPlanError> {
        if config.strategy != TransparentInterceptionStrategyConfig::InboundTproxy {
            return Err(NftablesPlanError::UnsupportedStrategy);
        }
        let Some(proxy_port @ 1..) = config.proxy.listen_port else {
            return Err(NftablesPlanError::MissingProxyPort);
        };

        let projection = NftSelectorProjection::from_selector(setup_selector)?;
        let host_resources = TransparentInterceptionNftablesPlan::reserved();
        Ok(Self {
            table_name: host_resources.table_name,
            proxy_port,
            mark: host_resources.mark,
            route_table: host_resources.route_table,
            rules: projection.rules,
        })
    }

    pub(super) fn setup_nft_script(&self) -> String {
        let mut lines = vec![
            format!("destroy table inet {}", self.table_name),
            format!("add table inet {}", self.table_name),
            self.add_chain_command(),
        ];
        lines.extend(self.rules.iter().map(|rule| self.add_rule_command(rule)));
        lines.join("\n") + "\n"
    }

    pub(super) fn cleanup_nft_script(&self) -> String {
        format!("destroy table inet {}\n", self.table_name)
    }

    pub(super) fn owner_name(&self) -> &'static str {
        INBOUND_TPROXY_OWNER_LOCK
    }

    pub(super) fn setup_ip_commands(&self) -> Vec<Vec<String>> {
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

    pub(super) fn cleanup_ip_commands(&self) -> Vec<Vec<String>> {
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

    pub(super) fn cleanup_all_ip_commands(&self) -> Vec<Vec<String>> {
        PolicyRouteFamily::all()
            .into_iter()
            .flat_map(|family| {
                [
                    family.rule_command("del", self.mark, self.route_table),
                    family.route_command("del", self.route_table),
                ]
            })
            .collect()
    }

    fn policy_route_families(&self) -> Vec<PolicyRouteFamily> {
        let mut families = Vec::new();
        if self.rules.iter().any(|rule| rule.family == NftFamily::Ipv4) {
            families.push(PolicyRouteFamily::Ipv4);
        }
        if self.rules.iter().any(|rule| rule.family == NftFamily::Ipv6) {
            families.push(PolicyRouteFamily::Ipv6);
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
        let rule_match = rule.match_expression();
        format!(
            "add rule inet {} inbound_tproxy {} tproxy {} to :{} meta mark set {}",
            self.table_name,
            rule_match,
            rule.family.tproxy_name(),
            self.proxy_port,
            hex_mark(self.mark),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NftSelectorProjection {
    rules: Vec<NftRule>,
}

impl NftSelectorProjection {
    fn from_selector(selector: Option<&Selector>) -> Result<Self, NftablesPlanError> {
        let Some(selector) = selector else {
            return Err(NftablesPlanError::MissingSelector);
        };
        let term = ProjectableSelectorTerm::from_selector(selector)?;
        Self::from_term(&term)
    }

    fn from_term(term: &ProjectableSelectorTerm) -> Result<Self, NftablesPlanError> {
        if has_process_constraints(&term.process) {
            return Err(NftablesPlanError::UnsupportedSelector(
                "process constraints cannot be represented by the current nftables rule planner without cgroup or owner classification".to_string(),
            ));
        }
        validate_direction_projection(&term.traffic)?;
        validate_has_traffic_constraint(&term.traffic)?;

        let addresses = parse_remote_addresses(&term.traffic.remote_addresses)?;
        let base = NftRuleBase::from_traffic(&term.traffic);
        let mut rules = Vec::new();
        match (addresses.ipv4.is_empty(), addresses.ipv6.is_empty()) {
            (true, true) => {
                rules.push(base.rule(NftFamily::Ipv4, None));
                rules.push(base.rule(NftFamily::Ipv6, None));
            }
            (false, true) => {
                rules.push(base.rule(NftFamily::Ipv4, Some(NftAddressMatch::Ipv4(addresses.ipv4))))
            }
            (true, false) => {
                rules.push(base.rule(NftFamily::Ipv6, Some(NftAddressMatch::Ipv6(addresses.ipv6))))
            }
            (false, false) => {
                rules.push(base.rule(NftFamily::Ipv4, Some(NftAddressMatch::Ipv4(addresses.ipv4))));
                rules.push(base.rule(NftFamily::Ipv6, Some(NftAddressMatch::Ipv6(addresses.ipv6))));
            }
        }
        Ok(Self { rules })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProjectableSelectorTerm {
    process: ProcessSelector,
    traffic: TrafficSelector,
}

impl ProjectableSelectorTerm {
    fn from_selector(selector: &Selector) -> Result<Self, NftablesPlanError> {
        match selector {
            Selector::Match { term } => Ok(Self::from((**term).clone())),
            Selector::All { selectors } => {
                if selectors.is_empty() {
                    return Err(NftablesPlanError::UnsupportedSelector(
                        "all selector requires at least one child".to_string(),
                    ));
                }
                selectors
                    .iter()
                    .map(Self::from_selector)
                    .try_fold(Self::default(), |current, next| {
                        current.intersect(next?)
                    })
            }
            Selector::Any { .. } | Selector::Not { .. } | Selector::Ref { .. } => Err(
                NftablesPlanError::UnsupportedSelector(
                    "only match selectors and all(match, ...) intersections can currently be projected to nftables; any, not, and named refs require proxy-side or cgroup classification"
                        .to_string(),
                ),
            ),
        }
    }

    fn intersect(self, other: Self) -> Result<Self, NftablesPlanError> {
        Ok(Self {
            process: intersect_process_selectors(self.process, other.process)?,
            traffic: intersect_traffic_selectors(self.traffic, other.traffic)?,
        })
    }
}

impl From<SelectorTerm> for ProjectableSelectorTerm {
    fn from(value: SelectorTerm) -> Self {
        Self {
            process: value.process,
            traffic: value.traffic,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NftRuleBase {
    local_port_field: &'static str,
    remote_port_field: &'static str,
    local_ports: Vec<u16>,
    remote_ports: Vec<u16>,
}

impl NftRuleBase {
    fn from_traffic(traffic: &TrafficSelector) -> Self {
        Self {
            local_port_field: "tcp dport",
            remote_port_field: "tcp sport",
            local_ports: traffic.local_ports.clone(),
            remote_ports: traffic.remote_ports.clone(),
        }
    }

    fn rule(&self, family: NftFamily, address: Option<NftAddressMatch>) -> NftRule {
        NftRule {
            family,
            local_port_field: self.local_port_field,
            remote_port_field: self.remote_port_field,
            local_ports: self.local_ports.clone(),
            remote_ports: self.remote_ports.clone(),
            address,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NftRule {
    family: NftFamily,
    local_port_field: &'static str,
    remote_port_field: &'static str,
    local_ports: Vec<u16>,
    remote_ports: Vec<u16>,
    address: Option<NftAddressMatch>,
}

impl NftRule {
    fn match_expression(&self) -> String {
        let mut clauses = vec!["meta l4proto tcp".to_string()];
        clauses.push(format!("meta nfproto {}", self.family.nfproto_name()));
        if !self.local_ports.is_empty() {
            clauses.push(port_match(self.local_port_field, &self.local_ports));
        }
        if !self.remote_ports.is_empty() {
            clauses.push(port_match(self.remote_port_field, &self.remote_ports));
        }
        if let Some(address) = &self.address {
            clauses.push(address.match_expression());
        }
        clauses.join(" ")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NftFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyRouteFamily {
    Ipv4,
    Ipv6,
}

impl PolicyRouteFamily {
    fn all() -> [Self; 2] {
        [Self::Ipv4, Self::Ipv6]
    }

    fn rule_command(self, operation: &str, mark: u32, route_table: u32) -> Vec<String> {
        let mut command = self.command_prefix();
        command.extend([
            "rule".to_string(),
            operation.to_string(),
            "fwmark".to_string(),
            hex_mark(mark),
            "lookup".to_string(),
            route_table.to_string(),
        ]);
        command
    }

    fn route_command(self, operation: &str, route_table: u32) -> Vec<String> {
        let mut command = self.command_prefix();
        command.extend([
            "route".to_string(),
            operation.to_string(),
            "local".to_string(),
            self.local_route().to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            route_table.to_string(),
        ]);
        command
    }

    fn command_prefix(self) -> Vec<String> {
        match self {
            Self::Ipv4 => Vec::new(),
            Self::Ipv6 => vec!["-6".to_string()],
        }
    }

    fn local_route(self) -> &'static str {
        match self {
            Self::Ipv4 => "0.0.0.0/0",
            Self::Ipv6 => "::/0",
        }
    }
}

impl NftFamily {
    fn nfproto_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    fn tproxy_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ip",
            Self::Ipv6 => "ip6",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NftAddressMatch {
    Ipv4(Vec<String>),
    Ipv6(Vec<String>),
}

impl NftAddressMatch {
    fn match_expression(&self) -> String {
        let family = match self {
            Self::Ipv4(_) => "ip",
            Self::Ipv6(_) => "ip6",
        };
        match self {
            Self::Ipv4(addresses) | Self::Ipv6(addresses) => {
                format!("{family} saddr {}", nft_set_or_value(addresses))
            }
        }
    }
}

#[derive(Default)]
struct ParsedRemoteAddresses {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

fn has_process_constraints(process: &ProcessSelector) -> bool {
    !process.pids.is_empty()
        || !process.names.is_empty()
        || !process.exe_path_globs.is_empty()
        || !process.cmdline_regexes.is_empty()
        || !process.systemd_services.is_empty()
        || !process.container_ids.is_empty()
}

fn intersect_process_selectors(
    left: ProcessSelector,
    right: ProcessSelector,
) -> Result<ProcessSelector, NftablesPlanError> {
    Ok(ProcessSelector {
        pids: intersect_values(left.pids, right.pids)?,
        names: intersect_values(left.names, right.names)?,
        exe_path_globs: intersect_values(left.exe_path_globs, right.exe_path_globs)?,
        cmdline_regexes: intersect_values(left.cmdline_regexes, right.cmdline_regexes)?,
        systemd_services: intersect_values(left.systemd_services, right.systemd_services)?,
        container_ids: intersect_values(left.container_ids, right.container_ids)?,
    })
}

fn intersect_traffic_selectors(
    left: TrafficSelector,
    right: TrafficSelector,
) -> Result<TrafficSelector, NftablesPlanError> {
    Ok(TrafficSelector {
        local_ports: intersect_values(left.local_ports, right.local_ports)?,
        remote_ports: intersect_values(left.remote_ports, right.remote_ports)?,
        directions: intersect_values(left.directions, right.directions)?,
        remote_addresses: intersect_values(left.remote_addresses, right.remote_addresses)?,
    })
}

fn intersect_values<T>(left: Vec<T>, right: Vec<T>) -> Result<Vec<T>, NftablesPlanError>
where
    T: Clone + Eq,
{
    match (left.is_empty(), right.is_empty()) {
        (true, true) => Ok(Vec::new()),
        (true, false) => Ok(right),
        (false, true) => Ok(left),
        (false, false) => {
            let mut values = Vec::new();
            for value in left {
                if right.contains(&value) && !values.contains(&value) {
                    values.push(value);
                }
            }
            if values.is_empty() {
                Err(NftablesPlanError::UnsupportedSelector(
                    "selector intersections do not overlap".to_string(),
                ))
            } else {
                Ok(values)
            }
        }
    }
}

fn validate_direction_projection(traffic: &TrafficSelector) -> Result<(), NftablesPlanError> {
    if traffic.directions.is_empty() {
        return Ok(());
    }
    let required = Direction::Inbound;
    if traffic
        .directions
        .iter()
        .all(|direction| *direction == required)
    {
        Ok(())
    } else {
        Err(NftablesPlanError::UnsupportedSelector(format!(
            "inbound TPROXY can only project {required:?} traffic selectors"
        )))
    }
}

fn validate_has_traffic_constraint(traffic: &TrafficSelector) -> Result<(), NftablesPlanError> {
    if traffic.local_ports.is_empty()
        && traffic.remote_ports.is_empty()
        && traffic.remote_addresses.is_empty()
    {
        Err(NftablesPlanError::UnconstrainedSelector)
    } else {
        Ok(())
    }
}

fn parse_remote_addresses(
    addresses: &[String],
) -> Result<ParsedRemoteAddresses, NftablesPlanError> {
    let mut parsed = ParsedRemoteAddresses::default();
    for address in addresses {
        match address.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => parsed.ipv4.push(address.to_string()),
            Ok(IpAddr::V6(address)) => parsed.ipv6.push(address.to_string()),
            Err(error) => {
                return Err(NftablesPlanError::UnsupportedSelector(format!(
                    "remote address {address:?} is not a valid IP address: {error}"
                )));
            }
        }
    }
    Ok(parsed)
}

fn port_match(field: &str, ports: &[u16]) -> String {
    format!("{field} {}", nft_set_or_value(ports))
}

fn nft_set_or_value<T>(values: &[T]) -> String
where
    T: ToString,
{
    if values.len() == 1 {
        values[0].to_string()
    } else {
        format!(
            "{{ {} }}",
            values
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn hex_mark(mark: u32) -> String {
    format!("0x{mark:x}")
}

#[cfg(test)]
mod tests {
    use probe_config::{EnforcementInterceptionConfig, TransparentInterceptionProxyConfig};

    use super::*;

    #[test]
    fn inbound_tproxy_plan_projects_traffic_selector_to_nft_and_policy_routing() {
        let config = interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![8443],
                    remote_ports: Vec::new(),
                    directions: vec![Direction::Inbound],
                    remote_addresses: vec!["203.0.113.10".to_string()],
                },
            )),
        );
        let plan =
            NftablesInterceptionPlan::from_config_and_scope(&config, config.selector.as_ref())
                .expect("selector should be projectable");

        let script = plan.setup_nft_script();

        assert!(script.contains("add chain inet sssa_probe inbound_tproxy"));
        assert!(script.contains("meta nfproto ipv4"));
        assert!(script.contains("tcp dport 8443"));
        assert!(script.contains("ip saddr 203.0.113.10"));
        assert!(script.contains("tproxy ip to :15001 meta mark set 0x53534101"));
        assert!(!script.contains("meta nfproto ipv6"));
        assert!(!script.contains("tproxy ip6 to :15001"));
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
        let config = interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![8443],
                    directions: vec![Direction::Inbound],
                    ..TrafficSelector::default()
                },
            )),
        );
        let plan =
            NftablesInterceptionPlan::from_config_and_scope(&config, config.selector.as_ref())
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
    fn process_selector_fails_closed_instead_of_becoming_global_interception() {
        let config = interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Some(Selector::term(
                ProcessSelector {
                    names: vec!["curl".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            )),
        );
        let error =
            NftablesInterceptionPlan::from_config_and_scope(&config, config.selector.as_ref())
                .expect_err("process selector must not be silently dropped");

        assert!(error.to_string().contains("process constraints"));
    }

    #[test]
    fn outbound_mitm_is_not_an_executable_nftables_plan_without_proxy_bypass() {
        let config = interception_config(
            TransparentInterceptionStrategyConfig::OutboundMitm,
            Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![443],
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            )),
        );
        let error =
            NftablesInterceptionPlan::from_config_and_scope(&config, config.selector.as_ref())
                .expect_err("outbound MITM must wait for proxy self-bypass");

        assert!(matches!(error, NftablesPlanError::UnsupportedStrategy));
    }

    #[test]
    fn wrong_direction_fails_closed() {
        let config = interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            )),
        );
        let error =
            NftablesInterceptionPlan::from_config_and_scope(&config, config.selector.as_ref())
                .expect_err("wrong direction must not be silently ignored");

        assert!(error.to_string().contains("Inbound"));
    }

    #[test]
    fn missing_or_unconstrained_selector_fails_closed() {
        let missing =
            interception_config(TransparentInterceptionStrategyConfig::InboundTproxy, None);
        let error = NftablesInterceptionPlan::from_config_and_scope(&missing, None)
            .expect_err("implicit global interception must be rejected");

        assert!(matches!(error, NftablesPlanError::MissingSelector));

        let unconstrained = interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    directions: vec![Direction::Inbound],
                    ..TrafficSelector::default()
                },
            )),
        );
        let error = NftablesInterceptionPlan::from_config_and_scope(
            &unconstrained,
            unconstrained.selector.as_ref(),
        )
        .expect_err("selector with only direction is still too broad");

        assert!(matches!(error, NftablesPlanError::UnconstrainedSelector));
    }

    #[test]
    fn all_selector_intersection_is_projected_as_narrower_rule() {
        let config = interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Some(Selector::All {
                selectors: vec![
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![8443, 9443],
                            directions: vec![Direction::Inbound],
                            ..TrafficSelector::default()
                        },
                    ),
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![9443],
                            remote_addresses: vec!["2001:db8::1".to_string()],
                            ..TrafficSelector::default()
                        },
                    ),
                ],
            }),
        );

        let script =
            NftablesInterceptionPlan::from_config_and_scope(&config, config.selector.as_ref())
                .expect("all(match, ...) selector should be projectable")
                .setup_nft_script();

        assert!(script.contains("tcp dport 9443"));
        assert!(!script.contains("tcp dport { 8443, 9443 }"));
        assert!(script.contains("ip6 saddr 2001:db8::1"));
    }

    #[test]
    fn owner_lock_is_coarse_for_the_single_supported_host_lifecycle() {
        let first = interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![8443],
                    directions: vec![Direction::Inbound],
                    ..TrafficSelector::default()
                },
            )),
        );
        let second = first.clone();

        let first_plan =
            NftablesInterceptionPlan::from_config_and_scope(&first, first.selector.as_ref())
                .expect("first plan should be valid");
        let second_plan =
            NftablesInterceptionPlan::from_config_and_scope(&second, second.selector.as_ref())
                .expect("second plan should be valid");

        assert_eq!(first_plan.owner_name(), "inbound_tproxy");
        assert_eq!(second_plan.owner_name(), "inbound_tproxy");
    }

    fn interception_config(
        strategy: TransparentInterceptionStrategyConfig,
        selector: Option<Selector>,
    ) -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy,
            selector,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
            },
        }
    }
}

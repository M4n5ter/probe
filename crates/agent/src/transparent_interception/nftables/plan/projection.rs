use std::net::IpAddr;

use probe_core::{Direction, ProcessSelector, Selector, SelectorTerm, TrafficSelector};

use super::NftablesPlanError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NftHookProjection {
    required_direction: Direction,
    description: &'static str,
    local_port_field: &'static str,
    remote_port_field: &'static str,
}

impl NftHookProjection {
    pub(super) fn inbound_tproxy() -> Self {
        Self {
            required_direction: Direction::Inbound,
            description: "inbound TPROXY",
            local_port_field: "tcp dport",
            remote_port_field: "tcp sport",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NftSelectorProjection {
    rules: Vec<NftRule>,
}

impl NftSelectorProjection {
    pub(super) fn from_selector(
        selector: Option<&Selector>,
        hook: NftHookProjection,
    ) -> Result<Self, NftablesPlanError> {
        let Some(selector) = selector else {
            return Err(NftablesPlanError::MissingSelector);
        };
        let term = ProjectableSelectorTerm::from_selector(selector)?;
        Self::from_term(&term, hook)
    }

    pub(super) fn into_rules(self) -> Vec<NftRule> {
        self.rules
    }

    fn from_term(
        term: &ProjectableSelectorTerm,
        hook: NftHookProjection,
    ) -> Result<Self, NftablesPlanError> {
        if has_process_constraints(&term.process) {
            return Err(NftablesPlanError::UnsupportedSelector(
                "process constraints cannot be represented by the current nftables rule planner without cgroup or owner classification".to_string(),
            ));
        }
        validate_direction_projection(&term.traffic, hook)?;
        validate_has_traffic_constraint(&term.traffic)?;

        let addresses = parse_remote_addresses(&term.traffic.remote_addresses)?;
        let traffic_projection = NftTrafficProjection::from_traffic(&term.traffic, hook);
        let mut rules = Vec::new();
        match (addresses.ipv4.is_empty(), addresses.ipv6.is_empty()) {
            (true, true) => {
                rules.push(traffic_projection.rule(NftFamily::Ipv4, None));
                rules.push(traffic_projection.rule(NftFamily::Ipv6, None));
            }
            (false, true) => {
                rules.push(traffic_projection.rule(NftFamily::Ipv4, Some(addresses.ipv4)))
            }
            (true, false) => {
                rules.push(traffic_projection.rule(NftFamily::Ipv6, Some(addresses.ipv6)))
            }
            (false, false) => {
                rules.push(traffic_projection.rule(NftFamily::Ipv4, Some(addresses.ipv4)));
                rules.push(traffic_projection.rule(NftFamily::Ipv6, Some(addresses.ipv6)));
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
                    .try_fold(Self::default(), |current, next| current.intersect(next?))
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
struct NftTrafficProjection {
    local_port_field: &'static str,
    remote_port_field: &'static str,
    local_ports: Vec<u16>,
    remote_ports: Vec<u16>,
}

impl NftTrafficProjection {
    fn from_traffic(traffic: &TrafficSelector, hook: NftHookProjection) -> Self {
        Self {
            local_port_field: hook.local_port_field,
            remote_port_field: hook.remote_port_field,
            local_ports: traffic.local_ports.clone(),
            remote_ports: traffic.remote_ports.clone(),
        }
    }

    fn rule(&self, family: NftFamily, remote_addresses: Option<Vec<String>>) -> NftRule {
        NftRule {
            family,
            traffic: self.clone(),
            remote_addresses,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NftRule {
    family: NftFamily,
    traffic: NftTrafficProjection,
    remote_addresses: Option<Vec<String>>,
}

impl NftRule {
    pub(super) fn family(&self) -> NftFamily {
        self.family
    }

    pub(super) fn match_expression(&self) -> String {
        let mut clauses = vec!["meta l4proto tcp".to_string()];
        clauses.push(format!("meta nfproto {}", self.family.nfproto_name()));
        if !self.traffic.local_ports.is_empty() {
            clauses.push(port_match(
                self.traffic.local_port_field,
                &self.traffic.local_ports,
            ));
        }
        if !self.traffic.remote_ports.is_empty() {
            clauses.push(port_match(
                self.traffic.remote_port_field,
                &self.traffic.remote_ports,
            ));
        }
        if let Some(addresses) = &self.remote_addresses {
            clauses.push(self.remote_address_match_expression(addresses));
        }
        clauses.join(" ")
    }

    fn remote_address_match_expression(&self, addresses: &[String]) -> String {
        let field = format!("{} saddr", self.family.nft_address_family());
        format!("{field} {}", nft_set_or_value(addresses))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NftFamily {
    Ipv4,
    Ipv6,
}

impl NftFamily {
    fn nfproto_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    pub(super) fn nft_address_family(self) -> &'static str {
        match self {
            Self::Ipv4 => "ip",
            Self::Ipv6 => "ip6",
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

fn validate_direction_projection(
    traffic: &TrafficSelector,
    hook: NftHookProjection,
) -> Result<(), NftablesPlanError> {
    if traffic.directions.is_empty() {
        return Ok(());
    }
    if traffic
        .directions
        .iter()
        .all(|direction| *direction == hook.required_direction)
    {
        Ok(())
    } else {
        Err(NftablesPlanError::UnsupportedSelector(format!(
            "{} can only project {:?} traffic selectors",
            hook.description, hook.required_direction
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_selector_fails_closed_instead_of_becoming_global_interception() {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        );
        let error = NftSelectorProjection::from_selector(
            Some(&selector),
            NftHookProjection::inbound_tproxy(),
        )
        .expect_err("process selector must not be silently dropped");

        assert!(error.to_string().contains("process constraints"));
    }

    #[test]
    fn wrong_direction_fails_closed() {
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        );
        let error = NftSelectorProjection::from_selector(
            Some(&selector),
            NftHookProjection::inbound_tproxy(),
        )
        .expect_err("wrong direction must not be silently ignored");

        assert!(error.to_string().contains("Inbound"));
    }

    #[test]
    fn missing_or_unconstrained_selector_fails_closed() {
        let error = NftSelectorProjection::from_selector(None, NftHookProjection::inbound_tproxy())
            .expect_err("implicit global interception must be rejected");

        assert!(matches!(error, NftablesPlanError::MissingSelector));

        let unconstrained = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        );
        let error = NftSelectorProjection::from_selector(
            Some(&unconstrained),
            NftHookProjection::inbound_tproxy(),
        )
        .expect_err("selector with only direction is still too broad");

        assert!(matches!(error, NftablesPlanError::UnconstrainedSelector));
    }

    #[test]
    fn all_selector_intersection_is_projected_as_narrower_rule() {
        let selector = Selector::All {
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
        };

        let projection = NftSelectorProjection::from_selector(
            Some(&selector),
            NftHookProjection::inbound_tproxy(),
        )
        .expect("all(match, ...) selector should be projectable");
        let expressions = projection
            .into_rules()
            .into_iter()
            .map(|rule| rule.match_expression())
            .collect::<Vec<_>>();

        assert!(
            expressions
                .iter()
                .any(|rule| rule.contains("tcp dport 9443"))
        );
        assert!(
            expressions
                .iter()
                .all(|rule| !rule.contains("tcp dport { 8443, 9443 }"))
        );
        assert!(
            expressions
                .iter()
                .any(|rule| rule.contains("ip6 saddr 2001:db8::1"))
        );
    }
}

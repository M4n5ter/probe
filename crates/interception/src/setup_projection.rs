use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use probe_core::{Direction, ProcessSelector, Selector, SelectorTerm, TrafficSelector};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionHostRuleScope {
    local_ports: TransparentInterceptionPortScope,
    remote_ports: TransparentInterceptionPortScope,
    remote_addresses: TransparentInterceptionRemoteAddressScope,
}

impl TransparentInterceptionHostRuleScope {
    pub fn new(
        local_ports: TransparentInterceptionPortScope,
        remote_ports: TransparentInterceptionPortScope,
        remote_addresses: TransparentInterceptionRemoteAddressScope,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        if local_ports.is_any() && remote_ports.is_any() && remote_addresses.is_empty() {
            return Err(TransparentInterceptionSetupProjectionError::UnconstrainedSelector);
        }
        Ok(Self {
            local_ports,
            remote_ports,
            remote_addresses,
        })
    }

    pub fn from_inbound_tproxy_selector(
        selector: Option<&Selector>,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        let Some(selector) = selector else {
            return Err(TransparentInterceptionSetupProjectionError::MissingSelector);
        };
        let term = ProjectableLocalSetupTerm::from_selector(selector)?;
        Self::from_term(term)
    }

    fn from_term(
        term: ProjectableLocalSetupTerm,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        if has_process_constraints(&term.process) {
            return Err(
                TransparentInterceptionSetupProjectionError::RequiresProcessClassifier {
                    reason: "selector contains process constraints that require cgroup/owner marking or proxy-side process classification before host rules can be safely narrowed".to_string(),
                },
            );
        }
        validate_direction_projection(&term.traffic)?;
        Self::new(
            TransparentInterceptionPortScope::from_values(term.traffic.local_ports),
            TransparentInterceptionPortScope::from_values(term.traffic.remote_ports),
            parse_remote_addresses(&term.traffic.remote_addresses)?,
        )
    }

    pub fn local_ports(&self) -> &TransparentInterceptionPortScope {
        &self.local_ports
    }

    pub fn remote_ports(&self) -> &TransparentInterceptionPortScope {
        &self.remote_ports
    }

    pub fn remote_addresses(&self) -> &TransparentInterceptionRemoteAddressScope {
        &self.remote_addresses
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionPortScope {
    kind: TransparentInterceptionPortScopeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransparentInterceptionPortScopeKind {
    Any,
    Only(Vec<u16>),
}

impl TransparentInterceptionPortScope {
    pub fn any() -> Self {
        Self {
            kind: TransparentInterceptionPortScopeKind::Any,
        }
    }

    pub fn only(ports: Vec<u16>) -> Self {
        assert!(
            !ports.is_empty(),
            "explicit transparent interception port scope cannot be empty"
        );
        Self {
            kind: TransparentInterceptionPortScopeKind::Only(ports),
        }
    }

    fn from_values(ports: Vec<u16>) -> Self {
        if ports.is_empty() {
            Self::any()
        } else {
            Self::only(ports)
        }
    }

    pub fn is_any(&self) -> bool {
        matches!(self.kind, TransparentInterceptionPortScopeKind::Any)
    }

    pub fn values(&self) -> &[u16] {
        match &self.kind {
            TransparentInterceptionPortScopeKind::Any => &[],
            TransparentInterceptionPortScopeKind::Only(ports) => ports,
        }
    }

    pub fn only_values(&self) -> Option<&[u16]> {
        match &self.kind {
            TransparentInterceptionPortScopeKind::Any => None,
            TransparentInterceptionPortScopeKind::Only(ports) => Some(ports),
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        match &self.kind {
            TransparentInterceptionPortScopeKind::Any => true,
            TransparentInterceptionPortScopeKind::Only(ports) => ports.contains(&port),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransparentInterceptionRemoteAddressScope {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

impl TransparentInterceptionRemoteAddressScope {
    pub fn new(ipv4: Vec<Ipv4Addr>, ipv6: Vec<Ipv6Addr>) -> Self {
        Self { ipv4, ipv6 }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    pub fn ipv4(&self) -> &[Ipv4Addr] {
        &self.ipv4
    }

    pub fn ipv6(&self) -> &[Ipv6Addr] {
        &self.ipv6
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TransparentInterceptionSetupSelectorSources<'a> {
    pub local_enforcement_selector: Option<&'a Selector>,
    pub effective_enforcement_selector: Option<&'a Selector>,
    pub interception_selector: Option<&'a Selector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionSetupSelectors {
    local_config_scope: Option<Selector>,
    final_effective_scope: Option<Selector>,
}

impl TransparentInterceptionSetupSelectors {
    pub fn from_sources(sources: TransparentInterceptionSetupSelectorSources<'_>) -> Self {
        Self {
            local_config_scope: setup_selector(
                sources.local_enforcement_selector,
                sources.interception_selector,
            ),
            final_effective_scope: setup_selector(
                sources.effective_enforcement_selector,
                sources.interception_selector,
            ),
        }
    }

    pub fn local_config_scope(&self) -> Option<&Selector> {
        self.local_config_scope.as_ref()
    }

    pub fn final_effective_scope(&self) -> Option<&Selector> {
        self.final_effective_scope.as_ref()
    }

    pub fn local_host_rule_scope(
        &self,
    ) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError>
    {
        TransparentInterceptionHostRuleScope::from_inbound_tproxy_selector(
            self.local_config_scope(),
        )
    }

    pub fn final_host_rule_scope(
        &self,
    ) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError>
    {
        TransparentInterceptionHostRuleScope::from_inbound_tproxy_selector(
            self.final_effective_scope(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransparentInterceptionSetupProjectionError {
    #[error("transparent interception requires an explicit selector for setup-time rules")]
    MissingSelector,
    #[error(
        "transparent interception selector must include at least one port or remote address constraint"
    )]
    UnconstrainedSelector,
    #[error("transparent interception selector requires process classifier: {reason}")]
    RequiresProcessClassifier { reason: String },
    #[error("transparent interception selector requires flow classifier: {reason}")]
    RequiresFlowClassifier { reason: String },
    #[error("transparent interception selector cannot be projected to host rules: {reason}")]
    Unsupported { reason: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProjectableLocalSetupTerm {
    process: ProcessSelector,
    traffic: TrafficSelector,
}

impl ProjectableLocalSetupTerm {
    fn from_selector(
        selector: &Selector,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        match selector {
            Selector::Match { term } => Ok(Self::from((**term).clone())),
            Selector::All { selectors } => {
                if selectors.is_empty() {
                    return Err(TransparentInterceptionSetupProjectionError::Unsupported {
                        reason: "all selector requires at least one child".to_string(),
                    });
                }
                selectors
                    .iter()
                    .map(Self::from_selector)
                    .try_fold(Self::default(), |current, next| current.intersect(next?))
            }
            Selector::Any { .. } | Selector::Not { .. } => {
                Err(
                    TransparentInterceptionSetupProjectionError::RequiresFlowClassifier {
                        reason: "any/not selectors require a flow-aware classifier and cannot be projected to setup-time host rules".to_string(),
                    },
                )
            }
            Selector::Ref { .. } => {
                Err(
                    TransparentInterceptionSetupProjectionError::RequiresFlowClassifier {
                        reason: "named selector refs require registry-backed classifier resolution before transparent interception setup".to_string(),
                    },
                )
            }
        }
    }

    fn intersect(self, other: Self) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        Ok(Self {
            process: intersect_process_selectors(self.process, other.process)?,
            traffic: intersect_traffic_selectors(self.traffic, other.traffic)?,
        })
    }
}

impl From<SelectorTerm> for ProjectableLocalSetupTerm {
    fn from(value: SelectorTerm) -> Self {
        Self {
            process: value.process,
            traffic: value.traffic,
        }
    }
}

fn setup_selector(
    enforcement_selector: Option<&Selector>,
    interception_selector: Option<&Selector>,
) -> Option<Selector> {
    match (enforcement_selector, interception_selector) {
        (Some(enforcement), Some(interception)) => Some(Selector::All {
            selectors: vec![enforcement.clone(), interception.clone()],
        }),
        (Some(selector), None) | (None, Some(selector)) => Some(selector.clone()),
        (None, None) => None,
    }
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
) -> Result<ProcessSelector, TransparentInterceptionSetupProjectionError> {
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
) -> Result<TrafficSelector, TransparentInterceptionSetupProjectionError> {
    Ok(TrafficSelector {
        local_ports: intersect_values(left.local_ports, right.local_ports)?,
        remote_ports: intersect_values(left.remote_ports, right.remote_ports)?,
        directions: intersect_values(left.directions, right.directions)?,
        remote_addresses: intersect_remote_addresses(
            left.remote_addresses,
            right.remote_addresses,
        )?,
    })
}

fn intersect_values<T>(
    left: Vec<T>,
    right: Vec<T>,
) -> Result<Vec<T>, TransparentInterceptionSetupProjectionError>
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
                Err(TransparentInterceptionSetupProjectionError::Unsupported {
                    reason: "selector intersections do not overlap".to_string(),
                })
            } else {
                Ok(values)
            }
        }
    }
}

fn validate_direction_projection(
    traffic: &TrafficSelector,
) -> Result<(), TransparentInterceptionSetupProjectionError> {
    if traffic.directions.is_empty()
        || traffic
            .directions
            .iter()
            .all(|direction| *direction == Direction::Inbound)
    {
        Ok(())
    } else {
        Err(TransparentInterceptionSetupProjectionError::Unsupported {
            reason: "inbound TPROXY can only project Inbound traffic selectors".to_string(),
        })
    }
}

fn intersect_remote_addresses(
    left: Vec<String>,
    right: Vec<String>,
) -> Result<Vec<String>, TransparentInterceptionSetupProjectionError> {
    match (left.is_empty(), right.is_empty()) {
        (true, true) => Ok(Vec::new()),
        (true, false) => normalize_remote_addresses(&right),
        (false, true) => normalize_remote_addresses(&left),
        (false, false) => {
            let left = parse_ip_addresses(&left)?;
            let right = parse_ip_addresses(&right)?;
            let values = left
                .into_iter()
                .filter(|address| right.contains(address))
                .fold(Vec::new(), |mut values, address| {
                    if !values.contains(&address) {
                        values.push(address);
                    }
                    values
                });
            if values.is_empty() {
                Err(TransparentInterceptionSetupProjectionError::Unsupported {
                    reason: "selector remote address intersections do not overlap".to_string(),
                })
            } else {
                Ok(format_ip_addresses(values))
            }
        }
    }
}

fn parse_remote_addresses(
    addresses: &[String],
) -> Result<TransparentInterceptionRemoteAddressScope, TransparentInterceptionSetupProjectionError>
{
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for address in parse_ip_addresses(addresses)? {
        match address {
            IpAddr::V4(address) => ipv4.push(address),
            IpAddr::V6(address) => ipv6.push(address),
        }
    }
    Ok(TransparentInterceptionRemoteAddressScope::new(ipv4, ipv6))
}

fn normalize_remote_addresses(
    addresses: &[String],
) -> Result<Vec<String>, TransparentInterceptionSetupProjectionError> {
    parse_ip_addresses(addresses).map(format_ip_addresses)
}

fn parse_ip_addresses(
    addresses: &[String],
) -> Result<Vec<IpAddr>, TransparentInterceptionSetupProjectionError> {
    addresses
        .iter()
        .map(|address| {
            address.parse::<IpAddr>().map_err(|error| {
                TransparentInterceptionSetupProjectionError::Unsupported {
                    reason: format!(
                        "remote address {address:?} is not a valid IP address: {error}"
                    ),
                }
            })
        })
        .collect()
}

fn format_ip_addresses(addresses: Vec<IpAddr>) -> Vec<String> {
    addresses
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_inbound_host_rule_scope() {
        let scope = scope_for(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                remote_addresses: vec!["203.0.113.10".to_string()],
                ..TrafficSelector::default()
            },
        ))
        .expect("selector should project");

        assert_eq!(scope.local_ports().values(), &[8443]);
        assert_eq!(
            scope.remote_addresses().ipv4(),
            &[Ipv4Addr::new(203, 0, 113, 10)]
        );
        assert!(scope.remote_addresses().ipv6().is_empty());
    }

    #[test]
    fn process_selector_reports_process_classifier_requirement() {
        let error = scope_for(Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ))
        .expect_err("process selector needs classifier");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::RequiresProcessClassifier { .. }
        ));
    }

    #[test]
    fn any_selector_reports_flow_classifier_requirement() {
        let error = scope_for(Selector::Any {
            selectors: vec![
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![8443],
                        ..TrafficSelector::default()
                    },
                ),
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![9443],
                        ..TrafficSelector::default()
                    },
                ),
            ],
        })
        .expect_err("any selector needs flow classifier");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::RequiresFlowClassifier { .. }
        ));
    }

    #[test]
    fn wrong_direction_is_unsupported() {
        let error = scope_for(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ))
        .expect_err("wrong direction should not project");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn disjoint_all_selector_is_unsupported() {
        let error = scope_for(Selector::All {
            selectors: vec![
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![8443],
                        ..TrafficSelector::default()
                    },
                ),
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![9443],
                        ..TrafficSelector::default()
                    },
                ),
            ],
        })
        .expect_err("disjoint selector should not project");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn remote_address_intersection_uses_ip_value() {
        let scope = scope_for(Selector::All {
            selectors: vec![
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![8443],
                        remote_addresses: vec!["2001:0db8::1".to_string()],
                        ..TrafficSelector::default()
                    },
                ),
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![8443],
                        remote_addresses: vec!["2001:db8::1".to_string()],
                        ..TrafficSelector::default()
                    },
                ),
            ],
        })
        .expect("equivalent IP address text should intersect");

        assert_eq!(
            scope.remote_addresses().ipv6(),
            &[Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)]
        );
    }

    #[test]
    fn invalid_remote_address_is_unsupported() {
        let error = scope_for(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_addresses: vec!["not an ip".to_string()],
                ..TrafficSelector::default()
            },
        ))
        .expect_err("invalid remote address should not project");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn checked_constructor_rejects_empty_host_rule_scope() {
        let error = TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionRemoteAddressScope::empty(),
        )
        .expect_err("empty host-rule scope would render broad host rules");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::UnconstrainedSelector
        ));
    }

    fn scope_for(
        selector: Selector,
    ) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError>
    {
        TransparentInterceptionHostRuleScope::from_inbound_tproxy_selector(Some(&selector))
    }
}

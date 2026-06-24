use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionHostRuleScope {
    local_ports: TransparentInterceptionPortScope,
    remote_ports: TransparentInterceptionPortScope,
    remote_addresses: TransparentInterceptionRemoteAddressScope,
    socket_owners: TransparentInterceptionSocketOwnerScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionProcessScope {
    expression: TransparentInterceptionProcessScopeExpression,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionProcessScopeExpression {
    Match { process: ProcessSelector },
    All { expressions: Vec<Self> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionFlowClassifierScope {
    selector: TransparentInterceptionClassifierSelector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionClassifierSelector {
    Match {
        term: Box<TransparentInterceptionClassifierTerm>,
    },
    All {
        selectors: Vec<Self>,
    },
    Any {
        selectors: Vec<Self>,
    },
    Not {
        selector: Box<Self>,
    },
    Ref {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionClassifierTerm {
    pub process: ProcessSelector,
    pub traffic: TrafficSelector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionHostRuleBoundary {
    NoHostRuleBoundary,
    Scope(TransparentInterceptionHostRuleScope),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionSetupPlan {
    HostRules(TransparentInterceptionHostRuleScope),
    RequiresProcessClassifier {
        host_rule_boundary: TransparentInterceptionHostRuleBoundary,
        process_scope: TransparentInterceptionProcessScope,
        reason: String,
    },
    RequiresFlowClassifier {
        host_rule_boundary: TransparentInterceptionHostRuleBoundary,
        flow_scope: TransparentInterceptionFlowClassifierScope,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentInterceptionSetupDirection {
    Inbound,
    Outbound,
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransparentInterceptionRemoteAddressScope {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransparentInterceptionSocketOwnerScope {
    uids: Vec<u32>,
    gids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransparentInterceptionSetupProjectionError {
    #[error("transparent interception requires an explicit selector for setup-time rules")]
    MissingSelector,
    #[error("transparent interception selector must include at least one host-rule constraint")]
    UnconstrainedSelector,
    #[error("transparent interception selector cannot be projected to host rules: {reason}")]
    Unsupported { reason: String },
}

impl TransparentInterceptionHostRuleScope {
    pub fn new(
        local_ports: TransparentInterceptionPortScope,
        remote_ports: TransparentInterceptionPortScope,
        remote_addresses: TransparentInterceptionRemoteAddressScope,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        Self::with_socket_owners(
            local_ports,
            remote_ports,
            remote_addresses,
            TransparentInterceptionSocketOwnerScope::any(),
        )
    }

    pub fn with_socket_owners(
        local_ports: TransparentInterceptionPortScope,
        remote_ports: TransparentInterceptionPortScope,
        remote_addresses: TransparentInterceptionRemoteAddressScope,
        socket_owners: TransparentInterceptionSocketOwnerScope,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        if local_ports.is_any()
            && remote_ports.is_any()
            && remote_addresses.is_empty()
            && socket_owners.is_any()
        {
            return Err(TransparentInterceptionSetupProjectionError::UnconstrainedSelector);
        }
        Ok(Self {
            local_ports,
            remote_ports,
            remote_addresses,
            socket_owners,
        })
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

    pub fn socket_owners(&self) -> &TransparentInterceptionSocketOwnerScope {
        &self.socket_owners
    }

    pub(crate) fn to_traffic_selector(
        &self,
        direction: TransparentInterceptionSetupDirection,
    ) -> TrafficSelector {
        TrafficSelector {
            local_ports: self.local_ports.traffic_selector_values(),
            remote_ports: self.remote_ports.traffic_selector_values(),
            directions: vec![direction.into()],
            remote_addresses: self.remote_addresses.traffic_selector_values(),
        }
    }

    pub(crate) fn union_without_expansion(scopes: &[Self]) -> Option<Self> {
        if scopes.is_empty()
            || !all_socket_owner_scopes_equivalent(scopes)
            || host_rule_scope_varying_dimensions(scopes) > 1
        {
            return None;
        }
        Some(
            Self::with_socket_owners(
                union_port_scopes(scopes.iter().map(Self::local_ports)),
                union_port_scopes(scopes.iter().map(Self::remote_ports)),
                union_remote_address_scopes(scopes.iter().map(Self::remote_addresses)),
                scopes
                    .first()
                    .expect("scope set should be non-empty")
                    .socket_owners
                    .clone(),
            )
            .expect("union of constrained host-rule scopes should remain constrained"),
        )
    }
}

impl From<TransparentInterceptionSetupDirection> for Direction {
    fn from(direction: TransparentInterceptionSetupDirection) -> Self {
        match direction {
            TransparentInterceptionSetupDirection::Inbound => Self::Inbound,
            TransparentInterceptionSetupDirection::Outbound => Self::Outbound,
        }
    }
}

impl TransparentInterceptionProcessScope {
    pub(crate) fn new(
        expression: TransparentInterceptionProcessScopeExpression,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        if !expression.has_process_constraints() {
            return Err(TransparentInterceptionSetupProjectionError::Unsupported {
                reason: "process classifier scope requires at least one process constraint"
                    .to_string(),
            });
        }
        Ok(Self { expression })
    }

    pub fn expression(&self) -> &TransparentInterceptionProcessScopeExpression {
        &self.expression
    }
}

impl TransparentInterceptionProcessScopeExpression {
    pub(crate) fn has_process_constraints(&self) -> bool {
        match self {
            Self::Match { process } => process_selector_has_constraints(process),
            Self::All { expressions } => {
                !expressions.is_empty() && expressions.iter().all(Self::has_process_constraints)
            }
        }
    }
}

impl TransparentInterceptionFlowClassifierScope {
    pub(crate) fn from_selector(selector: &Selector) -> Self {
        Self {
            selector: TransparentInterceptionClassifierSelector::from_selector(selector),
        }
    }

    pub fn selector(&self) -> &TransparentInterceptionClassifierSelector {
        &self.selector
    }
}

impl TransparentInterceptionClassifierSelector {
    fn from_selector(selector: &Selector) -> Self {
        match selector {
            Selector::Match { term } => Self::Match {
                term: Box::new(TransparentInterceptionClassifierTerm {
                    process: term.process.clone(),
                    traffic: term.traffic.clone(),
                }),
            },
            Selector::All { selectors } => Self::All {
                selectors: selectors.iter().map(Self::from_selector).collect(),
            },
            Selector::Any { selectors } => Self::Any {
                selectors: selectors.iter().map(Self::from_selector).collect(),
            },
            Selector::Not { selector } => Self::Not {
                selector: Box::new(Self::from_selector(selector)),
            },
            Selector::Ref { name } => Self::Ref { name: name.clone() },
        }
    }
}

impl TransparentInterceptionHostRuleBoundary {
    pub fn scope(&self) -> Option<&TransparentInterceptionHostRuleScope> {
        match self {
            Self::NoHostRuleBoundary => None,
            Self::Scope(scope) => Some(scope),
        }
    }
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

    pub(crate) fn from_values(ports: Vec<u16>) -> Self {
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

    fn equivalent_to(&self, other: &Self) -> bool {
        match (self.only_values(), other.only_values()) {
            (None, None) => true,
            (Some(left), Some(right)) => same_values(left, right),
            _ => false,
        }
    }

    fn traffic_selector_values(&self) -> Vec<u16> {
        self.only_values()
            .map_or_else(Vec::new, |ports| ports.to_vec())
    }
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

    fn equivalent_to(&self, other: &Self) -> bool {
        same_values(&self.ipv4, &other.ipv4) && same_values(&self.ipv6, &other.ipv6)
    }

    fn traffic_selector_values(&self) -> Vec<String> {
        self.ipv4
            .iter()
            .copied()
            .map(IpAddr::V4)
            .chain(self.ipv6.iter().copied().map(IpAddr::V6))
            .map(|address| address.to_string())
            .collect()
    }
}

impl TransparentInterceptionSocketOwnerScope {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn new(uids: Vec<u32>, gids: Vec<u32>) -> Self {
        Self { uids, gids }
    }

    pub fn is_any(&self) -> bool {
        self.uids.is_empty() && self.gids.is_empty()
    }

    pub fn uids(&self) -> &[u32] {
        &self.uids
    }

    pub fn gids(&self) -> &[u32] {
        &self.gids
    }

    fn equivalent_to(&self, other: &Self) -> bool {
        same_values(&self.uids, &other.uids) && same_values(&self.gids, &other.gids)
    }
}

pub(crate) fn process_selector_has_constraints(process: &ProcessSelector) -> bool {
    !process.pids.is_empty()
        || !process.uids.is_empty()
        || !process.gids.is_empty()
        || !process.names.is_empty()
        || !process.exe_path_globs.is_empty()
        || !process.cmdline_regexes.is_empty()
        || !process.systemd_services.is_empty()
        || !process.container_ids.is_empty()
}

fn host_rule_scope_varying_dimensions(scopes: &[TransparentInterceptionHostRuleScope]) -> u8 {
    [
        all_equivalent_by(scopes, |left, right| {
            left.local_ports.equivalent_to(&right.local_ports)
        }),
        all_equivalent_by(scopes, |left, right| {
            left.remote_ports.equivalent_to(&right.remote_ports)
        }),
        all_equivalent_by(scopes, |left, right| {
            left.remote_addresses.equivalent_to(&right.remote_addresses)
        }),
    ]
    .into_iter()
    .filter(|equal| !equal)
    .count() as u8
}

fn all_socket_owner_scopes_equivalent(scopes: &[TransparentInterceptionHostRuleScope]) -> bool {
    all_equivalent_by(scopes, |left, right| {
        left.socket_owners.equivalent_to(&right.socket_owners)
    })
}

fn union_port_scopes<'a>(
    scopes: impl Iterator<Item = &'a TransparentInterceptionPortScope>,
) -> TransparentInterceptionPortScope {
    let mut values = Vec::new();
    for scope in scopes {
        let Some(ports) = scope.only_values() else {
            return TransparentInterceptionPortScope::any();
        };
        push_unique_all(&mut values, ports);
    }
    TransparentInterceptionPortScope::from_values(values)
}

fn union_remote_address_scopes<'a>(
    scopes: impl Iterator<Item = &'a TransparentInterceptionRemoteAddressScope>,
) -> TransparentInterceptionRemoteAddressScope {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for scope in scopes {
        if scope.is_empty() {
            return TransparentInterceptionRemoteAddressScope::empty();
        }
        push_unique_all(&mut ipv4, scope.ipv4());
        push_unique_all(&mut ipv6, scope.ipv6());
    }
    TransparentInterceptionRemoteAddressScope::new(ipv4, ipv6)
}

fn all_equivalent_by<T, F>(values: &[T], equivalent: F) -> bool
where
    F: Fn(&T, &T) -> bool,
{
    values
        .split_first()
        .is_none_or(|(first, rest)| rest.iter().all(|value| equivalent(value, first)))
}

fn same_values<T>(left: &[T], right: &[T]) -> bool
where
    T: Eq,
{
    left.iter().all(|value| right.contains(value)) && right.iter().all(|value| left.contains(value))
}

fn push_unique_all<T>(values: &mut Vec<T>, candidates: &[T])
where
    T: Copy + Eq,
{
    for candidate in candidates {
        if !values.contains(candidate) {
            values.push(*candidate);
        }
    }
}

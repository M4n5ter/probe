use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};
use thiserror::Error;

const MAX_HOST_RULE_SCOPES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionHostRuleScope {
    local_ports: TransparentInterceptionPortScope,
    remote_ports: TransparentInterceptionPortScope,
    remote_addresses: TransparentInterceptionRemoteAddressScope,
    socket_owners: TransparentInterceptionSocketOwnerScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionHostRuleSet {
    scopes: Vec<TransparentInterceptionHostRuleScope>,
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
    HostRules(TransparentInterceptionHostRuleSet),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionSetupPlan {
    HostRules(TransparentInterceptionHostRuleSet),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionRemoteAddressScope {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
    family_scope: TransparentInterceptionRemoteAddressFamilyScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransparentInterceptionRemoteAddressFamilyScope {
    Any,
    Only { ipv4: bool, ipv6: bool },
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
            && remote_addresses.is_any()
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

    fn contains_scope(&self, other: &Self) -> bool {
        self.local_ports.contains_scope(&other.local_ports)
            && self.remote_ports.contains_scope(&other.remote_ports)
            && self
                .remote_addresses
                .contains_scope(&other.remote_addresses)
            && self.socket_owners.contains_scope(&other.socket_owners)
    }
}

impl TransparentInterceptionHostRuleSet {
    pub fn new(
        scopes: Vec<TransparentInterceptionHostRuleScope>,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        Self::canonicalize(scopes)?
            .ok_or(TransparentInterceptionSetupProjectionError::UnconstrainedSelector)
    }

    pub fn single(scope: TransparentInterceptionHostRuleScope) -> Self {
        Self {
            scopes: vec![scope],
        }
    }

    pub fn compacting(
        scopes: Vec<TransparentInterceptionHostRuleScope>,
    ) -> Result<Option<Self>, TransparentInterceptionSetupProjectionError> {
        Self::canonicalize(scopes)
    }

    pub fn scopes(&self) -> &[TransparentInterceptionHostRuleScope] {
        &self.scopes
    }

    pub fn explicit_local_ports(&self) -> Option<Vec<u16>> {
        collect_unique_explicit_ports(self.scopes.iter().map(|scope| scope.local_ports()))
    }

    fn canonicalize(
        scopes: Vec<TransparentInterceptionHostRuleScope>,
    ) -> Result<Option<Self>, TransparentInterceptionSetupProjectionError> {
        if scopes.is_empty() {
            return Ok(None);
        }
        let scopes = compact_host_rule_scopes(scopes);
        if scopes.len() > MAX_HOST_RULE_SCOPES {
            return Err(TransparentInterceptionSetupProjectionError::Unsupported {
                reason: format!(
                    "transparent interception selector expands to {} host rules, exceeding the maximum of {}",
                    scopes.len(),
                    MAX_HOST_RULE_SCOPES
                ),
            });
        }

        Ok(Some(Self { scopes }))
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
    pub fn rules(&self) -> Option<&TransparentInterceptionHostRuleSet> {
        match self {
            Self::NoHostRuleBoundary => None,
            Self::HostRules(rules) => Some(rules),
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

    fn contains_scope(&self, other: &Self) -> bool {
        match (self.only_values(), other.only_values()) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(left), Some(right)) => right.iter().all(|value| left.contains(value)),
        }
    }

    fn traffic_selector_values(&self) -> Vec<u16> {
        self.only_values()
            .map_or_else(Vec::new, |ports| ports.to_vec())
    }
}

impl TransparentInterceptionRemoteAddressScope {
    pub fn new(ipv4: Vec<Ipv4Addr>, ipv6: Vec<Ipv6Addr>) -> Self {
        let family_scope = if ipv4.is_empty() && ipv6.is_empty() {
            TransparentInterceptionRemoteAddressFamilyScope::Any
        } else {
            TransparentInterceptionRemoteAddressFamilyScope::Only {
                ipv4: false,
                ipv6: false,
            }
        };
        Self {
            ipv4,
            ipv6,
            family_scope,
        }
    }

    pub fn any() -> Self {
        Self::default()
    }

    pub fn any_ipv4() -> Self {
        Self::with_family_wildcards(true, false, Vec::new(), Vec::new())
    }

    pub fn any_ipv6() -> Self {
        Self::with_family_wildcards(false, true, Vec::new(), Vec::new())
    }

    pub fn is_any(&self) -> bool {
        self.ipv4.is_empty()
            && self.ipv6.is_empty()
            && matches!(
                self.family_scope,
                TransparentInterceptionRemoteAddressFamilyScope::Any
            )
    }

    pub fn ipv4(&self) -> &[Ipv4Addr] {
        &self.ipv4
    }

    pub fn ipv6(&self) -> &[Ipv6Addr] {
        &self.ipv6
    }

    pub fn ipv4_any(&self) -> bool {
        match self.family_scope {
            TransparentInterceptionRemoteAddressFamilyScope::Any => true,
            TransparentInterceptionRemoteAddressFamilyScope::Only { ipv4, .. } => ipv4,
        }
    }

    pub fn ipv6_any(&self) -> bool {
        match self.family_scope {
            TransparentInterceptionRemoteAddressFamilyScope::Any => true,
            TransparentInterceptionRemoteAddressFamilyScope::Only { ipv6, .. } => ipv6,
        }
    }

    fn with_family_wildcards(
        ipv4_any: bool,
        ipv6_any: bool,
        ipv4: Vec<Ipv4Addr>,
        ipv6: Vec<Ipv6Addr>,
    ) -> Self {
        let family_scope = if ipv4_any && ipv6_any && ipv4.is_empty() && ipv6.is_empty() {
            TransparentInterceptionRemoteAddressFamilyScope::Any
        } else {
            TransparentInterceptionRemoteAddressFamilyScope::Only {
                ipv4: ipv4_any,
                ipv6: ipv6_any,
            }
        };
        Self {
            ipv4,
            ipv6,
            family_scope,
        }
    }

    fn equivalent_to(&self, other: &Self) -> bool {
        self.family_scope == other.family_scope
            && same_values(&self.ipv4, &other.ipv4)
            && same_values(&self.ipv6, &other.ipv6)
    }

    fn contains_scope(&self, other: &Self) -> bool {
        remote_family_scope_contains(self.ipv4_any(), &self.ipv4, other.ipv4_any(), &other.ipv4)
            && remote_family_scope_contains(
                self.ipv6_any(),
                &self.ipv6,
                other.ipv6_any(),
                &other.ipv6,
            )
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

impl Default for TransparentInterceptionRemoteAddressScope {
    fn default() -> Self {
        Self {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            family_scope: TransparentInterceptionRemoteAddressFamilyScope::Any,
        }
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

    fn contains_scope(&self, other: &Self) -> bool {
        owner_values_contain(&self.uids, &other.uids)
            && owner_values_contain(&self.gids, &other.gids)
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
    let mut ipv4_any = false;
    let mut ipv6_any = false;
    for scope in scopes {
        if scope.is_any() {
            return TransparentInterceptionRemoteAddressScope::any();
        }
        if scope.ipv4_any() {
            ipv4_any = true;
            ipv4.clear();
        } else if !ipv4_any {
            push_unique_all(&mut ipv4, scope.ipv4());
        }
        if scope.ipv6_any() {
            ipv6_any = true;
            ipv6.clear();
        } else if !ipv6_any {
            push_unique_all(&mut ipv6, scope.ipv6());
        }
    }
    TransparentInterceptionRemoteAddressScope::with_family_wildcards(ipv4_any, ipv6_any, ipv4, ipv6)
}

fn compact_host_rule_scopes(
    scopes: Vec<TransparentInterceptionHostRuleScope>,
) -> Vec<TransparentInterceptionHostRuleScope> {
    let mut scopes = dedup_host_rule_scopes(scopes);
    scopes = collapse_covered_host_rule_scopes(scopes);
    match TransparentInterceptionHostRuleScope::union_without_expansion(&scopes) {
        Some(scope) => vec![scope],
        None => scopes,
    }
}

fn dedup_host_rule_scopes(
    scopes: Vec<TransparentInterceptionHostRuleScope>,
) -> Vec<TransparentInterceptionHostRuleScope> {
    let mut unique = Vec::new();
    for scope in scopes {
        if !unique.contains(&scope) {
            unique.push(scope);
        }
    }
    unique
}

fn collapse_covered_host_rule_scopes(
    scopes: Vec<TransparentInterceptionHostRuleScope>,
) -> Vec<TransparentInterceptionHostRuleScope> {
    scopes
        .iter()
        .enumerate()
        .filter_map(|(candidate_index, candidate)| {
            let covered = scopes.iter().enumerate().any(|(cover_index, cover)| {
                cover_index != candidate_index && cover.contains_scope(candidate)
            });
            (!covered).then(|| candidate.clone())
        })
        .collect()
}

fn collect_unique_explicit_ports<'a>(
    scopes: impl Iterator<Item = &'a TransparentInterceptionPortScope>,
) -> Option<Vec<u16>> {
    let mut ports = Vec::new();
    for scope in scopes {
        let scope_ports = scope.only_values()?;
        push_unique_all(&mut ports, scope_ports);
    }
    Some(ports)
}

fn owner_values_contain(left: &[u32], right: &[u32]) -> bool {
    left.is_empty() || (!right.is_empty() && right.iter().all(|value| left.contains(value)))
}

fn remote_family_scope_contains<T>(
    left_any: bool,
    left_values: &[T],
    right_any: bool,
    right_values: &[T],
) -> bool
where
    T: Eq,
{
    left_any || (!right_any && right_values.iter().all(|value| left_values.contains(value)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_rule_set_removes_duplicate_and_covered_scopes() {
        let narrow = local_port_scope_with_remote_addresses(8443, [Ipv4Addr::new(203, 0, 113, 10)]);
        let broad = local_port_scope(8443);

        let rules = TransparentInterceptionHostRuleSet::new(vec![narrow, broad.clone(), broad])
            .expect("covered and duplicate scopes should still form host rules");

        let [scope] = rules.scopes() else {
            panic!("covered scopes should collapse into one canonical scope");
        };
        assert_eq!(scope.local_ports().values(), &[8443]);
        assert!(scope.remote_addresses().is_any());
    }

    #[test]
    fn host_rule_set_preserves_single_family_remote_wildcard() {
        let rules =
            TransparentInterceptionHostRuleSet::new(vec![local_port_scope_with_remote_scope(
                8443,
                TransparentInterceptionRemoteAddressScope::any_ipv4(),
            )])
            .expect("single-family wildcard scope should form host rules");

        let [scope] = rules.scopes() else {
            panic!("single family scope should remain one scope");
        };
        assert!(scope.remote_addresses().ipv4_any());
        assert!(!scope.remote_addresses().ipv6_any());
    }

    #[test]
    fn host_rule_set_merges_both_family_remote_wildcards() {
        let rules = TransparentInterceptionHostRuleSet::new(vec![
            local_port_scope_with_remote_scope(
                8443,
                TransparentInterceptionRemoteAddressScope::any_ipv4(),
            ),
            local_port_scope_with_remote_scope(
                8443,
                TransparentInterceptionRemoteAddressScope::any_ipv6(),
            ),
        ])
        .expect("both family wildcard scopes should form host rules");

        let [scope] = rules.scopes() else {
            panic!("same-port family wildcard scopes should merge");
        };
        assert!(scope.remote_addresses().is_any());
    }

    #[test]
    fn host_rule_set_rejects_excessive_expansion_after_canonicalization() {
        let scopes = (0..=MAX_HOST_RULE_SCOPES)
            .map(|index| {
                local_port_scope_with_remote_addresses(
                    10000 + index as u16,
                    [Ipv4Addr::new(
                        198,
                        51,
                        (index / 256) as u8,
                        (index % 256) as u8,
                    )],
                )
            })
            .collect();

        let error = TransparentInterceptionHostRuleSet::new(scopes)
            .expect_err("excessive expansion should be rejected");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn host_rule_set_explicit_local_ports_are_unique_across_disjoint_scopes() {
        let rules = TransparentInterceptionHostRuleSet::new(vec![
            owner_local_port_scope(8443, 1000),
            owner_local_port_scope(8443, 1001),
            owner_local_port_scope(9443, 1002),
        ])
        .expect("owner-disjoint local port scopes should remain valid");

        assert_eq!(rules.explicit_local_ports(), Some(vec![8443, 9443]));
    }

    fn local_port_scope(local_port: u16) -> TransparentInterceptionHostRuleScope {
        TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::only(vec![local_port]),
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionRemoteAddressScope::any(),
        )
        .expect("test scope should contain a local port")
    }

    fn local_port_scope_with_remote_addresses<const N: usize>(
        local_port: u16,
        remote_addresses: [Ipv4Addr; N],
    ) -> TransparentInterceptionHostRuleScope {
        local_port_scope_with_remote_scope(
            local_port,
            TransparentInterceptionRemoteAddressScope::new(remote_addresses.to_vec(), Vec::new()),
        )
    }

    fn local_port_scope_with_remote_scope(
        local_port: u16,
        remote_addresses: TransparentInterceptionRemoteAddressScope,
    ) -> TransparentInterceptionHostRuleScope {
        TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::only(vec![local_port]),
            TransparentInterceptionPortScope::any(),
            remote_addresses,
        )
        .expect("test scope should contain a local port")
    }

    fn owner_local_port_scope(local_port: u16, uid: u32) -> TransparentInterceptionHostRuleScope {
        TransparentInterceptionHostRuleScope::with_socket_owners(
            TransparentInterceptionPortScope::only(vec![local_port]),
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionRemoteAddressScope::any(),
            TransparentInterceptionSocketOwnerScope::new(vec![uid], Vec::new()),
        )
        .expect("test scope should contain local port and owner constraints")
    }
}

use std::net::{Ipv4Addr, Ipv6Addr};

use probe_core::{ProcessSelector, Selector, TrafficSelector};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionHostRuleScope {
    local_ports: TransparentInterceptionPortScope,
    remote_ports: TransparentInterceptionPortScope,
    remote_addresses: TransparentInterceptionRemoteAddressScope,
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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransparentInterceptionSetupProjectionError {
    #[error("transparent interception requires an explicit selector for setup-time rules")]
    MissingSelector,
    #[error(
        "transparent interception selector must include at least one port or remote address constraint"
    )]
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
        if local_ports.is_any() && remote_ports.is_any() && remote_addresses.is_empty() {
            return Err(TransparentInterceptionSetupProjectionError::UnconstrainedSelector);
        }
        Ok(Self {
            local_ports,
            remote_ports,
            remote_addresses,
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

pub(crate) fn process_selector_has_constraints(process: &ProcessSelector) -> bool {
    !process.pids.is_empty()
        || !process.names.is_empty()
        || !process.exe_path_globs.is_empty()
        || !process.cmdline_regexes.is_empty()
        || !process.systemd_services.is_empty()
        || !process.container_ids.is_empty()
}

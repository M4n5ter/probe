use std::collections::{BTreeMap, BTreeSet};

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Direction, FlowContext};

#[derive(Debug, Error)]
pub enum SelectorError {
    #[error("invalid executable path glob: {0}")]
    InvalidGlob(String),
    #[error("invalid cmdline regex: {0}")]
    InvalidRegex(String),
    #[error("unknown named selector: {0}")]
    UnknownNamedSelector(String),
    #[error("recursive named selector reference: {0}")]
    RecursiveNamedSelector(String),
    #[error("selector {0} requires at least one child")]
    EmptyComposite(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Selector {
    Match { term: Box<SelectorTerm> },
    All { selectors: Vec<Selector> },
    Any { selectors: Vec<Selector> },
    Not { selector: Box<Selector> },
    Ref { name: String },
}

impl Default for Selector {
    fn default() -> Self {
        Self::Match {
            term: Box::<SelectorTerm>::default(),
        }
    }
}

impl Selector {
    pub fn term(process: ProcessSelector, traffic: TrafficSelector) -> Self {
        Self::Match {
            term: Box::new(SelectorTerm { process, traffic }),
        }
    }

    pub fn compile(&self) -> Result<CompiledSelector, SelectorError> {
        self.compile_with_registry(&SelectorRegistry::default())
    }

    pub fn compile_with_registry(
        &self,
        registry: &SelectorRegistry,
    ) -> Result<CompiledSelector, SelectorError> {
        let mut resolving = BTreeSet::new();
        Ok(CompiledSelector {
            node: CompiledSelectorNode::compile(self, registry, &mut resolving)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorTerm {
    pub process: ProcessSelector,
    pub traffic: TrafficSelector,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorRegistry {
    selectors: BTreeMap<String, Selector>,
}

impl SelectorRegistry {
    pub fn new(selectors: impl IntoIterator<Item = (String, Selector)>) -> Self {
        Self {
            selectors: selectors.into_iter().collect(),
        }
    }

    pub fn get(&self, name: &str) -> Option<&Selector> {
        self.selectors.get(name)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSelector {
    pub pids: Vec<u32>,
    pub names: Vec<String>,
    pub exe_path_globs: Vec<String>,
    pub cmdline_regexes: Vec<String>,
    pub systemd_services: Vec<String>,
    pub container_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSelector {
    pub local_ports: Vec<u16>,
    pub remote_ports: Vec<u16>,
    pub directions: Vec<Direction>,
    pub remote_addresses: Vec<String>,
}

pub struct CompiledSelector {
    node: CompiledSelectorNode,
}

impl CompiledSelector {
    pub fn matches_flow(&self, flow: &FlowContext, direction: Direction) -> bool {
        self.node.matches_flow(flow, direction)
    }
}

enum CompiledSelectorNode {
    Match(Box<CompiledSelectorTerm>),
    All(Vec<CompiledSelectorNode>),
    Any(Vec<CompiledSelectorNode>),
    Not(Box<CompiledSelectorNode>),
}

impl CompiledSelectorNode {
    fn compile(
        selector: &Selector,
        registry: &SelectorRegistry,
        resolving: &mut BTreeSet<String>,
    ) -> Result<Self, SelectorError> {
        match selector {
            Selector::Match { term } => CompiledSelectorTerm::new((**term).clone())
                .map(Box::new)
                .map(Self::Match),
            Selector::All { selectors } => selectors
                .iter()
                .map(|selector| Self::compile(selector, registry, resolving))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|selectors| non_empty_composite("all", selectors))
                .map(Self::All),
            Selector::Any { selectors } => selectors
                .iter()
                .map(|selector| Self::compile(selector, registry, resolving))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|selectors| non_empty_composite("any", selectors))
                .map(Self::Any),
            Selector::Not { selector } => Self::compile(selector, registry, resolving)
                .map(Box::new)
                .map(Self::Not),
            Selector::Ref { name } => {
                if !resolving.insert(name.clone()) {
                    return Err(SelectorError::RecursiveNamedSelector(name.clone()));
                }
                let target = registry
                    .get(name)
                    .ok_or_else(|| SelectorError::UnknownNamedSelector(name.clone()))?;
                let compiled = Self::compile(target, registry, resolving)?;
                resolving.remove(name);
                Ok(compiled)
            }
        }
    }

    fn matches_flow(&self, flow: &FlowContext, direction: Direction) -> bool {
        match self {
            Self::Match(term) => term.matches_flow(flow, direction),
            Self::All(selectors) => selectors
                .iter()
                .all(|selector| selector.matches_flow(flow, direction)),
            Self::Any(selectors) => selectors
                .iter()
                .any(|selector| selector.matches_flow(flow, direction)),
            Self::Not(selector) => !selector.matches_flow(flow, direction),
        }
    }
}

struct CompiledSelectorTerm {
    term: SelectorTerm,
    exe_path_globs: Option<GlobSet>,
    cmdline_regexes: Option<RegexSet>,
}

impl CompiledSelectorTerm {
    fn new(term: SelectorTerm) -> Result<Self, SelectorError> {
        let exe_path_globs = compile_globs(&term.process.exe_path_globs)?;
        let cmdline_regexes = compile_regexes(&term.process.cmdline_regexes)?;
        Ok(Self {
            term,
            exe_path_globs,
            cmdline_regexes,
        })
    }

    fn matches_flow(&self, flow: &FlowContext, direction: Direction) -> bool {
        self.matches_process(flow) && self.matches_traffic(flow, direction)
    }

    fn matches_process(&self, flow: &FlowContext) -> bool {
        let process = &flow.process;
        let spec = &self.term.process;
        all_match([
            spec.pids.is_empty() || spec.pids.contains(&process.identity.pid),
            spec.names.is_empty() || spec.names.iter().any(|name| name == &process.name),
            spec.systemd_services.is_empty()
                || process
                    .identity
                    .systemd_service
                    .as_ref()
                    .is_some_and(|service| spec.systemd_services.contains(service)),
            spec.container_ids.is_empty()
                || process
                    .identity
                    .container_id
                    .as_ref()
                    .is_some_and(|container_id| spec.container_ids.contains(container_id)),
            self.exe_path_globs
                .as_ref()
                .is_none_or(|globs| globs.is_match(&process.identity.exe_path)),
            self.cmdline_regexes.as_ref().is_none_or(|regexes| {
                let cmdline = process.cmdline.join(" ");
                regexes.is_match(&cmdline)
            }),
        ])
    }

    fn matches_traffic(&self, flow: &FlowContext, direction: Direction) -> bool {
        let spec = &self.term.traffic;
        all_match([
            spec.local_ports.is_empty() || spec.local_ports.contains(&flow.local.port),
            spec.remote_ports.is_empty() || spec.remote_ports.contains(&flow.remote.port),
            spec.directions.is_empty() || spec.directions.contains(&direction),
            spec.remote_addresses.is_empty()
                || spec.remote_addresses.contains(&flow.remote.address),
        ])
    }
}

fn compile_globs(patterns: &[String]) -> Result<Option<GlobSet>, SelectorError> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .map_err(|error| SelectorError::InvalidGlob(format!("{pattern}: {error}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map(Some)
        .map_err(|error| SelectorError::InvalidGlob(error.to_string()))
}

fn compile_regexes(patterns: &[String]) -> Result<Option<RegexSet>, SelectorError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    RegexSet::new(patterns)
        .map(Some)
        .map_err(|error| SelectorError::InvalidRegex(error.to_string()))
}

fn all_match<const N: usize>(matches: [bool; N]) -> bool {
    matches.into_iter().all(|matched| matched)
}

fn non_empty_composite<T>(name: &'static str, values: Vec<T>) -> Result<Vec<T>, SelectorError> {
    if values.is_empty() {
        Err(SelectorError::EmptyComposite(name))
    } else {
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        AddressPort, Direction, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity,
        ProcessSelector, Selector, SelectorRegistry, TrafficSelector, TransportProtocol,
    };

    #[test]
    fn selector_matches_process_and_traffic_dimensions() -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                exe_path_globs: vec!["/usr/bin/*".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![80],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;

        let flow = demo_flow();
        assert!(selector.matches_flow(&flow, Direction::Outbound));
        assert!(!selector.matches_flow(&flow, Direction::Inbound));
        Ok(())
    }

    #[test]
    fn selector_ast_supports_any_not_and_named_reuse() -> Result<(), Box<dyn std::error::Error>> {
        let registry = SelectorRegistry::new([(
            "demo-process".to_string(),
            Selector::term(
                ProcessSelector {
                    names: vec!["demo".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
        )]);
        let selector = Selector::All {
            selectors: vec![
                Selector::Ref {
                    name: "demo-process".to_string(),
                },
                Selector::Any {
                    selectors: vec![
                        Selector::term(
                            ProcessSelector::default(),
                            TrafficSelector {
                                remote_ports: vec![80],
                                ..TrafficSelector::default()
                            },
                        ),
                        Selector::term(
                            ProcessSelector::default(),
                            TrafficSelector {
                                remote_ports: vec![443],
                                ..TrafficSelector::default()
                            },
                        ),
                    ],
                },
                Selector::Not {
                    selector: Box::new(Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            directions: vec![Direction::Inbound],
                            ..TrafficSelector::default()
                        },
                    )),
                },
            ],
        }
        .compile_with_registry(&registry)?;

        let flow = demo_flow();
        assert!(selector.matches_flow(&flow, Direction::Outbound));
        assert!(!selector.matches_flow(&flow, Direction::Inbound));
        Ok(())
    }

    #[test]
    fn selector_rejects_recursive_named_references() {
        let registry = SelectorRegistry::new([(
            "self".to_string(),
            Selector::Ref {
                name: "self".to_string(),
            },
        )]);
        let result = Selector::Ref {
            name: "self".to_string(),
        }
        .compile_with_registry(&registry);

        assert!(result.is_err());
    }

    #[test]
    fn selector_rejects_empty_composites() {
        let result = Selector::Any {
            selectors: Vec::new(),
        }
        .compile();

        assert!(result.is_err());
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 42,
            tgid: 42,
            start_time_ticks: 100,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: Some("demo.service".to_string()),
            container_id: None,
            runtime_hint: None,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process,
                &AddressPort {
                    address: "127.0.0.1".to_string(),
                    port: 40_000,
                },
                &AddressPort {
                    address: "127.0.0.1".to_string(),
                    port: 80,
                },
                TransportProtocol::Tcp,
                1,
                Some(7),
            ),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 40_000,
            },
            remote: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 80,
            },
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(7),
            attribution_confidence: 100,
        }
    }
}

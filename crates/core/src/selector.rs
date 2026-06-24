use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Direction, EventEnvelope, FlowContext, ProcessContext};

#[derive(Debug, Error)]
pub enum SelectorError {
    #[error("invalid executable path glob: {0}")]
    InvalidGlob(String),
    #[error("invalid cmdline regex: {0}")]
    InvalidRegex(String),
    #[error("invalid remote address: {0}")]
    InvalidRemoteAddress(String),
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
    #[serde(default)]
    pub uids: Vec<u32>,
    #[serde(default)]
    pub gids: Vec<u32>,
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

#[derive(Clone)]
pub struct CompiledSelector {
    node: CompiledSelectorNode,
}

impl CompiledSelector {
    pub fn matches_flow(&self, flow: &FlowContext, direction: Direction) -> bool {
        self.node
            .matches_flow(flow, Some(direction))
            .unwrap_or(false)
    }

    pub fn matches_flow_without_direction(&self, flow: &FlowContext) -> bool {
        self.node.matches_flow(flow, None).unwrap_or(false)
    }

    /// Matches a flow candidate when only process identity and direction are known.
    ///
    /// This is intentionally fail-closed for selectors that require local/remote ports or remote
    /// addresses. It is useful for plaintext sources that can observe payload before they can prove
    /// a concrete socket flow.
    pub fn matches_unattributed_flow(
        &self,
        process: &ProcessContext,
        direction: Direction,
    ) -> bool {
        self.node
            .matches_unattributed_flow(process, direction)
            .unwrap_or(false)
    }

    pub fn matches_event(&self, event: &EventEnvelope) -> bool {
        let Some(flow) = event.flow() else {
            return false;
        };
        event.kind().direction().map_or_else(
            || self.matches_flow_without_direction(flow),
            |direction| self.matches_flow(flow, direction),
        )
    }

    /// Returns false only when `process` can be ruled out before flow attribution.
    ///
    /// This is a conservative prefilter for process-scoped setup. A true result keeps a candidate;
    /// final decisions must use a full flow and direction.
    pub fn may_match_process(&self, process: &ProcessContext) -> bool {
        self.node.may_match_process(process)
    }
}

#[derive(Clone)]
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

    fn matches_flow(&self, flow: &FlowContext, direction: Option<Direction>) -> Option<bool> {
        match self {
            Self::Match(term) => term.matches_flow(flow, direction),
            Self::All(selectors) => all_selector_matches(
                selectors
                    .iter()
                    .map(|selector| selector.matches_flow(flow, direction)),
            ),
            Self::Any(selectors) => any_selector_matches(
                selectors
                    .iter()
                    .map(|selector| selector.matches_flow(flow, direction)),
            ),
            Self::Not(selector) => selector
                .matches_flow(flow, direction)
                .map(|matched| !matched),
        }
    }

    fn matches_unattributed_flow(
        &self,
        process: &ProcessContext,
        direction: Direction,
    ) -> Option<bool> {
        match self {
            Self::Match(term) => term.matches_unattributed_flow(process, direction),
            Self::All(selectors) => all_selector_matches(
                selectors
                    .iter()
                    .map(|selector| selector.matches_unattributed_flow(process, direction)),
            ),
            Self::Any(selectors) => any_selector_matches(
                selectors
                    .iter()
                    .map(|selector| selector.matches_unattributed_flow(process, direction)),
            ),
            Self::Not(selector) => selector
                .matches_unattributed_flow(process, direction)
                .map(|matched| !matched),
        }
    }

    fn may_match_process(&self, process: &ProcessContext) -> bool {
        match self {
            Self::Match(term) => term.may_match_process(process),
            Self::All(selectors) => selectors
                .iter()
                .all(|selector| selector.may_match_process(process)),
            Self::Any(selectors) => selectors
                .iter()
                .any(|selector| selector.may_match_process(process)),
            // Negated subtrees can depend on traffic dimensions that are unknown before a flow
            // exists, so process-scoped pruning must not treat them as definitive misses.
            Self::Not(_) => true,
        }
    }
}

#[derive(Clone)]
struct CompiledSelectorTerm {
    term: SelectorTerm,
    exe_path_globs: Option<GlobSet>,
    cmdline_regexes: Option<RegexSet>,
    remote_addresses: Option<BTreeSet<IpAddr>>,
}

impl CompiledSelectorTerm {
    fn new(term: SelectorTerm) -> Result<Self, SelectorError> {
        let exe_path_globs = compile_globs(&term.process.exe_path_globs)?;
        let cmdline_regexes = compile_regexes(&term.process.cmdline_regexes)?;
        let remote_addresses = compile_remote_addresses(&term.traffic.remote_addresses)?;
        Ok(Self {
            term,
            exe_path_globs,
            cmdline_regexes,
            remote_addresses,
        })
    }

    fn matches_flow(&self, flow: &FlowContext, direction: Option<Direction>) -> Option<bool> {
        if !self.matches_process(&flow.process) {
            return Some(false);
        }
        self.matches_traffic(flow, direction)
    }

    fn matches_process(&self, process: &ProcessContext) -> bool {
        self.matches_process_with_unknowns(process).unwrap_or(false)
    }

    fn may_match_process(&self, process: &ProcessContext) -> bool {
        self.matches_process_with_unknowns(process).unwrap_or(true)
    }

    fn matches_process_with_unknowns(&self, process: &ProcessContext) -> Option<bool> {
        let spec = &self.term.process;
        let unknown_numeric_identity = process.identity.pid == 0;
        all_selector_matches(
            [
                match_u32_list(&spec.pids, process.identity.pid, process.identity.pid == 0),
                match_u32_list(&spec.uids, process.identity.uid, unknown_numeric_identity),
                match_u32_list(&spec.gids, process.identity.gid, unknown_numeric_identity),
                match_string_list(
                    &spec.names,
                    &process.name,
                    unknown_process_string(&process.name),
                ),
                match_optional_string_list(
                    &spec.systemd_services,
                    process.identity.systemd_service.as_ref(),
                ),
                match_optional_string_list(
                    &spec.container_ids,
                    process.identity.container_id.as_ref(),
                ),
                match_globs(
                    self.exe_path_globs.as_ref(),
                    &process.identity.exe_path,
                    unknown_process_string(&process.identity.exe_path),
                ),
                match_regexes(self.cmdline_regexes.as_ref(), process),
            ]
            .into_iter(),
        )
    }

    fn matches_traffic(&self, flow: &FlowContext, direction: Option<Direction>) -> Option<bool> {
        let spec = &self.term.traffic;
        let direction_matches = if spec.directions.is_empty() {
            Some(true)
        } else {
            direction.map(|direction| spec.directions.contains(&direction))
        };

        Some(all_match([
            spec.local_ports.is_empty() || spec.local_ports.contains(&flow.local.port),
            spec.remote_ports.is_empty() || spec.remote_ports.contains(&flow.remote.port),
            direction_matches?,
            match_remote_address(self.remote_addresses.as_ref(), &flow.remote.address),
        ]))
    }

    fn matches_unattributed_flow(
        &self,
        process: &ProcessContext,
        direction: Direction,
    ) -> Option<bool> {
        if !self.matches_process_with_unknowns(process)? {
            return Some(false);
        }
        let spec = &self.term.traffic;
        if !spec.local_ports.is_empty()
            || !spec.remote_ports.is_empty()
            || !spec.remote_addresses.is_empty()
        {
            return None;
        }
        Some(spec.directions.is_empty() || spec.directions.contains(&direction))
    }
}

fn match_u32_list(values: &[u32], value: u32, unknown: bool) -> Option<bool> {
    if values.is_empty() {
        Some(true)
    } else if unknown {
        None
    } else {
        Some(values.contains(&value))
    }
}

fn match_string_list(values: &[String], value: &str, unknown: bool) -> Option<bool> {
    if values.is_empty() {
        Some(true)
    } else if unknown {
        None
    } else {
        Some(values.iter().any(|candidate| candidate == value))
    }
}

fn match_optional_string_list(values: &[String], value: Option<&String>) -> Option<bool> {
    if values.is_empty() {
        return Some(true);
    }
    value.map(|value| values.contains(value))
}

fn match_globs(globs: Option<&GlobSet>, value: &str, unknown: bool) -> Option<bool> {
    match globs {
        None => Some(true),
        Some(_) if unknown => None,
        Some(globs) => Some(globs.is_match(value)),
    }
}

fn match_regexes(regexes: Option<&RegexSet>, process: &ProcessContext) -> Option<bool> {
    match regexes {
        None => Some(true),
        Some(_) if unknown_cmdline(process) => None,
        Some(regexes) => {
            let cmdline = process.cmdline.join(" ");
            Some(regexes.is_match(&cmdline))
        }
    }
}

fn all_selector_matches(matches: impl Iterator<Item = Option<bool>>) -> Option<bool> {
    let mut unknown = false;
    for matched in matches {
        match matched {
            Some(true) => {}
            Some(false) => return Some(false),
            None => unknown = true,
        }
    }
    (!unknown).then_some(true)
}

fn any_selector_matches(matches: impl Iterator<Item = Option<bool>>) -> Option<bool> {
    let mut unknown = false;
    for matched in matches {
        match matched {
            Some(true) => return Some(true),
            Some(false) => {}
            None => unknown = true,
        }
    }
    (!unknown).then_some(false)
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

fn compile_remote_addresses(
    addresses: &[String],
) -> Result<Option<BTreeSet<IpAddr>>, SelectorError> {
    if addresses.is_empty() {
        return Ok(None);
    }
    addresses
        .iter()
        .map(|address| {
            address
                .parse::<IpAddr>()
                .map_err(|error| SelectorError::InvalidRemoteAddress(format!("{address}: {error}")))
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map(Some)
}

fn match_remote_address(addresses: Option<&BTreeSet<IpAddr>>, flow_address: &str) -> bool {
    match addresses {
        None => true,
        Some(addresses) => flow_address
            .parse::<IpAddr>()
            .is_ok_and(|address| addresses.contains(&address)),
    }
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

fn unknown_process_string(value: &str) -> bool {
    value.is_empty() || value == "unknown"
}

fn unknown_cmdline(process: &ProcessContext) -> bool {
    unknown_process_string(&process.identity.cmdline_hash) || process.cmdline.is_empty()
}

#[cfg(test)]
mod tests {
    use crate::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity, ProcessSelector,
        Selector, SelectorError, SelectorRegistry, Timestamp, TrafficSelector, TransportProtocol,
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
    fn selector_matches_process_owner_dimensions() -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                uids: vec![1000],
                gids: vec![1000],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()?;
        let other_uid = Selector::term(
            ProcessSelector {
                uids: vec![2000],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()?;

        let flow = demo_flow();
        assert!(selector.matches_flow_without_direction(&flow));
        assert!(!other_uid.matches_flow_without_direction(&flow));
        Ok(())
    }

    #[test]
    fn selector_matches_flow_events_with_event_direction() -> Result<(), Box<dyn std::error::Error>>
    {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![80],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;

        assert!(selector.matches_event(&http_event(Direction::Outbound)));
        assert!(!selector.matches_event(&http_event(Direction::Inbound)));
        assert!(!selector.matches_event(&EventEnvelope::from_provider(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "test",
            EventKind::CaptureLoss(crate::CaptureLoss {
                lost_events: 1,
                reason: "lost".to_string(),
            }),
        )));
        Ok(())
    }

    #[test]
    fn directionless_match_misses_direction_constrained_selector()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let inverted = Selector::Not {
            selector: Box::new(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            )),
        }
        .compile()?;

        let flow = demo_flow();
        assert!(!selector.matches_flow_without_direction(&flow));
        assert!(!inverted.matches_flow_without_direction(&flow));
        Ok(())
    }

    #[test]
    fn directionless_match_still_allows_process_only_selector()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()?;

        assert!(selector.matches_flow_without_direction(&demo_flow()));
        Ok(())
    }

    #[test]
    fn process_scope_projection_prunes_only_process_mismatches()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let matching = demo_flow().process;
        let mut non_matching = matching.clone();
        non_matching.name = "other".to_string();

        assert!(selector.may_match_process(&matching));
        assert!(!selector.may_match_process(&non_matching));
        Ok(())
    }

    #[test]
    fn unattributed_flow_match_allows_process_and_direction_only_selectors()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let process = demo_flow().process;

        assert!(selector.matches_unattributed_flow(&process, Direction::Outbound));
        assert!(!selector.matches_unattributed_flow(&process, Direction::Inbound));
        Ok(())
    }

    #[test]
    fn unattributed_flow_match_fails_closed_for_unknown_traffic_dimensions()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let negated = Selector::Not {
            selector: Box::new(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![443],
                    ..TrafficSelector::default()
                },
            )),
        }
        .compile()?;
        let process = demo_flow().process;

        assert!(!selector.matches_unattributed_flow(&process, Direction::Outbound));
        assert!(!negated.matches_unattributed_flow(&process, Direction::Outbound));
        Ok(())
    }

    #[test]
    fn unattributed_flow_match_fails_closed_for_unknown_process_dimensions()
    -> Result<(), Box<dyn std::error::Error>> {
        let process = partial_process();
        for selector in unknown_process_dimension_selectors() {
            let positive = selector.clone().compile()?;
            let negated = Selector::Not {
                selector: Box::new(selector),
            }
            .compile()?;

            assert!(!positive.matches_unattributed_flow(&process, Direction::Outbound));
            assert!(!negated.matches_unattributed_flow(&process, Direction::Outbound));
        }
        Ok(())
    }

    #[test]
    fn unattributed_flow_match_fails_closed_for_unknown_owner_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let process = synthetic_process();
        for selector in owner_identity_selectors() {
            let positive = selector.clone().compile()?;
            let negated = Selector::Not {
                selector: Box::new(selector),
            }
            .compile()?;

            assert!(!positive.matches_unattributed_flow(&process, Direction::Outbound));
            assert!(!negated.matches_unattributed_flow(&process, Direction::Outbound));
        }
        Ok(())
    }

    #[test]
    fn unattributed_flow_match_keeps_unknown_process_dimensions_through_composites()
    -> Result<(), Box<dyn std::error::Error>> {
        let unknown_exe = Selector::term(
            ProcessSelector {
                exe_path_globs: vec!["/usr/bin/demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        );
        let matching_name = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        );
        let unknown_remote = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                ..TrafficSelector::default()
            },
        );
        let all = Selector::All {
            selectors: vec![
                matching_name.clone(),
                Selector::Not {
                    selector: Box::new(unknown_exe.clone()),
                },
            ],
        }
        .compile()?;
        let any = Selector::Any {
            selectors: vec![
                Selector::Not {
                    selector: Box::new(unknown_exe),
                },
                unknown_remote,
            ],
        }
        .compile()?;
        let known_any = Selector::Any {
            selectors: vec![
                matching_name,
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        remote_ports: vec![443],
                        ..TrafficSelector::default()
                    },
                ),
            ],
        }
        .compile()?;
        let process = partial_process();

        assert!(!all.matches_unattributed_flow(&process, Direction::Outbound));
        assert!(!any.matches_unattributed_flow(&process, Direction::Outbound));
        assert!(known_any.matches_unattributed_flow(&process, Direction::Outbound));
        Ok(())
    }

    #[test]
    fn process_scope_projection_keeps_traffic_and_negative_unknowns_conservative()
    -> Result<(), Box<dyn std::error::Error>> {
        let traffic_only = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let negated_process = Selector::Not {
            selector: Box::new(Selector::term(
                ProcessSelector {
                    names: vec!["demo".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            )),
        }
        .compile()?;
        let process = demo_flow().process;

        assert!(traffic_only.may_match_process(&process));
        assert!(negated_process.may_match_process(&process));
        Ok(())
    }

    #[test]
    fn process_scope_projection_keeps_partial_identity_fields_conservative()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                exe_path_globs: vec!["/opt/demo/*".to_string()],
                cmdline_regexes: vec!["--tenant managed".to_string()],
                systemd_services: vec!["demo.service".to_string()],
                container_ids: vec!["container-a".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()?;
        let partial = partial_process();

        assert!(selector.may_match_process(&partial));
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

    #[test]
    fn selector_matches_remote_addresses_by_ip_value() -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_addresses: vec!["2001:0db8::1".to_string()],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut flow = demo_flow();
        flow.remote.address = "2001:db8::1".to_string();

        assert!(selector.matches_flow_without_direction(&flow));
        Ok(())
    }

    #[test]
    fn selector_rejects_invalid_remote_addresses() {
        let result = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_addresses: vec!["not an ip".to_string()],
                ..TrafficSelector::default()
            },
        )
        .compile();

        assert!(matches!(
            result,
            Err(SelectorError::InvalidRemoteAddress(_))
        ));
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

    fn http_event(direction: Direction) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn partial_process() -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid: 42,
                tgid: 42,
                start_time_ticks: 0,
                boot_id: String::new(),
                exe_path: String::new(),
                cmdline_hash: String::new(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "demo".to_string(),
            cmdline: vec!["demo".to_string()],
        }
    }

    fn synthetic_process() -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid: 0,
                tgid: 0,
                start_time_ticks: 0,
                boot_id: "synthetic".to_string(),
                exe_path: "unknown".to_string(),
                cmdline_hash: "unknown".to_string(),
                uid: 0,
                gid: 0,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: Some("synthetic".to_string()),
            },
            name: "unknown".to_string(),
            cmdline: Vec::new(),
        }
    }

    fn unknown_process_dimension_selectors() -> Vec<Selector> {
        vec![
            Selector::term(
                ProcessSelector {
                    exe_path_globs: vec!["/usr/bin/demo".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
            Selector::term(
                ProcessSelector {
                    cmdline_regexes: vec!["--tenant managed".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
            Selector::term(
                ProcessSelector {
                    systemd_services: vec!["demo.service".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
            Selector::term(
                ProcessSelector {
                    container_ids: vec!["container-a".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
        ]
    }

    fn owner_identity_selectors() -> Vec<Selector> {
        vec![
            Selector::term(
                ProcessSelector {
                    uids: vec![0],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
            Selector::term(
                ProcessSelector {
                    gids: vec![0],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
        ]
    }
}

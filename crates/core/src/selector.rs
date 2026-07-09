use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CgroupPath, Direction, EventEnvelope, FlowContext, ProcessContext};

const MAX_RESOLVED_SELECTOR_NODES: usize = 4_096;
const MAX_SELECTOR_REF_RESOLUTION_DEPTH: usize = 64;

#[derive(Debug, Error)]
pub enum SelectorError {
    #[error("invalid executable path glob: {0}")]
    InvalidGlob(String),
    #[error("invalid cmdline regex: {0}")]
    InvalidRegex(String),
    #[error("invalid remote address: {0}")]
    InvalidRemoteAddress(String),
    #[error("invalid cgroup path: {0}")]
    InvalidCgroupPath(String),
    #[error("unknown named selector: {0}")]
    UnknownNamedSelector(String),
    #[error("recursive named selector reference: {0}")]
    RecursiveNamedSelector(String),
    #[error("selector {0} requires at least one child")]
    EmptyComposite(&'static str),
    #[error("resolved selector exceeds maximum expanded node count of {max}")]
    ResolvedSelectorTooLarge { max: usize },
    #[error("selector ref resolution exceeds maximum depth of {max}")]
    SelectorRefResolutionTooDeep { max: usize },
    #[error("resolved selector still contains named selector ref: {0}")]
    UnresolvedNamedSelector(String),
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

    pub fn resolve_refs_with_registry(
        &self,
        registry: &SelectorRegistry,
    ) -> Result<ResolvedSelector, SelectorError> {
        let mut context = ResolveSelectorRefsContext::default();
        ResolvedSelector::new(resolve_selector_refs(self, registry, &mut context, 0)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSelector {
    selector: Selector,
}

impl ResolvedSelector {
    pub fn new(selector: Selector) -> Result<Self, SelectorError> {
        let mut nodes = 0;
        validate_resolved_selector(&selector, &mut nodes)?;
        selector.compile()?;
        Ok(Self { selector })
    }

    pub fn as_selector(&self) -> &Selector {
        &self.selector
    }

    pub fn into_selector(self) -> Selector {
        self.selector
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorTerm {
    pub process: ProcessSelector,
    pub traffic: TrafficSelector,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
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

    pub fn is_empty(&self) -> bool {
        self.selectors.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Selector)> {
        self.selectors.iter()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSelector {
    #[serde(default)]
    pub pids: Vec<u32>,
    #[serde(default)]
    pub uids: Vec<u32>,
    #[serde(default)]
    pub gids: Vec<u32>,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub exe_path_globs: Vec<String>,
    #[serde(default)]
    pub cmdline_regexes: Vec<String>,
    #[serde(default)]
    pub systemd_services: Vec<String>,
    #[serde(default)]
    pub container_ids: Vec<String>,
    #[serde(default)]
    pub cgroup_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSelector {
    #[serde(default)]
    pub local_ports: Vec<u16>,
    #[serde(default)]
    pub remote_ports: Vec<u16>,
    #[serde(default)]
    pub directions: Vec<Direction>,
    #[serde(default)]
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

    pub fn matches_flow_with_unknown_process(
        &self,
        flow: &FlowContext,
        direction: Option<Direction>,
    ) -> bool {
        self.node
            .matches_flow_with_unknown_process(flow, direction)
            .unwrap_or(false)
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

    /// Matches an event when process identity is explicitly unknown but traffic dimensions match.
    ///
    /// This is for observation and diagnostics queries that want to surface weak-attribution
    /// candidates. Policy decisions and enforcement scopes should keep using `matches_event`.
    pub fn matches_event_with_unknown_process(&self, event: &EventEnvelope) -> bool {
        let Some(flow) = event.flow() else {
            return false;
        };
        event.kind().direction().map_or_else(
            || {
                self.node
                    .matches_flow_with_unknown_process(flow, None)
                    .unwrap_or(false)
            },
            |direction| {
                self.node
                    .matches_flow_with_unknown_process(flow, Some(direction))
                    .unwrap_or(false)
            },
        )
    }

    /// Returns false only when `process` can be ruled out before flow attribution.
    ///
    /// This is a conservative prefilter for process-scoped setup. A true result keeps a candidate;
    /// final decisions must use a full flow and direction.
    pub fn may_match_process(&self, process: &ProcessContext) -> bool {
        self.node.may_match_process(process)
    }

    /// Returns false only when `process` and `direction` can be ruled out before full flow
    /// attribution.
    ///
    /// This is a conservative prefilter for payload capture. Ports and addresses are intentionally
    /// left to final flow/event selection because they are unknown at syscall entry for generic
    /// process-level payload sampling.
    pub fn may_match_process_direction(
        &self,
        process: &ProcessContext,
        direction: Direction,
    ) -> bool {
        self.node.may_match_process_direction(process, direction)
    }

    pub fn may_match_observed_process_direction(
        &self,
        process: &ProcessContext,
        direction: Direction,
    ) -> bool {
        self.node
            .may_match_observed_process_direction(process, direction)
            .unwrap_or(false)
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

    fn matches_flow_with_unknown_process(
        &self,
        flow: &FlowContext,
        direction: Option<Direction>,
    ) -> Option<bool> {
        match self {
            Self::Match(term) => term.matches_flow_with_unknown_process(flow, direction),
            Self::All(selectors) => all_selector_matches(
                selectors
                    .iter()
                    .map(|selector| selector.matches_flow_with_unknown_process(flow, direction)),
            ),
            Self::Any(selectors) => any_selector_matches(
                selectors
                    .iter()
                    .map(|selector| selector.matches_flow_with_unknown_process(flow, direction)),
            ),
            Self::Not(selector) => selector
                .matches_flow_with_unknown_process(flow, direction)
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

    fn may_match_process_direction(&self, process: &ProcessContext, direction: Direction) -> bool {
        match self {
            Self::Match(term) => term.may_match_process_direction(process, direction),
            Self::All(selectors) => selectors
                .iter()
                .all(|selector| selector.may_match_process_direction(process, direction)),
            Self::Any(selectors) => selectors
                .iter()
                .any(|selector| selector.may_match_process_direction(process, direction)),
            Self::Not(_) => true,
        }
    }

    fn may_match_observed_process_direction(
        &self,
        process: &ProcessContext,
        direction: Direction,
    ) -> Option<bool> {
        match self {
            Self::Match(term) => term.may_match_observed_process_direction(process, direction),
            Self::All(selectors) => {
                all_selector_matches(selectors.iter().map(|selector| {
                    selector.may_match_observed_process_direction(process, direction)
                }))
            }
            Self::Any(selectors) => {
                any_selector_matches(selectors.iter().map(|selector| {
                    selector.may_match_observed_process_direction(process, direction)
                }))
            }
            Self::Not(selector) => selector
                .may_match_observed_process_direction(process, direction)
                .map(|matched| !matched),
        }
    }
}

#[derive(Default)]
struct ResolveSelectorRefsContext {
    resolving: BTreeSet<String>,
    nodes: usize,
}

impl ResolveSelectorRefsContext {
    fn reserve_node(&mut self) -> Result<(), SelectorError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_RESOLVED_SELECTOR_NODES {
            return Err(SelectorError::ResolvedSelectorTooLarge {
                max: MAX_RESOLVED_SELECTOR_NODES,
            });
        }
        Ok(())
    }
}

fn resolve_selector_refs(
    selector: &Selector,
    registry: &SelectorRegistry,
    context: &mut ResolveSelectorRefsContext,
    depth: usize,
) -> Result<Selector, SelectorError> {
    if depth > MAX_SELECTOR_REF_RESOLUTION_DEPTH {
        return Err(SelectorError::SelectorRefResolutionTooDeep {
            max: MAX_SELECTOR_REF_RESOLUTION_DEPTH,
        });
    }
    context.reserve_node()?;
    match selector {
        Selector::Match { term } => Ok(Selector::Match { term: term.clone() }),
        Selector::All { selectors } => {
            non_empty_selector_children("all", selectors)?;
            selectors
                .iter()
                .map(|selector| resolve_selector_refs(selector, registry, context, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(|selectors| Selector::All { selectors })
        }
        Selector::Any { selectors } => {
            non_empty_selector_children("any", selectors)?;
            selectors
                .iter()
                .map(|selector| resolve_selector_refs(selector, registry, context, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(|selectors| Selector::Any { selectors })
        }
        Selector::Not { selector } => resolve_selector_refs(selector, registry, context, depth + 1)
            .map(Box::new)
            .map(|selector| Selector::Not { selector }),
        Selector::Ref { name } => {
            if !context.resolving.insert(name.clone()) {
                return Err(SelectorError::RecursiveNamedSelector(name.clone()));
            }
            let target = registry
                .get(name)
                .ok_or_else(|| SelectorError::UnknownNamedSelector(name.clone()))?;
            let resolved = resolve_selector_refs(target, registry, context, depth + 1);
            context.resolving.remove(name);
            resolved
        }
    }
}

fn validate_resolved_selector(selector: &Selector, nodes: &mut usize) -> Result<(), SelectorError> {
    reserve_resolved_selector_node(nodes)?;
    match selector {
        Selector::Match { .. } => Ok(()),
        Selector::All { selectors } => {
            non_empty_selector_children("all", selectors)?;
            selectors
                .iter()
                .try_for_each(|selector| validate_resolved_selector(selector, nodes))
        }
        Selector::Any { selectors } => {
            non_empty_selector_children("any", selectors)?;
            selectors
                .iter()
                .try_for_each(|selector| validate_resolved_selector(selector, nodes))
        }
        Selector::Not { selector } => validate_resolved_selector(selector, nodes),
        Selector::Ref { name } => Err(SelectorError::UnresolvedNamedSelector(name.clone())),
    }
}

fn reserve_resolved_selector_node(nodes: &mut usize) -> Result<(), SelectorError> {
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_RESOLVED_SELECTOR_NODES {
        return Err(SelectorError::ResolvedSelectorTooLarge {
            max: MAX_RESOLVED_SELECTOR_NODES,
        });
    }
    Ok(())
}

#[derive(Clone)]
struct CompiledSelectorTerm {
    term: SelectorTerm,
    exe_path_globs: Option<GlobSet>,
    cmdline_regexes: Option<RegexSet>,
    remote_addresses: Option<BTreeSet<IpAddr>>,
    cgroup_path_prefixes: Option<BTreeSet<CgroupPath>>,
}

impl CompiledSelectorTerm {
    fn new(term: SelectorTerm) -> Result<Self, SelectorError> {
        let exe_path_globs = compile_globs(&term.process.exe_path_globs)?;
        let cmdline_regexes = compile_regexes(&term.process.cmdline_regexes)?;
        let remote_addresses = compile_remote_addresses(&term.traffic.remote_addresses)?;
        let cgroup_path_prefixes = compile_cgroup_paths(&term.process.cgroup_paths)?;
        Ok(Self {
            term,
            exe_path_globs,
            cmdline_regexes,
            remote_addresses,
            cgroup_path_prefixes,
        })
    }

    fn matches_flow(&self, flow: &FlowContext, direction: Option<Direction>) -> Option<bool> {
        if !self.matches_process(&flow.process) {
            return Some(false);
        }
        self.matches_traffic(flow, direction)
    }

    fn matches_flow_with_unknown_process(
        &self,
        flow: &FlowContext,
        direction: Option<Direction>,
    ) -> Option<bool> {
        if self.matches_process_with_unknowns(&flow.process) == Some(false) {
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

    fn may_match_process_direction(&self, process: &ProcessContext, direction: Direction) -> bool {
        if !self.may_match_process(process) {
            return false;
        }
        let directions = &self.term.traffic.directions;
        directions.is_empty() || directions.contains(&direction)
    }

    fn may_match_observed_process_direction(
        &self,
        process: &ProcessContext,
        direction: Direction,
    ) -> Option<bool> {
        let directions = &self.term.traffic.directions;
        all_selector_matches(
            [
                self.matches_observed_process(process),
                Some(directions.is_empty() || directions.contains(&direction)),
            ]
            .into_iter(),
        )
    }

    fn matches_observed_process(&self, process: &ProcessContext) -> Option<bool> {
        let spec = &self.term.process;
        all_selector_matches(
            [
                Some(spec.pids.is_empty() || spec.pids.contains(&process.identity.pid)),
                Some(spec.uids.is_empty() || spec.uids.contains(&process.identity.uid)),
                Some(spec.gids.is_empty() || spec.gids.contains(&process.identity.gid)),
                Some(spec.names.is_empty() || spec.names.contains(&process.name)),
                spec.exe_path_globs.is_empty().then_some(true),
                spec.cmdline_regexes.is_empty().then_some(true),
                spec.systemd_services.is_empty().then_some(true),
                spec.container_ids.is_empty().then_some(true),
                spec.cgroup_paths.is_empty().then_some(true),
            ]
            .into_iter(),
        )
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
                match_cgroup_path_prefixes(
                    self.cgroup_path_prefixes.as_ref(),
                    process.identity.cgroup.as_deref(),
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

fn compile_cgroup_paths(paths: &[String]) -> Result<Option<BTreeSet<CgroupPath>>, SelectorError> {
    if paths.is_empty() {
        return Ok(None);
    }
    let paths = paths
        .iter()
        .map(|path| {
            CgroupPath::parse(path)
                .map_err(|error| SelectorError::InvalidCgroupPath(format!("{path}: {error}")))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(Some(paths))
}

fn match_cgroup_path_prefixes(
    prefixes: Option<&BTreeSet<CgroupPath>>,
    path: Option<&str>,
) -> Option<bool> {
    let Some(prefixes) = prefixes else {
        return Some(true);
    };
    let path = path?;
    let Ok(path) = CgroupPath::parse(path) else {
        return None;
    };
    Some(prefixes.iter().any(|prefix| prefix.contains(&path)))
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

fn non_empty_selector_children(
    name: &'static str,
    selectors: &[Selector],
) -> Result<(), SelectorError> {
    if selectors.is_empty() {
        Err(SelectorError::EmptyComposite(name))
    } else {
        Ok(())
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
    fn selector_matches_cgroup_path_prefixes() -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                cgroup_paths: vec!["system.slice/demo.service".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()?;
        let other = Selector::term(
            ProcessSelector {
                cgroup_paths: vec!["system.slice/other.service".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()?;
        let mut flow = demo_flow();
        flow.process.identity.cgroup = Some("/system.slice/demo.service/workers".to_string());

        assert!(selector.matches_flow_without_direction(&flow));
        assert!(!other.matches_flow_without_direction(&flow));
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
    fn selector_can_match_event_when_process_is_unknown_for_observation_queries()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                exe_path_globs: vec!["/app/backend".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![80],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut flow = demo_flow();
        flow.process.identity.pid = 0;
        flow.process.identity.exe_path = "unknown".to_string();
        flow.process.identity.cmdline_hash = "unknown".to_string();
        flow.process.name = "unknown".to_string();
        flow.process.cmdline.clear();
        let event = http_event_with_flow(flow, Direction::Outbound);

        assert!(!selector.matches_event(&event));
        assert!(selector.matches_event_with_unknown_process(&event));
        Ok(())
    }

    #[test]
    fn unknown_process_event_still_respects_traffic_dimensions()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                exe_path_globs: vec!["/app/backend".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut flow = demo_flow();
        flow.process.identity.pid = 0;
        flow.process.identity.exe_path = "unknown".to_string();
        flow.process.identity.cmdline_hash = "unknown".to_string();
        flow.process.name = "unknown".to_string();
        flow.process.cmdline.clear();
        let event = http_event_with_flow(flow, Direction::Outbound);

        assert!(!selector.matches_event_with_unknown_process(&event));
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
    fn process_direction_prefilter_ignores_unknown_ports_but_keeps_direction()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                local_ports: vec![8080],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let matching = demo_flow().process;
        let mut non_matching = matching.clone();
        non_matching.name = "other".to_string();

        assert!(selector.may_match_process_direction(&matching, Direction::Inbound));
        assert!(!selector.may_match_process_direction(&matching, Direction::Outbound));
        assert!(!selector.may_match_process_direction(&non_matching, Direction::Inbound));
        Ok(())
    }

    #[test]
    fn observed_process_prefilter_requires_tracepoint_provable_process_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let pid_with_unknown_port = Selector::term(
            ProcessSelector {
                pids: vec![42],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let exe_path = Selector::term(
            ProcessSelector {
                exe_path_globs: vec!["/usr/bin/demo".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()?;
        let cmdline = Selector::term(
            ProcessSelector {
                cmdline_regexes: vec!["--tenant managed".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()?;
        let process = partial_process();

        assert!(
            pid_with_unknown_port
                .may_match_observed_process_direction(&process, Direction::Outbound)
        );
        assert!(
            !pid_with_unknown_port
                .may_match_observed_process_direction(&process, Direction::Inbound)
        );
        assert!(!exe_path.may_match_observed_process_direction(&process, Direction::Outbound));
        assert!(!cmdline.may_match_observed_process_direction(&process, Direction::Outbound));
        Ok(())
    }

    #[test]
    fn observed_process_prefilter_does_not_invert_unprovable_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::Not {
            selector: Box::new(Selector::term(
                ProcessSelector {
                    exe_path_globs: vec!["/usr/bin/demo".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            )),
        }
        .compile()?;

        assert!(
            !selector.may_match_observed_process_direction(&partial_process(), Direction::Outbound)
        );
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
    fn selector_refs_resolve_to_plain_selector_ast() -> Result<(), Box<dyn std::error::Error>> {
        let registry = SelectorRegistry::new([(
            "https".to_string(),
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![443],
                    ..TrafficSelector::default()
                },
            ),
        )]);
        let selector = Selector::All {
            selectors: vec![
                Selector::Ref {
                    name: "https".to_string(),
                },
                Selector::term(
                    ProcessSelector {
                        names: vec!["demo".to_string()],
                        ..ProcessSelector::default()
                    },
                    TrafficSelector::default(),
                ),
            ],
        };

        let resolved = selector.resolve_refs_with_registry(&registry)?;

        let Selector::All { selectors } = resolved.as_selector() else {
            panic!("resolved selector should preserve all composition");
        };
        assert!(matches!(selectors[0], Selector::Match { .. }));
        assert!(matches!(selectors[1], Selector::Match { .. }));
        Ok(())
    }

    #[test]
    fn selector_ref_resolution_rejects_excessive_expansion() {
        let mut entries = Vec::new();
        entries.push(("seed".to_string(), Selector::default()));
        let mut previous = "seed".to_string();
        for index in 0..16 {
            let name = format!("wide-{index}");
            entries.push((
                name.clone(),
                Selector::All {
                    selectors: vec![
                        Selector::Ref {
                            name: previous.clone(),
                        },
                        Selector::Ref {
                            name: previous.clone(),
                        },
                    ],
                },
            ));
            previous = name;
        }
        let registry = SelectorRegistry::new(entries);

        let result = Selector::Ref { name: previous }.resolve_refs_with_registry(&registry);

        assert!(matches!(
            result,
            Err(SelectorError::ResolvedSelectorTooLarge { .. })
        ));
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
            cgroup: Some("/system.slice/demo.service".to_string()),
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
        http_event_with_flow(demo_flow(), direction)
    }

    fn http_event_with_flow(flow: FlowContext, direction: Direction) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow,
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
            Selector::term(
                ProcessSelector {
                    cgroup_paths: vec!["system.slice/demo.service".to_string()],
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

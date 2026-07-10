use std::fmt;

use super::{
    AtomKind, AtomMatch, AtomResourceCost, MatchEvaluation, MatchOutcome, Predicate,
    PredicateBudget, PredicateKey, PredicateRef, PredicateRegistryRevision,
    PredicateRegistrySnapshot, SelectorValueContractError, TargetAtom, TargetFacts, TargetField,
    TargetVocabulary, TraceNodeKind, TraceStep, UnknownMatchReason, combine_all, combine_any,
};

pub(crate) const TRACE_NODE_PROOF_BYTES: usize = 512;
pub(crate) const TRACE_NODE_EVALUATION_COST: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorKind {
    Query,
    Capture,
    Enforcement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomEvaluationCost {
    DeclaredConstant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomSupport {
    Supported {
        required_field: TargetField,
        cost: AtomEvaluationCost,
    },
    Unsupported,
}

pub const fn atom_support(selector: SelectorKind, atom: AtomKind) -> AtomSupport {
    match selector {
        SelectorKind::Query => match atom {
            AtomKind::Workload
            | AtomKind::Process
            | AtomKind::Cgroup
            | AtomKind::Container
            | AtomKind::Service
            | AtomKind::NetworkNamespace
            | AtomKind::Executable
            | AtomKind::LocalEndpoint
            | AtomKind::RemoteEndpoint
            | AtomKind::TransportProtocol
            | AtomKind::Direction => supported(atom),
        },
        SelectorKind::Capture => match atom {
            AtomKind::Workload
            | AtomKind::Process
            | AtomKind::Cgroup
            | AtomKind::Container
            | AtomKind::Service
            | AtomKind::NetworkNamespace
            | AtomKind::Executable
            | AtomKind::LocalEndpoint
            | AtomKind::RemoteEndpoint
            | AtomKind::TransportProtocol
            | AtomKind::Direction => supported(atom),
        },
        SelectorKind::Enforcement => match atom {
            AtomKind::Executable => AtomSupport::Unsupported,
            AtomKind::Workload
            | AtomKind::Process
            | AtomKind::Cgroup
            | AtomKind::Container
            | AtomKind::Service
            | AtomKind::NetworkNamespace
            | AtomKind::LocalEndpoint
            | AtomKind::RemoteEndpoint
            | AtomKind::TransportProtocol
            | AtomKind::Direction => supported(atom),
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompileError {
    StaleReference {
        key: PredicateKey,
        expected: PredicateRegistryRevision,
        actual: PredicateRegistryRevision,
    },
    MissingReference {
        key: PredicateKey,
        revision: PredicateRegistryRevision,
    },
    ReferenceCycle {
        path: Box<[PredicateKey]>,
    },
    NodeBudgetExceeded {
        max: usize,
    },
    DepthBudgetExceeded {
        max: usize,
    },
    ReferenceBudgetExceeded {
        max: usize,
    },
    UnsupportedAtom {
        selector: SelectorKind,
        atom: AtomKind,
    },
    MissingPositiveTargetScope {
        selector: SelectorKind,
    },
    InvalidAtomContract {
        atom: AtomKind,
        source: SelectorValueContractError,
    },
    EvaluationCostBudgetExceeded {
        max: usize,
    },
    ProofBytesBudgetExceeded {
        max: usize,
    },
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleReference {
                key,
                expected,
                actual,
            } => write!(
                formatter,
                "predicate reference {}/{} uses revision {}, expected {}",
                key.namespace().as_str(),
                key.name().as_str(),
                actual.get(),
                expected.get()
            ),
            Self::MissingReference { key, revision } => write!(
                formatter,
                "predicate reference {}/{} is absent from revision {}",
                key.namespace().as_str(),
                key.name().as_str(),
                revision.get()
            ),
            Self::ReferenceCycle { path } => {
                formatter.write_str("predicate reference cycle:")?;
                for key in path {
                    write!(
                        formatter,
                        " {}/{}",
                        key.namespace().as_str(),
                        key.name().as_str()
                    )?;
                }
                Ok(())
            }
            Self::NodeBudgetExceeded { max } => {
                write!(formatter, "predicate exceeds the {max}-node budget")
            }
            Self::DepthBudgetExceeded { max } => {
                write!(formatter, "predicate exceeds the maximum depth of {max}")
            }
            Self::ReferenceBudgetExceeded { max } => write!(
                formatter,
                "predicate exceeds the {max}-reference expansion budget"
            ),
            Self::UnsupportedAtom { selector, atom } => write!(
                formatter,
                "{selector:?} selector does not support {atom:?} atoms"
            ),
            Self::MissingPositiveTargetScope { selector } => write!(
                formatter,
                "{selector:?} selector has a match path without a positive target scope"
            ),
            Self::InvalidAtomContract { atom, source } => {
                write!(
                    formatter,
                    "{atom:?} atom has an invalid value contract: {source}"
                )
            }
            Self::EvaluationCostBudgetExceeded { max } => write!(
                formatter,
                "predicate exceeds the {max}-unit evaluation cost budget"
            ),
            Self::ProofBytesBudgetExceeded { max } => {
                write!(formatter, "predicate exceeds the {max}-byte proof budget")
            }
        }
    }
}

impl std::error::Error for CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAtomContract { source, .. } => Some(source),
            Self::StaleReference { .. }
            | Self::MissingReference { .. }
            | Self::ReferenceCycle { .. }
            | Self::NodeBudgetExceeded { .. }
            | Self::DepthBudgetExceeded { .. }
            | Self::ReferenceBudgetExceeded { .. }
            | Self::UnsupportedAtom { .. }
            | Self::MissingPositiveTargetScope { .. }
            | Self::EvaluationCostBudgetExceeded { .. }
            | Self::ProofBytesBudgetExceeded { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryUnknownPolicy {
    Include,
    Exclude,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryDecision<V: TargetVocabulary> {
    Include(MatchEvaluation<V>),
    Exclude(MatchEvaluation<V>),
}

impl<V: TargetVocabulary> QueryDecision<V> {
    pub const fn is_included(&self) -> bool {
        matches!(self, Self::Include(_))
    }

    pub const fn evaluation(&self) -> &MatchEvaluation<V> {
        match self {
            Self::Include(evaluation) | Self::Exclude(evaluation) => evaluation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureDecision<V: TargetVocabulary> {
    Admit(MatchEvaluation<V>),
    RejectNoMatch(MatchEvaluation<V>),
    RejectUnknown(MatchEvaluation<V>),
}

impl<V: TargetVocabulary> CaptureDecision<V> {
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admit(_))
    }

    pub const fn evaluation(&self) -> &MatchEvaluation<V> {
        match self {
            Self::Admit(evaluation)
            | Self::RejectNoMatch(evaluation)
            | Self::RejectUnknown(evaluation) => evaluation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnforcementDecision<V: TargetVocabulary> {
    Select(MatchEvaluation<V>),
    RejectNoMatch(MatchEvaluation<V>),
    RejectUnknown(MatchEvaluation<V>),
}

impl<V: TargetVocabulary> EnforcementDecision<V> {
    pub const fn is_selected(&self) -> bool {
        matches!(self, Self::Select(_))
    }

    pub const fn evaluation(&self) -> &MatchEvaluation<V> {
        match self {
            Self::Select(evaluation)
            | Self::RejectNoMatch(evaluation)
            | Self::RejectUnknown(evaluation) => evaluation,
        }
    }
}

pub struct QuerySelector<V: TargetVocabulary> {
    compiled: CompiledSelector<V>,
}

impl<V: TargetVocabulary> QuerySelector<V> {
    pub fn compile(
        predicate: Predicate<TargetAtom<V>>,
        snapshot: &PredicateRegistrySnapshot<V>,
        budget: PredicateBudget,
    ) -> Result<Self, CompileError> {
        CompiledSelector::compile(predicate, snapshot, budget, SelectorKind::Query)
            .map(|compiled| Self { compiled })
    }

    pub fn evaluate(
        &self,
        facts: &TargetFacts<V>,
        unknown_policy: QueryUnknownPolicy,
    ) -> QueryDecision<V> {
        let evaluation = self.compiled.evaluate(facts);
        match evaluation.outcome() {
            MatchOutcome::Match => QueryDecision::Include(evaluation),
            MatchOutcome::NoMatch => QueryDecision::Exclude(evaluation),
            MatchOutcome::Unknown(_) => match unknown_policy {
                QueryUnknownPolicy::Include => QueryDecision::Include(evaluation),
                QueryUnknownPolicy::Exclude => QueryDecision::Exclude(evaluation),
            },
        }
    }

    pub const fn registry_revision(&self) -> PredicateRegistryRevision {
        self.compiled.registry_revision()
    }
}

pub struct CaptureSelector<V: TargetVocabulary> {
    compiled: CompiledSelector<V>,
}

impl<V: TargetVocabulary> CaptureSelector<V> {
    pub fn compile(
        predicate: Predicate<TargetAtom<V>>,
        snapshot: &PredicateRegistrySnapshot<V>,
        budget: PredicateBudget,
    ) -> Result<Self, CompileError> {
        CompiledSelector::compile(predicate, snapshot, budget, SelectorKind::Capture)
            .map(|compiled| Self { compiled })
    }

    pub fn evaluate(&self, facts: &TargetFacts<V>) -> CaptureDecision<V> {
        let evaluation = self.compiled.evaluate(facts);
        match evaluation.outcome() {
            MatchOutcome::Match => CaptureDecision::Admit(evaluation),
            MatchOutcome::NoMatch => CaptureDecision::RejectNoMatch(evaluation),
            MatchOutcome::Unknown(_) => CaptureDecision::RejectUnknown(evaluation),
        }
    }

    pub const fn registry_revision(&self) -> PredicateRegistryRevision {
        self.compiled.registry_revision()
    }
}

pub struct EnforcementSelector<V: TargetVocabulary> {
    compiled: CompiledSelector<V>,
}

impl<V: TargetVocabulary> EnforcementSelector<V> {
    pub fn compile(
        predicate: Predicate<TargetAtom<V>>,
        snapshot: &PredicateRegistrySnapshot<V>,
        budget: PredicateBudget,
    ) -> Result<Self, CompileError> {
        CompiledSelector::compile(predicate, snapshot, budget, SelectorKind::Enforcement)
            .map(|compiled| Self { compiled })
    }

    pub fn evaluate(&self, facts: &TargetFacts<V>) -> EnforcementDecision<V> {
        let evaluation = self.compiled.evaluate(facts);
        match evaluation.outcome() {
            MatchOutcome::Match => EnforcementDecision::Select(evaluation),
            MatchOutcome::NoMatch => EnforcementDecision::RejectNoMatch(evaluation),
            MatchOutcome::Unknown(_) => EnforcementDecision::RejectUnknown(evaluation),
        }
    }

    pub const fn registry_revision(&self) -> PredicateRegistryRevision {
        self.compiled.registry_revision()
    }
}

struct CompiledSelector<V: TargetVocabulary> {
    root: CompiledNode<V>,
    registry_revision: PredicateRegistryRevision,
    node_count: usize,
}

impl<V: TargetVocabulary> CompiledSelector<V> {
    fn compile(
        predicate: Predicate<TargetAtom<V>>,
        snapshot: &PredicateRegistrySnapshot<V>,
        budget: PredicateBudget,
        selector: SelectorKind,
    ) -> Result<Self, CompileError> {
        let mut state = CompileState::new(snapshot, budget, selector);
        let root = state.compile(&predicate, 1)?;
        if matches!(selector, SelectorKind::Capture | SelectorKind::Enforcement)
            && !root.scope.when_match
        {
            return Err(CompileError::MissingPositiveTargetScope { selector });
        }
        Ok(Self {
            root,
            registry_revision: snapshot.revision(),
            node_count: state.nodes,
        })
    }

    fn evaluate(&self, facts: &TargetFacts<V>) -> MatchEvaluation<V> {
        let mut trace = Vec::with_capacity(self.node_count);
        let outcome = self.root.evaluate(facts, None, &mut trace);
        MatchEvaluation::new(self.registry_revision, outcome, trace)
    }

    const fn registry_revision(&self) -> PredicateRegistryRevision {
        self.registry_revision
    }
}

#[derive(Clone, Copy)]
struct ScopeGuarantee {
    when_match: bool,
    when_no_match: bool,
}

struct CompiledNode<V: TargetVocabulary> {
    id: usize,
    depth: usize,
    kind: CompiledNodeKind<V>,
    scope: ScopeGuarantee,
}

enum CompiledNodeKind<V: TargetVocabulary> {
    Atom(TargetAtom<V>),
    All(Box<[CompiledNode<V>]>),
    Any(Box<[CompiledNode<V>]>),
    Not(Box<CompiledNode<V>>),
    Reference {
        reference: PredicateRef,
        target: Box<CompiledNode<V>>,
    },
}

impl<V: TargetVocabulary> CompiledNode<V> {
    fn evaluate(
        &self,
        facts: &TargetFacts<V>,
        parent_id: Option<usize>,
        trace: &mut Vec<TraceStep<V>>,
    ) -> MatchOutcome {
        let (kind, outcome) = match &self.kind {
            CompiledNodeKind::Atom(atom) => {
                let evaluation = atom.evaluate(facts);
                let outcome = match evaluation.matching {
                    AtomMatch::Match => MatchOutcome::Match,
                    AtomMatch::NoMatch => MatchOutcome::NoMatch,
                    AtomMatch::Unknown(field) => {
                        MatchOutcome::Unknown(UnknownMatchReason::MissingField(field))
                    }
                };
                (TraceNodeKind::Atom(evaluation.evidence), outcome)
            }
            CompiledNodeKind::All(children) => {
                let mut outcome = MatchOutcome::Match;
                for child in children {
                    outcome = combine_all(outcome, child.evaluate(facts, Some(self.id), trace));
                }
                (TraceNodeKind::All, outcome)
            }
            CompiledNodeKind::Any(children) => {
                let mut outcome = MatchOutcome::NoMatch;
                for child in children {
                    outcome = combine_any(outcome, child.evaluate(facts, Some(self.id), trace));
                }
                (TraceNodeKind::Any, outcome)
            }
            CompiledNodeKind::Not(child) => (
                TraceNodeKind::Not,
                child.evaluate(facts, Some(self.id), trace).negate(),
            ),
            CompiledNodeKind::Reference { reference, target } => (
                TraceNodeKind::Reference(reference.clone()),
                target.evaluate(facts, Some(self.id), trace),
            ),
        };
        trace.push(TraceStep::new(
            self.id, parent_id, self.depth, kind, outcome,
        ));
        outcome
    }
}

struct CompileState<'a, V: TargetVocabulary> {
    snapshot: &'a PredicateRegistrySnapshot<V>,
    budget: PredicateBudget,
    selector: SelectorKind,
    nodes: usize,
    references: usize,
    evaluation_cost: usize,
    proof_bytes: usize,
    stack: Vec<PredicateKey>,
}

impl<'a, V: TargetVocabulary> CompileState<'a, V> {
    fn new(
        snapshot: &'a PredicateRegistrySnapshot<V>,
        budget: PredicateBudget,
        selector: SelectorKind,
    ) -> Self {
        Self {
            snapshot,
            budget,
            selector,
            nodes: 0,
            references: 0,
            evaluation_cost: 0,
            proof_bytes: 0,
            stack: Vec::new(),
        }
    }

    fn compile(
        &mut self,
        predicate: &Predicate<TargetAtom<V>>,
        depth: usize,
    ) -> Result<CompiledNode<V>, CompileError> {
        let id = self.claim_node(depth)?;
        let (kind, scope) = match predicate {
            Predicate::Atom(atom) => {
                if atom_support(self.selector, atom.kind()) == AtomSupport::Unsupported {
                    return Err(CompileError::UnsupportedAtom {
                        selector: self.selector,
                        atom: atom.kind(),
                    });
                }
                let resource_cost =
                    atom.resource_cost()
                        .map_err(|source| CompileError::InvalidAtomContract {
                            atom: atom.kind(),
                            source,
                        })?;
                self.claim_atom_resources(resource_cost)?;
                (
                    CompiledNodeKind::Atom(*atom),
                    ScopeGuarantee {
                        when_match: atom.kind().proves_target_scope(),
                        when_no_match: false,
                    },
                )
            }
            Predicate::All(children) => {
                let compiled = children
                    .iter()
                    .map(|child| self.compile(child, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                let scope = ScopeGuarantee {
                    when_match: compiled.iter().any(|child| child.scope.when_match),
                    when_no_match: compiled.iter().all(|child| child.scope.when_no_match),
                };
                (CompiledNodeKind::All(compiled.into_boxed_slice()), scope)
            }
            Predicate::Any(children) => {
                let compiled = children
                    .iter()
                    .map(|child| self.compile(child, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                let scope = ScopeGuarantee {
                    when_match: compiled.iter().all(|child| child.scope.when_match),
                    when_no_match: compiled.iter().any(|child| child.scope.when_no_match),
                };
                (CompiledNodeKind::Any(compiled.into_boxed_slice()), scope)
            }
            Predicate::Not(child) => {
                let child = Box::new(self.compile(child, depth + 1)?);
                let scope = ScopeGuarantee {
                    when_match: child.scope.when_no_match,
                    when_no_match: child.scope.when_match,
                };
                (CompiledNodeKind::Not(child), scope)
            }
            Predicate::Ref(reference) => {
                self.claim_reference()?;
                let expected = self.snapshot.revision();
                if reference.revision() != expected {
                    return Err(CompileError::StaleReference {
                        key: reference.key().clone(),
                        expected,
                        actual: reference.revision(),
                    });
                }
                let target = self.snapshot.predicate(reference.key()).ok_or_else(|| {
                    CompileError::MissingReference {
                        key: reference.key().clone(),
                        revision: expected,
                    }
                })?;
                if let Some(cycle_start) = self
                    .stack
                    .iter()
                    .position(|candidate| candidate == reference.key())
                {
                    let mut path = self.stack[cycle_start..].to_vec();
                    path.push(reference.key().clone());
                    return Err(CompileError::ReferenceCycle {
                        path: path.into_boxed_slice(),
                    });
                }
                self.stack.push(reference.key().clone());
                let compiled_target = self.compile(target, depth + 1);
                self.stack.pop();
                let target = Box::new(compiled_target?);
                let scope = target.scope;
                (
                    CompiledNodeKind::Reference {
                        reference: reference.clone(),
                        target,
                    },
                    scope,
                )
            }
        };
        Ok(CompiledNode {
            id,
            depth,
            kind,
            scope,
        })
    }

    fn claim_node(&mut self, depth: usize) -> Result<usize, CompileError> {
        if depth > self.budget.max_depth() {
            return Err(CompileError::DepthBudgetExceeded {
                max: self.budget.max_depth(),
            });
        }
        if self.nodes == self.budget.max_nodes() {
            return Err(CompileError::NodeBudgetExceeded {
                max: self.budget.max_nodes(),
            });
        }
        let id = self.nodes;
        self.nodes += 1;
        self.evaluation_cost = add_with_budget(
            self.evaluation_cost,
            TRACE_NODE_EVALUATION_COST,
            self.budget.max_evaluation_cost(),
            CompileError::EvaluationCostBudgetExceeded {
                max: self.budget.max_evaluation_cost(),
            },
        )?;
        self.proof_bytes = add_with_budget(
            self.proof_bytes,
            TRACE_NODE_PROOF_BYTES,
            self.budget.max_proof_bytes(),
            CompileError::ProofBytesBudgetExceeded {
                max: self.budget.max_proof_bytes(),
            },
        )?;
        Ok(id)
    }

    fn claim_reference(&mut self) -> Result<(), CompileError> {
        if self.references == self.budget.max_ref_expansions() {
            return Err(CompileError::ReferenceBudgetExceeded {
                max: self.budget.max_ref_expansions(),
            });
        }
        self.references += 1;
        Ok(())
    }

    fn claim_atom_resources(
        &mut self,
        resource_cost: AtomResourceCost,
    ) -> Result<(), CompileError> {
        self.evaluation_cost = add_with_budget(
            self.evaluation_cost,
            resource_cost.comparison_units(),
            self.budget.max_evaluation_cost(),
            CompileError::EvaluationCostBudgetExceeded {
                max: self.budget.max_evaluation_cost(),
            },
        )?;
        let evidence_bytes = resource_cost.value_evidence_bytes().checked_mul(2).ok_or(
            CompileError::ProofBytesBudgetExceeded {
                max: self.budget.max_proof_bytes(),
            },
        )?;
        self.proof_bytes = add_with_budget(
            self.proof_bytes,
            evidence_bytes,
            self.budget.max_proof_bytes(),
            CompileError::ProofBytesBudgetExceeded {
                max: self.budget.max_proof_bytes(),
            },
        )?;
        Ok(())
    }
}

const fn supported(atom: AtomKind) -> AtomSupport {
    AtomSupport::Supported {
        required_field: atom.required_field(),
        cost: AtomEvaluationCost::DeclaredConstant,
    }
}

fn add_with_budget(
    current: usize,
    amount: usize,
    max: usize,
    error: CompileError,
) -> Result<usize, CompileError> {
    current
        .checked_add(amount)
        .filter(|total| *total <= max)
        .ok_or(error)
}

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, RwLock},
};

use super::compiler::{TRACE_NODE_EVALUATION_COST, TRACE_NODE_PROOF_BYTES};
use super::{
    CompileError, Predicate, PredicateBudget, PredicateKey, PredicateRegistryRevision, TargetAtom,
    TargetVocabulary,
};

#[derive(Debug)]
pub struct PredicateRegistrySnapshot<V: TargetVocabulary> {
    revision: PredicateRegistryRevision,
    predicates: BTreeMap<PredicateKey, Predicate<TargetAtom<V>>>,
}

impl<V: TargetVocabulary> PredicateRegistrySnapshot<V> {
    pub const fn revision(&self) -> PredicateRegistryRevision {
        self.revision
    }

    pub fn len(&self) -> usize {
        self.predicates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    pub fn predicate(&self, key: &PredicateKey) -> Option<&Predicate<TargetAtom<V>>> {
        self.predicates.get(key)
    }

    fn predicates(
        &self,
    ) -> impl ExactSizeIterator<Item = (&PredicateKey, &Predicate<TargetAtom<V>>)> {
        self.predicates.iter()
    }
}

pub struct PredicateRegistry<V: TargetVocabulary> {
    reload: Mutex<()>,
    current: RwLock<Arc<PredicateRegistrySnapshot<V>>>,
}

impl<V: TargetVocabulary> PredicateRegistry<V> {
    pub fn new(initial_revision: PredicateRegistryRevision) -> Self {
        Self {
            reload: Mutex::new(()),
            current: RwLock::new(Arc::new(PredicateRegistrySnapshot {
                revision: initial_revision,
                predicates: BTreeMap::new(),
            })),
        }
    }

    pub fn snapshot(&self) -> Result<Arc<PredicateRegistrySnapshot<V>>, PredicateRegistryError> {
        self.current
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| PredicateRegistryError::LockPoisoned)
    }

    pub fn replace(
        &self,
        expected_revision: PredicateRegistryRevision,
        next_revision: PredicateRegistryRevision,
        predicates: BTreeMap<PredicateKey, Predicate<TargetAtom<V>>>,
        budget: PredicateBudget,
    ) -> Result<Arc<PredicateRegistrySnapshot<V>>, PredicateRegistryError> {
        let _reload_guard = self
            .reload
            .lock()
            .map_err(|_| PredicateRegistryError::LockPoisoned)?;
        let observed = self.snapshot()?;
        ensure_expected_revision(expected_revision, observed.revision())?;
        ensure_revision_increases(observed.revision(), next_revision)?;

        let candidate = Arc::new(PredicateRegistrySnapshot {
            revision: next_revision,
            predicates,
        });
        RegistryValidator::new(&candidate, budget)
            .validate()
            .map_err(|(key, source)| PredicateRegistryError::InvalidPredicate { key, source })?;

        let mut current = self
            .current
            .write()
            .map_err(|_| PredicateRegistryError::LockPoisoned)?;
        ensure_expected_revision(expected_revision, current.revision())?;
        ensure_revision_increases(current.revision(), next_revision)?;
        *current = Arc::clone(&candidate);
        Ok(candidate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PredicateRegistryError {
    LockPoisoned,
    RevisionConflict {
        expected: PredicateRegistryRevision,
        actual: PredicateRegistryRevision,
    },
    RevisionDidNotIncrease {
        current: PredicateRegistryRevision,
        proposed: PredicateRegistryRevision,
    },
    InvalidPredicate {
        key: PredicateKey,
        source: CompileError,
    },
}

impl fmt::Display for PredicateRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("predicate registry lock is poisoned"),
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "predicate registry revision conflict: expected {}, actual {}",
                expected.get(),
                actual.get()
            ),
            Self::RevisionDidNotIncrease { current, proposed } => write!(
                formatter,
                "predicate registry revision {} does not advance current revision {}",
                proposed.get(),
                current.get()
            ),
            Self::InvalidPredicate { key, source } => write!(
                formatter,
                "predicate {}/{} is invalid: {source}",
                key.namespace().as_str(),
                key.name().as_str()
            ),
        }
    }
}

impl std::error::Error for PredicateRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPredicate { source, .. } => Some(source),
            Self::LockPoisoned
            | Self::RevisionConflict { .. }
            | Self::RevisionDidNotIncrease { .. } => None,
        }
    }
}

#[derive(Clone, Copy)]
struct ExpansionSummary {
    nodes: usize,
    depth: usize,
    references: usize,
    evaluation_cost: usize,
    proof_bytes: usize,
}

struct RegistryValidator<'a, V: TargetVocabulary> {
    snapshot: &'a PredicateRegistrySnapshot<V>,
    budget: PredicateBudget,
    memo: BTreeMap<PredicateKey, ExpansionSummary>,
    active: BTreeMap<PredicateKey, usize>,
    stack: Vec<PredicateKey>,
}

impl<'a, V: TargetVocabulary> RegistryValidator<'a, V> {
    fn new(snapshot: &'a PredicateRegistrySnapshot<V>, budget: PredicateBudget) -> Self {
        Self {
            snapshot,
            budget,
            memo: BTreeMap::new(),
            active: BTreeMap::new(),
            stack: Vec::new(),
        }
    }

    fn validate(mut self) -> Result<(), (PredicateKey, CompileError)> {
        let mut source_nodes = 0;
        for (key, predicate) in self.snapshot.predicates() {
            count_source_nodes(predicate, 1, self.budget, &mut source_nodes)
                .map_err(|error| (key.clone(), error))?;
        }

        let keys = self.snapshot.predicates.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            self.summarize_key(&key, self.budget.max_depth())
                .map_err(|error| (key.clone(), error))?;
        }
        Ok(())
    }

    fn summarize_key(
        &mut self,
        key: &PredicateKey,
        remaining_depth: usize,
    ) -> Result<ExpansionSummary, CompileError> {
        if remaining_depth == 0 {
            return Err(CompileError::DepthBudgetExceeded {
                max: self.budget.max_depth(),
            });
        }
        if let Some(summary) = self.memo.get(key) {
            if summary.depth > remaining_depth {
                return Err(CompileError::DepthBudgetExceeded {
                    max: self.budget.max_depth(),
                });
            }
            return Ok(*summary);
        }
        if let Some(cycle_start) = self.active.get(key).copied() {
            let mut path = self.stack[cycle_start..].to_vec();
            path.push(key.clone());
            return Err(CompileError::ReferenceCycle {
                path: path.into_boxed_slice(),
            });
        }
        let predicate = self.snapshot.predicate(key).cloned().ok_or_else(|| {
            CompileError::MissingReference {
                key: key.clone(),
                revision: self.snapshot.revision(),
            }
        })?;
        self.active.insert(key.clone(), self.stack.len());
        self.stack.push(key.clone());
        let summary = self.summarize_predicate(&predicate, remaining_depth);
        self.stack.pop();
        self.active.remove(key);
        let summary = summary?;
        self.memo.insert(key.clone(), summary);
        Ok(summary)
    }

    fn summarize_predicate(
        &mut self,
        predicate: &Predicate<TargetAtom<V>>,
        remaining_depth: usize,
    ) -> Result<ExpansionSummary, CompileError> {
        if remaining_depth == 0 {
            return Err(CompileError::DepthBudgetExceeded {
                max: self.budget.max_depth(),
            });
        }
        match predicate {
            Predicate::Atom(atom) => {
                let resource_cost =
                    atom.resource_cost()
                        .map_err(|source| CompileError::InvalidAtomContract {
                            atom: atom.kind(),
                            source,
                        })?;
                let mut summary = base_summary();
                summary.evaluation_cost = bounded_add(
                    summary.evaluation_cost,
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
                summary.proof_bytes = bounded_add(
                    summary.proof_bytes,
                    evidence_bytes,
                    self.budget.max_proof_bytes(),
                    CompileError::ProofBytesBudgetExceeded {
                        max: self.budget.max_proof_bytes(),
                    },
                )?;
                Ok(summary)
            }
            Predicate::All(children) | Predicate::Any(children) => {
                let mut summary = base_summary();
                for child in children.iter() {
                    let child =
                        self.summarize_predicate(child, remaining_depth.saturating_sub(1))?;
                    summary = add_child_summary(summary, child, self.budget)?;
                }
                Ok(summary)
            }
            Predicate::Not(child) => {
                let child = self.summarize_predicate(child, remaining_depth.saturating_sub(1))?;
                add_child_summary(base_summary(), child, self.budget)
            }
            Predicate::Ref(reference) => {
                let expected = self.snapshot.revision();
                if reference.revision() != expected {
                    return Err(CompileError::StaleReference {
                        key: reference.key().clone(),
                        expected,
                        actual: reference.revision(),
                    });
                }
                if self.snapshot.predicate(reference.key()).is_none() {
                    return Err(CompileError::MissingReference {
                        key: reference.key().clone(),
                        revision: expected,
                    });
                }
                let target =
                    self.summarize_key(reference.key(), remaining_depth.saturating_sub(1))?;
                let mut summary = base_summary();
                summary.references = 1;
                add_child_summary(summary, target, self.budget)
            }
        }
    }
}

const fn base_summary() -> ExpansionSummary {
    ExpansionSummary {
        nodes: 1,
        depth: 1,
        references: 0,
        evaluation_cost: TRACE_NODE_EVALUATION_COST,
        proof_bytes: TRACE_NODE_PROOF_BYTES,
    }
}

fn add_child_summary(
    mut parent: ExpansionSummary,
    child: ExpansionSummary,
    budget: PredicateBudget,
) -> Result<ExpansionSummary, CompileError> {
    parent.nodes = bounded_add(
        parent.nodes,
        child.nodes,
        budget.max_nodes(),
        CompileError::NodeBudgetExceeded {
            max: budget.max_nodes(),
        },
    )?;
    parent.references = bounded_add(
        parent.references,
        child.references,
        budget.max_ref_expansions(),
        CompileError::ReferenceBudgetExceeded {
            max: budget.max_ref_expansions(),
        },
    )?;
    parent.evaluation_cost = bounded_add(
        parent.evaluation_cost,
        child.evaluation_cost,
        budget.max_evaluation_cost(),
        CompileError::EvaluationCostBudgetExceeded {
            max: budget.max_evaluation_cost(),
        },
    )?;
    parent.proof_bytes = bounded_add(
        parent.proof_bytes,
        child.proof_bytes,
        budget.max_proof_bytes(),
        CompileError::ProofBytesBudgetExceeded {
            max: budget.max_proof_bytes(),
        },
    )?;
    parent.depth = parent.depth.max(bounded_increment(
        child.depth,
        budget.max_depth(),
        CompileError::DepthBudgetExceeded {
            max: budget.max_depth(),
        },
    )?);
    Ok(parent)
}

fn count_source_nodes<V: TargetVocabulary>(
    predicate: &Predicate<TargetAtom<V>>,
    depth: usize,
    budget: PredicateBudget,
    count: &mut usize,
) -> Result<(), CompileError> {
    if depth > budget.max_depth() {
        return Err(CompileError::DepthBudgetExceeded {
            max: budget.max_depth(),
        });
    }
    if *count == budget.max_nodes() {
        return Err(CompileError::NodeBudgetExceeded {
            max: budget.max_nodes(),
        });
    }
    *count += 1;
    match predicate {
        Predicate::Atom(_) | Predicate::Ref(_) => Ok(()),
        Predicate::All(children) | Predicate::Any(children) => {
            for child in children.iter() {
                count_source_nodes(child, depth + 1, budget, count)?;
            }
            Ok(())
        }
        Predicate::Not(child) => count_source_nodes(child, depth + 1, budget, count),
    }
}

fn bounded_increment(value: usize, max: usize, error: CompileError) -> Result<usize, CompileError> {
    bounded_add(value, 1, max, error)
}

fn bounded_add(
    left: usize,
    right: usize,
    max: usize,
    error: CompileError,
) -> Result<usize, CompileError> {
    left.checked_add(right)
        .filter(|sum| *sum <= max)
        .ok_or(error)
}

fn ensure_expected_revision(
    expected: PredicateRegistryRevision,
    actual: PredicateRegistryRevision,
) -> Result<(), PredicateRegistryError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PredicateRegistryError::RevisionConflict { expected, actual })
    }
}

fn ensure_revision_increases(
    current: PredicateRegistryRevision,
    proposed: PredicateRegistryRevision,
) -> Result<(), PredicateRegistryError> {
    if proposed > current {
        Ok(())
    } else {
        Err(PredicateRegistryError::RevisionDidNotIncrease { current, proposed })
    }
}

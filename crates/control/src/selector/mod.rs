mod algebra;
mod atom;
mod compiler;
mod evaluation;
mod registry;

pub use algebra::{
    NonEmpty, PREDICATE_DEPTH_HARD_LIMIT, PREDICATE_EVALUATION_COST_HARD_LIMIT,
    PREDICATE_NODE_HARD_LIMIT, PREDICATE_PROOF_BYTES_HARD_LIMIT, PREDICATE_REFERENCE_HARD_LIMIT,
    Predicate, PredicateBudget, PredicateBudgetError, PredicateBudgetResource, PredicateKey,
    PredicateName, PredicateNamespace, PredicateRef, PredicateRegistryRevision,
    PredicateValueError,
};
pub use atom::{
    AtomEvidence, AtomKind, AtomResourceCost, EndpointSide, FactProvenanceId,
    FactProvenanceIdError, ObservedTargetFact, SELECTOR_ATOM_SIZE_HARD_LIMIT,
    SELECTOR_VALUE_COST_HARD_LIMIT, SELECTOR_VALUE_EVIDENCE_HARD_LIMIT, SelectorValue,
    SelectorValueContractError, TargetAtom, TargetFacts, TargetField, TargetVocabulary,
};
pub use compiler::{
    AtomEvaluationCost, AtomSupport, CaptureDecision, CaptureSelector, CompileError,
    EnforcementDecision, EnforcementSelector, QueryDecision, QuerySelector, QueryUnknownPolicy,
    SelectorKind, atom_support,
};
pub use evaluation::{MatchEvaluation, MatchOutcome, TraceNodeKind, TraceStep, UnknownMatchReason};
pub use registry::{PredicateRegistry, PredicateRegistryError, PredicateRegistrySnapshot};

pub(crate) use atom::AtomMatch;
pub(crate) use evaluation::{combine_all, combine_any};

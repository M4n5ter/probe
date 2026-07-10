use std::{fmt, num::NonZeroU64, num::NonZeroUsize};

const PREDICATE_TEXT_MAX: usize = 128;
pub const PREDICATE_NODE_HARD_LIMIT: usize = 65_536;
pub const PREDICATE_DEPTH_HARD_LIMIT: usize = 128;
pub const PREDICATE_REFERENCE_HARD_LIMIT: usize = 16_384;
pub const PREDICATE_EVALUATION_COST_HARD_LIMIT: usize = 1_048_576;
pub const PREDICATE_PROOF_BYTES_HARD_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonEmpty<T> {
    items: Box<[T]>,
}

impl<T> NonEmpty<T> {
    pub fn new(first: T, rest: Vec<T>) -> Self {
        let mut items = Vec::with_capacity(1 + rest.len());
        items.push(first);
        items.extend(rest);
        Self {
            items: items.into_boxed_slice(),
        }
    }

    pub fn first(&self) -> &T {
        &self.items[0]
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.items.iter()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Predicate<A> {
    Atom(A),
    All(NonEmpty<Predicate<A>>),
    Any(NonEmpty<Predicate<A>>),
    Not(Box<Predicate<A>>),
    Ref(PredicateRef),
}

impl<A> Predicate<A> {
    pub fn atom(atom: A) -> Self {
        Self::Atom(atom)
    }

    pub fn all(first: Self, rest: Vec<Self>) -> Self {
        Self::All(NonEmpty::new(first, rest))
    }

    pub fn any(first: Self, rest: Vec<Self>) -> Self {
        Self::Any(NonEmpty::new(first, rest))
    }

    pub fn negate(predicate: Self) -> Self {
        Self::Not(Box::new(predicate))
    }

    pub fn reference(reference: PredicateRef) -> Self {
        Self::Ref(reference)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PredicateNamespace(String);

impl PredicateNamespace {
    pub fn new(value: impl Into<String>) -> Result<Self, PredicateValueError> {
        validate_text(value.into(), TextKind::Namespace).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PredicateName(String);

impl PredicateName {
    pub fn new(value: impl Into<String>) -> Result<Self, PredicateValueError> {
        validate_text(value.into(), TextKind::Name).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PredicateRegistryRevision(NonZeroU64);

impl PredicateRegistryRevision {
    pub fn new(value: u64) -> Result<Self, PredicateValueError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(PredicateValueError::ZeroRevision)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PredicateKey {
    namespace: PredicateNamespace,
    name: PredicateName,
}

impl PredicateKey {
    pub fn new(namespace: PredicateNamespace, name: PredicateName) -> Self {
        Self { namespace, name }
    }

    pub fn namespace(&self) -> &PredicateNamespace {
        &self.namespace
    }

    pub fn name(&self) -> &PredicateName {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PredicateRef {
    key: PredicateKey,
    revision: PredicateRegistryRevision,
}

impl PredicateRef {
    pub fn new(key: PredicateKey, revision: PredicateRegistryRevision) -> Self {
        Self { key, revision }
    }

    pub fn key(&self) -> &PredicateKey {
        &self.key
    }

    pub const fn revision(&self) -> PredicateRegistryRevision {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PredicateBudget {
    max_nodes: NonZeroUsize,
    max_depth: NonZeroUsize,
    max_ref_expansions: NonZeroUsize,
    max_evaluation_cost: NonZeroUsize,
    max_proof_bytes: NonZeroUsize,
}

impl PredicateBudget {
    pub fn new(
        max_nodes: usize,
        max_depth: usize,
        max_ref_expansions: usize,
        max_evaluation_cost: usize,
        max_proof_bytes: usize,
    ) -> Result<Self, PredicateBudgetError> {
        Ok(Self {
            max_nodes: validate_budget(
                PredicateBudgetResource::Nodes,
                max_nodes,
                PREDICATE_NODE_HARD_LIMIT,
            )?,
            max_depth: validate_budget(
                PredicateBudgetResource::Depth,
                max_depth,
                PREDICATE_DEPTH_HARD_LIMIT,
            )?,
            max_ref_expansions: validate_budget(
                PredicateBudgetResource::ReferenceExpansions,
                max_ref_expansions,
                PREDICATE_REFERENCE_HARD_LIMIT,
            )?,
            max_evaluation_cost: validate_budget(
                PredicateBudgetResource::EvaluationCost,
                max_evaluation_cost,
                PREDICATE_EVALUATION_COST_HARD_LIMIT,
            )?,
            max_proof_bytes: validate_budget(
                PredicateBudgetResource::ProofBytes,
                max_proof_bytes,
                PREDICATE_PROOF_BYTES_HARD_LIMIT,
            )?,
        })
    }

    pub const fn max_nodes(self) -> usize {
        self.max_nodes.get()
    }

    pub const fn max_depth(self) -> usize {
        self.max_depth.get()
    }

    pub const fn max_ref_expansions(self) -> usize {
        self.max_ref_expansions.get()
    }

    pub const fn max_evaluation_cost(self) -> usize {
        self.max_evaluation_cost.get()
    }

    pub const fn max_proof_bytes(self) -> usize {
        self.max_proof_bytes.get()
    }
}

impl Default for PredicateBudget {
    fn default() -> Self {
        Self {
            max_nodes: NonZeroUsize::new(4096).expect("non-zero default"),
            max_depth: NonZeroUsize::new(64).expect("non-zero default"),
            max_ref_expansions: NonZeroUsize::new(1024).expect("non-zero default"),
            max_evaluation_cost: NonZeroUsize::new(65_536).expect("non-zero default"),
            max_proof_bytes: NonZeroUsize::new(8 * 1024 * 1024).expect("non-zero default"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PredicateBudgetResource {
    Nodes,
    Depth,
    ReferenceExpansions,
    EvaluationCost,
    ProofBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PredicateBudgetError {
    Zero(PredicateBudgetResource),
    ExceedsHardLimit {
        resource: PredicateBudgetResource,
        requested: usize,
        hard_limit: usize,
    },
}

impl fmt::Display for PredicateBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero(resource) => {
                write!(formatter, "predicate {resource:?} budget must be non-zero")
            }
            Self::ExceedsHardLimit {
                resource,
                requested,
                hard_limit,
            } => write!(
                formatter,
                "predicate {resource:?} budget {requested} exceeds hard limit {hard_limit}"
            ),
        }
    }
}

impl std::error::Error for PredicateBudgetError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PredicateValueError {
    EmptyNamespace,
    EmptyName,
    TextTooLong { length: usize, max: usize },
    InvalidCharacter { index: usize },
    ZeroRevision,
}

impl fmt::Display for PredicateValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNamespace => formatter.write_str("predicate namespace must not be empty"),
            Self::EmptyName => formatter.write_str("predicate name must not be empty"),
            Self::TextTooLong { length, max } => {
                write!(formatter, "predicate text length {length} exceeds {max}")
            }
            Self::InvalidCharacter { index } => {
                write!(
                    formatter,
                    "predicate text has an invalid character at byte {index}"
                )
            }
            Self::ZeroRevision => {
                formatter.write_str("predicate registry revision must be non-zero")
            }
        }
    }
}

impl std::error::Error for PredicateValueError {}

#[derive(Clone, Copy)]
enum TextKind {
    Namespace,
    Name,
}

fn validate_text(value: String, kind: TextKind) -> Result<String, PredicateValueError> {
    if value.is_empty() {
        return Err(match kind {
            TextKind::Namespace => PredicateValueError::EmptyNamespace,
            TextKind::Name => PredicateValueError::EmptyName,
        });
    }
    if value.len() > PREDICATE_TEXT_MAX {
        return Err(PredicateValueError::TextTooLong {
            length: value.len(),
            max: PREDICATE_TEXT_MAX,
        });
    }
    if let Some((index, _)) = value.bytes().enumerate().find(|(_, byte)| {
        !(byte.is_ascii_alphanumeric()
            || matches!(*byte, b'.' | b'_' | b'-')
            || matches!(kind, TextKind::Namespace) && *byte == b'/')
    }) {
        return Err(PredicateValueError::InvalidCharacter { index });
    }
    Ok(value)
}

fn validate_budget(
    resource: PredicateBudgetResource,
    value: usize,
    hard_limit: usize,
) -> Result<NonZeroUsize, PredicateBudgetError> {
    let value = NonZeroUsize::new(value).ok_or(PredicateBudgetError::Zero(resource))?;
    if value.get() > hard_limit {
        Err(PredicateBudgetError::ExceedsHardLimit {
            resource,
            requested: value.get(),
            hard_limit,
        })
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_namespaces_names_and_non_empty_composites_by_construction() {
        let namespace = PredicateNamespace::new("tenant/api").expect("namespace");
        let name = PredicateName::new("frontend-1").expect("name");
        assert_eq!(namespace.as_str(), "tenant/api");
        assert_eq!(name.as_str(), "frontend-1");
        assert_eq!(
            PredicateName::new("bad/name"),
            Err(PredicateValueError::InvalidCharacter { index: 3 })
        );

        let predicate = Predicate::all(Predicate::atom(1_u8), vec![Predicate::atom(2)]);
        let Predicate::All(children) = predicate else {
            panic!("all predicate");
        };
        assert_eq!(children.iter().len(), 2);
    }

    #[test]
    fn predicate_budgets_cannot_disable_resource_safety() {
        assert_eq!(
            PredicateBudget::new(1, 0, 1, 1, 1),
            Err(PredicateBudgetError::Zero(PredicateBudgetResource::Depth))
        );
        assert_eq!(
            PredicateBudget::new(PREDICATE_NODE_HARD_LIMIT + 1, 1, 1, 1, 1),
            Err(PredicateBudgetError::ExceedsHardLimit {
                resource: PredicateBudgetResource::Nodes,
                requested: PREDICATE_NODE_HARD_LIMIT + 1,
                hard_limit: PREDICATE_NODE_HARD_LIMIT,
            })
        );
    }
}

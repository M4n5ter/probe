use super::{AtomEvidence, PredicateRef, PredicateRegistryRevision, TargetField, TargetVocabulary};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownMatchReason {
    MissingField(TargetField),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchOutcome {
    Match,
    NoMatch,
    Unknown(UnknownMatchReason),
}

impl MatchOutcome {
    pub const fn is_match(self) -> bool {
        matches!(self, Self::Match)
    }

    pub(crate) const fn negate(self) -> Self {
        match self {
            Self::Match => Self::NoMatch,
            Self::NoMatch => Self::Match,
            Self::Unknown(reason) => Self::Unknown(reason),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceNodeKind<V: TargetVocabulary> {
    Atom(AtomEvidence<V>),
    All,
    Any,
    Not,
    Reference(PredicateRef),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceStep<V: TargetVocabulary> {
    node_id: usize,
    parent_id: Option<usize>,
    depth: usize,
    kind: TraceNodeKind<V>,
    outcome: MatchOutcome,
}

impl<V: TargetVocabulary> TraceStep<V> {
    pub(crate) const fn new(
        node_id: usize,
        parent_id: Option<usize>,
        depth: usize,
        kind: TraceNodeKind<V>,
        outcome: MatchOutcome,
    ) -> Self {
        Self {
            node_id,
            parent_id,
            depth,
            kind,
            outcome,
        }
    }

    pub const fn node_id(&self) -> usize {
        self.node_id
    }

    pub const fn parent_id(&self) -> Option<usize> {
        self.parent_id
    }

    pub const fn depth(&self) -> usize {
        self.depth
    }

    pub const fn kind(&self) -> &TraceNodeKind<V> {
        &self.kind
    }

    pub const fn outcome(&self) -> MatchOutcome {
        self.outcome
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchEvaluation<V: TargetVocabulary> {
    registry_revision: PredicateRegistryRevision,
    outcome: MatchOutcome,
    trace: Box<[TraceStep<V>]>,
}

impl<V: TargetVocabulary> MatchEvaluation<V> {
    pub(crate) fn new(
        registry_revision: PredicateRegistryRevision,
        outcome: MatchOutcome,
        trace: Vec<TraceStep<V>>,
    ) -> Self {
        Self {
            registry_revision,
            outcome,
            trace: trace.into_boxed_slice(),
        }
    }

    pub const fn registry_revision(&self) -> PredicateRegistryRevision {
        self.registry_revision
    }

    pub const fn outcome(&self) -> MatchOutcome {
        self.outcome
    }

    pub fn trace(&self) -> &[TraceStep<V>] {
        &self.trace
    }
}

pub(crate) const fn combine_all(left: MatchOutcome, right: MatchOutcome) -> MatchOutcome {
    match (left, right) {
        (MatchOutcome::NoMatch, _) | (_, MatchOutcome::NoMatch) => MatchOutcome::NoMatch,
        (MatchOutcome::Unknown(reason), _) | (_, MatchOutcome::Unknown(reason)) => {
            MatchOutcome::Unknown(reason)
        }
        (MatchOutcome::Match, MatchOutcome::Match) => MatchOutcome::Match,
    }
}

pub(crate) const fn combine_any(left: MatchOutcome, right: MatchOutcome) -> MatchOutcome {
    match (left, right) {
        (MatchOutcome::Match, _) | (_, MatchOutcome::Match) => MatchOutcome::Match,
        (MatchOutcome::Unknown(reason), _) | (_, MatchOutcome::Unknown(reason)) => {
            MatchOutcome::Unknown(reason)
        }
        (MatchOutcome::NoMatch, MatchOutcome::NoMatch) => MatchOutcome::NoMatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_valued_lattice_matches_the_complete_truth_table() {
        let unknown = MatchOutcome::Unknown(UnknownMatchReason::MissingField(
            TargetField::RemoteEndpoint,
        ));
        let values = [MatchOutcome::Match, MatchOutcome::NoMatch, unknown];
        let all = [
            [MatchOutcome::Match, MatchOutcome::NoMatch, unknown],
            [
                MatchOutcome::NoMatch,
                MatchOutcome::NoMatch,
                MatchOutcome::NoMatch,
            ],
            [unknown, MatchOutcome::NoMatch, unknown],
        ];
        let any = [
            [
                MatchOutcome::Match,
                MatchOutcome::Match,
                MatchOutcome::Match,
            ],
            [MatchOutcome::Match, MatchOutcome::NoMatch, unknown],
            [MatchOutcome::Match, unknown, unknown],
        ];

        for (left_index, left) in values.into_iter().enumerate() {
            for (right_index, right) in values.into_iter().enumerate() {
                assert_eq!(combine_all(left, right), all[left_index][right_index]);
                assert_eq!(combine_any(left, right), any[left_index][right_index]);
            }
        }
        assert_eq!(MatchOutcome::Match.negate(), MatchOutcome::NoMatch);
        assert_eq!(MatchOutcome::NoMatch.negate(), MatchOutcome::Match);
        assert_eq!(unknown.negate(), unknown);
    }
}

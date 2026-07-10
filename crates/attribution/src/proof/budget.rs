use std::{fmt, num::NonZeroUsize};

use super::completeness::{
    ATTRIBUTION_SNAPSHOT_CANDIDATE_HARD_LIMIT, ATTRIBUTION_SNAPSHOT_COVERAGE_HARD_LIMIT,
    ATTRIBUTION_SNAPSHOT_DIRECT_HARD_LIMIT, ATTRIBUTION_SNAPSHOT_LOSS_HARD_LIMIT,
};

const PROOF_MEMORY_BYTES_HARD_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributionBudgetSpec {
    pub max_direct_facts: usize,
    pub max_candidates: usize,
    pub max_coverages: usize,
    pub max_loss_intervals: usize,
    pub max_proof_memory_bytes: usize,
    pub max_clock_error_ns: u64,
    pub correlation_slack_ns: u64,
}

impl Default for AttributionBudgetSpec {
    fn default() -> Self {
        Self {
            max_direct_facts: 128,
            max_candidates: 1024,
            max_coverages: 32,
            max_loss_intervals: 256,
            max_proof_memory_bytes: 1024 * 1024,
            max_clock_error_ns: 1_000_000,
            correlation_slack_ns: 1_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributionBudget {
    max_direct_facts: NonZeroUsize,
    max_candidates: NonZeroUsize,
    max_coverages: NonZeroUsize,
    max_loss_intervals: NonZeroUsize,
    max_proof_memory_bytes: NonZeroUsize,
    max_clock_error_ns: u64,
    correlation_slack_ns: u64,
}

impl AttributionBudget {
    pub fn new(spec: AttributionBudgetSpec) -> Result<Self, AttributionBudgetError> {
        Ok(Self {
            max_direct_facts: bounded_nonzero(
                AttributionResource::DirectFacts,
                spec.max_direct_facts,
                ATTRIBUTION_SNAPSHOT_DIRECT_HARD_LIMIT,
            )?,
            max_candidates: bounded_nonzero(
                AttributionResource::Candidates,
                spec.max_candidates,
                ATTRIBUTION_SNAPSHOT_CANDIDATE_HARD_LIMIT,
            )?,
            max_coverages: bounded_nonzero(
                AttributionResource::Coverages,
                spec.max_coverages,
                ATTRIBUTION_SNAPSHOT_COVERAGE_HARD_LIMIT,
            )?,
            max_loss_intervals: bounded_nonzero(
                AttributionResource::LossIntervals,
                spec.max_loss_intervals,
                ATTRIBUTION_SNAPSHOT_LOSS_HARD_LIMIT,
            )?,
            max_proof_memory_bytes: bounded_nonzero(
                AttributionResource::ProofMemoryBytes,
                spec.max_proof_memory_bytes,
                PROOF_MEMORY_BYTES_HARD_LIMIT,
            )?,
            max_clock_error_ns: spec.max_clock_error_ns,
            correlation_slack_ns: spec.correlation_slack_ns,
        })
    }

    pub const fn max_direct_facts(self) -> usize {
        self.max_direct_facts.get()
    }

    pub const fn max_candidates(self) -> usize {
        self.max_candidates.get()
    }

    pub const fn max_coverages(self) -> usize {
        self.max_coverages.get()
    }

    pub const fn max_loss_intervals(self) -> usize {
        self.max_loss_intervals.get()
    }

    pub const fn max_proof_memory_bytes(self) -> usize {
        self.max_proof_memory_bytes.get()
    }

    pub const fn max_clock_error_ns(self) -> u64 {
        self.max_clock_error_ns
    }

    pub const fn correlation_slack_ns(self) -> u64 {
        self.correlation_slack_ns
    }
}

impl Default for AttributionBudget {
    fn default() -> Self {
        Self::new(AttributionBudgetSpec::default()).expect("valid attribution budget defaults")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributionResource {
    DirectFacts,
    Candidates,
    Coverages,
    LossIntervals,
    ProofMemoryBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributionBudgetError {
    Zero(AttributionResource),
    ExceedsHardLimit {
        resource: AttributionResource,
        requested: usize,
        hard_limit: usize,
    },
}

impl fmt::Display for AttributionBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero(resource) => {
                write!(formatter, "attribution {resource:?} limit must be non-zero")
            }
            Self::ExceedsHardLimit {
                resource,
                requested,
                hard_limit,
            } => write!(
                formatter,
                "attribution {resource:?} limit {requested} exceeds hard limit {hard_limit}"
            ),
        }
    }
}

impl std::error::Error for AttributionBudgetError {}

fn bounded_nonzero(
    resource: AttributionResource,
    value: usize,
    hard_limit: usize,
) -> Result<NonZeroUsize, AttributionBudgetError> {
    let value = NonZeroUsize::new(value).ok_or(AttributionBudgetError::Zero(resource))?;
    if value.get() > hard_limit {
        Err(AttributionBudgetError::ExceedsHardLimit {
            resource,
            requested: value.get(),
            hard_limit,
        })
    } else {
        Ok(value)
    }
}

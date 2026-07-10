use std::fmt;

use probe_core::{AttributionEvidenceId, ClockCalibrationId, TimeInterval, TimeIntervalError};

use super::model::{AttributionProofParts, attribution_claim_memory_bytes};
use super::{
    AttributionBudget, AttributionClaim, AttributionConfidence, AttributionGapReason,
    AttributionJoinRule, AttributionProofBasis, AttributionResource, AttributionSnapshot,
    AttributionSnapshotVerifier, AttributionSource, CompletenessProof, CorrelationCandidate,
    DirectSocketFact, FactProvenance, PacketObservation, REQUIRED_CORRELATION_SOURCES,
    SnapshotVerificationError, SourceCoverage, StageRelation, TargetBinding,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttributionError {
    InputLimitExceeded {
        resource: AttributionResource,
        actual: usize,
        max: usize,
    },
    ProofMemoryBudgetExceeded {
        required: usize,
        max: usize,
    },
    SnapshotMismatch,
    SnapshotVerification(SnapshotVerificationError),
    Time(TimeIntervalError),
}

impl fmt::Display for AttributionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLimitExceeded {
                resource,
                actual,
                max,
            } => write!(
                formatter,
                "attribution input has {actual} {resource:?}, exceeding limit {max}"
            ),
            Self::ProofMemoryBudgetExceeded { required, max } => write!(
                formatter,
                "attribution proof requires {required} memory bytes, exceeding budget {max}"
            ),
            Self::SnapshotMismatch => formatter
                .write_str("attribution snapshot scope or flow differs from packet observation"),
            Self::SnapshotVerification(source) => {
                write!(
                    formatter,
                    "attribution snapshot verification failed: {source}"
                )
            }
            Self::Time(source) => write!(formatter, "attribution time error: {source}"),
        }
    }
}

impl std::error::Error for AttributionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SnapshotVerification(source) => Some(source),
            Self::Time(source) => Some(source),
            Self::InputLimitExceeded { .. }
            | Self::ProofMemoryBudgetExceeded { .. }
            | Self::SnapshotMismatch => None,
        }
    }
}

pub struct AttributionEngine {
    budget: AttributionBudget,
    verifier: AttributionSnapshotVerifier,
}

impl AttributionEngine {
    pub const fn new(budget: AttributionBudget, verifier: AttributionSnapshotVerifier) -> Self {
        Self { budget, verifier }
    }

    pub const fn budget(&self) -> AttributionBudget {
        self.budget
    }

    pub fn bind<'a>(
        &self,
        snapshot: &'a AttributionSnapshot,
    ) -> Result<AttributionEvaluator<'a>, AttributionError> {
        validate_input_limits(self.budget, snapshot)?;
        self.verifier
            .verify(snapshot)
            .map_err(AttributionError::SnapshotVerification)?;
        Ok(AttributionEvaluator {
            budget: self.budget,
            snapshot,
        })
    }
}

pub struct AttributionEvaluator<'a> {
    budget: AttributionBudget,
    snapshot: &'a AttributionSnapshot,
}

impl AttributionEvaluator<'_> {
    pub fn attribute(
        &self,
        packet: PacketObservation,
    ) -> Result<AttributionClaim, AttributionError> {
        let snapshot = self.snapshot;
        if snapshot.scope() != packet.scope() || snapshot.flow() != packet.flow() {
            return Err(AttributionError::SnapshotMismatch);
        }
        let correlation_window = packet
            .observed()
            .interval()
            .expand(self.budget.correlation_slack_ns())
            .map_err(AttributionError::Time)?;

        if let Some(claim) = self.direct_claim(packet, snapshot, correlation_window)? {
            return Ok(claim);
        }
        self.correlated_claim(packet, snapshot, correlation_window)
    }

    fn direct_claim(
        &self,
        packet: PacketObservation,
        snapshot: &AttributionSnapshot,
        correlation_window: TimeInterval,
    ) -> Result<Option<AttributionClaim>, AttributionError> {
        let packet_clock_uncertain =
            packet.observed().max_error_ns() > self.budget.max_clock_error_ns();
        let key_matches = snapshot
            .direct_facts()
            .iter()
            .filter(|fact| {
                fact.scope() == packet.scope()
                    && fact.fingerprint() == packet.fingerprint()
                    && fact.flow() == packet.flow()
            })
            .collect::<Vec<_>>();
        let mut relevant = Vec::with_capacity(key_matches.len());
        let mut verified = Vec::with_capacity(key_matches.len());
        let mut clock_uncertain = packet_clock_uncertain;
        let mut window_mismatch = false;

        for fact in key_matches {
            if !fact
                .observed()
                .interval()
                .overlaps(packet.observed().interval())
            {
                continue;
            }
            relevant.push(fact);
            if packet_clock_uncertain
                || fact.observed().max_error_ns() > self.budget.max_clock_error_ns()
            {
                clock_uncertain = true;
                continue;
            }
            if !fact
                .valid_during()
                .possible()
                .overlaps(packet.observed().interval())
                || !fact
                    .valid_during()
                    .guaranteed()
                    .contains(packet.observed().interval())
            {
                window_mismatch = true;
                continue;
            }
            verified.push(fact);
        }
        relevant.sort_unstable_by_key(|fact| (fact.socket(), fact.binding(), fact.evidence()));
        verified.sort_unstable_by_key(|fact| (fact.socket(), fact.binding(), fact.evidence()));

        if clock_uncertain || window_mismatch {
            let mut limitations = Vec::with_capacity(2);
            if clock_uncertain {
                limitations.push(AttributionGapReason::ClockUncertain);
            }
            if window_mismatch {
                limitations.push(AttributionGapReason::DirectFactWindowMismatch);
            }
            return self
                .build_claim(
                    packet,
                    snapshot,
                    ClaimParts {
                        outcome: ClaimOutcome::unknown(
                            unique_direct_identity_count(&relevant),
                            limitations,
                        ),
                        rule: AttributionJoinRule::Unresolved,
                        correlation_window,
                        completeness: Vec::new(),
                        fact_provenance: packet_and_fact_provenance(packet, &relevant),
                        clock_calibrations: packet_and_fact_calibrations(packet, &relevant),
                        evidence: direct_evidence(
                            packet,
                            correlation_window,
                            &relevant,
                            snapshot.coverages(),
                        ),
                    },
                )
                .map(Some);
        }

        let unique_verified = unique_direct_identity_count(&verified);
        if unique_verified > 1 {
            return self
                .build_claim(
                    packet,
                    snapshot,
                    ClaimParts {
                        outcome: ClaimOutcome::unknown(
                            unique_verified,
                            vec![AttributionGapReason::ConflictingDirectBindings],
                        ),
                        rule: AttributionJoinRule::Unresolved,
                        correlation_window,
                        completeness: Vec::new(),
                        fact_provenance: packet_and_fact_provenance(packet, &verified),
                        clock_calibrations: packet_and_fact_calibrations(packet, &verified),
                        evidence: direct_evidence(
                            packet,
                            correlation_window,
                            &verified,
                            snapshot.coverages(),
                        ),
                    },
                )
                .map(Some);
        }
        if unique_verified == 0 {
            if packet_clock_uncertain {
                return self
                    .build_claim(
                        packet,
                        snapshot,
                        ClaimParts {
                            outcome: ClaimOutcome::unknown(
                                0,
                                vec![AttributionGapReason::ClockUncertain],
                            ),
                            rule: AttributionJoinRule::Unresolved,
                            correlation_window,
                            completeness: Vec::new(),
                            fact_provenance: vec![packet.provenance()],
                            clock_calibrations: vec![packet.observed().calibration()],
                            evidence: vec![packet.evidence()],
                        },
                    )
                    .map(Some);
            }
            return Ok(None);
        }

        let fact = verified[0];
        let (completeness, limitations) = prove_direct_completeness(
            packet.scope(),
            correlation_window,
            &verified,
            snapshot.coverages(),
        );
        let complete = limitations.is_empty();
        self.build_claim(
            packet,
            snapshot,
            ClaimParts {
                outcome: ClaimOutcome {
                    binding: Some(fact.binding()),
                    confidence: if complete {
                        AttributionConfidence::Proven
                    } else {
                        AttributionConfidence::Inferred
                    },
                    socket: Some(fact.socket()),
                    matching_candidate_count: 1,
                    limitations,
                },
                rule: if complete {
                    AttributionJoinRule::DirectPacketFingerprint
                } else {
                    AttributionJoinRule::IncompleteDirectPacketFingerprint
                },
                correlation_window,
                completeness,
                fact_provenance: packet_and_fact_provenance(packet, &verified),
                clock_calibrations: packet_and_fact_calibrations(packet, &verified),
                evidence: direct_evidence(
                    packet,
                    correlation_window,
                    &verified,
                    snapshot.coverages(),
                ),
            },
        )
        .map(Some)
    }

    fn correlated_claim(
        &self,
        packet: PacketObservation,
        snapshot: &AttributionSnapshot,
        correlation_window: TimeInterval,
    ) -> Result<AttributionClaim, AttributionError> {
        let (completeness, source_limitations) = prove_closed_world(correlation_window, snapshot);
        let classification = classify_candidates(
            packet,
            snapshot.candidates(),
            correlation_window,
            self.budget.max_clock_error_ns(),
            source_limitations,
        );
        let outcome = classification.outcome;
        let rule = match outcome.confidence {
            AttributionConfidence::CorrelatedUnique => {
                AttributionJoinRule::ClosedWorldFlowCorrelation
            }
            AttributionConfidence::Inferred => AttributionJoinRule::IncompleteFlowCorrelation,
            AttributionConfidence::Proven | AttributionConfidence::Unknown => {
                AttributionJoinRule::Unresolved
            }
        };
        self.build_claim(
            packet,
            snapshot,
            ClaimParts {
                outcome,
                rule,
                correlation_window,
                completeness,
                fact_provenance: packet_and_candidate_provenance(packet, &classification.relevant),
                clock_calibrations: packet_and_candidate_calibrations(
                    packet,
                    &classification.relevant,
                ),
                evidence: correlation_evidence(
                    packet,
                    correlation_window,
                    &classification.relevant,
                    snapshot,
                ),
            },
        )
    }

    fn build_claim(
        &self,
        packet: PacketObservation,
        snapshot: &AttributionSnapshot,
        mut parts: ClaimParts,
    ) -> Result<AttributionClaim, AttributionError> {
        parts.evidence.sort_unstable();
        parts.evidence.dedup();
        parts.fact_provenance.sort_unstable();
        parts.fact_provenance.dedup();
        parts.clock_calibrations.sort_unstable();
        parts.clock_calibrations.dedup();
        parts.outcome.limitations.sort_unstable();
        parts.outcome.limitations.dedup();

        let proof_bytes = exact_proof_memory_bytes(&parts).ok_or(
            AttributionError::ProofMemoryBudgetExceeded {
                required: usize::MAX,
                max: self.budget.max_proof_memory_bytes(),
            },
        )?;
        if proof_bytes > self.budget.max_proof_memory_bytes() {
            return Err(AttributionError::ProofMemoryBudgetExceeded {
                required: proof_bytes,
                max: self.budget.max_proof_memory_bytes(),
            });
        }
        let basis = AttributionProofBasis::new(AttributionProofParts {
            rule: parts.rule,
            scope: packet.scope(),
            packet_fingerprint: packet.fingerprint(),
            flow: packet.flow(),
            correlation_window: parts.correlation_window,
            socket: parts.outcome.socket,
            candidate_set: snapshot.candidate_set(),
            snapshot_digest: snapshot.snapshot_digest(),
            fact_provenance: parts.fact_provenance,
            clock_calibrations: parts.clock_calibrations,
            completeness: parts.completeness,
            universe_candidate_count: snapshot.candidates().len(),
            matching_candidate_count: parts.outcome.matching_candidate_count,
            limitations: parts.outcome.limitations,
        });
        Ok(AttributionClaim::new(
            packet,
            parts.outcome.binding,
            parts.outcome.confidence,
            parts.evidence,
            basis,
        ))
    }
}

struct ClaimParts {
    outcome: ClaimOutcome,
    rule: AttributionJoinRule,
    correlation_window: TimeInterval,
    fact_provenance: Vec<FactProvenance>,
    clock_calibrations: Vec<ClockCalibrationId>,
    completeness: Vec<CompletenessProof>,
    evidence: Vec<AttributionEvidenceId>,
}

struct ClaimOutcome {
    binding: Option<TargetBinding>,
    confidence: AttributionConfidence,
    socket: Option<probe_core::SocketId>,
    matching_candidate_count: usize,
    limitations: Vec<AttributionGapReason>,
}

struct CandidateClassification<'a> {
    outcome: ClaimOutcome,
    relevant: Vec<&'a CorrelationCandidate>,
}

impl ClaimOutcome {
    fn unknown(matching_candidate_count: usize, limitations: Vec<AttributionGapReason>) -> Self {
        Self {
            binding: None,
            confidence: AttributionConfidence::Unknown,
            socket: None,
            matching_candidate_count,
            limitations,
        }
    }
}

fn classify_candidates(
    packet: PacketObservation,
    candidates: &[CorrelationCandidate],
    correlation_window: TimeInterval,
    max_clock_error_ns: u64,
    mut source_limitations: Vec<AttributionGapReason>,
) -> CandidateClassification<'_> {
    let packet_clock_uncertain = packet.observed().max_error_ns() > max_clock_error_ns;
    let mut eligible = Vec::new();
    let mut blockers = Vec::new();
    let mut blocker_reasons = Vec::new();
    let mut relevant = Vec::new();

    for candidate in candidates {
        if !candidate
            .valid_during()
            .possible()
            .overlaps(correlation_window)
        {
            continue;
        }
        relevant.push(candidate);
        if packet_clock_uncertain || candidate.valid_during().max_error_ns() > max_clock_error_ns {
            blocker_reasons.push(AttributionGapReason::ClockUncertain);
            blockers.push(candidate);
            continue;
        }
        if !candidate
            .valid_during()
            .guaranteed()
            .contains(correlation_window)
        {
            blocker_reasons.push(AttributionGapReason::CandidateWindowMismatch);
            blockers.push(candidate);
            continue;
        }
        if candidate.stage_relation() != StageRelation::SameCaptureStage {
            blocker_reasons.push(AttributionGapReason::UnsupportedStageRelation);
            blockers.push(candidate);
            continue;
        }
        if !candidate.role().supports_closed_world_correlation() {
            blocker_reasons.push(AttributionGapReason::UnsupportedSocketRole(
                candidate.role(),
            ));
            blockers.push(candidate);
            continue;
        }
        eligible.push(candidate);
    }
    eligible.sort_unstable_by_key(|candidate| {
        (
            candidate.socket(),
            candidate.binding(),
            candidate.evidence(),
        )
    });
    blockers.sort_unstable_by_key(|candidate| {
        (
            candidate.socket(),
            candidate.binding(),
            candidate.evidence(),
        )
    });
    let matching_candidates = unique_candidate_identity_count(&eligible);

    if !blockers.is_empty() {
        blocker_reasons.append(&mut source_limitations);
        return CandidateClassification {
            outcome: ClaimOutcome::unknown(
                unique_candidate_identity_count_across(&eligible, &blockers),
                blocker_reasons,
            ),
            relevant,
        };
    }
    if matching_candidates > 1 {
        source_limitations.push(AttributionGapReason::MultipleCandidates {
            count: matching_candidates,
        });
        return CandidateClassification {
            outcome: ClaimOutcome::unknown(matching_candidates, source_limitations),
            relevant,
        };
    }
    let Some(candidate) = eligible.first().copied() else {
        source_limitations.push(AttributionGapReason::NoCandidate);
        return CandidateClassification {
            outcome: ClaimOutcome::unknown(0, source_limitations),
            relevant,
        };
    };

    let complete = source_limitations.is_empty();
    CandidateClassification {
        outcome: ClaimOutcome {
            binding: Some(candidate.binding()),
            confidence: if complete {
                AttributionConfidence::CorrelatedUnique
            } else {
                AttributionConfidence::Inferred
            },
            socket: Some(candidate.socket()),
            matching_candidate_count: 1,
            limitations: source_limitations,
        },
        relevant,
    }
}

fn prove_direct_completeness(
    scope: super::AttributionScope,
    interval: TimeInterval,
    facts: &[&DirectSocketFact],
    coverages: &[SourceCoverage],
) -> (Vec<CompletenessProof>, Vec<AttributionGapReason>) {
    let mut sources = facts
        .iter()
        .map(|fact| fact.provenance().source())
        .collect::<Vec<_>>();
    sources.sort_unstable();
    sources.dedup();
    let mut proofs = Vec::with_capacity(sources.len());
    let mut limitations = Vec::new();

    for source_identity in sources {
        let source_sequences_are_covered = |coverage: &SourceCoverage| {
            facts
                .iter()
                .filter(|fact| fact.provenance().source() == source_identity)
                .all(|fact| {
                    coverage
                        .cursor()
                        .sequences()
                        .contains(fact.provenance().sequence())
                })
        };
        let proof = coverages
            .iter()
            .filter(|coverage| coverage.source() == AttributionSource::SocketLifecycle)
            .filter(|coverage| coverage.cursor().source_identity() == source_identity)
            .filter(|coverage| source_sequences_are_covered(coverage))
            .filter_map(|coverage| coverage.prove(scope, interval))
            .next();
        match proof {
            Some(proof) => proofs.push(proof),
            None => limitations.push(AttributionGapReason::SourceIncomplete(
                AttributionSource::SocketLifecycle,
            )),
        }
    }
    (proofs, limitations)
}

fn prove_closed_world(
    interval: TimeInterval,
    snapshot: &AttributionSnapshot,
) -> (Vec<CompletenessProof>, Vec<AttributionGapReason>) {
    let mut proofs = Vec::with_capacity(REQUIRED_CORRELATION_SOURCES.len());
    let mut limitations = Vec::new();
    for source in REQUIRED_CORRELATION_SOURCES {
        let proof = snapshot
            .coverages()
            .iter()
            .filter(|coverage| coverage.source() == source)
            .filter(|coverage| {
                source != AttributionSource::SocketLifecycle
                    || (coverage.cursor().source_identity()
                        == snapshot.candidate_source().source_identity()
                        && coverage.cursor().sequences() == snapshot.candidate_source().sequences())
            })
            .filter_map(|coverage| coverage.prove(snapshot.scope(), interval))
            .next();
        match proof {
            Some(proof) => proofs.push(proof),
            None => limitations.push(AttributionGapReason::SourceIncomplete(source)),
        }
    }
    (proofs, limitations)
}

fn direct_evidence(
    packet: PacketObservation,
    interval: TimeInterval,
    facts: &[&DirectSocketFact],
    coverages: &[SourceCoverage],
) -> Vec<AttributionEvidenceId> {
    std::iter::once(packet.evidence())
        .chain(facts.iter().map(|fact| fact.evidence()))
        .chain(
            coverages
                .iter()
                .filter(|coverage| coverage.source() == AttributionSource::SocketLifecycle)
                .filter(|coverage| coverage.scope() == packet.scope())
                .filter(|coverage| {
                    facts.iter().any(|fact| {
                        fact.provenance().source() == coverage.cursor().source_identity()
                    })
                })
                .map(|coverage| coverage.cursor().evidence()),
        )
        .chain(
            coverages
                .iter()
                .filter(|coverage| coverage.source() == AttributionSource::SocketLifecycle)
                .filter(|coverage| coverage.scope() == packet.scope())
                .filter(|coverage| {
                    facts.iter().any(|fact| {
                        fact.provenance().source() == coverage.cursor().source_identity()
                    })
                })
                .flat_map(|coverage| coverage.losses())
                .filter(|loss| loss.interval().overlaps(interval))
                .map(|loss| loss.evidence()),
        )
        .collect()
}

fn correlation_evidence(
    packet: PacketObservation,
    interval: TimeInterval,
    candidates: &[&CorrelationCandidate],
    snapshot: &AttributionSnapshot,
) -> Vec<AttributionEvidenceId> {
    std::iter::once(packet.evidence())
        .chain(std::iter::once(snapshot.candidate_source().evidence()))
        .chain(candidates.iter().map(|candidate| candidate.evidence()))
        .chain(candidates.iter().filter_map(|candidate| {
            if let StageRelation::Translated { topology_evidence } = candidate.stage_relation() {
                Some(topology_evidence)
            } else {
                None
            }
        }))
        .chain(
            snapshot
                .coverages()
                .iter()
                .filter(|coverage| coverage.scope() == snapshot.scope())
                .filter(|coverage| REQUIRED_CORRELATION_SOURCES.contains(&coverage.source()))
                .map(|coverage| coverage.cursor().evidence()),
        )
        .chain(
            snapshot
                .coverages()
                .iter()
                .filter(|coverage| coverage.scope() == snapshot.scope())
                .filter(|coverage| REQUIRED_CORRELATION_SOURCES.contains(&coverage.source()))
                .flat_map(|coverage| coverage.losses())
                .filter(|loss| loss.interval().overlaps(interval))
                .map(|loss| loss.evidence()),
        )
        .collect()
}

fn packet_and_fact_provenance(
    packet: PacketObservation,
    facts: &[&DirectSocketFact],
) -> Vec<FactProvenance> {
    std::iter::once(packet.provenance())
        .chain(facts.iter().map(|fact| fact.provenance()))
        .collect()
}

fn packet_and_fact_calibrations(
    packet: PacketObservation,
    facts: &[&DirectSocketFact],
) -> Vec<ClockCalibrationId> {
    std::iter::once(packet.observed().calibration())
        .chain(facts.iter().map(|fact| fact.observed().calibration()))
        .collect()
}

fn packet_and_candidate_provenance(
    packet: PacketObservation,
    candidates: &[&CorrelationCandidate],
) -> Vec<FactProvenance> {
    std::iter::once(packet.provenance())
        .chain(candidates.iter().map(|candidate| candidate.provenance()))
        .collect()
}

fn packet_and_candidate_calibrations(
    packet: PacketObservation,
    candidates: &[&CorrelationCandidate],
) -> Vec<ClockCalibrationId> {
    std::iter::once(packet.observed().calibration())
        .chain(
            candidates
                .iter()
                .map(|candidate| candidate.valid_during().calibration()),
        )
        .collect()
}

fn unique_direct_identity_count(facts: &[&DirectSocketFact]) -> usize {
    facts
        .iter()
        .map(|fact| (fact.socket(), fact.binding()))
        .fold((None, 0_usize), |(previous, count), identity| {
            if previous == Some(identity) {
                (previous, count)
            } else {
                (Some(identity), count + 1)
            }
        })
        .1
}

fn unique_candidate_identity_count(candidates: &[&CorrelationCandidate]) -> usize {
    candidates
        .iter()
        .map(|candidate| (candidate.socket(), candidate.binding()))
        .fold((None, 0_usize), |(previous, count), identity| {
            if previous == Some(identity) {
                (previous, count)
            } else {
                (Some(identity), count + 1)
            }
        })
        .1
}

fn unique_candidate_identity_count_across(
    left: &[&CorrelationCandidate],
    right: &[&CorrelationCandidate],
) -> usize {
    let mut identities = left
        .iter()
        .chain(right)
        .map(|candidate| (candidate.socket(), candidate.binding()))
        .collect::<Vec<_>>();
    identities.sort_unstable();
    identities.dedup();
    identities.len()
}

fn exact_proof_memory_bytes(parts: &ClaimParts) -> Option<usize> {
    attribution_claim_memory_bytes(
        parts.evidence.len(),
        parts.fact_provenance.len(),
        parts.clock_calibrations.len(),
        parts.completeness.len(),
        parts.outcome.limitations.len(),
    )
}

fn check_input_limit(
    resource: AttributionResource,
    actual: usize,
    max: usize,
) -> Result<(), AttributionError> {
    if actual <= max {
        Ok(())
    } else {
        Err(AttributionError::InputLimitExceeded {
            resource,
            actual,
            max,
        })
    }
}

fn validate_input_limits(
    budget: AttributionBudget,
    snapshot: &AttributionSnapshot,
) -> Result<(), AttributionError> {
    check_input_limit(
        AttributionResource::DirectFacts,
        snapshot.direct_facts().len(),
        budget.max_direct_facts(),
    )?;
    check_input_limit(
        AttributionResource::Candidates,
        snapshot.candidates().len(),
        budget.max_candidates(),
    )?;
    check_input_limit(
        AttributionResource::Coverages,
        snapshot.coverages().len(),
        budget.max_coverages(),
    )?;
    let loss_intervals = snapshot
        .coverages()
        .iter()
        .try_fold(0_usize, |total, coverage| {
            total.checked_add(coverage.losses().len())
        })
        .ok_or(AttributionError::InputLimitExceeded {
            resource: AttributionResource::LossIntervals,
            actual: usize::MAX,
            max: budget.max_loss_intervals(),
        })?;
    check_input_limit(
        AttributionResource::LossIntervals,
        loss_intervals,
        budget.max_loss_intervals(),
    )
}

use std::{collections::BTreeSet, fmt};

use blake3::Hasher;
use probe_core::{
    AttributionEvidenceId, AttributionSnapshotDigest, CandidateSetDigest, FlowId, MonotonicInstant,
    TimeInterval,
};

use super::authentication::{authenticators_match, keyed_authenticator};
use super::model::CompletenessProofParts;
use super::{
    AttributionScope, AttributionSource, CompletenessProof, CorrelationCandidate, DirectSocketFact,
    SourceIdentity, SourceSequence, SourceSequenceRange, StageRelation,
};

pub const REQUIRED_CORRELATION_SOURCES: [AttributionSource; 3] = [
    AttributionSource::SocketLifecycle,
    AttributionSource::ProcessLifecycle,
    AttributionSource::CaptureTopology,
];
pub const ATTRIBUTION_SNAPSHOT_DIRECT_HARD_LIMIT: usize = 4096;
pub const ATTRIBUTION_SNAPSHOT_CANDIDATE_HARD_LIMIT: usize = 16_384;
pub const ATTRIBUTION_SNAPSHOT_COVERAGE_HARD_LIMIT: usize = 256;
pub const ATTRIBUTION_SNAPSHOT_LOSS_HARD_LIMIT: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateSourceSnapshot {
    source_identity: SourceIdentity,
    sequences: SourceSequenceRange,
    evidence: AttributionEvidenceId,
}

impl CandidateSourceSnapshot {
    pub const fn new(
        source_identity: SourceIdentity,
        sequences: SourceSequenceRange,
        evidence: AttributionEvidenceId,
    ) -> Self {
        Self {
            source_identity,
            sequences,
            evidence,
        }
    }

    pub const fn source_identity(self) -> SourceIdentity {
        self.source_identity
    }

    pub const fn sequences(self) -> SourceSequenceRange {
        self.sequences
    }

    pub const fn evidence(self) -> AttributionEvidenceId {
        self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageCursor {
    source_identity: SourceIdentity,
    sequences: SourceSequenceRange,
    evidence: AttributionEvidenceId,
}

impl CoverageCursor {
    pub const fn new(
        source_identity: SourceIdentity,
        sequences: SourceSequenceRange,
        evidence: AttributionEvidenceId,
    ) -> Self {
        Self {
            source_identity,
            sequences,
            evidence,
        }
    }

    pub const fn source_identity(self) -> SourceIdentity {
        self.source_identity
    }

    pub const fn sequences(self) -> SourceSequenceRange {
        self.sequences
    }

    pub const fn evidence(self) -> AttributionEvidenceId {
        self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageWindow {
    attach_interval: TimeInterval,
    complete_interval: TimeInterval,
    watermark: MonotonicInstant,
}

impl CoverageWindow {
    pub fn new(
        attach_interval: TimeInterval,
        complete_interval: TimeInterval,
        watermark: MonotonicInstant,
    ) -> Result<Self, CoverageWindowError> {
        if !attach_interval.contains(complete_interval) {
            return Err(CoverageWindowError::CompleteOutsideAttach);
        }
        if watermark < complete_interval.end() {
            return Err(CoverageWindowError::WatermarkPrecedesCompleteInterval);
        }
        Ok(Self {
            attach_interval,
            complete_interval,
            watermark,
        })
    }

    pub const fn attach_interval(self) -> TimeInterval {
        self.attach_interval
    }

    pub const fn complete_interval(self) -> TimeInterval {
        self.complete_interval
    }

    pub const fn watermark(self) -> MonotonicInstant {
        self.watermark
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageWindowError {
    CompleteOutsideAttach,
    WatermarkPrecedesCompleteInterval,
}

impl fmt::Display for CoverageWindowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompleteOutsideAttach => {
                formatter.write_str("complete coverage interval lies outside attach interval")
            }
            Self::WatermarkPrecedesCompleteInterval => {
                formatter.write_str("coverage watermark precedes the complete interval")
            }
        }
    }
}

impl std::error::Error for CoverageWindowError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceLoss {
    interval: TimeInterval,
    evidence: AttributionEvidenceId,
}

impl SourceLoss {
    pub const fn new(interval: TimeInterval, evidence: AttributionEvidenceId) -> Self {
        Self { interval, evidence }
    }

    pub const fn interval(self) -> TimeInterval {
        self.interval
    }

    pub const fn evidence(self) -> AttributionEvidenceId {
        self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCoverage {
    source: AttributionSource,
    scope: AttributionScope,
    cursor: CoverageCursor,
    window: CoverageWindow,
    losses: Box<[SourceLoss]>,
}

impl SourceCoverage {
    pub fn new(
        source: AttributionSource,
        scope: AttributionScope,
        cursor: CoverageCursor,
        window: CoverageWindow,
        losses: Vec<SourceLoss>,
    ) -> Self {
        Self {
            source,
            scope,
            cursor,
            window,
            losses: losses.into_boxed_slice(),
        }
    }

    pub const fn source(&self) -> AttributionSource {
        self.source
    }

    pub const fn scope(&self) -> AttributionScope {
        self.scope
    }

    pub const fn cursor(&self) -> CoverageCursor {
        self.cursor
    }

    pub const fn window(&self) -> CoverageWindow {
        self.window
    }

    pub fn losses(&self) -> &[SourceLoss] {
        &self.losses
    }

    pub(crate) fn prove(
        &self,
        scope: AttributionScope,
        interval: TimeInterval,
    ) -> Option<CompletenessProof> {
        if self.scope != scope
            || !self.window.attach_interval().contains(interval)
            || !self.window.complete_interval().contains(interval)
            || self.window.watermark() < interval.end()
            || self
                .losses
                .iter()
                .any(|loss| loss.interval().overlaps(interval))
        {
            return None;
        }
        Some(CompletenessProof::new(CompletenessProofParts {
            source: self.source,
            source_identity: self.cursor.source_identity(),
            evidence: self.cursor.evidence(),
            attach_interval: self.window.attach_interval(),
            source_complete_interval: self.window.complete_interval(),
            proven_interval: interval,
            watermark: self.window.watermark(),
            sequences: self.cursor.sequences(),
        }))
    }
}

pub struct AttributionSnapshotParts {
    pub scope: AttributionScope,
    pub flow: FlowId,
    pub candidate_source: CandidateSourceSnapshot,
    pub direct_facts: Vec<DirectSocketFact>,
    pub candidates: Vec<CorrelationCandidate>,
    pub coverages: Vec<SourceCoverage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributionSnapshot {
    scope: AttributionScope,
    flow: FlowId,
    candidate_source: CandidateSourceSnapshot,
    direct_facts: Box<[DirectSocketFact]>,
    candidates: Box<[CorrelationCandidate]>,
    coverages: Box<[SourceCoverage]>,
    candidate_set: CandidateSetDigest,
    snapshot_digest: AttributionSnapshotDigest,
    authenticator: [u8; 32],
}

impl AttributionSnapshot {
    pub const fn scope(&self) -> AttributionScope {
        self.scope
    }

    pub const fn flow(&self) -> FlowId {
        self.flow
    }

    pub const fn candidate_source(&self) -> CandidateSourceSnapshot {
        self.candidate_source
    }

    pub fn direct_facts(&self) -> &[DirectSocketFact] {
        &self.direct_facts
    }

    pub fn candidates(&self) -> &[CorrelationCandidate] {
        &self.candidates
    }

    pub fn coverages(&self) -> &[SourceCoverage] {
        &self.coverages
    }

    pub const fn candidate_set(&self) -> CandidateSetDigest {
        self.candidate_set
    }

    pub const fn snapshot_digest(&self) -> AttributionSnapshotDigest {
        self.snapshot_digest
    }
}

pub struct AttributionSnapshotAuthority {
    key: [u8; 32],
}

impl fmt::Debug for AttributionSnapshotAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttributionSnapshotAuthority([REDACTED])")
    }
}

impl AttributionSnapshotAuthority {
    pub fn new(key: [u8; 32]) -> Result<Self, SnapshotAuthorityError> {
        if key == [0; 32] {
            Err(SnapshotAuthorityError)
        } else {
            Ok(Self { key })
        }
    }

    pub fn verifier(&self) -> AttributionSnapshotVerifier {
        AttributionSnapshotVerifier { key: self.key }
    }

    pub fn seal(
        &self,
        mut parts: AttributionSnapshotParts,
    ) -> Result<AttributionSnapshot, AttributionSnapshotError> {
        validate_snapshot_parts(&parts)?;
        parts
            .direct_facts
            .sort_unstable_by_key(|fact| fact.provenance());
        parts
            .candidates
            .sort_unstable_by_key(|candidate| candidate.provenance());
        for coverage in &mut parts.coverages {
            let mut losses = coverage.losses.to_vec();
            losses.sort_unstable_by_key(|loss| {
                (
                    loss.interval().start(),
                    loss.interval().end(),
                    loss.evidence(),
                )
            });
            losses.dedup();
            coverage.losses = losses.into_boxed_slice();
        }
        parts.coverages.sort_unstable_by_key(|coverage| {
            (coverage.source(), coverage.cursor().source_identity())
        });

        let candidate_set = digest_candidate_set(
            parts.scope,
            parts.flow,
            parts.candidate_source,
            &parts.candidates,
        )?;
        let snapshot_digest = digest_snapshot(
            parts.scope,
            parts.flow,
            candidate_set,
            &parts.direct_facts,
            &parts.coverages,
        )?;
        let authenticator = keyed_authenticator(
            &self.key,
            b"probe.attribution.snapshot-authenticator\0",
            snapshot_digest.as_bytes(),
        );
        Ok(AttributionSnapshot {
            scope: parts.scope,
            flow: parts.flow,
            candidate_source: parts.candidate_source,
            direct_facts: parts.direct_facts.into_boxed_slice(),
            candidates: parts.candidates.into_boxed_slice(),
            coverages: parts.coverages.into_boxed_slice(),
            candidate_set,
            snapshot_digest,
            authenticator,
        })
    }
}

#[derive(Clone)]
pub struct AttributionSnapshotVerifier {
    key: [u8; 32],
}

impl fmt::Debug for AttributionSnapshotVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttributionSnapshotVerifier([REDACTED])")
    }
}

impl AttributionSnapshotVerifier {
    pub(crate) fn verify(
        &self,
        snapshot: &AttributionSnapshot,
    ) -> Result<(), SnapshotVerificationError> {
        let candidate_set = digest_candidate_set(
            snapshot.scope,
            snapshot.flow,
            snapshot.candidate_source,
            &snapshot.candidates,
        )
        .map_err(|_| SnapshotVerificationError::DigestMismatch)?;
        if candidate_set != snapshot.candidate_set {
            return Err(SnapshotVerificationError::DigestMismatch);
        }
        let snapshot_digest = digest_snapshot(
            snapshot.scope,
            snapshot.flow,
            candidate_set,
            &snapshot.direct_facts,
            &snapshot.coverages,
        )
        .map_err(|_| SnapshotVerificationError::DigestMismatch)?;
        if snapshot_digest != snapshot.snapshot_digest {
            return Err(SnapshotVerificationError::DigestMismatch);
        }
        let expected_authenticator = keyed_authenticator(
            &self.key,
            b"probe.attribution.snapshot-authenticator\0",
            snapshot_digest.as_bytes(),
        );
        if !authenticators_match(expected_authenticator, snapshot.authenticator) {
            return Err(SnapshotVerificationError::AuthenticationFailed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotAuthorityError;

impl fmt::Display for SnapshotAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("attribution snapshot authority key must not be all zero")
    }
}

impl std::error::Error for SnapshotAuthorityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotVerificationError {
    DigestMismatch,
    AuthenticationFailed,
}

impl fmt::Display for SnapshotVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestMismatch => formatter.write_str("attribution snapshot digest mismatch"),
            Self::AuthenticationFailed => {
                formatter.write_str("attribution snapshot authentication failed")
            }
        }
    }
}

impl std::error::Error for SnapshotVerificationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributionSnapshotError {
    TooManyDirectFacts {
        actual: usize,
        hard_limit: usize,
    },
    TooManyCandidates {
        actual: usize,
        hard_limit: usize,
    },
    TooManyCoverages {
        actual: usize,
        hard_limit: usize,
    },
    TooManyLossIntervals {
        actual: usize,
        hard_limit: usize,
    },
    CandidateSourceMismatch,
    CandidateSequenceOutsideSnapshot {
        sequence: SourceSequence,
    },
    DuplicateCandidateSequence {
        sequence: SourceSequence,
    },
    DuplicateDirectFactSequence {
        source_identity: SourceIdentity,
        sequence: SourceSequence,
    },
    SameStageScopeMismatch,
    SameStageFlowMismatch,
    CoverageScopeMismatch {
        source: AttributionSource,
    },
    SocketCoverageSourceMismatch,
    SocketCoverageSequenceMismatch,
    DuplicateCoverageSource {
        source: AttributionSource,
        source_identity: SourceIdentity,
    },
    DigestConstructionFailed,
}

impl fmt::Display for AttributionSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyDirectFacts { actual, hard_limit } => write!(
                formatter,
                "attribution snapshot has {actual} direct facts, exceeding hard limit {hard_limit}"
            ),
            Self::TooManyCandidates { actual, hard_limit } => write!(
                formatter,
                "attribution snapshot has {actual} candidates, exceeding hard limit {hard_limit}"
            ),
            Self::TooManyCoverages { actual, hard_limit } => write!(
                formatter,
                "attribution snapshot has {actual} coverages, exceeding hard limit {hard_limit}"
            ),
            Self::TooManyLossIntervals { actual, hard_limit } => write!(
                formatter,
                "attribution snapshot has {actual} loss intervals, exceeding hard limit {hard_limit}"
            ),
            Self::CandidateSourceMismatch => {
                formatter.write_str("candidate source differs from the candidate source snapshot")
            }
            Self::CandidateSequenceOutsideSnapshot { sequence } => write!(
                formatter,
                "candidate sequence {} lies outside the source snapshot",
                sequence.get()
            ),
            Self::DuplicateCandidateSequence { sequence } => write!(
                formatter,
                "candidate snapshot contains duplicate source sequence {}",
                sequence.get()
            ),
            Self::DuplicateDirectFactSequence {
                source_identity,
                sequence,
            } => write!(
                formatter,
                "direct fact source {source_identity:?} repeats sequence {}",
                sequence.get()
            ),
            Self::SameStageScopeMismatch => {
                formatter.write_str("same-stage candidate scope differs from snapshot scope")
            }
            Self::SameStageFlowMismatch => {
                formatter.write_str("same-stage candidate flow differs from snapshot flow")
            }
            Self::CoverageScopeMismatch { source } => {
                write!(formatter, "{source:?} coverage differs from snapshot scope")
            }
            Self::SocketCoverageSourceMismatch => formatter
                .write_str("socket coverage source differs from the candidate source snapshot"),
            Self::SocketCoverageSequenceMismatch => formatter.write_str(
                "socket coverage sequence range differs from the candidate source snapshot",
            ),
            Self::DuplicateCoverageSource {
                source,
                source_identity,
            } => write!(
                formatter,
                "snapshot contains duplicate {source:?} coverage for {source_identity:?}"
            ),
            Self::DigestConstructionFailed => {
                formatter.write_str("attribution snapshot digest construction failed")
            }
        }
    }
}

impl std::error::Error for AttributionSnapshotError {}

fn validate_snapshot_parts(
    parts: &AttributionSnapshotParts,
) -> Result<(), AttributionSnapshotError> {
    if parts.direct_facts.len() > ATTRIBUTION_SNAPSHOT_DIRECT_HARD_LIMIT {
        return Err(AttributionSnapshotError::TooManyDirectFacts {
            actual: parts.direct_facts.len(),
            hard_limit: ATTRIBUTION_SNAPSHOT_DIRECT_HARD_LIMIT,
        });
    }
    if parts.candidates.len() > ATTRIBUTION_SNAPSHOT_CANDIDATE_HARD_LIMIT {
        return Err(AttributionSnapshotError::TooManyCandidates {
            actual: parts.candidates.len(),
            hard_limit: ATTRIBUTION_SNAPSHOT_CANDIDATE_HARD_LIMIT,
        });
    }
    if parts.coverages.len() > ATTRIBUTION_SNAPSHOT_COVERAGE_HARD_LIMIT {
        return Err(AttributionSnapshotError::TooManyCoverages {
            actual: parts.coverages.len(),
            hard_limit: ATTRIBUTION_SNAPSHOT_COVERAGE_HARD_LIMIT,
        });
    }
    let losses = parts.coverages.iter().try_fold(0_usize, |total, coverage| {
        total.checked_add(coverage.losses().len())
    });
    if !matches!(losses, Some(count) if count <= ATTRIBUTION_SNAPSHOT_LOSS_HARD_LIMIT) {
        return Err(AttributionSnapshotError::TooManyLossIntervals {
            actual: losses.unwrap_or(usize::MAX),
            hard_limit: ATTRIBUTION_SNAPSHOT_LOSS_HARD_LIMIT,
        });
    }

    let mut sequences = BTreeSet::new();
    for candidate in &parts.candidates {
        if candidate.provenance().source() != parts.candidate_source.source_identity() {
            return Err(AttributionSnapshotError::CandidateSourceMismatch);
        }
        let sequence = candidate.provenance().sequence();
        if !parts.candidate_source.sequences().contains(sequence) {
            return Err(AttributionSnapshotError::CandidateSequenceOutsideSnapshot { sequence });
        }
        if !sequences.insert(sequence) {
            return Err(AttributionSnapshotError::DuplicateCandidateSequence { sequence });
        }
        if candidate.stage_relation() == StageRelation::SameCaptureStage {
            if candidate.observed_scope() != parts.scope {
                return Err(AttributionSnapshotError::SameStageScopeMismatch);
            }
            if candidate.observed_flow() != parts.flow {
                return Err(AttributionSnapshotError::SameStageFlowMismatch);
            }
        }
    }

    let mut direct_sequences = BTreeSet::new();
    for fact in &parts.direct_facts {
        let source_identity = fact.provenance().source();
        let sequence = fact.provenance().sequence();
        if !direct_sequences.insert((source_identity, sequence)) {
            return Err(AttributionSnapshotError::DuplicateDirectFactSequence {
                source_identity,
                sequence,
            });
        }
    }

    let mut coverage_sources = BTreeSet::new();
    for coverage in &parts.coverages {
        if coverage.scope() != parts.scope {
            return Err(AttributionSnapshotError::CoverageScopeMismatch {
                source: coverage.source(),
            });
        }
        if !coverage_sources.insert(coverage.source()) {
            return Err(AttributionSnapshotError::DuplicateCoverageSource {
                source: coverage.source(),
                source_identity: coverage.cursor().source_identity(),
            });
        }
        if coverage.source() == AttributionSource::SocketLifecycle {
            if coverage.cursor().source_identity() != parts.candidate_source.source_identity() {
                return Err(AttributionSnapshotError::SocketCoverageSourceMismatch);
            }
            if coverage.cursor().sequences() != parts.candidate_source.sequences() {
                return Err(AttributionSnapshotError::SocketCoverageSequenceMismatch);
            }
        }
    }
    Ok(())
}

fn digest_candidate_set(
    scope: AttributionScope,
    flow: FlowId,
    candidate_source: CandidateSourceSnapshot,
    candidates: &[CorrelationCandidate],
) -> Result<CandidateSetDigest, AttributionSnapshotError> {
    let mut hasher = Hasher::new();
    hasher.update(b"probe.attribution.candidate-set\0");
    hash_scope(&mut hasher, scope);
    hash_id(&mut hasher, flow.as_bytes());
    hash_source_identity(&mut hasher, candidate_source.source_identity());
    hash_sequence_range(&mut hasher, candidate_source.sequences());
    hash_id(&mut hasher, candidate_source.evidence().as_bytes());
    hash_len(&mut hasher, candidates.len());
    for candidate in candidates {
        hash_candidate(&mut hasher, *candidate);
    }
    CandidateSetDigest::new(*hasher.finalize().as_bytes())
        .map_err(|_| AttributionSnapshotError::DigestConstructionFailed)
}

fn digest_snapshot(
    scope: AttributionScope,
    flow: FlowId,
    candidate_set: CandidateSetDigest,
    direct_facts: &[DirectSocketFact],
    coverages: &[SourceCoverage],
) -> Result<AttributionSnapshotDigest, AttributionSnapshotError> {
    let mut hasher = Hasher::new();
    hasher.update(b"probe.attribution.snapshot\0");
    hash_scope(&mut hasher, scope);
    hash_id(&mut hasher, flow.as_bytes());
    hash_id(&mut hasher, candidate_set.as_bytes());
    hash_len(&mut hasher, direct_facts.len());
    for fact in direct_facts {
        hash_direct_fact(&mut hasher, *fact);
    }
    hash_len(&mut hasher, coverages.len());
    for coverage in coverages {
        hash_coverage(&mut hasher, coverage);
    }
    AttributionSnapshotDigest::new(*hasher.finalize().as_bytes())
        .map_err(|_| AttributionSnapshotError::DigestConstructionFailed)
}

fn hash_direct_fact(hasher: &mut Hasher, fact: DirectSocketFact) {
    hash_scope(hasher, fact.scope());
    hasher.update(fact.fingerprint().as_bytes());
    hash_id(hasher, fact.flow().as_bytes());
    hash_id(hasher, fact.socket().as_bytes());
    hash_binding(hasher, fact.binding());
    hash_interval(hasher, fact.valid_during().possible());
    hash_interval(hasher, fact.valid_during().guaranteed());
    hash_interval(hasher, fact.observed().interval());
    hash_id(hasher, fact.observed().calibration().as_bytes());
    hasher.update(&fact.observed().max_error_ns().to_be_bytes());
    hash_provenance(hasher, fact.provenance());
}

fn hash_candidate(hasher: &mut Hasher, candidate: CorrelationCandidate) {
    hash_scope(hasher, candidate.observed_scope());
    hash_id(hasher, candidate.observed_flow().as_bytes());
    match candidate.stage_relation() {
        StageRelation::SameCaptureStage => {
            hasher.update(&[0]);
        }
        StageRelation::Translated { topology_evidence } => {
            hasher.update(&[1]);
            hash_id(hasher, topology_evidence.as_bytes());
        }
    }
    hash_id(hasher, candidate.socket().as_bytes());
    hash_binding(hasher, candidate.binding());
    hash_socket_role(hasher, candidate.role());
    hash_interval(hasher, candidate.valid_during().possible());
    hash_interval(hasher, candidate.valid_during().guaranteed());
    hash_id(hasher, candidate.valid_during().calibration().as_bytes());
    hasher.update(&candidate.valid_during().max_error_ns().to_be_bytes());
    hash_provenance(hasher, candidate.provenance());
}

fn hash_coverage(hasher: &mut Hasher, coverage: &SourceCoverage) {
    hash_attribution_source(hasher, coverage.source());
    hash_scope(hasher, coverage.scope());
    hash_source_identity(hasher, coverage.cursor().source_identity());
    hash_sequence_range(hasher, coverage.cursor().sequences());
    hash_id(hasher, coverage.cursor().evidence().as_bytes());
    hash_interval(hasher, coverage.window().attach_interval());
    hash_interval(hasher, coverage.window().complete_interval());
    hasher.update(&coverage.window().watermark().as_nanos().to_be_bytes());
    hash_len(hasher, coverage.losses().len());
    for loss in coverage.losses() {
        hash_interval(hasher, loss.interval());
        hash_id(hasher, loss.evidence().as_bytes());
    }
}

fn hash_socket_role(hasher: &mut Hasher, role: super::SocketRole) {
    let tag = match role {
        super::SocketRole::EstablishedStream => 0,
        super::SocketRole::ConnectedDatagram => 1,
        super::SocketRole::Listener => 2,
        super::SocketRole::UnconnectedDatagram => 3,
    };
    hasher.update(&[tag]);
}

fn hash_attribution_source(hasher: &mut Hasher, source: AttributionSource) {
    let tag = match source {
        AttributionSource::SocketLifecycle => 0,
        AttributionSource::ProcessLifecycle => 1,
        AttributionSource::CaptureTopology => 2,
    };
    hasher.update(&[tag]);
}

fn hash_binding(hasher: &mut Hasher, binding: super::TargetBinding) {
    match binding.workload() {
        Some(workload) => {
            hasher.update(&[1]);
            hash_id(hasher, workload.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match binding.process() {
        Some(process) => {
            hasher.update(&[1]);
            hash_id(hasher, process.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn hash_scope(hasher: &mut Hasher, scope: AttributionScope) {
    hash_id(hasher, scope.boot().as_bytes());
    hash_id(hasher, scope.network_namespace().as_bytes());
    hash_id(hasher, scope.capture_stage().as_bytes());
}

fn hash_provenance(hasher: &mut Hasher, provenance: super::FactProvenance) {
    hash_id(hasher, provenance.evidence().as_bytes());
    hash_source_identity(hasher, provenance.source());
    hasher.update(&provenance.sequence().get().to_be_bytes());
}

fn hash_source_identity(hasher: &mut Hasher, source: SourceIdentity) {
    hash_id(hasher, source.instance().as_bytes());
    hash_id(hasher, source.epoch().as_bytes());
}

fn hash_sequence_range(hasher: &mut Hasher, sequences: SourceSequenceRange) {
    hasher.update(&sequences.first().get().to_be_bytes());
    hasher.update(&sequences.last().get().to_be_bytes());
}

fn hash_interval(hasher: &mut Hasher, interval: TimeInterval) {
    hasher.update(&interval.start().as_nanos().to_be_bytes());
    hasher.update(&interval.end().as_nanos().to_be_bytes());
}

fn hash_len(hasher: &mut Hasher, len: usize) {
    hasher.update(&(len as u64).to_be_bytes());
}

fn hash_id(hasher: &mut Hasher, bytes: &[u8]) {
    hasher.update(bytes);
}

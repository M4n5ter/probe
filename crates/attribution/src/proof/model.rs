use std::{fmt, mem, num::NonZeroU64};

use probe_core::{
    AttributionEvidenceId, AttributionSnapshotDigest, BootId, CalibratedInterval,
    CalibratedValidity, CandidateSetDigest, CaptureStageId, CgroupId, ClockCalibrationId, FlowId,
    MonotonicInstant, NetworkNamespaceId, ProcessId, SocketId, SourceEpochId, SourceInstanceId,
    SubjectId, TimeInterval, ValidityInterval, WorkloadId,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceSequence(NonZeroU64);

impl SourceSequence {
    pub fn new(value: u64) -> Result<Self, SourceSequenceError> {
        NonZeroU64::new(value).map(Self).ok_or(SourceSequenceError)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSequenceError;

impl fmt::Display for SourceSequenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("attribution source sequence must be non-zero")
    }
}

impl std::error::Error for SourceSequenceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSequenceRange {
    first: SourceSequence,
    last: SourceSequence,
}

impl SourceSequenceRange {
    pub fn new(
        first: SourceSequence,
        last: SourceSequence,
    ) -> Result<Self, SourceSequenceRangeError> {
        if first <= last {
            Ok(Self { first, last })
        } else {
            Err(SourceSequenceRangeError { first, last })
        }
    }

    pub const fn first(self) -> SourceSequence {
        self.first
    }

    pub const fn last(self) -> SourceSequence {
        self.last
    }

    pub const fn contains(self, sequence: SourceSequence) -> bool {
        self.first.get() <= sequence.get() && sequence.get() <= self.last.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSequenceRangeError {
    first: SourceSequence,
    last: SourceSequence,
}

impl fmt::Display for SourceSequenceRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "source sequence range {}..={} is reversed",
            self.first.get(),
            self.last.get()
        )
    }
}

impl std::error::Error for SourceSequenceRangeError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceIdentity {
    instance: SourceInstanceId,
    epoch: SourceEpochId,
}

impl SourceIdentity {
    pub const fn new(instance: SourceInstanceId, epoch: SourceEpochId) -> Self {
        Self { instance, epoch }
    }

    pub const fn instance(self) -> SourceInstanceId {
        self.instance
    }

    pub const fn epoch(self) -> SourceEpochId {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FactProvenance {
    evidence: AttributionEvidenceId,
    source: SourceIdentity,
    sequence: SourceSequence,
}

impl FactProvenance {
    pub const fn new(
        evidence: AttributionEvidenceId,
        source: SourceIdentity,
        sequence: SourceSequence,
    ) -> Self {
        Self {
            evidence,
            source,
            sequence,
        }
    }

    pub const fn evidence(self) -> AttributionEvidenceId {
        self.evidence
    }

    pub const fn source(self) -> SourceIdentity {
        self.source
    }

    pub const fn sequence(self) -> SourceSequence {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PacketFingerprint([u8; 32]);

impl PacketFingerprint {
    pub fn new(bytes: [u8; 32]) -> Result<Self, PacketFingerprintError> {
        if bytes == [0; 32] {
            Err(PacketFingerprintError)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketFingerprintError;

impl fmt::Display for PacketFingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("packet fingerprint must not be all zero")
    }
}

impl std::error::Error for PacketFingerprintError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AttributionScope {
    boot: BootId,
    network_namespace: NetworkNamespaceId,
    capture_stage: CaptureStageId,
}

impl AttributionScope {
    pub const fn new(
        boot: BootId,
        network_namespace: NetworkNamespaceId,
        capture_stage: CaptureStageId,
    ) -> Self {
        Self {
            boot,
            network_namespace,
            capture_stage,
        }
    }

    pub const fn boot(self) -> BootId {
        self.boot
    }

    pub const fn network_namespace(self) -> NetworkNamespaceId {
        self.network_namespace
    }

    pub const fn capture_stage(self) -> CaptureStageId {
        self.capture_stage
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CapturePrincipal {
    uid: u32,
    cgroup: Option<CgroupId>,
}

impl CapturePrincipal {
    pub const fn new(uid: u32, cgroup: Option<CgroupId>) -> Self {
        Self { uid, cgroup }
    }

    pub const fn uid(self) -> u32 {
        self.uid
    }

    pub const fn cgroup(self) -> Option<CgroupId> {
        self.cgroup
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetBinding {
    workload: Option<WorkloadId>,
    process: Option<ProcessId>,
}

impl TargetBinding {
    pub fn new(
        workload: Option<WorkloadId>,
        process: Option<ProcessId>,
    ) -> Result<Self, TargetBindingError> {
        if workload.is_none() && process.is_none() {
            Err(TargetBindingError)
        } else {
            Ok(Self { workload, process })
        }
    }

    pub const fn workload(self) -> Option<WorkloadId> {
        self.workload
    }

    pub const fn process(self) -> Option<ProcessId> {
        self.process
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetBindingError;

impl fmt::Display for TargetBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("attribution target binding must identify a workload or process")
    }
}

impl std::error::Error for TargetBindingError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketObservation {
    subject: SubjectId,
    principal: CapturePrincipal,
    scope: AttributionScope,
    fingerprint: PacketFingerprint,
    flow: FlowId,
    observed: CalibratedInterval<ClockCalibrationId>,
    provenance: FactProvenance,
}

impl PacketObservation {
    pub const fn new(
        subject: SubjectId,
        principal: CapturePrincipal,
        scope: AttributionScope,
        fingerprint: PacketFingerprint,
        flow: FlowId,
        observed: CalibratedInterval<ClockCalibrationId>,
        provenance: FactProvenance,
    ) -> Self {
        Self {
            subject,
            principal,
            scope,
            fingerprint,
            flow,
            observed,
            provenance,
        }
    }

    pub const fn subject(self) -> SubjectId {
        self.subject
    }

    pub const fn principal(self) -> CapturePrincipal {
        self.principal
    }

    pub const fn scope(self) -> AttributionScope {
        self.scope
    }

    pub const fn fingerprint(self) -> PacketFingerprint {
        self.fingerprint
    }

    pub const fn flow(self) -> FlowId {
        self.flow
    }

    pub const fn observed(self) -> CalibratedInterval<ClockCalibrationId> {
        self.observed
    }

    pub const fn evidence(self) -> AttributionEvidenceId {
        self.provenance.evidence()
    }

    pub const fn provenance(self) -> FactProvenance {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectJoinKey {
    fingerprint: PacketFingerprint,
    flow: FlowId,
}

impl DirectJoinKey {
    pub const fn new(fingerprint: PacketFingerprint, flow: FlowId) -> Self {
        Self { fingerprint, flow }
    }

    pub const fn fingerprint(self) -> PacketFingerprint {
        self.fingerprint
    }

    pub const fn flow(self) -> FlowId {
        self.flow
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectSocketFact {
    scope: AttributionScope,
    join: DirectJoinKey,
    socket: SocketId,
    binding: TargetBinding,
    valid_during: ValidityInterval,
    observed: CalibratedInterval<ClockCalibrationId>,
    provenance: FactProvenance,
}

impl DirectSocketFact {
    pub const fn new(
        scope: AttributionScope,
        join: DirectJoinKey,
        socket: SocketId,
        binding: TargetBinding,
        valid_during: ValidityInterval,
        observed: CalibratedInterval<ClockCalibrationId>,
        provenance: FactProvenance,
    ) -> Self {
        Self {
            scope,
            join,
            socket,
            binding,
            valid_during,
            observed,
            provenance,
        }
    }

    pub const fn scope(self) -> AttributionScope {
        self.scope
    }

    pub const fn fingerprint(self) -> PacketFingerprint {
        self.join.fingerprint()
    }

    pub const fn flow(self) -> FlowId {
        self.join.flow()
    }

    pub const fn socket(self) -> SocketId {
        self.socket
    }

    pub const fn binding(self) -> TargetBinding {
        self.binding
    }

    pub const fn valid_during(self) -> ValidityInterval {
        self.valid_during
    }

    pub const fn observed(self) -> CalibratedInterval<ClockCalibrationId> {
        self.observed
    }

    pub const fn evidence(self) -> AttributionEvidenceId {
        self.provenance.evidence()
    }

    pub const fn provenance(self) -> FactProvenance {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SocketRole {
    EstablishedStream,
    ConnectedDatagram,
    Listener,
    UnconnectedDatagram,
}

impl SocketRole {
    pub const fn supports_closed_world_correlation(self) -> bool {
        matches!(self, Self::EstablishedStream | Self::ConnectedDatagram)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StageRelation {
    SameCaptureStage,
    Translated {
        topology_evidence: AttributionEvidenceId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelationCandidate {
    observed_scope: AttributionScope,
    observed_flow: FlowId,
    stage_relation: StageRelation,
    socket: SocketId,
    binding: TargetBinding,
    role: SocketRole,
    valid_during: CalibratedValidity<ClockCalibrationId>,
    provenance: FactProvenance,
}

pub struct CorrelationCandidateParts {
    pub observed_scope: AttributionScope,
    pub observed_flow: FlowId,
    pub stage_relation: StageRelation,
    pub socket: SocketId,
    pub binding: TargetBinding,
    pub role: SocketRole,
    pub valid_during: CalibratedValidity<ClockCalibrationId>,
    pub provenance: FactProvenance,
}

impl CorrelationCandidate {
    pub const fn new(parts: CorrelationCandidateParts) -> Self {
        Self {
            observed_scope: parts.observed_scope,
            observed_flow: parts.observed_flow,
            stage_relation: parts.stage_relation,
            socket: parts.socket,
            binding: parts.binding,
            role: parts.role,
            valid_during: parts.valid_during,
            provenance: parts.provenance,
        }
    }

    pub const fn observed_scope(self) -> AttributionScope {
        self.observed_scope
    }

    pub const fn observed_flow(self) -> FlowId {
        self.observed_flow
    }

    pub const fn stage_relation(self) -> StageRelation {
        self.stage_relation
    }

    pub const fn socket(self) -> SocketId {
        self.socket
    }

    pub const fn binding(self) -> TargetBinding {
        self.binding
    }

    pub const fn role(self) -> SocketRole {
        self.role
    }

    pub const fn valid_during(self) -> CalibratedValidity<ClockCalibrationId> {
        self.valid_during
    }

    pub const fn evidence(self) -> AttributionEvidenceId {
        self.provenance.evidence()
    }

    pub const fn provenance(self) -> FactProvenance {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttributionSource {
    SocketLifecycle,
    ProcessLifecycle,
    CaptureTopology,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributionConfidence {
    Proven,
    CorrelatedUnique,
    Inferred,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributionJoinRule {
    DirectPacketFingerprint,
    IncompleteDirectPacketFingerprint,
    ClosedWorldFlowCorrelation,
    IncompleteFlowCorrelation,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttributionGapReason {
    ConflictingDirectBindings,
    ClockUncertain,
    DirectFactWindowMismatch,
    NoCandidate,
    MultipleCandidates { count: usize },
    UnsupportedSocketRole(SocketRole),
    UnsupportedStageRelation,
    CandidateWindowMismatch,
    SourceIncomplete(AttributionSource),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletenessProof {
    source: AttributionSource,
    source_identity: SourceIdentity,
    evidence: AttributionEvidenceId,
    attach_interval: TimeInterval,
    source_complete_interval: TimeInterval,
    proven_interval: TimeInterval,
    watermark: MonotonicInstant,
    sequences: SourceSequenceRange,
}

impl CompletenessProof {
    pub(crate) const fn new(parts: CompletenessProofParts) -> Self {
        Self {
            source: parts.source,
            source_identity: parts.source_identity,
            evidence: parts.evidence,
            attach_interval: parts.attach_interval,
            source_complete_interval: parts.source_complete_interval,
            proven_interval: parts.proven_interval,
            watermark: parts.watermark,
            sequences: parts.sequences,
        }
    }

    pub const fn source(self) -> AttributionSource {
        self.source
    }

    pub const fn source_identity(self) -> SourceIdentity {
        self.source_identity
    }

    pub const fn evidence(self) -> AttributionEvidenceId {
        self.evidence
    }

    pub const fn attach_interval(self) -> TimeInterval {
        self.attach_interval
    }

    pub const fn source_complete_interval(self) -> TimeInterval {
        self.source_complete_interval
    }

    pub const fn proven_interval(self) -> TimeInterval {
        self.proven_interval
    }

    pub const fn watermark(self) -> MonotonicInstant {
        self.watermark
    }

    pub const fn sequences(self) -> SourceSequenceRange {
        self.sequences
    }
}

pub(crate) struct CompletenessProofParts {
    pub(crate) source: AttributionSource,
    pub(crate) source_identity: SourceIdentity,
    pub(crate) evidence: AttributionEvidenceId,
    pub(crate) attach_interval: TimeInterval,
    pub(crate) source_complete_interval: TimeInterval,
    pub(crate) proven_interval: TimeInterval,
    pub(crate) watermark: MonotonicInstant,
    pub(crate) sequences: SourceSequenceRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributionProofBasis {
    rule: AttributionJoinRule,
    scope: AttributionScope,
    packet_fingerprint: PacketFingerprint,
    flow: FlowId,
    correlation_window: TimeInterval,
    socket: Option<SocketId>,
    candidate_set: CandidateSetDigest,
    snapshot_digest: AttributionSnapshotDigest,
    fact_provenance: Box<[FactProvenance]>,
    clock_calibrations: Box<[ClockCalibrationId]>,
    completeness: Box<[CompletenessProof]>,
    universe_candidate_count: usize,
    matching_candidate_count: usize,
    limitations: Box<[AttributionGapReason]>,
}

impl AttributionProofBasis {
    pub(crate) fn new(parts: AttributionProofParts) -> Self {
        Self {
            rule: parts.rule,
            scope: parts.scope,
            packet_fingerprint: parts.packet_fingerprint,
            flow: parts.flow,
            correlation_window: parts.correlation_window,
            socket: parts.socket,
            candidate_set: parts.candidate_set,
            snapshot_digest: parts.snapshot_digest,
            fact_provenance: parts.fact_provenance.into_boxed_slice(),
            clock_calibrations: parts.clock_calibrations.into_boxed_slice(),
            completeness: parts.completeness.into_boxed_slice(),
            universe_candidate_count: parts.universe_candidate_count,
            matching_candidate_count: parts.matching_candidate_count,
            limitations: parts.limitations.into_boxed_slice(),
        }
    }

    pub const fn rule(&self) -> AttributionJoinRule {
        self.rule
    }

    pub const fn scope(&self) -> AttributionScope {
        self.scope
    }

    pub const fn packet_fingerprint(&self) -> PacketFingerprint {
        self.packet_fingerprint
    }

    pub const fn flow(&self) -> FlowId {
        self.flow
    }

    pub const fn correlation_window(&self) -> TimeInterval {
        self.correlation_window
    }

    pub const fn socket(&self) -> Option<SocketId> {
        self.socket
    }

    pub const fn candidate_set(&self) -> CandidateSetDigest {
        self.candidate_set
    }

    pub const fn snapshot_digest(&self) -> AttributionSnapshotDigest {
        self.snapshot_digest
    }

    pub fn fact_provenance(&self) -> &[FactProvenance] {
        &self.fact_provenance
    }

    pub fn clock_calibrations(&self) -> &[ClockCalibrationId] {
        &self.clock_calibrations
    }

    pub fn completeness(&self) -> &[CompletenessProof] {
        &self.completeness
    }

    pub const fn universe_candidate_count(&self) -> usize {
        self.universe_candidate_count
    }

    pub const fn matching_candidate_count(&self) -> usize {
        self.matching_candidate_count
    }

    pub fn limitations(&self) -> &[AttributionGapReason] {
        &self.limitations
    }
}

pub(crate) struct AttributionProofParts {
    pub(crate) rule: AttributionJoinRule,
    pub(crate) scope: AttributionScope,
    pub(crate) packet_fingerprint: PacketFingerprint,
    pub(crate) flow: FlowId,
    pub(crate) correlation_window: TimeInterval,
    pub(crate) socket: Option<SocketId>,
    pub(crate) candidate_set: CandidateSetDigest,
    pub(crate) snapshot_digest: AttributionSnapshotDigest,
    pub(crate) fact_provenance: Vec<FactProvenance>,
    pub(crate) clock_calibrations: Vec<ClockCalibrationId>,
    pub(crate) completeness: Vec<CompletenessProof>,
    pub(crate) universe_candidate_count: usize,
    pub(crate) matching_candidate_count: usize,
    pub(crate) limitations: Vec<AttributionGapReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributionClaim {
    subject: SubjectId,
    principal: CapturePrincipal,
    binding: Option<TargetBinding>,
    confidence: AttributionConfidence,
    proof: Box<[AttributionEvidenceId]>,
    proof_basis: AttributionProofBasis,
    valid_during: TimeInterval,
}

impl AttributionClaim {
    pub(crate) fn new(
        packet: PacketObservation,
        binding: Option<TargetBinding>,
        confidence: AttributionConfidence,
        proof: Vec<AttributionEvidenceId>,
        proof_basis: AttributionProofBasis,
    ) -> Self {
        Self {
            subject: packet.subject(),
            principal: packet.principal(),
            binding,
            confidence,
            proof: proof.into_boxed_slice(),
            proof_basis,
            valid_during: packet.observed().interval(),
        }
    }

    pub const fn subject(&self) -> SubjectId {
        self.subject
    }

    pub const fn principal(&self) -> CapturePrincipal {
        self.principal
    }

    pub const fn binding(&self) -> Option<TargetBinding> {
        self.binding
    }

    pub const fn confidence(&self) -> AttributionConfidence {
        self.confidence
    }

    pub fn proof(&self) -> &[AttributionEvidenceId] {
        &self.proof
    }

    pub const fn proof_basis(&self) -> &AttributionProofBasis {
        &self.proof_basis
    }

    pub const fn valid_during(&self) -> TimeInterval {
        self.valid_during
    }

    pub fn proof_memory_bytes(&self) -> Option<usize> {
        attribution_claim_memory_bytes(
            self.proof.len(),
            self.proof_basis.fact_provenance.len(),
            self.proof_basis.clock_calibrations.len(),
            self.proof_basis.completeness.len(),
            self.proof_basis.limitations.len(),
        )
    }
}

pub(crate) fn attribution_claim_memory_bytes(
    evidence: usize,
    fact_provenance: usize,
    clock_calibrations: usize,
    completeness: usize,
    limitations: usize,
) -> Option<usize> {
    mem::size_of::<AttributionClaim>()
        .checked_add(evidence.checked_mul(mem::size_of::<AttributionEvidenceId>())?)?
        .checked_add(fact_provenance.checked_mul(mem::size_of::<FactProvenance>())?)?
        .checked_add(clock_calibrations.checked_mul(mem::size_of::<ClockCalibrationId>())?)?
        .checked_add(completeness.checked_mul(mem::size_of::<CompletenessProof>())?)?
        .checked_add(limitations.checked_mul(mem::size_of::<AttributionGapReason>())?)
}

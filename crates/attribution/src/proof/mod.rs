mod admission;
mod authentication;
mod budget;
mod completeness;
mod engine;
mod model;

pub use admission::{
    AdmissionDecision, AdmissionPolicy, AdmissionPolicyParts, AdmissionRejection,
    AttributionConfidenceGrant, AttributionConfidenceGrantError, AuthorityKeyError,
    AuthorizationLiveness, AuthorizationStatus, CaptureGrant, CaptureSubjectScope,
    CompletenessAllowance, HostAuthorizationContext, HostAuthorizationIssueError,
    HostAuthorizationVerificationError, HostCaptureAuthority, HostCaptureAuthorization,
    HostCaptureAuthorizationParts, HostCaptureGrant, HostCaptureVerifier, PayloadAccess,
    RetentionLimit, RetentionLimitError, SelectionAttestation, SelectionAttestationParts,
    SelectionAuthority, SelectionVerificationError, SelectionVerifier, TargetSelection,
};
pub use budget::{
    AttributionBudget, AttributionBudgetError, AttributionBudgetSpec, AttributionResource,
};
pub use completeness::{
    AttributionSnapshot, AttributionSnapshotAuthority, AttributionSnapshotError,
    AttributionSnapshotParts, AttributionSnapshotVerifier, CandidateSourceSnapshot, CoverageCursor,
    CoverageWindow, CoverageWindowError, REQUIRED_CORRELATION_SOURCES, SnapshotAuthorityError,
    SnapshotVerificationError, SourceCoverage, SourceLoss,
};
pub use engine::{AttributionEngine, AttributionError, AttributionEvaluator};
pub use model::{
    AttributionClaim, AttributionConfidence, AttributionGapReason, AttributionJoinRule,
    AttributionProofBasis, AttributionScope, AttributionSource, CapturePrincipal,
    CompletenessProof, CorrelationCandidate, CorrelationCandidateParts, DirectJoinKey,
    DirectSocketFact, FactProvenance, PacketFingerprint, PacketFingerprintError, PacketObservation,
    SocketRole, SourceIdentity, SourceSequence, SourceSequenceError, SourceSequenceRange,
    SourceSequenceRangeError, StageRelation, TargetBinding, TargetBindingError,
};
pub use probe_core::{
    CalibratedInterval, CalibratedValidity, MonotonicInstant, TimeInterval, TimeIntervalError,
    ValidityInterval, ValidityIntervalError,
};

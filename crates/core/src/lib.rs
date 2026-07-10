mod attribution;
mod cancellation;
mod canonical;
mod capability;
mod cgroup;
mod event;
mod identity;
mod procfs;
mod protocol;
mod schema;
mod selector;
mod socket;
mod verdict;
mod webhook;

pub const DEFAULT_POLICY_RUNTIME_ERROR_DISABLE_THRESHOLD: u64 = 3;

pub use attribution::{
    LIBPCAP_FALLBACK_RUNTIME_HINT, UNKNOWN_PROCESS_LABEL, is_libpcap_unknown_process_candidate,
};
pub use cancellation::CancellationToken;
pub use canonical::{
    AttributionEvidenceId, AttributionSnapshotDigest, AuthorizationAuditId, AuthorizationId,
    AuthorizationIssuerId, AuthorizationNonce, BootId, CalibratedInterval, CalibratedValidity,
    CandidateSetDigest, CanonicalIdError, CaptureSelectorDigest, CaptureStageId, CgroupId,
    ClockCalibrationId, FlowId, HostAuthorizationDigest, MonotonicInstant, NetworkNamespaceId,
    ObservationIntentId, ProcessId, Revision, RevisionError, SelectionProofId, SocketId,
    SourceEpochId, SourceInstanceId, SubjectId, TimeInterval, TimeIntervalError, ValidityInterval,
    ValidityIntervalError, WorkloadId,
};
pub use capability::{
    CapabilityKind, CapabilityMatrix, CapabilityRequirement, CapabilityState, RuntimeMode,
};
pub use cgroup::{CgroupPath, CgroupPathError};
pub use event::{
    BodyChunk, CaptureLoss, CaptureOrigin, CaptureProviderKind, CaptureSource,
    CaptureTrafficSecurity, Direction, DomainEvent, EnforcementEvidence, EventEmission,
    EventEnvelope, EventId, EventKind, EventProvenance, EventSubject, EventType, Gap, HttpHeaders,
    L7MitmAuditEvent, L7MitmAuditPhase, L7MitmExternalBackendAudit, L7MitmManagedProcessAudit,
    L7MitmManagedProcessBackendAudit, L7MitmReadinessProbeAudit, ObservationOnlyReason,
    OpaqueStream, PolicyEmissionStage, PolicyRuntimeError, ProtocolError, SseEvent, Timestamp,
    UnknownEventType, WebSocketFrame, WebSocketHandoff, WebSocketMessage, WebSocketMessageOpcode,
    WebSocketOpcode,
};
pub use identity::{
    AddressPort, FlowContext, FlowIdentity, ProcessContext, ProcessGeneration, ProcessIdentity,
    TransportProtocol,
};
pub use procfs::{LinuxProcStat, LinuxProcStatParseError, parse_linux_proc_stat};
pub use protocol::{
    ApplicationProtocol, ApplicationProtocolParseError, ApplicationProtocolPolicy,
    ApplicationProtocolPolicyError,
};
pub use schema::{SpoolPayloadSchema, SpoolPayloadSchemaError};
pub use selector::{
    CompiledSelector, ProcessSelector, ResolvedSelector, Selector, SelectorError, SelectorRegistry,
    SelectorTerm, TrafficSelector,
};
pub use socket::{
    TcpConnection, TcpConnectionFromFlowError, TcpEndpoint, UpstreamRoute, UpstreamRouteError,
    UpstreamRouteHost, UpstreamRouteHostPattern, socket_addr_points_to_listener,
};
pub use verdict::{
    Action, ConnectionBackendExecutionEvidence, ConnectionEnforcementSurface, EnforcementDecision,
    EnforcementExecutionEvidence, EnforcementMode, EnforcementOutcome, ProtectiveActionError,
    ProtectiveActionProfile, ProxySideEnforcementSurface, Verdict, VerdictScope,
};
pub use webhook::{
    RESERVED_WEBHOOK_HEADERS, WEBHOOK_CODEC_HEADER, WEBHOOK_CONTENT_TYPE_HEADER,
    WEBHOOK_CONTENT_TYPE_PROTOBUF, WEBHOOK_IDEMPOTENCY_KEY_HEADER,
};

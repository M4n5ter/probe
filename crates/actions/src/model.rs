use std::fmt;

use blake3::Hasher;
use probe_core::{
    ActionAuditId, ActionAuthorizationDigest, ActionAuthorizationId, ActionBackendId,
    ActionEffectDigest, ActionIntentDigest, ActionParametersDigest, ActionRequestId,
    ActionResultDigest, ActionScopeProofId, BootId, BootScopedInstant, BpfLinkId,
    CapabilitySnapshotDigest, CgroupId, EffectiveStateRevisionId, InterceptionAuthorizationId,
    InterceptionConversationId, MonotonicInstant, NetworkNamespaceId, PolicyDigest,
    PolicyRevisionId, SocketId, TimeInterval, WorkloadId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionDecisionPoint {
    OutboundConnect,
    InboundAccepted,
    RequestHead,
    RequestBodyChunk,
    RequestEnd,
    ResponseHead,
    ResponseBodyChunk,
    ResponseEnd,
    WebSocketMessage,
}

impl ActionDecisionPoint {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::OutboundConnect => 0,
            Self::InboundAccepted => 1,
            Self::RequestHead => 2,
            Self::RequestBodyChunk => 3,
            Self::RequestEnd => 4,
            Self::ResponseHead => 5,
            Self::ResponseBodyChunk => 6,
            Self::ResponseEnd => 7,
            Self::WebSocketMessage => 8,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, ActionModelDecodeError> {
        match tag {
            0 => Ok(Self::OutboundConnect),
            1 => Ok(Self::InboundAccepted),
            2 => Ok(Self::RequestHead),
            3 => Ok(Self::RequestBodyChunk),
            4 => Ok(Self::RequestEnd),
            5 => Ok(Self::ResponseHead),
            6 => Ok(Self::ResponseBodyChunk),
            7 => Ok(Self::ResponseEnd),
            8 => Ok(Self::WebSocketMessage),
            other => Err(ActionModelDecodeError::DecisionPoint(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionKind {
    Deny,
    Reset,
    DestroySocket,
    Redirect,
    Modify,
    Replace,
    Quarantine,
    DropMessage,
    CloseSession,
}

impl ActionKind {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::Reset => 1,
            Self::DestroySocket => 2,
            Self::Redirect => 3,
            Self::Modify => 4,
            Self::Replace => 5,
            Self::Quarantine => 6,
            Self::DropMessage => 7,
            Self::CloseSession => 8,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, ActionModelDecodeError> {
        match tag {
            0 => Ok(Self::Deny),
            1 => Ok(Self::Reset),
            2 => Ok(Self::DestroySocket),
            3 => Ok(Self::Redirect),
            4 => Ok(Self::Modify),
            5 => Ok(Self::Replace),
            6 => Ok(Self::Quarantine),
            7 => Ok(Self::DropMessage),
            8 => Ok(Self::CloseSession),
            other => Err(ActionModelDecodeError::ActionKind(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionFailureProfile {
    FailOpen,
    AuthorizedFailClosed,
}

impl ActionFailureProfile {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::FailOpen => 0,
            Self::AuthorizedFailClosed => 1,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, ActionModelDecodeError> {
        match tag {
            0 => Ok(Self::FailOpen),
            1 => Ok(Self::AuthorizedFailClosed),
            other => Err(ActionModelDecodeError::FailureProfile(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionScopeProof {
    KernelSocket {
        proof: ActionScopeProofId,
        socket: SocketId,
        network_namespace: NetworkNamespaceId,
        workload: WorkloadId,
        valid_during: TimeInterval,
    },
    CgroupHook {
        proof: ActionScopeProofId,
        cgroup: CgroupId,
        attachment: BpfLinkId,
        valid_during: TimeInterval,
    },
    InterceptedFlow {
        proof: ActionScopeProofId,
        conversation: InterceptionConversationId,
        authorization: InterceptionAuthorizationId,
        effective_revision: EffectiveStateRevisionId,
        valid_during: TimeInterval,
    },
}

impl ActionScopeProof {
    pub const fn proof(self) -> ActionScopeProofId {
        match self {
            Self::KernelSocket { proof, .. }
            | Self::CgroupHook { proof, .. }
            | Self::InterceptedFlow { proof, .. } => proof,
        }
    }

    pub const fn valid_during(self) -> TimeInterval {
        match self {
            Self::KernelSocket { valid_during, .. }
            | Self::CgroupHook { valid_during, .. }
            | Self::InterceptedFlow { valid_during, .. } => valid_during,
        }
    }

    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::KernelSocket { .. } => 0,
            Self::CgroupHook { .. } => 1,
            Self::InterceptedFlow { .. } => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateChangingAction {
    request: ActionRequestId,
    audit: ActionAuditId,
    backend: ActionBackendId,
    authorization: ActionAuthorizationId,
    authorization_digest: ActionAuthorizationDigest,
    authorization_validity: TimeInterval,
    policy_revision: PolicyRevisionId,
    policy_digest: PolicyDigest,
    capability_snapshot: CapabilitySnapshotDigest,
    boot: BootId,
    decided_at: MonotonicInstant,
    execute_before: MonotonicInstant,
    decision_point: ActionDecisionPoint,
    requested: ActionKind,
    effective: ActionKind,
    failure: ActionFailureProfile,
    scope: ActionScopeProof,
    parameters: ActionParametersDigest,
    effect: ActionEffectDigest,
    digest: ActionIntentDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateChangingActionParts {
    pub request: ActionRequestId,
    pub audit: ActionAuditId,
    pub backend: ActionBackendId,
    pub authorization: ActionAuthorizationId,
    pub authorization_digest: ActionAuthorizationDigest,
    pub authorization_validity: TimeInterval,
    pub policy_revision: PolicyRevisionId,
    pub policy_digest: PolicyDigest,
    pub capability_snapshot: CapabilitySnapshotDigest,
    pub boot: BootId,
    pub decided_at: MonotonicInstant,
    pub execute_before: MonotonicInstant,
    pub decision_point: ActionDecisionPoint,
    pub requested: ActionKind,
    pub effective: ActionKind,
    pub failure: ActionFailureProfile,
    pub scope: ActionScopeProof,
    pub parameters: ActionParametersDigest,
    pub effect: ActionEffectDigest,
}

impl StateChangingAction {
    pub fn new(parts: StateChangingActionParts) -> Result<Self, StateChangingActionError> {
        let execution_window = TimeInterval::new(parts.decided_at, parts.execute_before)
            .map_err(|_| StateChangingActionError::DeadlineBeforeDecision)?;
        if !parts.scope.valid_during().contains(execution_window) {
            return Err(StateChangingActionError::ScopeDoesNotCoverExecution);
        }
        if !parts.authorization_validity.contains(execution_window) {
            return Err(StateChangingActionError::AuthorizationDoesNotCoverExecution);
        }
        let digest = action_digest(parts)?;
        Ok(Self {
            request: parts.request,
            audit: parts.audit,
            backend: parts.backend,
            authorization: parts.authorization,
            authorization_digest: parts.authorization_digest,
            authorization_validity: parts.authorization_validity,
            policy_revision: parts.policy_revision,
            policy_digest: parts.policy_digest,
            capability_snapshot: parts.capability_snapshot,
            boot: parts.boot,
            decided_at: parts.decided_at,
            execute_before: parts.execute_before,
            decision_point: parts.decision_point,
            requested: parts.requested,
            effective: parts.effective,
            failure: parts.failure,
            scope: parts.scope,
            parameters: parts.parameters,
            effect: parts.effect,
            digest,
        })
    }

    pub const fn request(self) -> ActionRequestId {
        self.request
    }

    pub const fn audit(self) -> ActionAuditId {
        self.audit
    }

    pub const fn backend(self) -> ActionBackendId {
        self.backend
    }

    pub const fn authorization(self) -> ActionAuthorizationId {
        self.authorization
    }

    pub const fn authorization_digest(self) -> ActionAuthorizationDigest {
        self.authorization_digest
    }

    pub const fn authorization_validity(self) -> TimeInterval {
        self.authorization_validity
    }

    pub const fn policy_revision(self) -> PolicyRevisionId {
        self.policy_revision
    }

    pub const fn policy_digest(self) -> PolicyDigest {
        self.policy_digest
    }

    pub const fn capability_snapshot(self) -> CapabilitySnapshotDigest {
        self.capability_snapshot
    }

    pub const fn boot(self) -> BootId {
        self.boot
    }

    pub const fn decided_at(self) -> MonotonicInstant {
        self.decided_at
    }

    pub const fn execute_before(self) -> MonotonicInstant {
        self.execute_before
    }

    pub const fn decision_point(self) -> ActionDecisionPoint {
        self.decision_point
    }

    pub const fn requested(self) -> ActionKind {
        self.requested
    }

    pub const fn effective(self) -> ActionKind {
        self.effective
    }

    pub const fn failure(self) -> ActionFailureProfile {
        self.failure
    }

    pub const fn scope(self) -> ActionScopeProof {
        self.scope
    }

    pub const fn parameters(self) -> ActionParametersDigest {
        self.parameters
    }

    pub const fn effect(self) -> ActionEffectDigest {
        self.effect
    }

    pub const fn digest(self) -> ActionIntentDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateChangingActionError {
    DeadlineBeforeDecision,
    ScopeDoesNotCoverExecution,
    AuthorizationDoesNotCoverExecution,
    DigestConstructionFailed,
}

impl fmt::Display for StateChangingActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineBeforeDecision => {
                formatter.write_str("action deadline precedes its decision time")
            }
            Self::ScopeDoesNotCoverExecution => formatter
                .write_str("action scope proof does not cover the complete execution window"),
            Self::AuthorizationDoesNotCoverExecution => formatter
                .write_str("action authorization does not cover the complete execution window"),
            Self::DigestConstructionFailed => {
                formatter.write_str("action intent digest construction failed")
            }
        }
    }
}

impl std::error::Error for StateChangingActionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionOutcome {
    Applied,
    NotApplied,
    InDoubt,
}

impl ActionOutcome {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Applied => 0,
            Self::NotApplied => 1,
            Self::InDoubt => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, ActionModelDecodeError> {
        match tag {
            0 => Ok(Self::Applied),
            1 => Ok(Self::NotApplied),
            2 => Ok(Self::InDoubt),
            other => Err(ActionModelDecodeError::Outcome(other)),
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::NotApplied)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionResultSource {
    DirectBackendReceipt,
    ExecutionUncertainty,
    ReconciledEffectTruth,
}

impl ActionResultSource {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::DirectBackendReceipt => 0,
            Self::ExecutionUncertainty => 1,
            Self::ReconciledEffectTruth => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, ActionModelDecodeError> {
        match tag {
            0 => Ok(Self::DirectBackendReceipt),
            1 => Ok(Self::ExecutionUncertainty),
            2 => Ok(Self::ReconciledEffectTruth),
            other => Err(ActionModelDecodeError::ResultSource(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionCausality {
    Known,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionResult {
    outcome: ActionOutcome,
    source: ActionResultSource,
    observed_at: BootScopedInstant,
    evidence: ActionResultDigest,
}

impl ActionResult {
    pub const fn direct(
        outcome: ActionOutcome,
        observed_at: BootScopedInstant,
        receipt: ActionResultDigest,
    ) -> Result<Self, ActionResultError> {
        if outcome.is_terminal() {
            Ok(Self {
                outcome,
                source: ActionResultSource::DirectBackendReceipt,
                observed_at,
                evidence: receipt,
            })
        } else {
            Err(ActionResultError::DirectReceiptMustBeTerminal)
        }
    }

    pub const fn uncertain(observed_at: BootScopedInstant, evidence: ActionResultDigest) -> Self {
        Self {
            outcome: ActionOutcome::InDoubt,
            source: ActionResultSource::ExecutionUncertainty,
            observed_at,
            evidence,
        }
    }

    pub const fn reconciled(
        outcome: ActionOutcome,
        observed_at: BootScopedInstant,
        evidence: ActionResultDigest,
    ) -> Result<Self, ActionResultError> {
        if outcome.is_terminal() {
            Ok(Self {
                outcome,
                source: ActionResultSource::ReconciledEffectTruth,
                observed_at,
                evidence,
            })
        } else {
            Err(ActionResultError::ReconciledTruthMustBeTerminal)
        }
    }

    pub const fn outcome(self) -> ActionOutcome {
        self.outcome
    }

    pub const fn source(self) -> ActionResultSource {
        self.source
    }

    pub const fn causality(self) -> ActionCausality {
        match self.source {
            ActionResultSource::DirectBackendReceipt => ActionCausality::Known,
            ActionResultSource::ExecutionUncertainty
            | ActionResultSource::ReconciledEffectTruth => ActionCausality::Unknown,
        }
    }

    pub const fn observed_at(self) -> BootScopedInstant {
        self.observed_at
    }

    pub const fn evidence(self) -> ActionResultDigest {
        self.evidence
    }

    pub(crate) fn from_parts(
        outcome: ActionOutcome,
        source: ActionResultSource,
        observed_at: BootScopedInstant,
        evidence: ActionResultDigest,
    ) -> Result<Self, ActionResultError> {
        match source {
            ActionResultSource::DirectBackendReceipt => {
                Self::direct(outcome, observed_at, evidence)
            }
            ActionResultSource::ExecutionUncertainty if outcome == ActionOutcome::InDoubt => {
                Ok(Self::uncertain(observed_at, evidence))
            }
            ActionResultSource::ExecutionUncertainty => {
                Err(ActionResultError::UncertaintyMustBeInDoubt)
            }
            ActionResultSource::ReconciledEffectTruth => {
                Self::reconciled(outcome, observed_at, evidence)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionResultError {
    DirectReceiptMustBeTerminal,
    UncertaintyMustBeInDoubt,
    ReconciledTruthMustBeTerminal,
}

impl fmt::Display for ActionResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectReceiptMustBeTerminal => {
                formatter.write_str("a direct backend receipt must have a terminal outcome")
            }
            Self::UncertaintyMustBeInDoubt => {
                formatter.write_str("execution uncertainty must have an in-doubt outcome")
            }
            Self::ReconciledTruthMustBeTerminal => {
                formatter.write_str("reconciled effect truth must have a terminal outcome")
            }
        }
    }
}

impl std::error::Error for ActionResultError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActionModelDecodeError {
    DecisionPoint(u8),
    ActionKind(u8),
    FailureProfile(u8),
    Outcome(u8),
    ResultSource(u8),
}

fn action_digest(
    action: StateChangingActionParts,
) -> Result<ActionIntentDigest, StateChangingActionError> {
    let mut hasher = Hasher::new();
    hasher.update(b"probe.action.intent\0");
    hasher.update(action.request.as_bytes());
    hasher.update(action.audit.as_bytes());
    hasher.update(action.backend.as_bytes());
    hasher.update(action.authorization.as_bytes());
    hasher.update(action.authorization_digest.as_bytes());
    hash_interval(&mut hasher, action.authorization_validity);
    hasher.update(action.policy_revision.as_bytes());
    hasher.update(action.policy_digest.as_bytes());
    hasher.update(action.capability_snapshot.as_bytes());
    hasher.update(action.boot.as_bytes());
    hasher.update(&action.decided_at.as_nanos().to_be_bytes());
    hasher.update(&action.execute_before.as_nanos().to_be_bytes());
    hasher.update(&[
        action.decision_point.tag(),
        action.requested.tag(),
        action.effective.tag(),
        action.failure.tag(),
    ]);
    hasher.update(action.parameters.as_bytes());
    hasher.update(action.effect.as_bytes());
    hash_scope(&mut hasher, action.scope);
    ActionIntentDigest::new(*hasher.finalize().as_bytes())
        .map_err(|_| StateChangingActionError::DigestConstructionFailed)
}

fn hash_scope(hasher: &mut Hasher, scope: ActionScopeProof) {
    hasher.update(&[scope.tag()]);
    hasher.update(scope.proof().as_bytes());
    match scope {
        ActionScopeProof::KernelSocket {
            socket,
            network_namespace,
            workload,
            ..
        } => {
            hasher.update(socket.as_bytes());
            hasher.update(network_namespace.as_bytes());
            hasher.update(workload.as_bytes());
        }
        ActionScopeProof::CgroupHook {
            cgroup, attachment, ..
        } => {
            hasher.update(cgroup.as_bytes());
            hasher.update(attachment.as_bytes());
        }
        ActionScopeProof::InterceptedFlow {
            conversation,
            authorization,
            effective_revision,
            ..
        } => {
            hasher.update(conversation.as_bytes());
            hasher.update(authorization.as_bytes());
            hasher.update(effective_revision.as_bytes());
        }
    }
    hash_interval(hasher, scope.valid_during());
}

fn hash_interval(hasher: &mut Hasher, interval: TimeInterval) {
    hasher.update(&interval.start().as_nanos().to_be_bytes());
    hasher.update(&interval.end().as_nanos().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_source_preserves_causality() {
        let evidence = ActionResultDigest::new([1; 32]).expect("result evidence");
        let observed = |nanos| {
            BootScopedInstant::new(
                BootId::new([2; 16]).expect("boot id"),
                MonotonicInstant::from_nanos(nanos),
            )
        };
        let direct = ActionResult::direct(ActionOutcome::Applied, observed(10), evidence)
            .expect("direct result");
        let reconciled = ActionResult::reconciled(ActionOutcome::Applied, observed(11), evidence)
            .expect("reconciled result");

        assert_eq!(direct.causality(), ActionCausality::Known);
        assert_eq!(reconciled.causality(), ActionCausality::Unknown);
        assert_eq!(
            ActionResult::direct(ActionOutcome::InDoubt, observed(12), evidence,),
            Err(ActionResultError::DirectReceiptMustBeTerminal)
        );
    }
}

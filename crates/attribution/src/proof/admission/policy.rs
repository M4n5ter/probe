use probe_core::{
    CaptureSelectorDigest, MonotonicInstant, ObservationIntentId, Revision, TimeInterval,
};

use super::super::{AttributionClaim, AttributionConfidence};
use super::{
    AuthorizationStatus, CaptureGrant, HostAuthorizationContext,
    HostAuthorizationVerificationError, HostCaptureVerifier, SelectionAttestation,
    SelectionVerifier, TargetSelection,
};

pub struct AdmissionPolicyParts {
    pub observation_intent: ObservationIntentId,
    pub selector: CaptureSelectorDigest,
    pub active_selection_revision: Revision,
    pub requested_grant: CaptureGrant,
    pub decision_time: MonotonicInstant,
    pub allow_inferred: bool,
    pub selection_verifier: SelectionVerifier,
    pub host_verifier: HostCaptureVerifier,
    pub active_host_state_revision: Option<Revision>,
    pub host_authorization: Option<HostAuthorizationContext>,
}

pub struct AdmissionPolicy {
    observation_intent: ObservationIntentId,
    selector: CaptureSelectorDigest,
    active_selection_revision: Revision,
    requested_grant: CaptureGrant,
    decision_time: MonotonicInstant,
    allow_inferred: bool,
    selection_verifier: SelectionVerifier,
    host_verifier: HostCaptureVerifier,
    active_host_state_revision: Option<Revision>,
    host_authorization: Option<HostAuthorizationContext>,
}

impl AdmissionPolicy {
    pub const fn new(parts: AdmissionPolicyParts) -> Self {
        Self {
            observation_intent: parts.observation_intent,
            selector: parts.selector,
            active_selection_revision: parts.active_selection_revision,
            requested_grant: parts.requested_grant,
            decision_time: parts.decision_time,
            allow_inferred: parts.allow_inferred,
            selection_verifier: parts.selection_verifier,
            host_verifier: parts.host_verifier,
            active_host_state_revision: parts.active_host_state_revision,
            host_authorization: parts.host_authorization,
        }
    }

    pub fn decide(&self, claim: AttributionClaim, selection: TargetSelection) -> AdmissionDecision {
        let confidence = claim.confidence();
        let binding_is_valid = match confidence {
            AttributionConfidence::Proven
            | AttributionConfidence::CorrelatedUnique
            | AttributionConfidence::Inferred => claim.binding().is_some(),
            AttributionConfidence::Unknown => claim.binding().is_none(),
        };
        if !binding_is_valid {
            return reject(claim, selection, AdmissionRejection::InvalidClaim);
        }
        if confidence == AttributionConfidence::Inferred && !self.allow_inferred {
            return reject(claim, selection, AdmissionRejection::InferredDisabled);
        }
        if confidence == AttributionConfidence::Unknown {
            return self.host_decision(
                claim,
                selection,
                AdmissionRejection::HostAuthorizationRequired,
            );
        }

        match selection {
            TargetSelection::Selected(attestation) => {
                let attestation = *attestation;
                self.selected_decision(
                    claim,
                    TargetSelection::Selected(Box::new(attestation)),
                    attestation,
                )
            }
            selection @ TargetSelection::NotSelected { revision } => {
                if revision != self.active_selection_revision {
                    return self.reject_selection_revision(claim, selection, revision);
                }
                self.host_decision(claim, selection, AdmissionRejection::UnselectedTarget)
            }
            selection @ TargetSelection::Unknown { revision } => {
                if revision != self.active_selection_revision {
                    return self.reject_selection_revision(claim, selection, revision);
                }
                self.host_decision(claim, selection, AdmissionRejection::SelectorUnknown)
            }
        }
    }

    fn selected_decision(
        &self,
        claim: AttributionClaim,
        selection: TargetSelection,
        attestation: SelectionAttestation,
    ) -> AdmissionDecision {
        if self.selection_verifier.verify(attestation).is_err() {
            return reject(
                claim,
                selection,
                AdmissionRejection::SelectionProofUntrusted,
            );
        }
        if attestation.observation_intent() != self.observation_intent {
            return reject(
                claim,
                selection,
                AdmissionRejection::SelectionIntentMismatch,
            );
        }
        if attestation.selector() != self.selector {
            return reject(
                claim,
                selection,
                AdmissionRejection::SelectionSelectorMismatch,
            );
        }
        if attestation.revision() != self.active_selection_revision {
            return self.reject_selection_revision(claim, selection, attestation.revision());
        }
        if attestation.grant() != self.requested_grant {
            return reject(claim, selection, AdmissionRejection::SelectionGrantMismatch);
        }
        let Some(claim_binding) = claim.binding() else {
            return reject(claim, selection, AdmissionRejection::InvalidClaim);
        };
        if attestation.binding() != claim_binding {
            return reject(
                claim,
                selection,
                AdmissionRejection::SelectionBindingMismatch,
            );
        }
        if attestation.scope() != claim.proof_basis().scope() {
            return reject(claim, selection, AdmissionRejection::SelectionScopeMismatch);
        }
        let decision = TimeInterval::point(self.decision_time);
        if !attestation.valid_during().contains(claim.valid_during())
            || !attestation.valid_during().contains(decision)
        {
            return reject(claim, selection, AdmissionRejection::SelectionExpired);
        }
        AdmissionDecision::AdmitTarget {
            claim,
            selection: Box::new(attestation),
            grant: self.requested_grant,
        }
    }

    fn reject_selection_revision(
        &self,
        claim: AttributionClaim,
        selection: TargetSelection,
        actual: Revision,
    ) -> AdmissionDecision {
        reject(
            claim,
            selection,
            AdmissionRejection::SelectionRevisionMismatch {
                expected: self.active_selection_revision,
                actual,
            },
        )
    }

    fn host_decision(
        &self,
        claim: AttributionClaim,
        selection: TargetSelection,
        missing_reason: AdmissionRejection,
    ) -> AdmissionDecision {
        let Some(context) = self.host_authorization else {
            return reject(claim, selection, missing_reason);
        };
        if let Err(error) = self.host_verifier.verify(context) {
            let reason = match error {
                HostAuthorizationVerificationError::StateMismatch => {
                    AdmissionRejection::HostAuthorizationStateMismatch
                }
                HostAuthorizationVerificationError::UntrustedIssuer
                | HostAuthorizationVerificationError::AuthenticationFailed => {
                    AdmissionRejection::HostAuthorizationUntrusted
                }
            };
            return reject(claim, selection, reason);
        }
        let authorization = context.authorization();
        let liveness = context.liveness();
        if Some(liveness.state_revision()) != self.active_host_state_revision {
            return reject(
                claim,
                selection,
                AdmissionRejection::HostAuthorizationStateMismatch,
            );
        }
        if liveness.status() == AuthorizationStatus::Revoked {
            return reject(
                claim,
                selection,
                AdmissionRejection::HostAuthorizationRevoked,
            );
        }
        let decision = TimeInterval::point(self.decision_time);
        if !liveness.fresh_during().contains(decision) {
            return reject(
                claim,
                selection,
                AdmissionRejection::HostAuthorizationStateStale,
            );
        }
        if !authorization.valid_during().contains(claim.valid_during())
            || !authorization.valid_during().contains(decision)
        {
            return reject(
                claim,
                selection,
                AdmissionRejection::HostAuthorizationExpired,
            );
        }
        if authorization.observation_intent() != self.observation_intent {
            return reject(claim, selection, AdmissionRejection::HostIntentMismatch);
        }
        if authorization.attribution_scope() != claim.proof_basis().scope() {
            return reject(claim, selection, AdmissionRejection::HostScopeMismatch);
        }
        if !authorization.subject_scope().matches(claim.principal()) {
            return reject(claim, selection, AdmissionRejection::HostSubjectMismatch);
        }
        if !authorization
            .grant()
            .allows(claim.confidence(), self.requested_grant)
        {
            return reject(claim, selection, AdmissionRejection::HostGrantDenied);
        }
        AdmissionDecision::AdmitHost {
            claim,
            selection,
            authorization: Box::new(context),
            grant: self.requested_grant,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRejection {
    InvalidClaim,
    UnselectedTarget,
    SelectorUnknown,
    InferredDisabled,
    HostAuthorizationRequired,
    SelectionProofUntrusted,
    SelectionIntentMismatch,
    SelectionSelectorMismatch,
    SelectionGrantMismatch,
    SelectionRevisionMismatch {
        expected: Revision,
        actual: Revision,
    },
    SelectionBindingMismatch,
    SelectionScopeMismatch,
    SelectionExpired,
    HostAuthorizationUntrusted,
    HostAuthorizationStateMismatch,
    HostAuthorizationRevoked,
    HostAuthorizationStateStale,
    HostAuthorizationExpired,
    HostIntentMismatch,
    HostScopeMismatch,
    HostSubjectMismatch,
    HostGrantDenied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    AdmitTarget {
        claim: AttributionClaim,
        selection: Box<SelectionAttestation>,
        grant: CaptureGrant,
    },
    AdmitHost {
        claim: AttributionClaim,
        selection: TargetSelection,
        authorization: Box<HostAuthorizationContext>,
        grant: CaptureGrant,
    },
    Reject {
        claim: AttributionClaim,
        selection: TargetSelection,
        reason: AdmissionRejection,
    },
}

impl AdmissionDecision {
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::AdmitTarget { .. } | Self::AdmitHost { .. })
    }

    pub const fn claim(&self) -> &AttributionClaim {
        match self {
            Self::AdmitTarget { claim, .. }
            | Self::AdmitHost { claim, .. }
            | Self::Reject { claim, .. } => claim,
        }
    }

    pub const fn grant(&self) -> Option<CaptureGrant> {
        match self {
            Self::AdmitTarget { grant, .. } | Self::AdmitHost { grant, .. } => Some(*grant),
            Self::Reject { .. } => None,
        }
    }
}

fn reject(
    claim: AttributionClaim,
    selection: TargetSelection,
    reason: AdmissionRejection,
) -> AdmissionDecision {
    AdmissionDecision::Reject {
        claim,
        selection,
        reason,
    }
}

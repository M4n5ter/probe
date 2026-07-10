use std::fmt;

use blake3::Hasher;
use probe_core::{
    CaptureSelectorDigest, ObservationIntentId, Revision, SelectionProofId, TimeInterval,
};

use super::super::authentication::{
    AuthorityKeyError, authenticators_match, keyed_authenticator, validate_authority_key,
};
use super::super::{AttributionScope, TargetBinding};
use super::CaptureGrant;
use super::encoding::{hash_binding, hash_capture_grant, hash_interval, hash_scope};

const SELECTION_DIGEST_DOMAIN: &[u8] = b"probe.attribution.selection-attestation\0";
const SELECTION_AUTHENTICATOR_DOMAIN: &[u8] =
    b"probe.attribution.selection-attestation-authenticator\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionAttestation {
    observation_intent: ObservationIntentId,
    selector: CaptureSelectorDigest,
    binding: TargetBinding,
    scope: AttributionScope,
    proof: SelectionProofId,
    revision: Revision,
    grant: CaptureGrant,
    valid_during: TimeInterval,
    authenticator: [u8; 32],
}

pub struct SelectionAttestationParts {
    pub observation_intent: ObservationIntentId,
    pub selector: CaptureSelectorDigest,
    pub binding: TargetBinding,
    pub scope: AttributionScope,
    pub proof: SelectionProofId,
    pub revision: Revision,
    pub grant: CaptureGrant,
    pub valid_during: TimeInterval,
}

impl SelectionAttestation {
    pub const fn observation_intent(self) -> ObservationIntentId {
        self.observation_intent
    }

    pub const fn selector(self) -> CaptureSelectorDigest {
        self.selector
    }

    pub const fn binding(self) -> TargetBinding {
        self.binding
    }

    pub const fn scope(self) -> AttributionScope {
        self.scope
    }

    pub const fn proof(self) -> SelectionProofId {
        self.proof
    }

    pub const fn revision(self) -> Revision {
        self.revision
    }

    pub const fn grant(self) -> CaptureGrant {
        self.grant
    }

    pub const fn valid_during(self) -> TimeInterval {
        self.valid_during
    }
}

pub struct SelectionAuthority {
    key: [u8; 32],
}

impl fmt::Debug for SelectionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectionAuthority([REDACTED])")
    }
}

impl SelectionAuthority {
    pub fn new(key: [u8; 32]) -> Result<Self, AuthorityKeyError> {
        validate_authority_key(key).map(|key| Self { key })
    }

    pub fn verifier(&self) -> SelectionVerifier {
        SelectionVerifier { key: self.key }
    }

    pub fn attest(&self, parts: SelectionAttestationParts) -> SelectionAttestation {
        let mut attestation = SelectionAttestation {
            observation_intent: parts.observation_intent,
            selector: parts.selector,
            binding: parts.binding,
            scope: parts.scope,
            proof: parts.proof,
            revision: parts.revision,
            grant: parts.grant,
            valid_during: parts.valid_during,
            authenticator: [0; 32],
        };
        attestation.authenticator = keyed_authenticator(
            &self.key,
            SELECTION_AUTHENTICATOR_DOMAIN,
            &selection_digest(attestation),
        );
        attestation
    }
}

#[derive(Clone)]
pub struct SelectionVerifier {
    key: [u8; 32],
}

impl fmt::Debug for SelectionVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectionVerifier([REDACTED])")
    }
}

impl SelectionVerifier {
    pub fn verify(
        &self,
        attestation: SelectionAttestation,
    ) -> Result<(), SelectionVerificationError> {
        let expected = keyed_authenticator(
            &self.key,
            SELECTION_AUTHENTICATOR_DOMAIN,
            &selection_digest(attestation),
        );
        if authenticators_match(expected, attestation.authenticator) {
            Ok(())
        } else {
            Err(SelectionVerificationError)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionVerificationError;

impl fmt::Display for SelectionVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("selection attestation authentication failed")
    }
}

impl std::error::Error for SelectionVerificationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetSelection {
    Selected(Box<SelectionAttestation>),
    NotSelected { revision: Revision },
    Unknown { revision: Revision },
}

impl TargetSelection {
    pub const fn revision(&self) -> Revision {
        match self {
            Self::Selected(attestation) => attestation.revision(),
            Self::NotSelected { revision } | Self::Unknown { revision } => *revision,
        }
    }
}

fn selection_digest(attestation: SelectionAttestation) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(SELECTION_DIGEST_DOMAIN);
    hasher.update(attestation.observation_intent.as_bytes());
    hasher.update(attestation.selector.as_bytes());
    hash_binding(&mut hasher, attestation.binding);
    hash_scope(&mut hasher, attestation.scope);
    hasher.update(attestation.proof.as_bytes());
    hasher.update(&attestation.revision.get().to_be_bytes());
    hash_capture_grant(&mut hasher, attestation.grant);
    hash_interval(&mut hasher, attestation.valid_during);
    *hasher.finalize().as_bytes()
}

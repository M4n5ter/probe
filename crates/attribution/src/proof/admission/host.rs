use std::fmt;

use blake3::Hasher;
use probe_core::{
    AuthorizationAuditId, AuthorizationId, AuthorizationIssuerId, AuthorizationNonce, CgroupId,
    HostAuthorizationDigest, ObservationIntentId, Revision, TimeInterval,
};

use super::super::authentication::{
    AuthorityKeyError, authenticators_match, keyed_authenticator, validate_authority_key,
};
use super::super::{AttributionScope, CapturePrincipal};
use super::HostCaptureGrant;
use super::encoding::{hash_capture_grant, hash_interval, hash_scope};

const AUTHORIZATION_DIGEST_DOMAIN: &[u8] = b"probe.attribution.host-authorization\0";
const AUTHORIZATION_AUTHENTICATOR_DOMAIN: &[u8] =
    b"probe.attribution.host-authorization-authenticator\0";
const LIVENESS_DIGEST_DOMAIN: &[u8] = b"probe.attribution.host-authorization-state\0";
const LIVENESS_AUTHENTICATOR_DOMAIN: &[u8] =
    b"probe.attribution.host-authorization-state-authenticator\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureSubjectScope {
    Host,
    User(u32),
    Cgroup(CgroupId),
}

impl CaptureSubjectScope {
    pub(super) fn matches(self, principal: CapturePrincipal) -> bool {
        match self {
            Self::Host => true,
            Self::User(uid) => uid == principal.uid(),
            Self::Cgroup(cgroup) => principal.cgroup() == Some(cgroup),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCaptureAuthorization {
    claims: HostCaptureAuthorizationClaims,
    digest: HostAuthorizationDigest,
    authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostCaptureAuthorizationClaims {
    authorization: AuthorizationId,
    issuer: AuthorizationIssuerId,
    observation_intent: ObservationIntentId,
    nonce: AuthorizationNonce,
    audit: AuthorizationAuditId,
    subject_scope: CaptureSubjectScope,
    attribution_scope: AttributionScope,
    grant: HostCaptureGrant,
    revision: Revision,
    valid_during: TimeInterval,
}

pub struct HostCaptureAuthorizationParts {
    pub authorization: AuthorizationId,
    pub issuer: AuthorizationIssuerId,
    pub observation_intent: ObservationIntentId,
    pub nonce: AuthorizationNonce,
    pub audit: AuthorizationAuditId,
    pub subject_scope: CaptureSubjectScope,
    pub attribution_scope: AttributionScope,
    pub grant: HostCaptureGrant,
    pub revision: Revision,
    pub valid_during: TimeInterval,
}

impl HostCaptureAuthorization {
    pub const fn authorization(self) -> AuthorizationId {
        self.claims.authorization
    }

    pub const fn issuer(self) -> AuthorizationIssuerId {
        self.claims.issuer
    }

    pub const fn observation_intent(self) -> ObservationIntentId {
        self.claims.observation_intent
    }

    pub const fn nonce(self) -> AuthorizationNonce {
        self.claims.nonce
    }

    pub const fn audit(self) -> AuthorizationAuditId {
        self.claims.audit
    }

    pub const fn subject_scope(self) -> CaptureSubjectScope {
        self.claims.subject_scope
    }

    pub const fn attribution_scope(self) -> AttributionScope {
        self.claims.attribution_scope
    }

    pub const fn grant(self) -> HostCaptureGrant {
        self.claims.grant
    }

    pub const fn revision(self) -> Revision {
        self.claims.revision
    }

    pub const fn valid_during(self) -> TimeInterval {
        self.claims.valid_during
    }

    pub const fn digest(self) -> HostAuthorizationDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationLiveness {
    authorization: AuthorizationId,
    issuer: AuthorizationIssuerId,
    authorization_digest: HostAuthorizationDigest,
    authorization_revision: Revision,
    state_revision: Revision,
    status: AuthorizationStatus,
    fresh_during: TimeInterval,
    authenticator: [u8; 32],
}

impl AuthorizationLiveness {
    pub const fn authorization(self) -> AuthorizationId {
        self.authorization
    }

    pub const fn issuer(self) -> AuthorizationIssuerId {
        self.issuer
    }

    pub const fn authorization_digest(self) -> HostAuthorizationDigest {
        self.authorization_digest
    }

    pub const fn authorization_revision(self) -> Revision {
        self.authorization_revision
    }

    pub const fn state_revision(self) -> Revision {
        self.state_revision
    }

    pub const fn status(self) -> AuthorizationStatus {
        self.status
    }

    pub const fn fresh_during(self) -> TimeInterval {
        self.fresh_during
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostAuthorizationContext {
    authorization: HostCaptureAuthorization,
    liveness: AuthorizationLiveness,
}

impl HostAuthorizationContext {
    pub const fn new(
        authorization: HostCaptureAuthorization,
        liveness: AuthorizationLiveness,
    ) -> Self {
        Self {
            authorization,
            liveness,
        }
    }

    pub const fn authorization(self) -> HostCaptureAuthorization {
        self.authorization
    }

    pub const fn liveness(self) -> AuthorizationLiveness {
        self.liveness
    }
}

pub struct HostCaptureAuthority {
    issuer: AuthorizationIssuerId,
    key: [u8; 32],
}

impl fmt::Debug for HostCaptureAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostCaptureAuthority([REDACTED])")
    }
}

impl HostCaptureAuthority {
    pub fn new(issuer: AuthorizationIssuerId, key: [u8; 32]) -> Result<Self, AuthorityKeyError> {
        validate_authority_key(key).map(|key| Self { issuer, key })
    }

    pub fn verifier(&self) -> HostCaptureVerifier {
        HostCaptureVerifier {
            trusted_issuer: self.issuer,
            key: self.key,
        }
    }

    pub const fn issuer(&self) -> AuthorizationIssuerId {
        self.issuer
    }

    pub fn authorize(
        &self,
        parts: HostCaptureAuthorizationParts,
    ) -> Result<HostCaptureAuthorization, HostAuthorizationIssueError> {
        if parts.issuer != self.issuer {
            return Err(HostAuthorizationIssueError::IssuerMismatch);
        }
        let claims = HostCaptureAuthorizationClaims {
            authorization: parts.authorization,
            issuer: parts.issuer,
            observation_intent: parts.observation_intent,
            nonce: parts.nonce,
            audit: parts.audit,
            subject_scope: parts.subject_scope,
            attribution_scope: parts.attribution_scope,
            grant: parts.grant,
            revision: parts.revision,
            valid_during: parts.valid_during,
        };
        let digest = authorization_digest(claims)?;
        let authenticator = keyed_authenticator(
            &self.key,
            AUTHORIZATION_AUTHENTICATOR_DOMAIN,
            digest.as_bytes(),
        );
        Ok(HostCaptureAuthorization {
            claims,
            digest,
            authenticator,
        })
    }

    pub fn issue_liveness(
        &self,
        authorization: HostCaptureAuthorization,
        state_revision: Revision,
        status: AuthorizationStatus,
        fresh_during: TimeInterval,
    ) -> Result<AuthorizationLiveness, HostAuthorizationIssueError> {
        self.verifier()
            .verify_authorization(authorization)
            .map_err(|_| HostAuthorizationIssueError::ForeignAuthorization)?;
        let mut liveness = AuthorizationLiveness {
            authorization: authorization.authorization(),
            issuer: authorization.issuer(),
            authorization_digest: authorization.digest,
            authorization_revision: authorization.revision(),
            state_revision,
            status,
            fresh_during,
            authenticator: [0; 32],
        };
        liveness.authenticator = keyed_authenticator(
            &self.key,
            LIVENESS_AUTHENTICATOR_DOMAIN,
            &liveness_digest(liveness),
        );
        Ok(liveness)
    }
}

#[derive(Clone)]
pub struct HostCaptureVerifier {
    trusted_issuer: AuthorizationIssuerId,
    key: [u8; 32],
}

impl fmt::Debug for HostCaptureVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostCaptureVerifier([REDACTED])")
    }
}

impl HostCaptureVerifier {
    pub fn verify(
        &self,
        context: HostAuthorizationContext,
    ) -> Result<(), HostAuthorizationVerificationError> {
        self.verify_authorization(context.authorization)?;
        self.verify_liveness(context.liveness)?;
        if context.authorization.authorization() != context.liveness.authorization
            || context.authorization.issuer() != context.liveness.issuer
            || context.authorization.digest != context.liveness.authorization_digest
            || context.authorization.revision() != context.liveness.authorization_revision
        {
            return Err(HostAuthorizationVerificationError::StateMismatch);
        }
        Ok(())
    }

    fn verify_authorization(
        &self,
        authorization: HostCaptureAuthorization,
    ) -> Result<(), HostAuthorizationVerificationError> {
        if authorization.issuer() != self.trusted_issuer {
            return Err(HostAuthorizationVerificationError::UntrustedIssuer);
        }
        let digest = authorization_digest(authorization.claims)
            .map_err(|_| HostAuthorizationVerificationError::AuthenticationFailed)?;
        let expected = keyed_authenticator(
            &self.key,
            AUTHORIZATION_AUTHENTICATOR_DOMAIN,
            digest.as_bytes(),
        );
        if digest != authorization.digest
            || !authenticators_match(expected, authorization.authenticator)
        {
            return Err(HostAuthorizationVerificationError::AuthenticationFailed);
        }
        Ok(())
    }

    fn verify_liveness(
        &self,
        liveness: AuthorizationLiveness,
    ) -> Result<(), HostAuthorizationVerificationError> {
        if liveness.issuer != self.trusted_issuer {
            return Err(HostAuthorizationVerificationError::UntrustedIssuer);
        }
        let expected = keyed_authenticator(
            &self.key,
            LIVENESS_AUTHENTICATOR_DOMAIN,
            &liveness_digest(liveness),
        );
        if !authenticators_match(expected, liveness.authenticator) {
            return Err(HostAuthorizationVerificationError::AuthenticationFailed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAuthorizationIssueError {
    IssuerMismatch,
    ForeignAuthorization,
    DigestConstructionFailed,
}

impl fmt::Display for HostAuthorizationIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IssuerMismatch => {
                formatter.write_str("authorization issuer differs from authority issuer")
            }
            Self::ForeignAuthorization => {
                formatter.write_str("cannot issue state for a foreign authorization")
            }
            Self::DigestConstructionFailed => {
                formatter.write_str("host authorization digest construction failed")
            }
        }
    }
}

impl std::error::Error for HostAuthorizationIssueError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAuthorizationVerificationError {
    UntrustedIssuer,
    AuthenticationFailed,
    StateMismatch,
}

impl fmt::Display for HostAuthorizationVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UntrustedIssuer => formatter.write_str("host authorization issuer is untrusted"),
            Self::AuthenticationFailed => {
                formatter.write_str("host authorization authentication failed")
            }
            Self::StateMismatch => {
                formatter.write_str("host authorization and state refer to different grants")
            }
        }
    }
}

impl std::error::Error for HostAuthorizationVerificationError {}

fn authorization_digest(
    authorization: HostCaptureAuthorizationClaims,
) -> Result<HostAuthorizationDigest, HostAuthorizationIssueError> {
    let mut hasher = Hasher::new();
    hasher.update(AUTHORIZATION_DIGEST_DOMAIN);
    hasher.update(authorization.authorization.as_bytes());
    hasher.update(authorization.issuer.as_bytes());
    hasher.update(authorization.observation_intent.as_bytes());
    hasher.update(authorization.nonce.as_bytes());
    hasher.update(authorization.audit.as_bytes());
    hash_subject_scope(&mut hasher, authorization.subject_scope);
    hash_scope(&mut hasher, authorization.attribution_scope);
    hasher.update(&[authorization.grant.confidences().bits()]);
    hash_capture_grant(&mut hasher, authorization.grant.maximum_capture());
    hasher.update(&authorization.revision.get().to_be_bytes());
    hash_interval(&mut hasher, authorization.valid_during);
    HostAuthorizationDigest::new(*hasher.finalize().as_bytes())
        .map_err(|_| HostAuthorizationIssueError::DigestConstructionFailed)
}

fn liveness_digest(liveness: AuthorizationLiveness) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(LIVENESS_DIGEST_DOMAIN);
    hasher.update(liveness.authorization.as_bytes());
    hasher.update(liveness.issuer.as_bytes());
    hasher.update(liveness.authorization_digest.as_bytes());
    hasher.update(&liveness.authorization_revision.get().to_be_bytes());
    hasher.update(&liveness.state_revision.get().to_be_bytes());
    let status = match liveness.status {
        AuthorizationStatus::Active => 0,
        AuthorizationStatus::Revoked => 1,
    };
    hasher.update(&[status]);
    hash_interval(&mut hasher, liveness.fresh_during);
    *hasher.finalize().as_bytes()
}

fn hash_subject_scope(hasher: &mut Hasher, scope: CaptureSubjectScope) {
    match scope {
        CaptureSubjectScope::Host => {
            hasher.update(&[0]);
        }
        CaptureSubjectScope::User(uid) => {
            hasher.update(&[1]);
            hasher.update(&uid.to_be_bytes());
        }
        CaptureSubjectScope::Cgroup(cgroup) => {
            hasher.update(&[2]);
            hasher.update(cgroup.as_bytes());
        }
    }
}

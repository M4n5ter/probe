use std::fmt;

use blake3::Hasher;
use probe_core::{
    ActionAuditId, ActionAuthorizationDigest, ActionAuthorizationId, ActionBackendId,
    ActionEffectDigest, ActionId, ActionIntentDigest, ActionJournalId, ActionParametersDigest,
    ActionRequestId, ActionResultDigest, ActionScopeProofId, BootId, BootScopedInstant, BpfLinkId,
    CanonicalIdError, CapabilitySnapshotDigest, CgroupId, EffectiveStateRevisionId,
    InterceptionAuthorizationId, InterceptionConversationId, MonotonicInstant, NetworkNamespaceId,
    PolicyDigest, PolicyRevisionId, PreparedActionId, SocketId, TimeInterval, TimeIntervalError,
    WorkloadId,
};

use crate::model::{
    ActionDecisionPoint, ActionFailureProfile, ActionKind, ActionModelDecodeError, ActionOutcome,
    ActionResult, ActionResultError, ActionResultSource, ActionScopeProof, StateChangingAction,
    StateChangingActionError, StateChangingActionParts,
};

pub(crate) const HEADER_LEN: usize = 4096;
pub(crate) const SLOT_LEN: usize = 1024;

const AUTHENTICATOR_LEN: usize = 32;
const HEADER_MAGIC: &[u8; 16] = b"PROBE_ACTION_JNL";
const SLOT_MAGIC: &[u8; 16] = b"PROBE_ACTION_SLT";
const FORMAT_CONTRACT: &[u8] = b"probe.action-journal\n\
header=magic,fingerprint,journal-id,capacity,header-len,slot-len,padding,mac\n\
slot=magic,fingerprint,kind,payload-len,sequence,previous-digest,payload,padding,mac\n\
slot-mac-binding=journal-id\n\
prepare=action-id,prepared-id,state-changing-action\n\
outcome=action-id,prepared-id,request-id,intent-digest,result\n\
result=outcome,source,observed-boot-id,observed-monotonic-ns,evidence\n\
integers=big-endian;identifiers=canonical-nonzero;unused-bytes=zero";
const HEADER_AUTHENTICATOR_OFFSET: usize = HEADER_LEN - AUTHENTICATOR_LEN;
const SLOT_AUTHENTICATOR_OFFSET: usize = SLOT_LEN - AUTHENTICATOR_LEN;
const SLOT_KIND_OFFSET: usize = 48;
const SLOT_PAYLOAD_LENGTH_OFFSET: usize = 52;
const SLOT_SEQUENCE_OFFSET: usize = 56;
const SLOT_PREVIOUS_DIGEST_OFFSET: usize = 64;
const SLOT_PAYLOAD_OFFSET: usize = 96;
const MAX_PAYLOAD_LEN: usize = SLOT_AUTHENTICATOR_OFFSET - SLOT_PAYLOAD_OFFSET;
const HEADER_AUTHENTICATION_DOMAIN: &[u8] = b"probe.action-journal.header-authentication\0";
const SLOT_AUTHENTICATION_DOMAIN: &[u8] = b"probe.action-journal.slot-authentication\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalHeader {
    journal: ActionJournalId,
    capacity: u64,
}

impl JournalHeader {
    pub(crate) const fn new(journal: ActionJournalId, capacity: u64) -> Self {
        Self { journal, capacity }
    }

    pub(crate) const fn journal(self) -> ActionJournalId {
        self.journal
    }

    pub(crate) const fn capacity(self) -> u64 {
        self.capacity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalPayload {
    Prepare {
        action_id: ActionId,
        prepared_id: PreparedActionId,
        action: Box<StateChangingAction>,
    },
    Outcome {
        action_id: ActionId,
        prepared_id: PreparedActionId,
        request: ActionRequestId,
        intent: ActionIntentDigest,
        result: ActionResult,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedSlot {
    payload: JournalPayload,
    digest: [u8; 32],
}

impl DecodedSlot {
    pub(crate) const fn payload(&self) -> &JournalPayload {
        &self.payload
    }

    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub(crate) fn encode_header(journal_header: &JournalHeader, key: &[u8; 32]) -> [u8; HEADER_LEN] {
    let mut header = [0_u8; HEADER_LEN];
    header[..16].copy_from_slice(HEADER_MAGIC);
    header[16..48].copy_from_slice(&format_fingerprint());
    header[48..64].copy_from_slice(journal_header.journal.as_bytes());
    header[64..72].copy_from_slice(&journal_header.capacity.to_be_bytes());
    header[72..76].copy_from_slice(&(HEADER_LEN as u32).to_be_bytes());
    header[76..80].copy_from_slice(&(SLOT_LEN as u32).to_be_bytes());

    let authenticator = keyed_authenticator(
        key,
        HEADER_AUTHENTICATION_DOMAIN,
        &header[..HEADER_AUTHENTICATOR_OFFSET],
    );
    header[HEADER_AUTHENTICATOR_OFFSET..].copy_from_slice(&authenticator);
    header
}

pub(crate) fn decode_header(
    header: &[u8; HEADER_LEN],
    key: &[u8; 32],
) -> Result<JournalHeader, JournalFormatError> {
    let expected_authenticator = keyed_authenticator(
        key,
        HEADER_AUTHENTICATION_DOMAIN,
        &header[..HEADER_AUTHENTICATOR_OFFSET],
    );
    if !constant_time_eq(
        &header[HEADER_AUTHENTICATOR_OFFSET..],
        &expected_authenticator,
    ) {
        return Err(JournalFormatError::AuthenticationFailed(
            AuthenticatedRegion::Header,
        ));
    }
    if &header[..16] != HEADER_MAGIC {
        return Err(JournalFormatError::InvalidMagic(
            AuthenticatedRegion::Header,
        ));
    }
    if header[16..48] != format_fingerprint() {
        return Err(JournalFormatError::FormatFingerprintMismatch(
            AuthenticatedRegion::Header,
        ));
    }

    let journal_id = ActionJournalId::new(copy_array(&header[48..64]))
        .map_err(|_| JournalFormatError::InvalidCanonicalValue)?;
    let file_capacity = u64::from_be_bytes(copy_array(&header[64..72]));
    let header_length = u32::from_be_bytes(copy_array(&header[72..76]));
    let slot_length = u32::from_be_bytes(copy_array(&header[76..80]));
    if header_length != HEADER_LEN as u32 {
        return Err(JournalFormatError::HeaderLengthMismatch {
            stored: header_length,
        });
    }
    if slot_length != SLOT_LEN as u32 {
        return Err(JournalFormatError::SlotLengthMismatch {
            stored: slot_length,
        });
    }
    if header[80..HEADER_AUTHENTICATOR_OFFSET]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(JournalFormatError::NonCanonicalPadding(
            AuthenticatedRegion::Header,
        ));
    }
    Ok(JournalHeader::new(journal_id, file_capacity))
}

pub(crate) fn encode_slot(
    journal: ActionJournalId,
    sequence: u64,
    previous: [u8; 32],
    payload: JournalPayload,
    key: &[u8; 32],
) -> Result<[u8; SLOT_LEN], JournalFormatError> {
    let mut slot = [0_u8; SLOT_LEN];
    slot[..16].copy_from_slice(SLOT_MAGIC);
    slot[16..48].copy_from_slice(&format_fingerprint());
    slot[SLOT_KIND_OFFSET] = RecordKind::for_payload(&payload).tag();
    slot[SLOT_SEQUENCE_OFFSET..SLOT_SEQUENCE_OFFSET + 8].copy_from_slice(&sequence.to_be_bytes());
    slot[SLOT_PREVIOUS_DIGEST_OFFSET..SLOT_PREVIOUS_DIGEST_OFFSET + 32].copy_from_slice(&previous);

    let payload_length = {
        let mut encoder = Encoder::new(&mut slot[SLOT_PAYLOAD_OFFSET..SLOT_AUTHENTICATOR_OFFSET]);
        encode_payload(&mut encoder, &payload)?;
        encoder.len()
    };
    let encoded_payload_length =
        u32::try_from(payload_length).map_err(|_| JournalFormatError::PayloadTooLarge {
            length: payload_length,
            maximum: MAX_PAYLOAD_LEN,
        })?;
    slot[SLOT_PAYLOAD_LENGTH_OFFSET..SLOT_PAYLOAD_LENGTH_OFFSET + 4]
        .copy_from_slice(&encoded_payload_length.to_be_bytes());

    let authenticator = keyed_journal_authenticator(
        key,
        SLOT_AUTHENTICATION_DOMAIN,
        journal,
        &slot[..SLOT_AUTHENTICATOR_OFFSET],
    );
    slot[SLOT_AUTHENTICATOR_OFFSET..].copy_from_slice(&authenticator);
    Ok(slot)
}

pub(crate) fn decode_slot(
    journal: ActionJournalId,
    expected_sequence: u64,
    expected_previous: [u8; 32],
    slot: &[u8; SLOT_LEN],
    key: &[u8; 32],
) -> Result<Option<DecodedSlot>, JournalFormatError> {
    if slot.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }

    let expected_authenticator = keyed_journal_authenticator(
        key,
        SLOT_AUTHENTICATION_DOMAIN,
        journal,
        &slot[..SLOT_AUTHENTICATOR_OFFSET],
    );
    if !constant_time_eq(&slot[SLOT_AUTHENTICATOR_OFFSET..], &expected_authenticator) {
        return Err(JournalFormatError::AuthenticationFailed(
            AuthenticatedRegion::Slot,
        ));
    }
    if &slot[..16] != SLOT_MAGIC {
        return Err(JournalFormatError::InvalidMagic(AuthenticatedRegion::Slot));
    }
    if slot[16..48] != format_fingerprint() {
        return Err(JournalFormatError::FormatFingerprintMismatch(
            AuthenticatedRegion::Slot,
        ));
    }
    if slot[49..52].iter().any(|byte| *byte != 0) {
        return Err(JournalFormatError::NonCanonicalPadding(
            AuthenticatedRegion::Slot,
        ));
    }

    let kind = RecordKind::from_tag(slot[SLOT_KIND_OFFSET])?;
    let payload_length = u32::from_be_bytes(copy_array(
        &slot[SLOT_PAYLOAD_LENGTH_OFFSET..SLOT_PAYLOAD_LENGTH_OFFSET + 4],
    ));
    let payload_length =
        usize::try_from(payload_length).map_err(|_| JournalFormatError::PayloadTooLarge {
            length: usize::MAX,
            maximum: MAX_PAYLOAD_LEN,
        })?;
    if payload_length > MAX_PAYLOAD_LEN {
        return Err(JournalFormatError::PayloadTooLarge {
            length: payload_length,
            maximum: MAX_PAYLOAD_LEN,
        });
    }

    let sequence = u64::from_be_bytes(copy_array(
        &slot[SLOT_SEQUENCE_OFFSET..SLOT_SEQUENCE_OFFSET + 8],
    ));
    if sequence != expected_sequence {
        return Err(JournalFormatError::SequenceMismatch {
            expected: expected_sequence,
            stored: sequence,
        });
    }
    let previous_digest =
        copy_array(&slot[SLOT_PREVIOUS_DIGEST_OFFSET..SLOT_PREVIOUS_DIGEST_OFFSET + 32]);
    if previous_digest != expected_previous {
        return Err(JournalFormatError::PreviousDigestMismatch);
    }

    let payload_end = SLOT_PAYLOAD_OFFSET + payload_length;
    if slot[payload_end..SLOT_AUTHENTICATOR_OFFSET]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(JournalFormatError::NonCanonicalPadding(
            AuthenticatedRegion::Slot,
        ));
    }
    let mut decoder = Decoder::new(&slot[SLOT_PAYLOAD_OFFSET..payload_end]);
    let payload = decode_payload(&mut decoder, kind)?;
    if !decoder.is_finished() {
        return Err(JournalFormatError::TrailingPayloadBytes {
            remaining: decoder.remaining(),
        });
    }

    Ok(Some(DecodedSlot {
        payload,
        digest: *blake3::hash(slot).as_bytes(),
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedRegion {
    Header,
    Slot,
}

impl fmt::Display for AuthenticatedRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header => formatter.write_str("journal header"),
            Self::Slot => formatter.write_str("journal slot"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalFormatError {
    AuthenticationFailed(AuthenticatedRegion),
    InvalidMagic(AuthenticatedRegion),
    FormatFingerprintMismatch(AuthenticatedRegion),
    HeaderLengthMismatch { stored: u32 },
    SlotLengthMismatch { stored: u32 },
    NonCanonicalPadding(AuthenticatedRegion),
    UnknownRecordKind(u8),
    PayloadTooLarge { length: usize, maximum: usize },
    PayloadTruncated { needed: usize, remaining: usize },
    TrailingPayloadBytes { remaining: usize },
    SequenceMismatch { expected: u64, stored: u64 },
    PreviousDigestMismatch,
    InvalidCanonicalValue,
    InvalidTimeInterval(TimeIntervalError),
    UnknownDecisionPoint(u8),
    UnknownActionKind(u8),
    UnknownFailureProfile(u8),
    UnknownScopeProof(u8),
    UnknownOutcome(u8),
    UnknownResultSource(u8),
    InvalidStateChangingAction(StateChangingActionError),
    StoredActionDigestMismatch,
    InvalidActionResult(ActionResultError),
}

impl fmt::Display for JournalFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed(region) => {
                write!(formatter, "{region} authentication failed")
            }
            Self::InvalidMagic(region) => write!(formatter, "{region} magic is invalid"),
            Self::FormatFingerprintMismatch(region) => {
                write!(formatter, "{region} format fingerprint does not match")
            }
            Self::HeaderLengthMismatch { stored } => write!(
                formatter,
                "journal header stores length {stored}, expected {HEADER_LEN}"
            ),
            Self::SlotLengthMismatch { stored } => write!(
                formatter,
                "journal header stores slot length {stored}, expected {SLOT_LEN}"
            ),
            Self::NonCanonicalPadding(region) => {
                write!(formatter, "{region} contains non-zero reserved bytes")
            }
            Self::UnknownRecordKind(tag) => {
                write!(formatter, "journal slot has unknown record kind {tag}")
            }
            Self::PayloadTooLarge { length, maximum } => write!(
                formatter,
                "journal payload is {length} bytes, exceeding the {maximum}-byte slot bound"
            ),
            Self::PayloadTruncated { needed, remaining } => write!(
                formatter,
                "journal payload needs {needed} bytes with only {remaining} remaining"
            ),
            Self::TrailingPayloadBytes { remaining } => write!(
                formatter,
                "journal payload has {remaining} trailing canonical bytes"
            ),
            Self::SequenceMismatch { expected, stored } => write!(
                formatter,
                "journal slot sequence is {stored}, expected exactly {expected}"
            ),
            Self::PreviousDigestMismatch => {
                formatter.write_str("journal slot does not continue the authenticated digest chain")
            }
            Self::InvalidCanonicalValue => {
                formatter.write_str("journal contains an all-zero canonical identifier or digest")
            }
            Self::InvalidTimeInterval(error) => {
                write!(
                    formatter,
                    "journal payload contains an invalid time interval: {error}"
                )
            }
            Self::UnknownDecisionPoint(tag) => {
                write!(
                    formatter,
                    "journal payload has unknown action decision point {tag}"
                )
            }
            Self::UnknownActionKind(tag) => {
                write!(formatter, "journal payload has unknown action kind {tag}")
            }
            Self::UnknownFailureProfile(tag) => {
                write!(
                    formatter,
                    "journal payload has unknown failure profile {tag}"
                )
            }
            Self::UnknownScopeProof(tag) => {
                write!(formatter, "journal payload has unknown scope proof {tag}")
            }
            Self::UnknownOutcome(tag) => {
                write!(
                    formatter,
                    "journal payload has unknown action outcome {tag}"
                )
            }
            Self::UnknownResultSource(tag) => {
                write!(
                    formatter,
                    "journal payload has unknown action result source {tag}"
                )
            }
            Self::InvalidStateChangingAction(error) => {
                write!(
                    formatter,
                    "journal contains an invalid state-changing action: {error}"
                )
            }
            Self::StoredActionDigestMismatch => formatter.write_str(
                "journal action digest does not match its canonical reconstructed value",
            ),
            Self::InvalidActionResult(error) => {
                write!(
                    formatter,
                    "journal contains an invalid action result: {error}"
                )
            }
        }
    }
}

impl std::error::Error for JournalFormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTimeInterval(error) => Some(error),
            Self::InvalidStateChangingAction(error) => Some(error),
            Self::InvalidActionResult(error) => Some(error),
            Self::AuthenticationFailed(_)
            | Self::InvalidMagic(_)
            | Self::FormatFingerprintMismatch(_)
            | Self::HeaderLengthMismatch { .. }
            | Self::SlotLengthMismatch { .. }
            | Self::NonCanonicalPadding(_)
            | Self::UnknownRecordKind(_)
            | Self::PayloadTooLarge { .. }
            | Self::PayloadTruncated { .. }
            | Self::TrailingPayloadBytes { .. }
            | Self::SequenceMismatch { .. }
            | Self::PreviousDigestMismatch
            | Self::InvalidCanonicalValue
            | Self::UnknownDecisionPoint(_)
            | Self::UnknownActionKind(_)
            | Self::UnknownFailureProfile(_)
            | Self::UnknownScopeProof(_)
            | Self::UnknownOutcome(_)
            | Self::UnknownResultSource(_)
            | Self::StoredActionDigestMismatch => None,
        }
    }
}

#[derive(Clone, Copy)]
enum RecordKind {
    Prepare,
    Outcome,
}

impl RecordKind {
    const fn for_payload(payload: &JournalPayload) -> Self {
        match payload {
            JournalPayload::Prepare { .. } => Self::Prepare,
            JournalPayload::Outcome { .. } => Self::Outcome,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Prepare => 0,
            Self::Outcome => 1,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, JournalFormatError> {
        match tag {
            0 => Ok(Self::Prepare),
            1 => Ok(Self::Outcome),
            other => Err(JournalFormatError::UnknownRecordKind(other)),
        }
    }
}

fn keyed_authenticator(
    key: &[u8; 32],
    domain: &[u8],
    authenticated_bytes: &[u8],
) -> [u8; AUTHENTICATOR_LEN] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(domain);
    hasher.update(authenticated_bytes);
    *hasher.finalize().as_bytes()
}

fn keyed_journal_authenticator(
    key: &[u8; 32],
    domain: &[u8],
    journal: ActionJournalId,
    authenticated_bytes: &[u8],
) -> [u8; AUTHENTICATOR_LEN] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(domain);
    hasher.update(journal.as_bytes());
    hasher.update(authenticated_bytes);
    *hasher.finalize().as_bytes()
}

pub(crate) fn format_fingerprint() -> [u8; 32] {
    *blake3::hash(FORMAT_CONTRACT).as_bytes()
}

pub(crate) fn header_digest(header: &[u8; HEADER_LEN]) -> [u8; 32] {
    *blake3::hash(header).as_bytes()
}

fn constant_time_eq(actual: &[u8], expected: &[u8; AUTHENTICATOR_LEN]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes);
    output
}

fn encode_payload(
    encoder: &mut Encoder<'_>,
    payload: &JournalPayload,
) -> Result<(), JournalFormatError> {
    match payload {
        JournalPayload::Prepare {
            action_id,
            prepared_id,
            action,
        } => {
            encoder.write(action_id.as_bytes())?;
            encoder.write(prepared_id.as_bytes())?;
            encode_action(encoder, **action)
        }
        JournalPayload::Outcome {
            action_id,
            prepared_id,
            request,
            intent,
            result,
        } => {
            encoder.write(action_id.as_bytes())?;
            encoder.write(prepared_id.as_bytes())?;
            encoder.write(request.as_bytes())?;
            encoder.write(intent.as_bytes())?;
            encode_result(encoder, *result)
        }
    }
}

fn decode_payload(
    decoder: &mut Decoder<'_>,
    kind: RecordKind,
) -> Result<JournalPayload, JournalFormatError> {
    let action_id = read_id(decoder, ActionId::new)?;
    let prepared_id = read_id(decoder, PreparedActionId::new)?;
    match kind {
        RecordKind::Prepare => Ok(JournalPayload::Prepare {
            action_id,
            prepared_id,
            action: Box::new(decode_action(decoder)?),
        }),
        RecordKind::Outcome => Ok(JournalPayload::Outcome {
            action_id,
            prepared_id,
            request: read_id(decoder, ActionRequestId::new)?,
            intent: read_digest(decoder, ActionIntentDigest::new)?,
            result: decode_result(decoder)?,
        }),
    }
}

fn encode_action(
    encoder: &mut Encoder<'_>,
    action: StateChangingAction,
) -> Result<(), JournalFormatError> {
    encoder.write(action.request().as_bytes())?;
    encoder.write(action.audit().as_bytes())?;
    encoder.write(action.backend().as_bytes())?;
    encoder.write(action.authorization().as_bytes())?;
    encoder.write(action.authorization_digest().as_bytes())?;
    encode_interval(encoder, action.authorization_validity())?;
    encoder.write(action.policy_revision().as_bytes())?;
    encoder.write(action.policy_digest().as_bytes())?;
    encoder.write(action.capability_snapshot().as_bytes())?;
    encoder.write(action.boot().as_bytes())?;
    encoder.write_u64(action.decided_at().as_nanos())?;
    encoder.write_u64(action.execute_before().as_nanos())?;
    encoder.write_u8(action.decision_point().tag())?;
    encoder.write_u8(action.requested().tag())?;
    encoder.write_u8(action.effective().tag())?;
    encoder.write_u8(action.failure().tag())?;
    encode_scope(encoder, action.scope())?;
    encoder.write(action.parameters().as_bytes())?;
    encoder.write(action.effect().as_bytes())?;
    encoder.write(action.digest().as_bytes())
}

fn decode_action(decoder: &mut Decoder<'_>) -> Result<StateChangingAction, JournalFormatError> {
    let parts = StateChangingActionParts {
        request: read_id(decoder, ActionRequestId::new)?,
        audit: read_id(decoder, ActionAuditId::new)?,
        backend: read_id(decoder, ActionBackendId::new)?,
        authorization: read_id(decoder, ActionAuthorizationId::new)?,
        authorization_digest: read_digest(decoder, ActionAuthorizationDigest::new)?,
        authorization_validity: decode_interval(decoder)?,
        policy_revision: read_id(decoder, PolicyRevisionId::new)?,
        policy_digest: read_digest(decoder, PolicyDigest::new)?,
        capability_snapshot: read_digest(decoder, CapabilitySnapshotDigest::new)?,
        boot: read_id(decoder, BootId::new)?,
        decided_at: MonotonicInstant::from_nanos(decoder.read_u64()?),
        execute_before: MonotonicInstant::from_nanos(decoder.read_u64()?),
        decision_point: ActionDecisionPoint::from_tag(decoder.read_u8()?)
            .map_err(map_model_decode_error)?,
        requested: ActionKind::from_tag(decoder.read_u8()?).map_err(map_model_decode_error)?,
        effective: ActionKind::from_tag(decoder.read_u8()?).map_err(map_model_decode_error)?,
        failure: ActionFailureProfile::from_tag(decoder.read_u8()?)
            .map_err(map_model_decode_error)?,
        scope: decode_scope(decoder)?,
        parameters: read_digest(decoder, ActionParametersDigest::new)?,
        effect: read_digest(decoder, ActionEffectDigest::new)?,
    };
    let stored_digest = read_digest(decoder, ActionIntentDigest::new)?;
    let action =
        StateChangingAction::new(parts).map_err(JournalFormatError::InvalidStateChangingAction)?;
    if action.digest() != stored_digest {
        return Err(JournalFormatError::StoredActionDigestMismatch);
    }
    Ok(action)
}

fn encode_scope(
    encoder: &mut Encoder<'_>,
    scope: ActionScopeProof,
) -> Result<(), JournalFormatError> {
    encoder.write_u8(scope.tag())?;
    encoder.write(scope.proof().as_bytes())?;
    match scope {
        ActionScopeProof::KernelSocket {
            socket,
            network_namespace,
            workload,
            ..
        } => {
            encoder.write(socket.as_bytes())?;
            encoder.write(network_namespace.as_bytes())?;
            encoder.write(workload.as_bytes())?;
        }
        ActionScopeProof::CgroupHook {
            cgroup, attachment, ..
        } => {
            encoder.write(cgroup.as_bytes())?;
            encoder.write(attachment.as_bytes())?;
        }
        ActionScopeProof::InterceptedFlow {
            conversation,
            authorization,
            effective_revision,
            ..
        } => {
            encoder.write(conversation.as_bytes())?;
            encoder.write(authorization.as_bytes())?;
            encoder.write(effective_revision.as_bytes())?;
        }
    }
    encode_interval(encoder, scope.valid_during())
}

fn decode_scope(decoder: &mut Decoder<'_>) -> Result<ActionScopeProof, JournalFormatError> {
    let tag = decoder.read_u8()?;
    let proof = read_id(decoder, ActionScopeProofId::new)?;
    match tag {
        0 => Ok(ActionScopeProof::KernelSocket {
            proof,
            socket: read_id(decoder, SocketId::new)?,
            network_namespace: read_id(decoder, NetworkNamespaceId::new)?,
            workload: read_id(decoder, WorkloadId::new)?,
            valid_during: decode_interval(decoder)?,
        }),
        1 => Ok(ActionScopeProof::CgroupHook {
            proof,
            cgroup: read_id(decoder, CgroupId::new)?,
            attachment: read_id(decoder, BpfLinkId::new)?,
            valid_during: decode_interval(decoder)?,
        }),
        2 => Ok(ActionScopeProof::InterceptedFlow {
            proof,
            conversation: read_id(decoder, InterceptionConversationId::new)?,
            authorization: read_id(decoder, InterceptionAuthorizationId::new)?,
            effective_revision: read_id(decoder, EffectiveStateRevisionId::new)?,
            valid_during: decode_interval(decoder)?,
        }),
        other => Err(JournalFormatError::UnknownScopeProof(other)),
    }
}

fn encode_result(
    encoder: &mut Encoder<'_>,
    result: ActionResult,
) -> Result<(), JournalFormatError> {
    encoder.write_u8(result.outcome().tag())?;
    encoder.write_u8(result.source().tag())?;
    encoder.write(result.observed_at().boot().as_bytes())?;
    encoder.write_u64(result.observed_at().instant().as_nanos())?;
    encoder.write(result.evidence().as_bytes())
}

fn decode_result(decoder: &mut Decoder<'_>) -> Result<ActionResult, JournalFormatError> {
    let outcome = ActionOutcome::from_tag(decoder.read_u8()?).map_err(map_model_decode_error)?;
    let source =
        ActionResultSource::from_tag(decoder.read_u8()?).map_err(map_model_decode_error)?;
    let observed_at = BootScopedInstant::new(
        read_id(decoder, BootId::new)?,
        MonotonicInstant::from_nanos(decoder.read_u64()?),
    );
    let evidence = read_digest(decoder, ActionResultDigest::new)?;
    ActionResult::from_parts(outcome, source, observed_at, evidence)
        .map_err(JournalFormatError::InvalidActionResult)
}

fn encode_interval(
    encoder: &mut Encoder<'_>,
    interval: TimeInterval,
) -> Result<(), JournalFormatError> {
    encoder.write_u64(interval.start().as_nanos())?;
    encoder.write_u64(interval.end().as_nanos())
}

fn decode_interval(decoder: &mut Decoder<'_>) -> Result<TimeInterval, JournalFormatError> {
    let start = MonotonicInstant::from_nanos(decoder.read_u64()?);
    let end = MonotonicInstant::from_nanos(decoder.read_u64()?);
    TimeInterval::new(start, end).map_err(JournalFormatError::InvalidTimeInterval)
}

fn read_id<T>(
    decoder: &mut Decoder<'_>,
    constructor: fn([u8; 16]) -> Result<T, CanonicalIdError>,
) -> Result<T, JournalFormatError> {
    constructor(decoder.read_array()?).map_err(|_| JournalFormatError::InvalidCanonicalValue)
}

fn read_digest<T>(
    decoder: &mut Decoder<'_>,
    constructor: fn([u8; 32]) -> Result<T, CanonicalIdError>,
) -> Result<T, JournalFormatError> {
    constructor(decoder.read_array()?).map_err(|_| JournalFormatError::InvalidCanonicalValue)
}

fn map_model_decode_error(error: ActionModelDecodeError) -> JournalFormatError {
    match error {
        ActionModelDecodeError::DecisionPoint(tag) => JournalFormatError::UnknownDecisionPoint(tag),
        ActionModelDecodeError::ActionKind(tag) => JournalFormatError::UnknownActionKind(tag),
        ActionModelDecodeError::FailureProfile(tag) => {
            JournalFormatError::UnknownFailureProfile(tag)
        }
        ActionModelDecodeError::Outcome(tag) => JournalFormatError::UnknownOutcome(tag),
        ActionModelDecodeError::ResultSource(tag) => JournalFormatError::UnknownResultSource(tag),
    }
}

struct Encoder<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Encoder<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn len(&self) -> usize {
        self.position
    }

    fn write(&mut self, input: &[u8]) -> Result<(), JournalFormatError> {
        let end =
            self.position
                .checked_add(input.len())
                .ok_or(JournalFormatError::PayloadTooLarge {
                    length: usize::MAX,
                    maximum: self.bytes.len(),
                })?;
        let maximum = self.bytes.len();
        let destination =
            self.bytes
                .get_mut(self.position..end)
                .ok_or(JournalFormatError::PayloadTooLarge {
                    length: end,
                    maximum,
                })?;
        destination.copy_from_slice(input);
        self.position = end;
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> Result<(), JournalFormatError> {
        self.write(&[value])
    }

    fn write_u64(&mut self, value: u64) -> Result<(), JournalFormatError> {
        self.write(&value.to_be_bytes())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], JournalFormatError> {
        let remaining = self.remaining();
        let end = self
            .position
            .checked_add(N)
            .ok_or(JournalFormatError::PayloadTruncated {
                needed: N,
                remaining,
            })?;
        let source =
            self.bytes
                .get(self.position..end)
                .ok_or(JournalFormatError::PayloadTruncated {
                    needed: N,
                    remaining,
                })?;
        self.position = end;
        Ok(copy_array(source))
    }

    fn read_u8(&mut self) -> Result<u8, JournalFormatError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u64(&mut self) -> Result<u64, JournalFormatError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x5a; 32];
    const ROOT_DIGEST: [u8; 32] = [0; 32];

    macro_rules! canonical {
        ($type:ty, $byte:expr) => {
            <$type>::new([$byte; 16]).expect("non-zero canonical identifier")
        };
    }

    macro_rules! digest {
        ($type:ty, $byte:expr) => {
            <$type>::new([$byte; 32]).expect("non-zero canonical digest")
        };
    }

    fn test_journal() -> ActionJournalId {
        canonical!(ActionJournalId, 1)
    }

    #[test]
    fn header_and_all_scope_proofs_round_trip_canonically() {
        let capacity = (HEADER_LEN + 8 * SLOT_LEN) as u64;
        let journal = canonical!(ActionJournalId, 1);
        let journal_header = JournalHeader::new(journal, capacity);
        let header = encode_header(&journal_header, &TEST_KEY);
        let decoded_header = decode_header(&header, &TEST_KEY).expect("decoded header");
        assert_eq!(decoded_header.journal(), journal);
        assert_eq!(decoded_header.capacity(), capacity);

        let validity = interval(5, 25);
        let scopes = [
            ActionScopeProof::KernelSocket {
                proof: canonical!(ActionScopeProofId, 2),
                socket: canonical!(SocketId, 3),
                network_namespace: canonical!(NetworkNamespaceId, 4),
                workload: canonical!(WorkloadId, 5),
                valid_during: validity,
            },
            ActionScopeProof::CgroupHook {
                proof: canonical!(ActionScopeProofId, 6),
                cgroup: canonical!(CgroupId, 7),
                attachment: canonical!(BpfLinkId, 8),
                valid_during: validity,
            },
            ActionScopeProof::InterceptedFlow {
                proof: canonical!(ActionScopeProofId, 9),
                conversation: canonical!(InterceptionConversationId, 10),
                authorization: canonical!(InterceptionAuthorizationId, 11),
                effective_revision: canonical!(EffectiveStateRevisionId, 12),
                valid_during: validity,
            },
        ];

        for (index, scope) in scopes.into_iter().enumerate() {
            let sequence = index as u64;
            let payload = prepare_payload(scope);
            let encoded = encode_slot(
                test_journal(),
                sequence,
                ROOT_DIGEST,
                payload.clone(),
                &TEST_KEY,
            )
            .expect("encoded prepare slot");
            assert_ne!(encoded, [0; SLOT_LEN]);
            let decoded = decode_slot(test_journal(), sequence, ROOT_DIGEST, &encoded, &TEST_KEY)
                .expect("decoded prepare slot")
                .expect("occupied prepare slot");
            assert_eq!(decoded.payload(), &payload);
            assert_eq!(decoded.digest(), *blake3::hash(&encoded).as_bytes());
        }

        let result = ActionResult::reconciled(
            ActionOutcome::Applied,
            boot_instant(30),
            digest!(ActionResultDigest, 24),
        )
        .expect("reconciled result");
        let outcome = JournalPayload::Outcome {
            action_id: canonical!(ActionId, 20),
            prepared_id: canonical!(PreparedActionId, 21),
            request: canonical!(ActionRequestId, 13),
            intent: digest!(ActionIntentDigest, 25),
            result,
        };
        let encoded = encode_slot(test_journal(), 3, ROOT_DIGEST, outcome.clone(), &TEST_KEY)
            .expect("encoded outcome slot");
        let decoded = decode_slot(test_journal(), 3, ROOT_DIGEST, &encoded, &TEST_KEY)
            .expect("decoded outcome slot")
            .expect("occupied outcome slot");
        assert_eq!(decoded.payload(), &outcome);
    }

    #[test]
    fn authenticated_bytes_detect_tampering() {
        let mut tampered = encode_slot(
            test_journal(),
            7,
            ROOT_DIGEST,
            prepare_payload(kernel_scope()),
            &TEST_KEY,
        )
        .expect("encoded slot");
        tampered[SLOT_PAYLOAD_OFFSET + 8] ^= 0x80;

        assert_eq!(
            decode_slot(test_journal(), 7, ROOT_DIGEST, &tampered, &TEST_KEY),
            Err(JournalFormatError::AuthenticationFailed(
                AuthenticatedRegion::Slot
            ))
        );
    }

    #[test]
    fn exact_sequence_and_previous_digest_are_required() {
        let encoded = encode_slot(
            test_journal(),
            41,
            ROOT_DIGEST,
            prepare_payload(kernel_scope()),
            &TEST_KEY,
        )
        .expect("encoded slot");

        assert!(matches!(
            decode_slot(test_journal(), 42, ROOT_DIGEST, &encoded, &TEST_KEY),
            Err(JournalFormatError::SequenceMismatch {
                expected: 42,
                stored: 41
            })
        ));
        assert_eq!(
            decode_slot(test_journal(), 41, [0x7f; 32], &encoded, &TEST_KEY),
            Err(JournalFormatError::PreviousDigestMismatch)
        );
    }

    #[test]
    fn an_all_zero_slot_is_empty() {
        assert_eq!(
            decode_slot(test_journal(), u64::MAX, [9; 32], &[0; SLOT_LEN], &TEST_KEY)
                .expect("empty slot"),
            None
        );
    }

    #[test]
    fn authenticated_noncanonical_models_are_rejected() {
        let mut invalid_id = encode_slot(
            test_journal(),
            5,
            ROOT_DIGEST,
            prepare_payload(kernel_scope()),
            &TEST_KEY,
        )
        .expect("encoded slot");
        invalid_id[SLOT_PAYLOAD_OFFSET..SLOT_PAYLOAD_OFFSET + 16].fill(0);
        resign_slot(&mut invalid_id);
        assert_eq!(
            decode_slot(test_journal(), 5, ROOT_DIGEST, &invalid_id, &TEST_KEY),
            Err(JournalFormatError::InvalidCanonicalValue)
        );

        let mut mismatched_digest = encode_slot(
            test_journal(),
            6,
            ROOT_DIGEST,
            prepare_payload(kernel_scope()),
            &TEST_KEY,
        )
        .expect("encoded slot");
        let payload_length = u32::from_be_bytes(copy_array(
            &mismatched_digest[SLOT_PAYLOAD_LENGTH_OFFSET..SLOT_PAYLOAD_LENGTH_OFFSET + 4],
        )) as usize;
        mismatched_digest[SLOT_PAYLOAD_OFFSET + payload_length - 1] ^= 1;
        resign_slot(&mut mismatched_digest);
        assert_eq!(
            decode_slot(
                test_journal(),
                6,
                ROOT_DIGEST,
                &mismatched_digest,
                &TEST_KEY,
            ),
            Err(JournalFormatError::StoredActionDigestMismatch)
        );

        let uncertain = ActionResult::uncertain(boot_instant(30), digest!(ActionResultDigest, 24));
        let outcome = JournalPayload::Outcome {
            action_id: canonical!(ActionId, 20),
            prepared_id: canonical!(PreparedActionId, 21),
            request: canonical!(ActionRequestId, 13),
            intent: digest!(ActionIntentDigest, 25),
            result: uncertain,
        };
        let mut invalid_result = encode_slot(test_journal(), 7, ROOT_DIGEST, outcome, &TEST_KEY)
            .expect("encoded outcome slot");
        let result_offset = SLOT_PAYLOAD_OFFSET + 16 + 16 + 16 + 32;
        invalid_result[result_offset + 1] = ActionResultSource::DirectBackendReceipt.tag();
        resign_slot(&mut invalid_result);
        assert_eq!(
            decode_slot(test_journal(), 7, ROOT_DIGEST, &invalid_result, &TEST_KEY,),
            Err(JournalFormatError::InvalidActionResult(
                ActionResultError::DirectReceiptMustBeTerminal
            ))
        );
    }

    fn prepare_payload(scope: ActionScopeProof) -> JournalPayload {
        JournalPayload::Prepare {
            action_id: canonical!(ActionId, 20),
            prepared_id: canonical!(PreparedActionId, 21),
            action: Box::new(action(scope)),
        }
    }

    fn action(scope: ActionScopeProof) -> StateChangingAction {
        StateChangingAction::new(StateChangingActionParts {
            request: canonical!(ActionRequestId, 13),
            audit: canonical!(ActionAuditId, 14),
            backend: canonical!(ActionBackendId, 15),
            authorization: canonical!(ActionAuthorizationId, 16),
            authorization_digest: digest!(ActionAuthorizationDigest, 17),
            authorization_validity: interval(0, 30),
            policy_revision: canonical!(PolicyRevisionId, 18),
            policy_digest: digest!(PolicyDigest, 19),
            capability_snapshot: digest!(CapabilitySnapshotDigest, 20),
            boot: canonical!(BootId, 21),
            decided_at: MonotonicInstant::from_nanos(10),
            execute_before: MonotonicInstant::from_nanos(20),
            decision_point: ActionDecisionPoint::RequestHead,
            requested: ActionKind::Modify,
            effective: ActionKind::Replace,
            failure: ActionFailureProfile::AuthorizedFailClosed,
            scope,
            parameters: digest!(ActionParametersDigest, 22),
            effect: digest!(ActionEffectDigest, 23),
        })
        .expect("valid state-changing action")
    }

    fn kernel_scope() -> ActionScopeProof {
        ActionScopeProof::KernelSocket {
            proof: canonical!(ActionScopeProofId, 2),
            socket: canonical!(SocketId, 3),
            network_namespace: canonical!(NetworkNamespaceId, 4),
            workload: canonical!(WorkloadId, 5),
            valid_during: interval(5, 25),
        }
    }

    fn interval(start: u64, end: u64) -> TimeInterval {
        TimeInterval::new(
            MonotonicInstant::from_nanos(start),
            MonotonicInstant::from_nanos(end),
        )
        .expect("ordered interval")
    }

    fn boot_instant(nanos: u64) -> BootScopedInstant {
        BootScopedInstant::new(canonical!(BootId, 21), MonotonicInstant::from_nanos(nanos))
    }

    fn resign_slot(slot: &mut [u8; SLOT_LEN]) {
        let authenticator = keyed_journal_authenticator(
            &TEST_KEY,
            SLOT_AUTHENTICATION_DOMAIN,
            test_journal(),
            &slot[..SLOT_AUTHENTICATOR_OFFSET],
        );
        slot[SLOT_AUTHENTICATOR_OFFSET..].copy_from_slice(&authenticator);
    }
}

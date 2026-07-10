use std::{fmt, num::NonZeroU64};

use evidence::{ContentDigest, EvidenceId, SegmentId};

pub const SEGMENT_HEADER_LEN: usize = 192;
pub const FRAME_HEADER_LEN: usize = 128;
pub const FRAME_CHECKSUM_LEN: usize = 32;
pub const AEAD_TAG_LEN: usize = 16;
pub const FRAME_PHYSICAL_MAX: usize = 1024 * 1024;
pub const RECORD_CHUNK_MAX: usize =
    FRAME_PHYSICAL_MAX - FRAME_HEADER_LEN - FRAME_CHECKSUM_LEN - AEAD_TAG_LEN;

const SEGMENT_MAGIC: [u8; 16] = *b"PROBE-SEGMENT\0\0\0";
const FRAME_MAGIC: [u8; 4] = *b"PRBF";
const KEY_REFERENCE_MAX: usize = 64;
const SEGMENT_SCHEMA: &[u8] = b"probe.segment.header=192;frame.header=128;checksum=blake3;cipher=xchacha20poly1305;batch=commit-marker;payload=chunked";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumAlgorithm {
    Blake3,
}

impl ChecksumAlgorithm {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Blake3 => 1,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, SegmentFormatError> {
        match tag {
            1 => Ok(Self::Blake3),
            other => Err(SegmentFormatError::UnsupportedChecksum(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherAlgorithm {
    XChaCha20Poly1305,
}

impl CipherAlgorithm {
    const fn tag(self) -> u8 {
        match self {
            Self::XChaCha20Poly1305 => 1,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SegmentFormatError> {
        match tag {
            1 => Ok(Self::XChaCha20Poly1305),
            other => Err(SegmentFormatError::UnsupportedCipher(other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyReference(String);

impl KeyReference {
    pub fn new(value: impl Into<String>) -> Result<Self, SegmentFormatError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SegmentFormatError::EmptyKeyReference);
        }
        if value.len() > KEY_REFERENCE_MAX {
            return Err(SegmentFormatError::KeyReferenceTooLong(value.len()));
        }
        if value.chars().any(char::is_control) {
            return Err(SegmentFormatError::InvalidKeyReference);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentHeader {
    segment: SegmentId,
    created_unix_nanos: u64,
    key_reference: KeyReference,
    checksum: ChecksumAlgorithm,
    cipher: CipherAlgorithm,
    digest: ContentDigest,
}

impl SegmentHeader {
    pub fn new(segment: SegmentId, created_unix_nanos: u64, key_reference: KeyReference) -> Self {
        let mut header = Self {
            segment,
            created_unix_nanos,
            key_reference,
            checksum: ChecksumAlgorithm::Blake3,
            cipher: CipherAlgorithm::XChaCha20Poly1305,
            digest: ContentDigest::new([0; 32]),
        };
        header.digest = digest_header_prefix(&header.encode_prefix());
        header
    }

    pub fn decode(bytes: &[u8; SEGMENT_HEADER_LEN]) -> Result<Self, SegmentFormatError> {
        if bytes[..16] != SEGMENT_MAGIC {
            return Err(SegmentFormatError::BadSegmentMagic);
        }
        if bytes[16..48] != schema_fingerprint().as_bytes()[..] {
            return Err(SegmentFormatError::SchemaFingerprintMismatch);
        }
        let declared_len = u16::from_be_bytes([bytes[48], bytes[49]]) as usize;
        if declared_len != SEGMENT_HEADER_LEN {
            return Err(SegmentFormatError::HeaderLengthMismatch(declared_len));
        }
        let checksum = ChecksumAlgorithm::from_tag(bytes[50])?;
        let cipher = CipherAlgorithm::from_tag(bytes[51])?;
        let segment = SegmentId::new(read_u128(bytes, 52))
            .map_err(|_| SegmentFormatError::ZeroIdentifier("segment"))?;
        let created_unix_nanos = read_u64(bytes, 68);
        let key_len = u16::from_be_bytes([bytes[76], bytes[77]]) as usize;
        if key_len == 0 || key_len > KEY_REFERENCE_MAX {
            return Err(SegmentFormatError::InvalidKeyReferenceLength(key_len));
        }
        if bytes[78 + key_len..142].iter().any(|byte| *byte != 0)
            || bytes[142..160].iter().any(|byte| *byte != 0)
        {
            return Err(SegmentFormatError::NonZeroReservedBytes);
        }
        let key_reference = std::str::from_utf8(&bytes[78..78 + key_len])
            .map_err(|_| SegmentFormatError::InvalidKeyReference)?;
        let key_reference = KeyReference::new(key_reference)?;
        let digest = digest_from_slice(&bytes[160..192]);
        if digest != digest_header_prefix(&bytes[..160]) {
            return Err(SegmentFormatError::HeaderDigestMismatch);
        }
        Ok(Self {
            segment,
            created_unix_nanos,
            key_reference,
            checksum,
            cipher,
            digest,
        })
    }

    pub fn encode(&self) -> [u8; SEGMENT_HEADER_LEN] {
        let mut bytes = [0_u8; SEGMENT_HEADER_LEN];
        bytes[..160].copy_from_slice(&self.encode_prefix());
        bytes[160..192].copy_from_slice(self.digest.as_bytes());
        bytes
    }

    pub const fn segment(&self) -> SegmentId {
        self.segment
    }

    pub const fn created_unix_nanos(&self) -> u64 {
        self.created_unix_nanos
    }

    pub fn key_reference(&self) -> &KeyReference {
        &self.key_reference
    }

    pub const fn checksum(&self) -> ChecksumAlgorithm {
        self.checksum
    }

    pub const fn cipher(&self) -> CipherAlgorithm {
        self.cipher
    }

    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    fn encode_prefix(&self) -> [u8; 160] {
        let mut bytes = [0_u8; 160];
        bytes[..16].copy_from_slice(&SEGMENT_MAGIC);
        bytes[16..48].copy_from_slice(schema_fingerprint().as_bytes());
        bytes[48..50].copy_from_slice(&(SEGMENT_HEADER_LEN as u16).to_be_bytes());
        bytes[50] = self.checksum.tag();
        bytes[51] = self.cipher.tag();
        bytes[52..68].copy_from_slice(&self.segment.get().to_be_bytes());
        bytes[68..76].copy_from_slice(&self.created_unix_nanos.to_be_bytes());
        let key = self.key_reference.as_str().as_bytes();
        bytes[76..78].copy_from_slice(&(key.len() as u16).to_be_bytes());
        bytes[78..78 + key.len()].copy_from_slice(key);
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BatchId(u128);

impl BatchId {
    pub fn new(value: u128) -> Result<Self, SegmentFormatError> {
        if value == 0 {
            Err(SegmentFormatError::ZeroIdentifier("batch"))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u128 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Packet,
    Plaintext,
    ExtentPage,
    MappingPage,
    Projection,
    Audit,
}

impl RecordKind {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Packet => 1,
            Self::Plaintext => 2,
            Self::ExtentPage => 3,
            Self::MappingPage => 4,
            Self::Projection => 5,
            Self::Audit => 6,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, SegmentFormatError> {
        match tag {
            1 => Ok(Self::Packet),
            2 => Ok(Self::Plaintext),
            3 => Ok(Self::ExtentPage),
            4 => Ok(Self::MappingPage),
            5 => Ok(Self::Projection),
            6 => Ok(Self::Audit),
            other => Err(SegmentFormatError::UnknownRecordKind(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataFrameHeader {
    pub sequence: u64,
    pub batch: BatchId,
    pub evidence: EvidenceId,
    pub kind: RecordKind,
    pub starts_record: bool,
    pub ends_record: bool,
    pub logical_offset: u64,
    pub plaintext_len: u32,
    pub nonce: [u8; 24],
    pub plaintext_digest: ContentDigest,
}

impl DataFrameHeader {
    pub fn encode(self) -> Result<[u8; FRAME_HEADER_LEN], SegmentFormatError> {
        if self.sequence == 0 {
            return Err(SegmentFormatError::ZeroFrameSequence);
        }
        if self.plaintext_len == 0 || self.plaintext_len as usize > RECORD_CHUNK_MAX {
            return Err(SegmentFormatError::InvalidPlaintextLength(
                self.plaintext_len,
            ));
        }
        let ciphertext_len = self
            .plaintext_len
            .checked_add(AEAD_TAG_LEN as u32)
            .ok_or(SegmentFormatError::FrameLengthOverflow)?;
        let mut bytes = base_frame(self.sequence, self.batch);
        bytes[4] = 1;
        bytes[5] = self.kind.tag();
        bytes[6] = u8::from(self.starts_record) | (u8::from(self.ends_record) << 1);
        bytes[32..48].copy_from_slice(&self.evidence.get().to_be_bytes());
        bytes[48..56].copy_from_slice(&self.logical_offset.to_be_bytes());
        bytes[56..60].copy_from_slice(&self.plaintext_len.to_be_bytes());
        bytes[60..64].copy_from_slice(&ciphertext_len.to_be_bytes());
        bytes[64..88].copy_from_slice(&self.nonce);
        bytes[88..120].copy_from_slice(self.plaintext_digest.as_bytes());
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommitFrameHeader {
    pub sequence: u64,
    pub batch: BatchId,
    pub first_sequence: u64,
    pub frame_count: NonZeroU64,
    pub batch_digest: ContentDigest,
}

impl CommitFrameHeader {
    pub fn encode(self) -> Result<[u8; FRAME_HEADER_LEN], SegmentFormatError> {
        if self.sequence == 0 || self.first_sequence == 0 {
            return Err(SegmentFormatError::ZeroFrameSequence);
        }
        let mut bytes = base_frame(self.sequence, self.batch);
        bytes[4] = 2;
        bytes[48..56].copy_from_slice(&self.first_sequence.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.frame_count.get().to_be_bytes());
        bytes[88..120].copy_from_slice(self.batch_digest.as_bytes());
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameHeader {
    Data(DataFrameHeader),
    Commit(CommitFrameHeader),
}

impl FrameHeader {
    pub fn decode(bytes: &[u8; FRAME_HEADER_LEN]) -> Result<Self, SegmentFormatError> {
        if bytes[..4] != FRAME_MAGIC {
            return Err(SegmentFormatError::BadFrameMagic);
        }
        if bytes[7] != 0 || bytes[120..128].iter().any(|byte| *byte != 0) {
            return Err(SegmentFormatError::NonZeroReservedBytes);
        }
        let sequence = read_u64(bytes, 8);
        if sequence == 0 {
            return Err(SegmentFormatError::ZeroFrameSequence);
        }
        let batch = BatchId::new(read_u128(bytes, 16))?;
        match bytes[4] {
            1 => decode_data_frame(bytes, sequence, batch).map(Self::Data),
            2 => decode_commit_frame(bytes, sequence, batch).map(Self::Commit),
            other => Err(SegmentFormatError::UnknownFrameKind(other)),
        }
    }

    pub fn encode(self) -> Result<[u8; FRAME_HEADER_LEN], SegmentFormatError> {
        match self {
            Self::Data(header) => header.encode(),
            Self::Commit(header) => header.encode(),
        }
    }

    pub const fn sequence(self) -> u64 {
        match self {
            Self::Data(header) => header.sequence,
            Self::Commit(header) => header.sequence,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentFormatError {
    BadSegmentMagic,
    BadFrameMagic,
    SchemaFingerprintMismatch,
    HeaderLengthMismatch(usize),
    HeaderDigestMismatch,
    UnsupportedChecksum(u8),
    UnsupportedCipher(u8),
    UnknownFrameKind(u8),
    UnknownRecordKind(u8),
    ZeroIdentifier(&'static str),
    ZeroFrameSequence,
    EmptyKeyReference,
    KeyReferenceTooLong(usize),
    InvalidKeyReference,
    InvalidKeyReferenceLength(usize),
    InvalidPlaintextLength(u32),
    InvalidCiphertextLength(u32),
    InvalidRecordFlags(u8),
    CommitCarriesDataFields,
    FrameLengthOverflow,
    NonZeroReservedBytes,
}

impl fmt::Display for SegmentFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSegmentMagic => formatter.write_str("segment magic does not match"),
            Self::BadFrameMagic => formatter.write_str("frame magic does not match"),
            Self::SchemaFingerprintMismatch => {
                formatter.write_str("segment schema fingerprint does not match")
            }
            Self::HeaderLengthMismatch(length) => {
                write!(formatter, "segment header declares invalid length {length}")
            }
            Self::HeaderDigestMismatch => formatter.write_str("segment header digest mismatch"),
            Self::UnsupportedChecksum(tag) => {
                write!(formatter, "unsupported checksum algorithm tag {tag}")
            }
            Self::UnsupportedCipher(tag) => {
                write!(formatter, "unsupported cipher algorithm tag {tag}")
            }
            Self::UnknownFrameKind(tag) => write!(formatter, "unknown frame kind tag {tag}"),
            Self::UnknownRecordKind(tag) => write!(formatter, "unknown record kind tag {tag}"),
            Self::ZeroIdentifier(kind) => write!(formatter, "{kind} identifier must be non-zero"),
            Self::ZeroFrameSequence => formatter.write_str("frame sequence must be non-zero"),
            Self::EmptyKeyReference => formatter.write_str("key reference must not be empty"),
            Self::KeyReferenceTooLong(length) => {
                write!(
                    formatter,
                    "key reference length {length} exceeds {KEY_REFERENCE_MAX}"
                )
            }
            Self::InvalidKeyReference => formatter.write_str("key reference is invalid"),
            Self::InvalidKeyReferenceLength(length) => {
                write!(
                    formatter,
                    "key reference has invalid encoded length {length}"
                )
            }
            Self::InvalidPlaintextLength(length) => {
                write!(formatter, "frame has invalid plaintext length {length}")
            }
            Self::InvalidCiphertextLength(length) => {
                write!(formatter, "frame has invalid ciphertext length {length}")
            }
            Self::InvalidRecordFlags(flags) => {
                write!(formatter, "frame has invalid record flags {flags:#04x}")
            }
            Self::CommitCarriesDataFields => {
                formatter.write_str("commit frame carries non-zero data-only fields")
            }
            Self::FrameLengthOverflow => formatter.write_str("frame length overflows"),
            Self::NonZeroReservedBytes => formatter.write_str("reserved format bytes are non-zero"),
        }
    }
}

impl std::error::Error for SegmentFormatError {}

pub(crate) fn frame_checksum(header: &[u8; FRAME_HEADER_LEN], payload: &[u8]) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-segment-frame\0");
    hasher.update(header);
    hasher.update(payload);
    ContentDigest::new(*hasher.finalize().as_bytes())
}

fn decode_data_frame(
    bytes: &[u8; FRAME_HEADER_LEN],
    sequence: u64,
    batch: BatchId,
) -> Result<DataFrameHeader, SegmentFormatError> {
    let flags = bytes[6];
    if flags & !0b11 != 0 {
        return Err(SegmentFormatError::InvalidRecordFlags(flags));
    }
    let kind = RecordKind::from_tag(bytes[5])?;
    let evidence = EvidenceId::new(read_u128(bytes, 32))
        .map_err(|_| SegmentFormatError::ZeroIdentifier("evidence"))?;
    let plaintext_len = read_u32(bytes, 56);
    if plaintext_len == 0 || plaintext_len as usize > RECORD_CHUNK_MAX {
        return Err(SegmentFormatError::InvalidPlaintextLength(plaintext_len));
    }
    let ciphertext_len = read_u32(bytes, 60);
    if ciphertext_len != plaintext_len + AEAD_TAG_LEN as u32 {
        return Err(SegmentFormatError::InvalidCiphertextLength(ciphertext_len));
    }
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&bytes[64..88]);
    Ok(DataFrameHeader {
        sequence,
        batch,
        evidence,
        kind,
        starts_record: flags & 1 != 0,
        ends_record: flags & 2 != 0,
        logical_offset: read_u64(bytes, 48),
        plaintext_len,
        nonce,
        plaintext_digest: digest_from_slice(&bytes[88..120]),
    })
}

fn decode_commit_frame(
    bytes: &[u8; FRAME_HEADER_LEN],
    sequence: u64,
    batch: BatchId,
) -> Result<CommitFrameHeader, SegmentFormatError> {
    if bytes[5] != 0
        || bytes[6] != 0
        || bytes[32..48].iter().any(|byte| *byte != 0)
        || bytes[64..88].iter().any(|byte| *byte != 0)
    {
        return Err(SegmentFormatError::CommitCarriesDataFields);
    }
    let first_sequence = read_u64(bytes, 48);
    let frame_count = NonZeroU64::new(read_u64(bytes, 56))
        .ok_or(SegmentFormatError::ZeroIdentifier("commit frame count"))?;
    Ok(CommitFrameHeader {
        sequence,
        batch,
        first_sequence,
        frame_count,
        batch_digest: digest_from_slice(&bytes[88..120]),
    })
}

fn base_frame(sequence: u64, batch: BatchId) -> [u8; FRAME_HEADER_LEN] {
    let mut bytes = [0_u8; FRAME_HEADER_LEN];
    bytes[..4].copy_from_slice(&FRAME_MAGIC);
    bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
    bytes[16..32].copy_from_slice(&batch.get().to_be_bytes());
    bytes
}

fn schema_fingerprint() -> ContentDigest {
    ContentDigest::for_bytes(SEGMENT_SCHEMA)
}

fn digest_header_prefix(bytes: &[u8]) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-segment-header\0");
    hasher.update(bytes);
    ContentDigest::new(*hasher.finalize().as_bytes())
}

fn digest_from_slice(bytes: &[u8]) -> ContentDigest {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(bytes);
    ContentDigest::new(digest)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("fixed range"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("fixed range"))
}

fn read_u128(bytes: &[u8], offset: usize) -> u128 {
    u128::from_be_bytes(bytes[offset..offset + 16].try_into().expect("fixed range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_header_round_trips_and_rejects_tampering() {
        let header = SegmentHeader::new(
            SegmentId::new(7).expect("segment ID"),
            42,
            KeyReference::new("local/master").expect("key reference"),
        );
        let bytes = header.encode();
        assert_eq!(SegmentHeader::decode(&bytes), Ok(header));

        let mut tampered = bytes;
        tampered[68] ^= 1;
        assert_eq!(
            SegmentHeader::decode(&tampered),
            Err(SegmentFormatError::HeaderDigestMismatch)
        );
    }

    #[test]
    fn frame_sum_types_reject_cross_kind_fields() {
        let header = CommitFrameHeader {
            sequence: 2,
            batch: BatchId::new(3).expect("batch ID"),
            first_sequence: 1,
            frame_count: NonZeroU64::new(1).expect("frame count"),
            batch_digest: ContentDigest::for_bytes(b"batch"),
        };
        let encoded = header.encode().expect("commit frame");
        assert_eq!(
            FrameHeader::decode(&encoded),
            Ok(FrameHeader::Commit(header))
        );

        let mut malformed = encoded;
        malformed[32] = 1;
        assert_eq!(
            FrameHeader::decode(&malformed),
            Err(SegmentFormatError::CommitCarriesDataFields)
        );
    }
}

use std::fmt;

use evidence::{ContentDigest, EvidenceId, OffsetRange, RangeError, SegmentId};

use super::{BatchId, RecordKind, SegmentFormatError};

pub(crate) const STORED_CHUNK_VALUE_LEN: usize = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StoredChunkRef {
    pub segment: SegmentId,
    pub evidence: EvidenceId,
    pub batch: BatchId,
    pub kind: RecordKind,
    pub logical: OffsetRange,
    pub file_offset: u64,
    pub sequence: u64,
    pub plaintext_digest: ContentDigest,
}

impl StoredChunkRef {
    pub(crate) const fn segment(self) -> SegmentId {
        self.segment
    }

    pub(crate) const fn evidence(self) -> EvidenceId {
        self.evidence
    }

    pub(crate) const fn batch(self) -> BatchId {
        self.batch
    }

    pub(crate) const fn kind(self) -> RecordKind {
        self.kind
    }

    pub(crate) const fn logical(self) -> OffsetRange {
        self.logical
    }

    pub(crate) const fn file_offset(self) -> u64 {
        self.file_offset
    }

    pub(crate) const fn sequence(self) -> u64 {
        self.sequence
    }

    pub(crate) const fn plaintext_digest(self) -> ContentDigest {
        self.plaintext_digest
    }
}

pub(crate) fn encode_chunk_value(chunk: StoredChunkRef) -> [u8; STORED_CHUNK_VALUE_LEN] {
    let mut bytes = [0_u8; STORED_CHUNK_VALUE_LEN];
    bytes[..16].copy_from_slice(&chunk.evidence().get().to_be_bytes());
    bytes[16..32].copy_from_slice(&chunk.batch().get().to_be_bytes());
    bytes[32] = chunk.kind().tag();
    bytes[40..48].copy_from_slice(&chunk.logical().length().get().to_be_bytes());
    bytes[48..56].copy_from_slice(&chunk.file_offset().to_be_bytes());
    bytes[56..64].copy_from_slice(&chunk.sequence().to_be_bytes());
    bytes[64..96].copy_from_slice(chunk.plaintext_digest().as_bytes());
    bytes
}

pub(crate) fn decode_chunk_value(
    segment: SegmentId,
    logical_start: u64,
    bytes: &[u8],
) -> Result<StoredChunkRef, ChunkCodecError> {
    if bytes.len() != STORED_CHUNK_VALUE_LEN {
        return Err(ChunkCodecError::Length {
            expected: STORED_CHUNK_VALUE_LEN,
            actual: bytes.len(),
        });
    }
    if bytes[33..40].iter().any(|byte| *byte != 0) {
        return Err(ChunkCodecError::ReservedBytes);
    }
    let evidence = EvidenceId::new(read_u128(bytes, 0))
        .map_err(|_| ChunkCodecError::ZeroIdentifier("evidence"))?;
    let batch = BatchId::new(read_u128(bytes, 16)).map_err(ChunkCodecError::Format)?;
    let kind = RecordKind::from_tag(bytes[32]).map_err(ChunkCodecError::Format)?;
    let logical = OffsetRange::new(logical_start, read_u64(bytes, 40))
        .map_err(ChunkCodecError::InvalidRange)?;
    Ok(StoredChunkRef {
        segment,
        evidence,
        batch,
        kind,
        logical,
        file_offset: read_u64(bytes, 48),
        sequence: read_u64(bytes, 56),
        plaintext_digest: read_digest(bytes, 64),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChunkCodecError {
    Length { expected: usize, actual: usize },
    ReservedBytes,
    ZeroIdentifier(&'static str),
    InvalidRange(RangeError),
    Format(SegmentFormatError),
}

impl fmt::Display for ChunkCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(
                    formatter,
                    "chunk value length is {actual}, expected {expected}"
                )
            }
            Self::ReservedBytes => formatter.write_str("chunk value has non-zero reserved bytes"),
            Self::ZeroIdentifier(kind) => write!(formatter, "chunk {kind} ID is zero"),
            Self::InvalidRange(error) => write!(formatter, "chunk range is invalid: {error}"),
            Self::Format(error) => write!(formatter, "chunk value is invalid: {error}"),
        }
    }
}

impl std::error::Error for ChunkCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRange(error) => Some(error),
            Self::Format(error) => Some(error),
            Self::Length { .. } | Self::ReservedBytes | Self::ZeroIdentifier(_) => None,
        }
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("fixed range"))
}

fn read_u128(bytes: &[u8], offset: usize) -> u128 {
    u128::from_be_bytes(bytes[offset..offset + 16].try_into().expect("fixed range"))
}

fn read_digest(bytes: &[u8], offset: usize) -> ContentDigest {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes[offset..offset + 32]);
    ContentDigest::new(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_chunk_value_round_trips_and_rejects_reserved_bytes() {
        let chunk = StoredChunkRef {
            segment: SegmentId::new(1).expect("segment ID"),
            evidence: EvidenceId::new(2).expect("evidence ID"),
            batch: BatchId::new(3).expect("batch ID"),
            kind: RecordKind::Plaintext,
            logical: OffsetRange::new(4, 5).expect("range"),
            file_offset: 192,
            sequence: 1,
            plaintext_digest: ContentDigest::for_bytes(b"chunk"),
        };
        let encoded = encode_chunk_value(chunk);
        assert_eq!(
            decode_chunk_value(chunk.segment(), chunk.logical().start(), &encoded),
            Ok(chunk)
        );

        let mut malformed = encoded;
        malformed[33] = 1;
        assert_eq!(
            decode_chunk_value(chunk.segment(), chunk.logical().start(), &malformed),
            Err(ChunkCodecError::ReservedBytes)
        );
    }
}

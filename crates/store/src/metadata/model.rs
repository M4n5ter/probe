use evidence::{ByteRangeRef, ContentDigest, EvidenceId, OffsetRange, SegmentId};

use crate::{
    BatchId, RecordKind, SegmentFormatError, SegmentWatermark, StoredRecordRef,
    segment::{
        ChunkCodecError, STORED_CHUNK_VALUE_LEN, StoredChunkRef, decode_chunk_value,
        encode_chunk_value,
    },
};

pub const METADATA_VALUE_MAX: usize = 4096;
pub const RECORD_VALUE_LEN: usize = 88;
pub const CHUNK_VALUE_LEN: usize = STORED_CHUNK_VALUE_LEN;
pub const WATERMARK_VALUE_LEN: usize = 40;
pub const RANGE_VALUE_LEN: usize = 40;
pub const BATCH_MARKER_VALUE_LEN: usize = 96;

const _: () = {
    assert!(RECORD_VALUE_LEN < METADATA_VALUE_MAX);
    assert!(CHUNK_VALUE_LEN < METADATA_VALUE_MAX);
    assert!(WATERMARK_VALUE_LEN < METADATA_VALUE_MAX);
    assert!(RANGE_VALUE_LEN < METADATA_VALUE_MAX);
    assert!(BATCH_MARKER_VALUE_LEN < METADATA_VALUE_MAX);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchMarker {
    pub watermark: SegmentWatermark,
    pub first_logical_offset: u64,
    pub record_count: u64,
    pub chunk_count: u64,
    pub entries_digest: ContentDigest,
}

pub fn evidence_key(evidence: EvidenceId) -> [u8; 16] {
    evidence.get().to_be_bytes()
}

pub fn segment_key(segment: SegmentId) -> [u8; 16] {
    segment.get().to_be_bytes()
}

pub fn batch_key(segment: SegmentId, batch: BatchId) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..16].copy_from_slice(&segment.get().to_be_bytes());
    key[16..].copy_from_slice(&batch.get().to_be_bytes());
    key
}

pub fn range_key(segment: SegmentId, start: u64) -> [u8; 24] {
    let mut key = [0_u8; 24];
    key[..16].copy_from_slice(&segment.get().to_be_bytes());
    key[16..].copy_from_slice(&start.to_be_bytes());
    key
}

pub fn decode_range_key_start(bytes: &[u8]) -> Result<u64, MetadataModelError> {
    require_length("range index key", bytes, 24)?;
    Ok(read_u64(bytes, 16))
}

pub fn encode_record(record: StoredRecordRef) -> [u8; RECORD_VALUE_LEN] {
    let bytes_ref = record.bytes();
    let mut bytes = [0_u8; RECORD_VALUE_LEN];
    bytes[..16].copy_from_slice(&bytes_ref.segment.get().to_be_bytes());
    bytes[16..32].copy_from_slice(&record.batch().get().to_be_bytes());
    bytes[32] = record.kind().tag();
    bytes[40..48].copy_from_slice(&bytes_ref.range.start().to_be_bytes());
    bytes[48..56].copy_from_slice(&bytes_ref.range.length().get().to_be_bytes());
    bytes[56..88].copy_from_slice(bytes_ref.digest.as_bytes());
    bytes
}

pub fn decode_record(
    evidence: EvidenceId,
    bytes: &[u8],
) -> Result<StoredRecordRef, MetadataModelError> {
    require_length("record", bytes, RECORD_VALUE_LEN)?;
    require_reserved_zero("record", &bytes[33..40])?;
    let segment = decode_segment_id(bytes, 0)?;
    let batch = BatchId::new(read_u128(bytes, 16)).map_err(MetadataModelError::Format)?;
    let kind = RecordKind::from_tag(bytes[32]).map_err(MetadataModelError::Format)?;
    let range = decode_range(bytes, 40, 48)?;
    Ok(StoredRecordRef::from_metadata(
        evidence,
        batch,
        kind,
        ByteRangeRef {
            segment,
            range,
            digest: read_digest(bytes, 56),
        },
    ))
}

pub fn encode_chunk(chunk: StoredChunkRef) -> [u8; CHUNK_VALUE_LEN] {
    encode_chunk_value(chunk)
}

pub fn decode_chunk(
    segment: SegmentId,
    logical_start: u64,
    bytes: &[u8],
) -> Result<StoredChunkRef, MetadataModelError> {
    decode_chunk_value(segment, logical_start, bytes).map_err(map_chunk_codec_error)
}

pub fn encode_watermark(watermark: SegmentWatermark) -> [u8; WATERMARK_VALUE_LEN] {
    let mut bytes = [0_u8; WATERMARK_VALUE_LEN];
    bytes[..16].copy_from_slice(&watermark.batch().get().to_be_bytes());
    bytes[16..24].copy_from_slice(&watermark.committed_file_len().to_be_bytes());
    bytes[24..32].copy_from_slice(&watermark.commit_sequence().to_be_bytes());
    bytes[32..40].copy_from_slice(&watermark.logical_len().to_be_bytes());
    bytes
}

pub fn decode_watermark(
    segment: SegmentId,
    bytes: &[u8],
) -> Result<SegmentWatermark, MetadataModelError> {
    require_length("watermark", bytes, WATERMARK_VALUE_LEN)?;
    Ok(SegmentWatermark::from_metadata(
        segment,
        BatchId::new(read_u128(bytes, 0)).map_err(MetadataModelError::Format)?,
        read_u64(bytes, 16),
        read_u64(bytes, 24),
        read_u64(bytes, 32),
    ))
}

pub fn encode_range_value(record: StoredRecordRef) -> [u8; RANGE_VALUE_LEN] {
    let mut bytes = [0_u8; RANGE_VALUE_LEN];
    bytes[..16].copy_from_slice(&record.evidence().get().to_be_bytes());
    bytes[16..24].copy_from_slice(&record.bytes().range.length().get().to_be_bytes());
    bytes[24..40].copy_from_slice(&record.batch().get().to_be_bytes());
    bytes
}

pub fn decode_range_value(bytes: &[u8]) -> Result<(EvidenceId, u64, BatchId), MetadataModelError> {
    require_length("range index", bytes, RANGE_VALUE_LEN)?;
    Ok((
        EvidenceId::new(read_u128(bytes, 0))
            .map_err(|_| MetadataModelError::ZeroIdentifier("evidence"))?,
        read_u64(bytes, 16),
        BatchId::new(read_u128(bytes, 24)).map_err(MetadataModelError::Format)?,
    ))
}

pub fn encode_batch_marker(marker: BatchMarker) -> [u8; BATCH_MARKER_VALUE_LEN] {
    let mut bytes = [0_u8; BATCH_MARKER_VALUE_LEN];
    bytes[..40].copy_from_slice(&encode_watermark(marker.watermark));
    bytes[40..48].copy_from_slice(&marker.first_logical_offset.to_be_bytes());
    bytes[48..56].copy_from_slice(&marker.record_count.to_be_bytes());
    bytes[56..64].copy_from_slice(&marker.chunk_count.to_be_bytes());
    bytes[64..96].copy_from_slice(marker.entries_digest.as_bytes());
    bytes
}

pub fn decode_batch_marker(
    segment: SegmentId,
    bytes: &[u8],
) -> Result<BatchMarker, MetadataModelError> {
    require_length("batch marker", bytes, BATCH_MARKER_VALUE_LEN)?;
    Ok(BatchMarker {
        watermark: decode_watermark(segment, &bytes[..40])?,
        first_logical_offset: read_u64(bytes, 40),
        record_count: read_u64(bytes, 48),
        chunk_count: read_u64(bytes, 56),
        entries_digest: read_digest(bytes, 64),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataModelError {
    Length {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
    ReservedBytes(&'static str),
    ZeroIdentifier(&'static str),
    InvalidRange,
    Format(SegmentFormatError),
}

impl std::fmt::Display for MetadataModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length {
                kind,
                expected,
                actual,
            } => write!(
                formatter,
                "{kind} metadata length is {actual}, expected {expected}"
            ),
            Self::ReservedBytes(kind) => {
                write!(formatter, "{kind} metadata has non-zero reserved bytes")
            }
            Self::ZeroIdentifier(kind) => write!(formatter, "{kind} metadata ID is zero"),
            Self::InvalidRange => formatter.write_str("metadata contains an invalid byte range"),
            Self::Format(error) => write!(formatter, "metadata contains invalid data: {error}"),
        }
    }
}

impl std::error::Error for MetadataModelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            _ => None,
        }
    }
}

fn require_length(
    kind: &'static str,
    bytes: &[u8],
    expected: usize,
) -> Result<(), MetadataModelError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(MetadataModelError::Length {
            kind,
            expected,
            actual: bytes.len(),
        })
    }
}

fn map_chunk_codec_error(error: ChunkCodecError) -> MetadataModelError {
    match error {
        ChunkCodecError::Length { expected, actual } => MetadataModelError::Length {
            kind: "chunk",
            expected,
            actual,
        },
        ChunkCodecError::ReservedBytes => MetadataModelError::ReservedBytes("chunk"),
        ChunkCodecError::ZeroIdentifier(kind) => MetadataModelError::ZeroIdentifier(kind),
        ChunkCodecError::InvalidRange(_) => MetadataModelError::InvalidRange,
        ChunkCodecError::Format(error) => MetadataModelError::Format(error),
    }
}

fn require_reserved_zero(kind: &'static str, bytes: &[u8]) -> Result<(), MetadataModelError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(MetadataModelError::ReservedBytes(kind))
    }
}

fn decode_segment_id(bytes: &[u8], offset: usize) -> Result<SegmentId, MetadataModelError> {
    SegmentId::new(read_u128(bytes, offset))
        .map_err(|_| MetadataModelError::ZeroIdentifier("segment"))
}

fn decode_range(
    bytes: &[u8],
    start_offset: usize,
    length_offset: usize,
) -> Result<OffsetRange, MetadataModelError> {
    OffsetRange::new(
        read_u64(bytes, start_offset),
        read_u64(bytes, length_offset),
    )
    .map_err(|_| MetadataModelError::InvalidRange)
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
    use std::error::Error;

    use super::*;

    #[test]
    fn fixed_metadata_values_are_bounded_and_reject_reserved_bytes() {
        let evidence = EvidenceId::new(1).expect("evidence ID");
        let mut record = [0_u8; RECORD_VALUE_LEN];
        record[33] = 1;
        assert_eq!(
            decode_record(evidence, &record),
            Err(MetadataModelError::ReservedBytes("record"))
        );

        let segment = SegmentId::new(1).expect("segment ID");
        let mut chunk = [0_u8; CHUNK_VALUE_LEN];
        chunk[33] = 1;
        assert_eq!(
            decode_chunk(segment, 0, &chunk),
            Err(MetadataModelError::ReservedBytes("chunk"))
        );

        let format = MetadataModelError::Format(SegmentFormatError::UnknownRecordKind(255));
        assert!(format.source().is_some());
    }
}

use std::{fmt, fs::File, num::NonZeroUsize};

use evidence::{ContentDigest, EvidenceId, OffsetRange, SegmentId};
use redb::{
    Database, Durability, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition,
};

use crate::{
    AEAD_TAG_LEN, ChunkJournalSnapshot, DurabilityProfile, FRAME_CHECKSUM_LEN, FRAME_HEADER_LEN,
    SEGMENT_HEADER_LEN, SegmentWatermark, StoredRecordRef,
    metadata::model::{
        BatchMarker, METADATA_VALUE_MAX, MetadataModelError, batch_key, decode_batch_marker,
        decode_chunk, decode_range_key_start, decode_range_value, decode_record, decode_watermark,
        encode_batch_marker, encode_chunk, encode_range_value, encode_record, encode_watermark,
        evidence_key, range_key, segment_key,
    },
    segment::StoredChunkRef,
};

const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("evidence_records");
const SEGMENT_RANGES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("segment_ranges");
const SEGMENT_CHUNKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("segment_chunks");
const BATCH_MARKERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("batch_markers");
const WATERMARKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("segment_watermarks");
const COMMIT_FRAME_PHYSICAL_LEN: u64 = (FRAME_HEADER_LEN + FRAME_CHECKSUM_LEN) as u64;
const DATA_FRAME_OVERHEAD: u64 = (FRAME_HEADER_LEN + AEAD_TAG_LEN + FRAME_CHECKSUM_LEN) as u64;

pub(crate) struct MetadataStore {
    database: Database,
    durability: DurabilityProfile,
}

impl MetadataStore {
    pub(crate) fn open(file: File, durability: DurabilityProfile) -> Result<Self, MetadataError> {
        let database = Database::builder()
            .create_file(file)
            .map_err(engine_error)?;
        initialize_tables(&database)?;
        Ok(Self {
            database,
            durability,
        })
    }

    pub(crate) fn publish_batch(
        &self,
        watermark: SegmentWatermark,
        records: &[StoredRecordRef],
        chunks: &ChunkJournalSnapshot,
    ) -> Result<PublishOutcome, MetadataError> {
        let first_chunk = validate_batch_shape(watermark, records, chunks)?;
        let marker = batch_marker(watermark, records, chunks)?;
        let mut transaction = self.database.begin_write().map_err(engine_error)?;
        transaction
            .set_durability(match self.durability {
                DurabilityProfile::PowerLoss | DurabilityProfile::ProcessCrash => {
                    Durability::Immediate
                }
                DurabilityProfile::BestEffort => Durability::None,
            })
            .map_err(engine_error)?;
        transaction.set_quick_repair(self.durability != DurabilityProfile::BestEffort);

        let previous = {
            let table = transaction.open_table(WATERMARKS).map_err(engine_error)?;
            table
                .get(segment_key(watermark.segment()).as_slice())
                .map_err(engine_error)?
                .map(|value| decode_watermark(watermark.segment(), value.value()))
                .transpose()
                .map_err(MetadataError::Model)?
        };
        if previous == Some(watermark) {
            verify_existing(&transaction, marker, records, chunks)?;
            return Ok(PublishOutcome::AlreadyPublished);
        }
        validate_watermark_advance(previous, watermark, records, first_chunk)?;

        insert_records(&transaction, records)?;
        insert_range_indexes(&transaction, records)?;
        insert_chunk_indexes(&transaction, chunks)?;
        insert_batch_marker(&transaction, marker)?;
        insert_watermark(&transaction, watermark)?;
        transaction.commit().map_err(engine_error)?;
        Ok(PublishOutcome::Published)
    }

    pub(crate) fn snapshot(&self) -> Result<MetadataSnapshot, MetadataError> {
        Ok(MetadataSnapshot {
            transaction: self.database.begin_read().map_err(engine_error)?,
        })
    }
}

pub struct MetadataSnapshot {
    transaction: ReadTransaction,
}

impl MetadataSnapshot {
    pub fn record(&self, evidence: EvidenceId) -> Result<Option<StoredRecordRef>, MetadataError> {
        let table = self.transaction.open_table(RECORDS).map_err(engine_error)?;
        table
            .get(evidence_key(evidence).as_slice())
            .map_err(engine_error)?
            .map(|value| decode_record(evidence, value.value()))
            .transpose()
            .map_err(MetadataError::Model)
    }

    pub fn watermark(&self, segment: SegmentId) -> Result<Option<SegmentWatermark>, MetadataError> {
        let table = self
            .transaction
            .open_table(WATERMARKS)
            .map_err(engine_error)?;
        table
            .get(segment_key(segment).as_slice())
            .map_err(engine_error)?
            .map(|value| decode_watermark(segment, value.value()))
            .transpose()
            .map_err(MetadataError::Model)
    }

    pub fn visit_segment_records(
        &self,
        segment: SegmentId,
        range: OffsetRange,
        limit: NonZeroUsize,
        mut visitor: impl FnMut(StoredRecordRef) -> Result<(), MetadataError>,
    ) -> Result<usize, MetadataError> {
        let table = self
            .transaction
            .open_table(SEGMENT_RANGES)
            .map_err(engine_error)?;
        let segment_start = range_key(segment, 0);
        let start = range_key(segment, range.start());
        let end = range_key(segment, range.end());
        let mut visited = 0;
        {
            let mut preceding = table
                .range(segment_start.as_slice()..=start.as_slice())
                .map_err(engine_error)?;
            if let Some(entry) = preceding.next_back() {
                let (key, value) = entry.map_err(engine_error)?;
                let record_start =
                    decode_range_key_start(key.value()).map_err(MetadataError::Model)?;
                if record_start < range.start() {
                    let (evidence, length, batch) =
                        decode_range_value(value.value()).map_err(MetadataError::Model)?;
                    if range_end(record_start, length)? > range.start() {
                        visitor(self.indexed_record(
                            segment,
                            record_start,
                            length,
                            batch,
                            evidence,
                        )?)?;
                        visited += 1;
                        if visited == limit.get() {
                            return Ok(visited);
                        }
                    }
                }
            }
        }
        for entry in table
            .range(start.as_slice()..end.as_slice())
            .map_err(engine_error)?
        {
            let (key, value) = entry.map_err(engine_error)?;
            let record_start = decode_range_key_start(key.value()).map_err(MetadataError::Model)?;
            let (evidence, length, batch) =
                decode_range_value(value.value()).map_err(MetadataError::Model)?;
            visitor(self.indexed_record(segment, record_start, length, batch, evidence)?)?;
            visited += 1;
            if visited == limit.get() {
                break;
            }
        }
        Ok(visited)
    }

    pub(crate) fn chunks_for_record(
        &self,
        record: StoredRecordRef,
        query: OffsetRange,
    ) -> Result<Vec<StoredChunkRef>, MetadataError> {
        let record_bytes = record.bytes();
        let start_offset = query.start().max(record_bytes.range.start());
        let end_offset = query.end().min(record_bytes.range.end());
        if start_offset >= end_offset {
            return Ok(Vec::new());
        }

        let table = self
            .transaction
            .open_table(SEGMENT_CHUNKS)
            .map_err(engine_error)?;
        let segment_start = range_key(record_bytes.segment, 0);
        let start = range_key(record_bytes.segment, start_offset);
        let end = range_key(record_bytes.segment, end_offset);
        let mut chunks = Vec::new();
        {
            let mut preceding = table
                .range(segment_start.as_slice()..=start.as_slice())
                .map_err(engine_error)?;
            if let Some(entry) = preceding.next_back() {
                let (key, value) = entry.map_err(engine_error)?;
                let logical_start =
                    decode_range_key_start(key.value()).map_err(MetadataError::Model)?;
                if logical_start < start_offset {
                    let chunk = decode_chunk(record_bytes.segment, logical_start, value.value())
                        .map_err(MetadataError::Model)?;
                    if chunk.logical().end() > start_offset {
                        require_chunk_identity(record, chunk)?;
                        chunks.push(chunk);
                    }
                }
            }
        }
        for entry in table
            .range(start.as_slice()..end.as_slice())
            .map_err(engine_error)?
        {
            let (key, value) = entry.map_err(engine_error)?;
            let logical_start =
                decode_range_key_start(key.value()).map_err(MetadataError::Model)?;
            let chunk = decode_chunk(record_bytes.segment, logical_start, value.value())
                .map_err(MetadataError::Model)?;
            require_chunk_identity(record, chunk)?;
            chunks.push(chunk);
        }
        Ok(chunks)
    }

    fn indexed_record(
        &self,
        segment: SegmentId,
        start: u64,
        length: u64,
        batch: crate::BatchId,
        evidence: EvidenceId,
    ) -> Result<StoredRecordRef, MetadataError> {
        let record = self
            .record(evidence)?
            .ok_or(MetadataError::DanglingRangeIndex(evidence))?;
        let bytes = record.bytes();
        if bytes.segment != segment
            || bytes.range.start() != start
            || bytes.range.length().get() != length
            || record.batch() != batch
        {
            return Err(MetadataError::CorruptRangeIndex { segment, start });
        }
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    Published,
    AlreadyPublished,
}

#[derive(Debug)]
pub enum MetadataError {
    Engine(redb::Error),
    Model(MetadataModelError),
    DescriptorReplay(Box<dyn std::error::Error + Send + Sync>),
    EmptyBatch,
    EmptyChunkSet,
    BatchMismatch,
    SegmentMismatch,
    DiscontinuousRecords,
    DiscontinuousChunks,
    IncompleteLogicalCoverage,
    ChunkRecordMismatch { segment: SegmentId, start: u64 },
    InvalidChunkPhysicalOrder { segment: SegmentId, start: u64 },
    ChunkBeyondCommit { segment: SegmentId, start: u64 },
    WatermarkRegression,
    ConflictingEvidence(EvidenceId),
    ConflictingRange { segment: SegmentId, start: u64 },
    ConflictingChunk { segment: SegmentId, start: u64 },
    ConflictingBatch(crate::BatchId),
    DanglingRangeIndex(EvidenceId),
    CorruptRangeIndex { segment: SegmentId, start: u64 },
    MetadataValueTooLarge(usize),
}

impl fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(formatter, "metadata engine failed: {error}"),
            Self::Model(error) => write!(formatter, "invalid metadata record: {error}"),
            Self::DescriptorReplay(error) => {
                write!(formatter, "chunk descriptor replay failed: {error}")
            }
            Self::EmptyBatch => formatter.write_str("metadata batch must not be empty"),
            Self::EmptyChunkSet => formatter.write_str("metadata batch must contain chunks"),
            Self::BatchMismatch => {
                formatter.write_str("record or chunk batch does not match watermark")
            }
            Self::SegmentMismatch => {
                formatter.write_str("record or chunk segment does not match watermark")
            }
            Self::DiscontinuousRecords => {
                formatter.write_str("metadata record ranges are not exactly continuous")
            }
            Self::DiscontinuousChunks => {
                formatter.write_str("metadata chunk ranges are not exactly continuous")
            }
            Self::IncompleteLogicalCoverage => formatter.write_str(
                "metadata records and chunks do not exactly cover the newly committed logical range",
            ),
            Self::ChunkRecordMismatch { segment, start } => write!(
                formatter,
                "segment {} chunk at logical offset {start} does not match its record",
                segment.get()
            ),
            Self::InvalidChunkPhysicalOrder { segment, start } => write!(
                formatter,
                "segment {} chunk at logical offset {start} is not in physical frame order",
                segment.get()
            ),
            Self::ChunkBeyondCommit { segment, start } => write!(
                formatter,
                "segment {} chunk at logical offset {start} reaches or exceeds its commit marker",
                segment.get()
            ),
            Self::WatermarkRegression => {
                formatter.write_str("segment watermark does not advance monotonically")
            }
            Self::ConflictingEvidence(evidence) => write!(
                formatter,
                "evidence {} already has different metadata",
                evidence.get()
            ),
            Self::ConflictingRange { segment, start } => write!(
                formatter,
                "segment {} logical offset {start} already has a different record",
                segment.get()
            ),
            Self::ConflictingChunk { segment, start } => write!(
                formatter,
                "segment {} logical offset {start} already has a different chunk",
                segment.get()
            ),
            Self::ConflictingBatch(batch) => write!(
                formatter,
                "batch {} already has a different marker",
                batch.get()
            ),
            Self::DanglingRangeIndex(evidence) => write!(
                formatter,
                "range index references missing evidence {}",
                evidence.get()
            ),
            Self::CorruptRangeIndex { segment, start } => write!(
                formatter,
                "segment {} range index at logical offset {start} does not match its record",
                segment.get()
            ),
            Self::MetadataValueTooLarge(length) => write!(
                formatter,
                "metadata value length {length} is not below {METADATA_VALUE_MAX}"
            ),
        }
    }
}

impl std::error::Error for MetadataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::DescriptorReplay(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

fn validate_batch_shape(
    watermark: SegmentWatermark,
    records: &[StoredRecordRef],
    chunks: &ChunkJournalSnapshot,
) -> Result<StoredChunkRef, MetadataError> {
    if records.is_empty() {
        return Err(MetadataError::EmptyBatch);
    }
    if chunks.is_empty() {
        return Err(MetadataError::EmptyChunkSet);
    }
    validate_record_chain(watermark, records)?;
    let first = validate_chunk_chain(watermark, records, chunks)?;
    if records[0].bytes().range.start() != first.logical().start() {
        return Err(MetadataError::IncompleteLogicalCoverage);
    }
    Ok(first)
}

fn validate_record_chain(
    watermark: SegmentWatermark,
    records: &[StoredRecordRef],
) -> Result<(), MetadataError> {
    let mut previous_end = records[0].bytes().range.start();
    for record in records {
        let bytes = record.bytes();
        if record.batch() != watermark.batch() {
            return Err(MetadataError::BatchMismatch);
        }
        if bytes.segment != watermark.segment() {
            return Err(MetadataError::SegmentMismatch);
        }
        if bytes.range.start() != previous_end {
            return Err(MetadataError::DiscontinuousRecords);
        }
        previous_end = bytes.range.end();
    }
    if previous_end != watermark.logical_len() {
        return Err(MetadataError::IncompleteLogicalCoverage);
    }
    Ok(())
}

fn validate_chunk_chain(
    watermark: SegmentWatermark,
    records: &[StoredRecordRef],
    chunks: &ChunkJournalSnapshot,
) -> Result<StoredChunkRef, MetadataError> {
    let commit_start = watermark
        .committed_file_len()
        .checked_sub(COMMIT_FRAME_PHYSICAL_LEN)
        .ok_or(MetadataError::ChunkBeyondCommit {
            segment: watermark.segment(),
            start: records[0].bytes().range.start(),
        })?;
    let mut first = None;
    let mut previous_logical_end = None;
    let mut previous_physical_end = None;
    let mut previous_sequence = None;
    let mut record_index = 0;
    for chunk in chunks.iter() {
        let chunk = chunk.map_err(descriptor_replay_error)?;
        let logical = chunk.logical();
        first.get_or_insert(chunk);
        if chunk.batch() != watermark.batch() {
            return Err(MetadataError::BatchMismatch);
        }
        if chunk.segment() != watermark.segment() {
            return Err(MetadataError::SegmentMismatch);
        }
        if previous_logical_end.is_some_and(|end| logical.start() != end) {
            return Err(MetadataError::DiscontinuousChunks);
        }
        let physical_end = chunk
            .file_offset()
            .checked_add(DATA_FRAME_OVERHEAD)
            .and_then(|offset| offset.checked_add(logical.length().get()))
            .ok_or(MetadataError::ChunkBeyondCommit {
                segment: chunk.segment(),
                start: logical.start(),
            })?;
        if previous_physical_end.is_some_and(|end| chunk.file_offset() != end)
            || previous_sequence
                .and_then(|sequence: u64| sequence.checked_add(1))
                .is_some_and(|sequence| chunk.sequence() != sequence)
        {
            return Err(MetadataError::InvalidChunkPhysicalOrder {
                segment: chunk.segment(),
                start: logical.start(),
            });
        }
        if chunk.file_offset() < SEGMENT_HEADER_LEN as u64
            || chunk.sequence() == 0
            || physical_end > commit_start
            || chunk.sequence() >= watermark.commit_sequence()
        {
            return Err(MetadataError::ChunkBeyondCommit {
                segment: chunk.segment(),
                start: logical.start(),
            });
        }
        previous_logical_end = Some(logical.end());
        previous_physical_end = Some(physical_end);
        previous_sequence = Some(chunk.sequence());
        while record_index + 1 < records.len()
            && logical.start() >= records[record_index].bytes().range.end()
        {
            record_index += 1;
        }
        let record = records[record_index];
        let record_range = record.bytes().range;
        if logical.start() < record_range.start()
            || logical.end() > record_range.end()
            || chunk.evidence() != record.evidence()
            || chunk.batch() != record.batch()
            || chunk.kind() != record.kind()
        {
            return Err(MetadataError::ChunkRecordMismatch {
                segment: chunk.segment(),
                start: chunk.logical().start(),
            });
        }
    }
    if previous_logical_end != Some(watermark.logical_len()) {
        return Err(MetadataError::IncompleteLogicalCoverage);
    }
    if previous_physical_end != Some(commit_start)
        || previous_sequence.and_then(|sequence| sequence.checked_add(1))
            != Some(watermark.commit_sequence())
    {
        return Err(MetadataError::InvalidChunkPhysicalOrder {
            segment: watermark.segment(),
            start: previous_logical_end.unwrap_or(0),
        });
    }
    first.ok_or(MetadataError::EmptyChunkSet)
}

fn validate_watermark_advance(
    previous: Option<SegmentWatermark>,
    next: SegmentWatermark,
    records: &[StoredRecordRef],
    first_chunk: StoredChunkRef,
) -> Result<(), MetadataError> {
    let previous_logical = previous.map_or(0, SegmentWatermark::logical_len);
    if records[0].bytes().range.start() != previous_logical
        || first_chunk.logical().start() != previous_logical
    {
        return Err(MetadataError::IncompleteLogicalCoverage);
    }
    let expected_file_offset = previous.map_or(SEGMENT_HEADER_LEN as u64, |watermark| {
        watermark.committed_file_len()
    });
    let expected_sequence = previous.map_or(Some(1), |watermark| {
        watermark.commit_sequence().checked_add(1)
    });
    if first_chunk.file_offset() != expected_file_offset
        || Some(first_chunk.sequence()) != expected_sequence
    {
        return Err(MetadataError::InvalidChunkPhysicalOrder {
            segment: first_chunk.segment(),
            start: first_chunk.logical().start(),
        });
    }
    if let Some(previous) = previous
        && (next.commit_sequence() <= previous.commit_sequence()
            || next.committed_file_len() <= previous.committed_file_len()
            || next.logical_len() <= previous.logical_len())
    {
        return Err(MetadataError::WatermarkRegression);
    }
    Ok(())
}

fn batch_marker(
    watermark: SegmentWatermark,
    records: &[StoredRecordRef],
    chunks: &ChunkJournalSnapshot,
) -> Result<BatchMarker, MetadataError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-metadata-batch-entries\0");
    hasher.update(&(records.len() as u64).to_be_bytes());
    hasher.update(&chunks.len().to_be_bytes());
    for record in records {
        hasher.update(b"record\0");
        hasher.update(&evidence_key(record.evidence()));
        hasher.update(&encode_record(*record));
    }
    for chunk in chunks.iter() {
        let chunk = chunk.map_err(descriptor_replay_error)?;
        hasher.update(b"chunk\0");
        hasher.update(&range_key(chunk.segment(), chunk.logical().start()));
        hasher.update(&encode_chunk(chunk));
    }
    Ok(BatchMarker {
        watermark,
        first_logical_offset: records[0].bytes().range.start(),
        record_count: records.len() as u64,
        chunk_count: chunks.len(),
        entries_digest: ContentDigest::new(*hasher.finalize().as_bytes()),
    })
}

fn insert_records(
    transaction: &redb::WriteTransaction,
    records: &[StoredRecordRef],
) -> Result<(), MetadataError> {
    let mut table = transaction.open_table(RECORDS).map_err(engine_error)?;
    for record in records {
        let key = evidence_key(record.evidence());
        let value = encode_record(*record);
        ensure_metadata_bound(value.len())?;
        if let Some(existing) = table.get(key.as_slice()).map_err(engine_error)?
            && existing.value() != value
        {
            return Err(MetadataError::ConflictingEvidence(record.evidence()));
        }
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(engine_error)?;
    }
    Ok(())
}

fn insert_range_indexes(
    transaction: &redb::WriteTransaction,
    records: &[StoredRecordRef],
) -> Result<(), MetadataError> {
    let mut table = transaction
        .open_table(SEGMENT_RANGES)
        .map_err(engine_error)?;
    for record in records {
        let bytes = record.bytes();
        let key = range_key(bytes.segment, bytes.range.start());
        let value = encode_range_value(*record);
        ensure_metadata_bound(value.len())?;
        if let Some(existing) = table.get(key.as_slice()).map_err(engine_error)?
            && existing.value() != value
        {
            return Err(MetadataError::ConflictingRange {
                segment: bytes.segment,
                start: bytes.range.start(),
            });
        }
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(engine_error)?;
    }
    Ok(())
}

fn insert_chunk_indexes(
    transaction: &redb::WriteTransaction,
    chunks: &ChunkJournalSnapshot,
) -> Result<(), MetadataError> {
    let mut table = transaction
        .open_table(SEGMENT_CHUNKS)
        .map_err(engine_error)?;
    for chunk in chunks.iter() {
        let chunk = chunk.map_err(descriptor_replay_error)?;
        let key = range_key(chunk.segment(), chunk.logical().start());
        let value = encode_chunk(chunk);
        ensure_metadata_bound(value.len())?;
        if let Some(existing) = table.get(key.as_slice()).map_err(engine_error)?
            && existing.value() != value
        {
            return Err(MetadataError::ConflictingChunk {
                segment: chunk.segment(),
                start: chunk.logical().start(),
            });
        }
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(engine_error)?;
    }
    Ok(())
}

fn insert_batch_marker(
    transaction: &redb::WriteTransaction,
    marker: BatchMarker,
) -> Result<(), MetadataError> {
    let mut table = transaction
        .open_table(BATCH_MARKERS)
        .map_err(engine_error)?;
    let key = batch_key(marker.watermark.segment(), marker.watermark.batch());
    if table.get(key.as_slice()).map_err(engine_error)?.is_some() {
        return Err(MetadataError::ConflictingBatch(marker.watermark.batch()));
    }
    let value = encode_batch_marker(marker);
    ensure_metadata_bound(value.len())?;
    table
        .insert(key.as_slice(), value.as_slice())
        .map_err(engine_error)?;
    Ok(())
}

fn insert_watermark(
    transaction: &redb::WriteTransaction,
    watermark: SegmentWatermark,
) -> Result<(), MetadataError> {
    let mut table = transaction.open_table(WATERMARKS).map_err(engine_error)?;
    let value = encode_watermark(watermark);
    ensure_metadata_bound(value.len())?;
    table
        .insert(
            segment_key(watermark.segment()).as_slice(),
            value.as_slice(),
        )
        .map_err(engine_error)?;
    Ok(())
}

fn verify_existing(
    transaction: &redb::WriteTransaction,
    marker: BatchMarker,
    records: &[StoredRecordRef],
    chunks: &ChunkJournalSnapshot,
) -> Result<(), MetadataError> {
    verify_batch_marker(transaction, marker)?;
    verify_records(transaction, records)?;
    verify_range_indexes(transaction, records)?;
    verify_chunk_indexes(transaction, chunks)
}

fn verify_batch_marker(
    transaction: &redb::WriteTransaction,
    marker: BatchMarker,
) -> Result<(), MetadataError> {
    let table = transaction
        .open_table(BATCH_MARKERS)
        .map_err(engine_error)?;
    let key = batch_key(marker.watermark.segment(), marker.watermark.batch());
    let expected = encode_batch_marker(marker);
    let Some(actual) = table.get(key.as_slice()).map_err(engine_error)? else {
        return Err(MetadataError::ConflictingBatch(marker.watermark.batch()));
    };
    let decoded = decode_batch_marker(marker.watermark.segment(), actual.value())
        .map_err(MetadataError::Model)?;
    if actual.value() != expected || decoded != marker {
        return Err(MetadataError::ConflictingBatch(marker.watermark.batch()));
    }
    Ok(())
}

fn verify_records(
    transaction: &redb::WriteTransaction,
    records: &[StoredRecordRef],
) -> Result<(), MetadataError> {
    let table = transaction.open_table(RECORDS).map_err(engine_error)?;
    for record in records {
        let key = evidence_key(record.evidence());
        let expected = encode_record(*record);
        let Some(actual) = table.get(key.as_slice()).map_err(engine_error)? else {
            return Err(MetadataError::ConflictingEvidence(record.evidence()));
        };
        if actual.value() != expected {
            return Err(MetadataError::ConflictingEvidence(record.evidence()));
        }
    }
    Ok(())
}

fn verify_range_indexes(
    transaction: &redb::WriteTransaction,
    records: &[StoredRecordRef],
) -> Result<(), MetadataError> {
    let table = transaction
        .open_table(SEGMENT_RANGES)
        .map_err(engine_error)?;
    for record in records {
        let bytes = record.bytes();
        let key = range_key(bytes.segment, bytes.range.start());
        let expected = encode_range_value(*record);
        let Some(actual) = table.get(key.as_slice()).map_err(engine_error)? else {
            return Err(MetadataError::ConflictingRange {
                segment: bytes.segment,
                start: bytes.range.start(),
            });
        };
        if actual.value() != expected {
            return Err(MetadataError::ConflictingRange {
                segment: bytes.segment,
                start: bytes.range.start(),
            });
        }
    }
    Ok(())
}

fn verify_chunk_indexes(
    transaction: &redb::WriteTransaction,
    chunks: &ChunkJournalSnapshot,
) -> Result<(), MetadataError> {
    let table = transaction
        .open_table(SEGMENT_CHUNKS)
        .map_err(engine_error)?;
    for chunk in chunks.iter() {
        let chunk = chunk.map_err(descriptor_replay_error)?;
        let key = range_key(chunk.segment(), chunk.logical().start());
        let expected = encode_chunk(chunk);
        let Some(actual) = table.get(key.as_slice()).map_err(engine_error)? else {
            return Err(MetadataError::ConflictingChunk {
                segment: chunk.segment(),
                start: chunk.logical().start(),
            });
        };
        if actual.value() != expected {
            return Err(MetadataError::ConflictingChunk {
                segment: chunk.segment(),
                start: chunk.logical().start(),
            });
        }
    }
    Ok(())
}

fn require_chunk_identity(
    record: StoredRecordRef,
    chunk: StoredChunkRef,
) -> Result<(), MetadataError> {
    let record_bytes = record.bytes();
    if chunk.segment() != record_bytes.segment
        || chunk.evidence() != record.evidence()
        || chunk.batch() != record.batch()
        || chunk.kind() != record.kind()
        || chunk.logical().start() < record_bytes.range.start()
        || chunk.logical().end() > record_bytes.range.end()
    {
        return Err(MetadataError::ChunkRecordMismatch {
            segment: chunk.segment(),
            start: chunk.logical().start(),
        });
    }
    Ok(())
}

fn range_end(start: u64, length: u64) -> Result<u64, MetadataError> {
    start
        .checked_add(length)
        .ok_or(MetadataError::Model(MetadataModelError::InvalidRange))
}

fn ensure_metadata_bound(length: usize) -> Result<(), MetadataError> {
    if length >= METADATA_VALUE_MAX {
        Err(MetadataError::MetadataValueTooLarge(length))
    } else {
        Ok(())
    }
}

fn initialize_tables(database: &Database) -> Result<(), MetadataError> {
    let mut transaction = database.begin_write().map_err(engine_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(engine_error)?;
    transaction.set_quick_repair(true);
    {
        transaction.open_table(RECORDS).map_err(engine_error)?;
    }
    {
        transaction
            .open_table(SEGMENT_RANGES)
            .map_err(engine_error)?;
    }
    {
        transaction
            .open_table(SEGMENT_CHUNKS)
            .map_err(engine_error)?;
    }
    {
        transaction
            .open_table(BATCH_MARKERS)
            .map_err(engine_error)?;
    }
    {
        transaction.open_table(WATERMARKS).map_err(engine_error)?;
    }
    transaction.commit().map_err(engine_error)
}

fn engine_error(error: impl Into<redb::Error>) -> MetadataError {
    MetadataError::Engine(error.into())
}

fn descriptor_replay_error(error: crate::segment::ChunkJournalError) -> MetadataError {
    MetadataError::DescriptorReplay(Box::new(error))
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs::OpenOptions,
        io,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use evidence::{ByteRangeRef, ContentDigest};
    use redb::{ReadableTableMetadata, StorageBackend, backends::FileBackend};
    use tempfile::{NamedTempFile, tempfile};

    use super::*;
    use crate::{BatchId, RecordKind};

    #[test]
    fn snapshots_keep_record_chunk_and_watermark_boundaries_atomic() {
        let store = metadata_store(DurabilityProfile::PowerLoss);
        let first = fixture(1, 0, 192, 1, &[(1, RecordKind::Packet, &[5])]);
        assert_eq!(publish(&store, &first), PublishOutcome::Published);
        let old_snapshot = store.snapshot().expect("old snapshot");

        let second = fixture(
            2,
            first.watermark.logical_len(),
            first.watermark.committed_file_len(),
            first.watermark.commit_sequence() + 1,
            &[(2, RecordKind::Plaintext, &[3, 4])],
        );
        assert_eq!(publish(&store, &second), PublishOutcome::Published);

        assert_eq!(
            old_snapshot.watermark(segment()).expect("old watermark"),
            Some(first.watermark)
        );
        assert_eq!(
            old_snapshot
                .record(second.records[0].evidence())
                .expect("old record"),
            None
        );
        assert!(
            old_snapshot
                .chunks_for_record(second.records[0], second.records[0].bytes().range)
                .expect("old chunks")
                .is_empty()
        );

        let current = store.snapshot().expect("current snapshot");
        assert_eq!(
            current.watermark(segment()).expect("current watermark"),
            Some(second.watermark)
        );
        assert_eq!(
            current
                .chunks_for_record(second.records[0], second.records[0].bytes().range)
                .expect("current chunks"),
            second.chunks
        );
    }

    #[test]
    fn rejects_internal_record_and_chunk_gaps() {
        let store = metadata_store(DurabilityProfile::ProcessCrash);
        let valid = fixture(
            1,
            0,
            192,
            1,
            &[
                (1, RecordKind::Packet, &[4]),
                (2, RecordKind::Plaintext, &[4]),
            ],
        );
        let mut gapped_records = valid.records.clone();
        gapped_records[1] = stored_record(
            2,
            1,
            RecordKind::Plaintext,
            OffsetRange::new(5, 3).expect("gapped range"),
        );
        let valid_chunks = chunk_journal(&valid.chunks);
        assert!(matches!(
            store.publish_batch(valid.watermark, &gapped_records, &valid_chunks),
            Err(MetadataError::DiscontinuousRecords)
        ));

        let mut gapped_chunks = valid.chunks.clone();
        let chunk = gapped_chunks[1];
        gapped_chunks[1] = stored_chunk(
            chunk.evidence().get(),
            chunk.batch().get(),
            chunk.kind(),
            OffsetRange::new(5, 3).expect("gapped chunk"),
            chunk.file_offset(),
            chunk.sequence(),
        );
        let gapped_chunks = chunk_journal(&gapped_chunks);
        assert!(matches!(
            store.publish_batch(valid.watermark, &valid.records, &gapped_chunks),
            Err(MetadataError::DiscontinuousChunks)
        ));
    }

    #[test]
    fn exact_set_retry_is_idempotent_but_subset_with_same_watermark_fails() {
        let store = metadata_store(DurabilityProfile::ProcessCrash);
        let batch = fixture(
            1,
            0,
            192,
            1,
            &[
                (1, RecordKind::Packet, &[4]),
                (2, RecordKind::Plaintext, &[3, 5]),
            ],
        );
        assert_eq!(publish(&store, &batch), PublishOutcome::Published);
        assert_eq!(publish(&store, &batch), PublishOutcome::AlreadyPublished);

        let subset_chunks = chunk_journal(&batch.chunks[1..]);
        assert!(matches!(
            store.publish_batch(batch.watermark, &batch.records[1..], &subset_chunks),
            Err(MetadataError::ConflictingBatch(_))
        ));
    }

    #[test]
    fn direct_chunk_lookup_returns_only_query_overlaps() {
        let store = metadata_store(DurabilityProfile::BestEffort);
        let batch = fixture(1, 0, 192, 1, &[(1, RecordKind::Plaintext, &[4, 4, 4])]);
        publish(&store, &batch);
        let snapshot = store.snapshot().expect("snapshot");

        let across_boundary = snapshot
            .chunks_for_record(batch.records[0], OffsetRange::new(3, 3).expect("query"))
            .expect("chunks");
        assert_eq!(across_boundary, batch.chunks[..2]);

        let exact_middle = snapshot
            .chunks_for_record(batch.records[0], OffsetRange::new(4, 4).expect("query"))
            .expect("chunks");
        assert_eq!(exact_middle, batch.chunks[1..2]);

        let outside_record = snapshot
            .chunks_for_record(batch.records[0], OffsetRange::new(20, 2).expect("query"))
            .expect("chunks");
        assert!(outside_record.is_empty());
    }

    #[test]
    fn range_query_includes_a_record_that_starts_before_the_query() {
        let store = metadata_store(DurabilityProfile::ProcessCrash);
        let batch = fixture(
            1,
            0,
            192,
            1,
            &[
                (1, RecordKind::Plaintext, &[5]),
                (2, RecordKind::Plaintext, &[6]),
            ],
        );
        publish(&store, &batch);

        let snapshot = store.snapshot().expect("snapshot");
        let mut found = Vec::new();
        let visited = snapshot
            .visit_segment_records(
                segment(),
                OffsetRange::new(3, 5).expect("query"),
                NonZeroUsize::new(10).expect("limit"),
                |record| {
                    found.push(record.evidence());
                    Ok(())
                },
            )
            .expect("range query");
        assert_eq!(visited, 2);
        assert_eq!(found, [evidence(1), evidence(2)]);
    }

    #[test]
    fn range_query_rejects_an_index_that_points_to_the_wrong_record() {
        let store = metadata_store(DurabilityProfile::ProcessCrash);
        let batch = fixture(
            1,
            0,
            192,
            1,
            &[
                (1, RecordKind::Packet, &[4]),
                (2, RecordKind::Plaintext, &[5]),
            ],
        );
        publish(&store, &batch);
        {
            let transaction = store.database.begin_write().expect("write transaction");
            {
                let mut table = transaction.open_table(SEGMENT_RANGES).expect("range table");
                let key = range_key(segment(), 0);
                let mismatched = encode_range_value(batch.records[1]);
                table
                    .insert(key.as_slice(), mismatched.as_slice())
                    .expect("corrupt range index");
            }
            transaction.commit().expect("commit corruption");
        }

        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            snapshot.visit_segment_records(
                segment(),
                OffsetRange::new(0, 2).expect("query"),
                NonZeroUsize::new(1).expect("limit"),
                |_| Ok(()),
            ),
            Err(MetadataError::CorruptRangeIndex { start: 0, .. })
        ));
    }

    #[test]
    fn metadata_sync_failure_exposes_all_tables_or_none() {
        let database_file = NamedTempFile::new().expect("metadata file");
        let backend = FileBackend::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(database_file.path())
                .expect("metadata handle"),
        )
        .expect("file backend");
        let fail_sync = Arc::new(AtomicBool::new(false));
        let database = Database::builder()
            .create_with_backend(FailingSyncBackend {
                inner: backend,
                fail_sync: Arc::clone(&fail_sync),
            })
            .expect("metadata database");
        initialize_tables(&database).expect("metadata schema");
        let store = MetadataStore {
            database,
            durability: DurabilityProfile::PowerLoss,
        };
        let batch = fixture(1, 0, 192, 1, &[(1, RecordKind::Packet, &[3, 4])]);
        fail_sync.store(true, Ordering::SeqCst);
        let chunks = chunk_journal(&batch.chunks);
        assert!(matches!(
            store.publish_batch(batch.watermark, &batch.records, &chunks),
            Err(MetadataError::Engine(_))
        ));
        drop(store);

        let reopened = MetadataStore::open(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(database_file.path())
                .expect("reopened metadata handle"),
            DurabilityProfile::PowerLoss,
        )
        .expect("reopened metadata store");
        let counts = table_counts(&reopened);
        assert!(
            counts == [0, 0, 0, 0, 0]
                || counts
                    == [
                        batch.records.len() as u64,
                        batch.records.len() as u64,
                        batch.chunks.len() as u64,
                        1,
                        1,
                    ],
            "unexpected partially visible table counts: {counts:?}"
        );
        if counts[0] != 0 {
            let snapshot = reopened.snapshot().expect("snapshot");
            assert_eq!(
                snapshot
                    .chunks_for_record(batch.records[0], batch.records[0].bytes().range)
                    .expect("chunks"),
                batch.chunks
            );
            assert_eq!(
                snapshot.watermark(segment()).expect("watermark"),
                Some(batch.watermark)
            );
        }
    }

    #[test]
    fn metadata_errors_preserve_model_source() {
        let error = MetadataError::Model(MetadataModelError::InvalidRange);
        assert!(error.source().is_some());
    }

    fn metadata_store(durability: DurabilityProfile) -> MetadataStore {
        MetadataStore::open(tempfile().expect("metadata file"), durability).expect("metadata store")
    }

    fn publish(store: &MetadataStore, batch: &BatchFixture) -> PublishOutcome {
        let chunks = chunk_journal(&batch.chunks);
        store
            .publish_batch(batch.watermark, &batch.records, &chunks)
            .expect("publish")
    }

    fn chunk_journal(chunks: &[StoredChunkRef]) -> ChunkJournalSnapshot {
        ChunkJournalSnapshot::from_chunks(tempfile().expect("chunk journal"), segment(), chunks)
            .expect("chunk journal snapshot")
    }

    fn fixture(
        batch_number: u128,
        logical_start: u64,
        physical_start: u64,
        first_sequence: u64,
        records: &[(u128, RecordKind, &[u64])],
    ) -> BatchFixture {
        let mut logical_offset = logical_start;
        let mut file_offset = physical_start;
        let mut sequence = first_sequence;
        let mut stored_records = Vec::new();
        let mut stored_chunks = Vec::new();
        for (evidence_number, kind, chunk_lengths) in records {
            let record_start = logical_offset;
            for length in *chunk_lengths {
                let logical = OffsetRange::new(logical_offset, *length).expect("chunk range");
                stored_chunks.push(stored_chunk(
                    *evidence_number,
                    batch_number,
                    *kind,
                    logical,
                    file_offset,
                    sequence,
                ));
                logical_offset = logical.end();
                file_offset += DATA_FRAME_OVERHEAD + *length;
                sequence += 1;
            }
            stored_records.push(stored_record(
                *evidence_number,
                batch_number,
                *kind,
                OffsetRange::new(record_start, logical_offset - record_start)
                    .expect("record range"),
            ));
        }
        let committed_file_len = file_offset + COMMIT_FRAME_PHYSICAL_LEN;
        BatchFixture {
            watermark: SegmentWatermark::from_metadata(
                segment(),
                batch(batch_number),
                committed_file_len,
                sequence,
                logical_offset,
            ),
            records: stored_records,
            chunks: stored_chunks,
        }
    }

    fn stored_record(
        evidence_number: u128,
        batch_number: u128,
        kind: RecordKind,
        range: OffsetRange,
    ) -> StoredRecordRef {
        StoredRecordRef::from_metadata(
            evidence(evidence_number),
            batch(batch_number),
            kind,
            ByteRangeRef {
                segment: segment(),
                range,
                digest: ContentDigest::for_bytes(&evidence_number.to_be_bytes()),
            },
        )
    }

    fn stored_chunk(
        evidence_number: u128,
        batch_number: u128,
        kind: RecordKind,
        logical: OffsetRange,
        file_offset: u64,
        sequence: u64,
    ) -> StoredChunkRef {
        StoredChunkRef {
            segment: segment(),
            evidence: evidence(evidence_number),
            batch: batch(batch_number),
            kind,
            logical,
            file_offset,
            sequence,
            plaintext_digest: ContentDigest::for_bytes(&logical.start().to_be_bytes()),
        }
    }

    fn table_counts(store: &MetadataStore) -> [u64; 5] {
        let transaction = store.database.begin_read().expect("read transaction");
        [
            transaction
                .open_table(RECORDS)
                .expect("records")
                .len()
                .expect("record count"),
            transaction
                .open_table(SEGMENT_RANGES)
                .expect("ranges")
                .len()
                .expect("range count"),
            transaction
                .open_table(SEGMENT_CHUNKS)
                .expect("chunks")
                .len()
                .expect("chunk count"),
            transaction
                .open_table(BATCH_MARKERS)
                .expect("markers")
                .len()
                .expect("marker count"),
            transaction
                .open_table(WATERMARKS)
                .expect("watermarks")
                .len()
                .expect("watermark count"),
        ]
    }

    fn segment() -> SegmentId {
        SegmentId::new(1).expect("segment ID")
    }

    fn evidence(value: u128) -> EvidenceId {
        EvidenceId::new(value).expect("evidence ID")
    }

    fn batch(value: u128) -> BatchId {
        BatchId::new(value).expect("batch ID")
    }

    struct BatchFixture {
        watermark: SegmentWatermark,
        records: Vec<StoredRecordRef>,
        chunks: Vec<StoredChunkRef>,
    }

    #[derive(Debug)]
    struct FailingSyncBackend {
        inner: FileBackend,
        fail_sync: Arc<AtomicBool>,
    }

    impl StorageBackend for FailingSyncBackend {
        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }

        fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.inner.read(offset, out)
        }

        fn set_len(&self, len: u64) -> io::Result<()> {
            self.inner.set_len(len)
        }

        fn sync_data(&self) -> io::Result<()> {
            if self.fail_sync.load(Ordering::SeqCst) {
                Err(io::Error::other("injected metadata sync failure"))
            } else {
                self.inner.sync_data()
            }
        }

        fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            self.inner.write(offset, data)
        }

        fn close(&self) -> io::Result<()> {
            self.inner.close()
        }
    }
}

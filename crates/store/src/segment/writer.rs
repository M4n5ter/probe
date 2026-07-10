use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use evidence::{ByteRangeRef, ContentDigest, EvidenceId, OffsetRange, SegmentId};

use super::{
    chunk::StoredChunkRef,
    chunk_journal::{ChunkJournal, ChunkJournalError, ChunkJournalSnapshot},
    crypto::{SegmentCryptoError, SegmentKey},
    format::{
        BatchId, CommitFrameHeader, DataFrameHeader, FRAME_CHECKSUM_LEN, FRAME_HEADER_LEN,
        FrameHeader, RECORD_CHUNK_MAX, RecordKind, SEGMENT_HEADER_LEN, SegmentFormatError,
        SegmentHeader, frame_checksum,
    },
    lock::{SegmentLockError, lock_exclusive},
};

const DEFAULT_BATCH_LIMITS: BatchLimits = BatchLimits { records: 4096 };

#[derive(Clone, Copy)]
struct BatchLimits {
    records: u64,
}

struct BatchBudget {
    limits: BatchLimits,
    records: u64,
    chunks: u64,
}

impl BatchBudget {
    const fn new(limits: BatchLimits) -> Self {
        Self {
            limits,
            records: 0,
            chunks: 0,
        }
    }

    fn ensure_record_available(&self) -> Result<(), SegmentWriterError> {
        if self.records == self.limits.records {
            Err(SegmentWriterError::RecordLimitReached(self.limits.records))
        } else {
            Ok(())
        }
    }

    fn record_appended(&mut self) {
        self.records += 1;
    }

    fn chunk_appended(&mut self) -> Result<(), SegmentWriterError> {
        self.chunks = self
            .chunks
            .checked_add(1)
            .ok_or(SegmentWriterError::FrameCountOverflow)?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct StoreOwnerToken;

#[derive(Debug)]
struct WriterState {
    poisoned: AtomicBool,
    publication_pending: AtomicBool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityProfile {
    PowerLoss,
    ProcessCrash,
    BestEffort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentWatermark {
    segment: SegmentId,
    batch: BatchId,
    committed_file_len: u64,
    commit_sequence: u64,
    logical_len: u64,
}

impl SegmentWatermark {
    pub(crate) const fn from_metadata(
        segment: SegmentId,
        batch: BatchId,
        committed_file_len: u64,
        commit_sequence: u64,
        logical_len: u64,
    ) -> Self {
        Self {
            segment,
            batch,
            committed_file_len,
            commit_sequence,
            logical_len,
        }
    }

    pub const fn segment(self) -> SegmentId {
        self.segment
    }

    pub const fn batch(self) -> BatchId {
        self.batch
    }

    pub const fn committed_file_len(self) -> u64 {
        self.committed_file_len
    }

    pub const fn commit_sequence(self) -> u64 {
        self.commit_sequence
    }

    pub const fn logical_len(self) -> u64 {
        self.logical_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredRecordRef {
    evidence: EvidenceId,
    batch: BatchId,
    kind: RecordKind,
    bytes: ByteRangeRef,
}

impl StoredRecordRef {
    pub(crate) const fn from_metadata(
        evidence: EvidenceId,
        batch: BatchId,
        kind: RecordKind,
        bytes: ByteRangeRef,
    ) -> Self {
        Self {
            evidence,
            batch,
            kind,
            bytes,
        }
    }

    pub const fn evidence(self) -> EvidenceId {
        self.evidence
    }

    pub const fn batch(self) -> BatchId {
        self.batch
    }

    pub const fn kind(self) -> RecordKind {
        self.kind
    }

    pub const fn bytes(self) -> ByteRangeRef {
        self.bytes
    }
}

pub struct SegmentWriter {
    file: File,
    owner_lease: File,
    chunk_journal: ChunkJournal,
    header: SegmentHeader,
    key: SegmentKey,
    durability: DurabilityProfile,
    next_sequence: u64,
    next_logical_offset: u64,
    file_len: u64,
    committed_file_len: u64,
    state: Arc<WriterState>,
    owner: Arc<StoreOwnerToken>,
}

impl SegmentWriter {
    pub(crate) fn create(
        mut file: File,
        owner_lease: File,
        chunk_journal_file: File,
        header: SegmentHeader,
        key: SegmentKey,
        durability: DurabilityProfile,
        owner: Arc<StoreOwnerToken>,
    ) -> Result<Self, SegmentWriterError> {
        lock_exclusive(&owner_lease).map_err(SegmentWriterError::Lock)?;
        lock_exclusive(&file).map_err(SegmentWriterError::Lock)?;
        let chunk_journal = ChunkJournal::new(chunk_journal_file, header.segment())
            .map_err(descriptor_staging_error)?;
        if file.metadata().map_err(SegmentWriterError::Inspect)?.len() != 0 {
            return Err(SegmentWriterError::NonEmptyFile);
        }
        file.write_all(&header.encode())
            .map_err(SegmentWriterError::Write)?;
        if durability == DurabilityProfile::PowerLoss {
            file.sync_data().map_err(SegmentWriterError::Sync)?;
        }
        file.unlock().map_err(SegmentWriterError::Unlock)?;
        Ok(Self {
            file,
            owner_lease,
            chunk_journal,
            header,
            key,
            durability,
            next_sequence: 1,
            next_logical_offset: 0,
            file_len: SEGMENT_HEADER_LEN as u64,
            committed_file_len: SEGMENT_HEADER_LEN as u64,
            state: Arc::new(WriterState {
                poisoned: AtomicBool::new(false),
                publication_pending: AtomicBool::new(false),
            }),
            owner,
        })
    }

    pub fn begin_batch(&mut self, batch: BatchId) -> Result<SegmentBatch<'_>, SegmentWriterError> {
        self.require_healthy()?;
        if let Err(error) = self.chunk_journal.reset() {
            self.poison();
            return Err(descriptor_staging_error(error));
        }
        lock_exclusive(&self.file).map_err(SegmentWriterError::Lock)?;
        let mut batch_hasher = blake3::Hasher::new();
        batch_hasher.update(b"probe-segment-batch\0");
        batch_hasher.update(&batch.get().to_be_bytes());
        let first_sequence = self.next_sequence;
        Ok(SegmentBatch {
            writer: self,
            batch,
            first_sequence,
            budget: BatchBudget::new(DEFAULT_BATCH_LIMITS),
            batch_hasher,
            records: Vec::new(),
            committed: false,
        })
    }

    pub fn header(&self) -> &SegmentHeader {
        &self.header
    }

    pub const fn committed_file_len(&self) -> u64 {
        self.committed_file_len
    }

    #[cfg(test)]
    pub(crate) fn into_file(self) -> Result<File, SegmentWriterError> {
        self.require_healthy()?;
        Ok(self.file)
    }

    fn require_healthy(&self) -> Result<(), SegmentWriterError> {
        if self.state.poisoned.load(Ordering::Acquire) {
            Err(SegmentWriterError::Poisoned)
        } else if self.state.publication_pending.load(Ordering::Acquire) {
            Err(SegmentWriterError::PublicationPending)
        } else {
            Ok(())
        }
    }

    fn poison(&self) {
        self.state.poisoned.store(true, Ordering::Release);
    }

    fn write_data_frame(
        &mut self,
        batch: BatchId,
        evidence: EvidenceId,
        kind: RecordKind,
        starts_record: bool,
        ends_record: bool,
        plaintext: &[u8],
    ) -> Result<WrittenFrame, SegmentWriterError> {
        self.require_healthy()?;
        let plaintext_len = u32::try_from(plaintext.len())
            .map_err(|_| SegmentWriterError::ChunkTooLarge(plaintext.len()))?;
        let logical_offset = self.next_logical_offset;
        let file_offset = self.file_len;
        let sequence = self.next_sequence;
        self.next_logical_offset = logical_offset
            .checked_add(plaintext.len() as u64)
            .ok_or(SegmentWriterError::LogicalOffsetOverflow)?;
        let header = DataFrameHeader {
            sequence,
            batch,
            evidence,
            kind,
            starts_record,
            ends_record,
            logical_offset,
            plaintext_len,
            nonce: self.key.nonce(self.header.digest(), sequence),
            plaintext_digest: ContentDigest::for_bytes(plaintext),
        };
        let header_bytes = FrameHeader::Data(header)
            .encode()
            .map_err(SegmentWriterError::Format)?;
        let ciphertext = self
            .key
            .encrypt(self.header.digest(), header, plaintext)
            .map_err(SegmentWriterError::Crypto)?;
        let checksum = frame_checksum(&header_bytes, &ciphertext);
        if let Err(error) = write_frame(&mut self.file, &header_bytes, &ciphertext, checksum) {
            self.poison();
            return Err(SegmentWriterError::Write(error));
        }
        self.file_len = self
            .file_len
            .checked_add(FRAME_HEADER_LEN as u64)
            .and_then(|value| value.checked_add(ciphertext.len() as u64))
            .and_then(|value| value.checked_add(FRAME_CHECKSUM_LEN as u64))
            .ok_or_else(|| {
                self.poison();
                SegmentWriterError::FileOffsetOverflow
            })?;
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            self.poison();
            SegmentWriterError::FrameSequenceOverflow
        })?;
        Ok(WrittenFrame {
            checksum,
            chunk: StoredChunkRef {
                segment: self.header.segment(),
                evidence,
                batch,
                kind,
                logical: OffsetRange::new(logical_offset, plaintext.len() as u64)
                    .map_err(|_| SegmentWriterError::LogicalOffsetOverflow)?,
                file_offset,
                sequence,
                plaintext_digest: header.plaintext_digest,
            },
        })
    }

    fn write_commit_frame(
        &mut self,
        batch: BatchId,
        first_sequence: u64,
        frame_count: NonZeroU64,
        batch_digest: ContentDigest,
    ) -> Result<SegmentWatermark, SegmentWriterError> {
        self.require_healthy()?;
        let commit_sequence = self.next_sequence;
        let header = FrameHeader::Commit(CommitFrameHeader {
            sequence: commit_sequence,
            batch,
            first_sequence,
            frame_count,
            batch_digest,
        });
        let header_bytes = header.encode().map_err(SegmentWriterError::Format)?;
        let checksum = frame_checksum(&header_bytes, &[]);
        if let Err(error) = write_frame(&mut self.file, &header_bytes, &[], checksum) {
            self.poison();
            return Err(SegmentWriterError::Write(error));
        }
        self.file_len = self
            .file_len
            .checked_add((FRAME_HEADER_LEN + FRAME_CHECKSUM_LEN) as u64)
            .ok_or_else(|| {
                self.poison();
                SegmentWriterError::FileOffsetOverflow
            })?;
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            self.poison();
            SegmentWriterError::FrameSequenceOverflow
        })?;
        if self.durability == DurabilityProfile::PowerLoss
            && let Err(error) = self.file.sync_data()
        {
            self.poison();
            return Err(SegmentWriterError::Sync(error));
        }
        self.committed_file_len = self.file_len;
        Ok(SegmentWatermark {
            segment: self.header.segment(),
            batch,
            committed_file_len: self.committed_file_len,
            commit_sequence,
            logical_len: self.next_logical_offset,
        })
    }
}

struct WrittenFrame {
    checksum: ContentDigest,
    chunk: StoredChunkRef,
}

pub struct SegmentBatch<'writer> {
    writer: &'writer mut SegmentWriter,
    batch: BatchId,
    first_sequence: u64,
    budget: BatchBudget,
    batch_hasher: blake3::Hasher,
    records: Vec<StoredRecordRef>,
    committed: bool,
}

impl SegmentBatch<'_> {
    pub fn append_reader(
        &mut self,
        evidence: EvidenceId,
        kind: RecordKind,
        mut reader: impl Read,
    ) -> Result<(), SegmentWriterError> {
        self.writer.require_healthy()?;
        self.budget.ensure_record_available()?;
        if self
            .records
            .iter()
            .any(|record| record.evidence == evidence)
        {
            return Err(SegmentWriterError::DuplicateEvidence(evidence));
        }
        let start = self.writer.next_logical_offset;
        let mut record_hasher = blake3::Hasher::new();
        let mut current = read_chunk(&mut reader).map_err(|error| self.fail_read(error))?;
        if current.is_empty() {
            return Err(SegmentWriterError::EmptyPayload);
        }
        let mut starts_record = true;
        let mut total_len = 0_u64;
        loop {
            let next = read_chunk(&mut reader).map_err(|error| self.fail_read(error))?;
            let ends_record = next.is_empty();
            record_hasher.update(&current);
            total_len = total_len
                .checked_add(current.len() as u64)
                .ok_or_else(|| self.fail(SegmentWriterError::LogicalOffsetOverflow))?;
            let written = self
                .writer
                .write_data_frame(
                    self.batch,
                    evidence,
                    kind,
                    starts_record,
                    ends_record,
                    &current,
                )
                .map_err(|error| self.fail(error))?;
            self.batch_hasher.update(written.checksum.as_bytes());
            self.writer
                .chunk_journal
                .append(written.chunk)
                .map_err(|error| self.fail(descriptor_staging_error(error)))?;
            self.budget
                .chunk_appended()
                .map_err(|error| self.fail(error))?;
            if ends_record {
                break;
            }
            starts_record = false;
            current = next;
        }

        let range = OffsetRange::new(start, total_len)
            .map_err(|_| self.fail(SegmentWriterError::LogicalOffsetOverflow))?;
        self.records.push(StoredRecordRef {
            evidence,
            batch: self.batch,
            kind,
            bytes: ByteRangeRef {
                segment: self.writer.header.segment(),
                range,
                digest: ContentDigest::new(*record_hasher.finalize().as_bytes()),
            },
        });
        self.budget.record_appended();
        Ok(())
    }

    pub fn commit(mut self) -> Result<CommittedBatch, SegmentWriterError> {
        let frame_count =
            NonZeroU64::new(self.budget.chunks).ok_or(SegmentWriterError::EmptyBatch)?;
        let batch_digest = ContentDigest::new(*self.batch_hasher.finalize().as_bytes());
        let watermark = self.writer.write_commit_frame(
            self.batch,
            self.first_sequence,
            frame_count,
            batch_digest,
        )?;
        let owner_lease = self
            .writer
            .owner_lease
            .try_clone()
            .map_err(SegmentWriterError::CloneOwnerLease)?;
        let chunks = self
            .writer
            .chunk_journal
            .snapshot()
            .map_err(descriptor_staging_error)?;
        if let Err(error) = self.writer.file.unlock() {
            self.writer.poison();
            return Err(SegmentWriterError::Unlock(error));
        }
        self.writer
            .state
            .publication_pending
            .store(true, Ordering::Release);
        let committed = CommittedBatch {
            watermark,
            records: std::mem::take(&mut self.records).into_boxed_slice(),
            chunks,
            owner: Arc::clone(&self.writer.owner),
            writer_state: Arc::clone(&self.writer.state),
            _owner_lease: owner_lease,
            published: false,
        };
        self.committed = true;
        Ok(committed)
    }

    fn fail_read(&mut self, error: io::Error) -> SegmentWriterError {
        self.fail(SegmentWriterError::Read(error))
    }

    fn fail(&mut self, error: SegmentWriterError) -> SegmentWriterError {
        self.writer.poison();
        error
    }
}

impl Drop for SegmentBatch<'_> {
    fn drop(&mut self) {
        if !self.committed && self.budget.chunks != 0 {
            self.writer.poison();
        }
        if !self.committed && self.writer.file.unlock().is_err() {
            self.writer.poison();
        }
    }
}

pub struct CommittedBatch {
    watermark: SegmentWatermark,
    records: Box<[StoredRecordRef]>,
    chunks: ChunkJournalSnapshot,
    owner: Arc<StoreOwnerToken>,
    writer_state: Arc<WriterState>,
    _owner_lease: File,
    published: bool,
}

impl CommittedBatch {
    pub const fn watermark(&self) -> SegmentWatermark {
        self.watermark
    }

    pub fn records(&self) -> &[StoredRecordRef] {
        &self.records
    }

    pub(crate) const fn chunks(&self) -> &ChunkJournalSnapshot {
        &self.chunks
    }

    pub(crate) fn belongs_to(&self, owner: &Arc<StoreOwnerToken>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }

    pub(crate) fn mark_published(mut self) -> PublishedBatch {
        self.published = true;
        self.writer_state
            .publication_pending
            .store(false, Ordering::Release);
        PublishedBatch {
            watermark: self.watermark,
            records: std::mem::take(&mut self.records),
        }
    }
}

impl Drop for CommittedBatch {
    fn drop(&mut self) {
        if !self.published {
            self.writer_state.poisoned.store(true, Ordering::Release);
            self.writer_state
                .publication_pending
                .store(false, Ordering::Release);
        }
    }
}

pub struct PublishedBatch {
    watermark: SegmentWatermark,
    records: Box<[StoredRecordRef]>,
}

impl PublishedBatch {
    pub const fn watermark(&self) -> SegmentWatermark {
        self.watermark
    }

    pub fn records(&self) -> &[StoredRecordRef] {
        &self.records
    }
}

#[derive(Debug)]
pub enum SegmentWriterError {
    Inspect(io::Error),
    Read(io::Error),
    Write(io::Error),
    Sync(io::Error),
    CloneOwnerLease(io::Error),
    Unlock(io::Error),
    Lock(SegmentLockError),
    DescriptorStaging(Box<dyn std::error::Error + Send + Sync>),
    Format(SegmentFormatError),
    Crypto(SegmentCryptoError),
    NonEmptyFile,
    EmptyPayload,
    EmptyBatch,
    Poisoned,
    PublicationPending,
    DuplicateEvidence(EvidenceId),
    RecordLimitReached(u64),
    ChunkTooLarge(usize),
    LogicalOffsetOverflow,
    FileOffsetOverflow,
    FrameSequenceOverflow,
    FrameCountOverflow,
}

impl fmt::Display for SegmentWriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => write!(formatter, "failed to inspect segment file: {error}"),
            Self::Read(error) => write!(formatter, "failed to read record payload: {error}"),
            Self::Write(error) => write!(formatter, "failed to write segment file: {error}"),
            Self::Sync(error) => write!(formatter, "failed to sync segment file: {error}"),
            Self::CloneOwnerLease(error) => {
                write!(formatter, "failed to retain segment owner lease: {error}")
            }
            Self::Unlock(error) => {
                write!(formatter, "failed to release segment data lock: {error}")
            }
            Self::Lock(error) => write!(formatter, "failed to own segment: {error}"),
            Self::DescriptorStaging(error) => {
                write!(formatter, "chunk descriptor staging failed: {error}")
            }
            Self::Format(error) => write!(formatter, "invalid segment frame: {error}"),
            Self::Crypto(error) => write!(formatter, "segment encryption failed: {error}"),
            Self::NonEmptyFile => formatter.write_str("new segment file is not empty"),
            Self::EmptyPayload => formatter.write_str("segment record payload must not be empty"),
            Self::EmptyBatch => {
                formatter.write_str("segment batch must contain at least one frame")
            }
            Self::Poisoned => formatter.write_str("segment writer is poisoned"),
            Self::PublicationPending => {
                formatter.write_str("segment batch is committed but not published")
            }
            Self::DuplicateEvidence(evidence) => write!(
                formatter,
                "evidence {} appears more than once in a segment batch",
                evidence.get()
            ),
            Self::RecordLimitReached(limit) => {
                write!(formatter, "segment batch record count reached {limit}")
            }
            Self::ChunkTooLarge(length) => {
                write!(
                    formatter,
                    "record chunk length {length} exceeds {RECORD_CHUNK_MAX}"
                )
            }
            Self::LogicalOffsetOverflow => formatter.write_str("segment logical offset overflows"),
            Self::FileOffsetOverflow => formatter.write_str("segment file offset overflows"),
            Self::FrameSequenceOverflow => formatter.write_str("segment frame sequence overflows"),
            Self::FrameCountOverflow => formatter.write_str("segment batch frame count overflows"),
        }
    }
}

impl std::error::Error for SegmentWriterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspect(error)
            | Self::Read(error)
            | Self::Write(error)
            | Self::Sync(error)
            | Self::CloneOwnerLease(error)
            | Self::Unlock(error) => Some(error),
            Self::Lock(error) => Some(error),
            Self::DescriptorStaging(error) => Some(error.as_ref()),
            Self::Format(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::NonEmptyFile
            | Self::EmptyPayload
            | Self::EmptyBatch
            | Self::Poisoned
            | Self::PublicationPending
            | Self::DuplicateEvidence(_)
            | Self::RecordLimitReached(_)
            | Self::ChunkTooLarge(_)
            | Self::LogicalOffsetOverflow
            | Self::FileOffsetOverflow
            | Self::FrameSequenceOverflow
            | Self::FrameCountOverflow => None,
        }
    }
}

fn descriptor_staging_error(error: ChunkJournalError) -> SegmentWriterError {
    SegmentWriterError::DescriptorStaging(Box::new(error))
}

fn read_chunk(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut chunk = vec![0_u8; RECORD_CHUNK_MAX];
    let mut filled = 0;
    while filled < chunk.len() {
        match reader.read(&mut chunk[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    chunk.truncate(filled);
    Ok(chunk)
}

fn write_frame(
    file: &mut File,
    header: &[u8; FRAME_HEADER_LEN],
    payload: &[u8],
    checksum: ContentDigest,
) -> io::Result<()> {
    file.write_all(header)?;
    file.write_all(payload)?;
    file.write_all(checksum.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek, SeekFrom};

    use tempfile::tempfile;

    use super::*;
    use crate::KeyReference;

    #[test]
    fn streams_multi_megabyte_records_across_fixed_physical_frames() {
        let mut writer = writer(DurabilityProfile::ProcessCrash);
        let payload = vec![9_u8; RECORD_CHUNK_MAX * 2 + 17];
        let mut batch = writer
            .begin_batch(BatchId::new(4).expect("batch ID"))
            .expect("batch");
        batch
            .append_reader(
                EvidenceId::new(5).expect("evidence ID"),
                RecordKind::Plaintext,
                Cursor::new(&payload),
            )
            .expect("stored record");
        let committed = batch.commit().expect("commit");
        let watermark = committed.watermark();
        let stored = committed.records()[0];
        assert_eq!(committed.chunks().len(), 3);
        committed.mark_published();

        assert_eq!(stored.bytes().range.length().get(), payload.len() as u64);
        assert_eq!(stored.bytes().digest, ContentDigest::for_bytes(&payload));
        assert_eq!(watermark.logical_len(), payload.len() as u64);
        assert!(watermark.committed_file_len() > payload.len() as u64);

        let mut file = writer.into_file().expect("healthy writer");
        assert_eq!(
            file.seek(SeekFrom::End(0)).expect("segment length"),
            watermark.committed_file_len()
        );
    }

    #[test]
    fn dropping_a_partially_written_batch_poisoned_the_writer() {
        let mut writer = writer(DurabilityProfile::BestEffort);
        {
            let mut batch = writer
                .begin_batch(BatchId::new(4).expect("batch ID"))
                .expect("batch");
            batch
                .append_reader(
                    EvidenceId::new(5).expect("evidence ID"),
                    RecordKind::Packet,
                    Cursor::new(b"packet"),
                )
                .expect("record");
        }
        assert!(matches!(
            writer.begin_batch(BatchId::new(6).expect("batch ID")),
            Err(SegmentWriterError::Poisoned)
        ));
    }

    #[test]
    fn rejects_an_extra_record_before_committing_a_publishable_batch() {
        let mut writer = writer(DurabilityProfile::BestEffort);
        let mut batch = writer
            .begin_batch(BatchId::new(1).expect("batch ID"))
            .expect("batch");
        let record_limit = DEFAULT_BATCH_LIMITS.records;
        for value in 1..=record_limit {
            batch
                .append_reader(
                    EvidenceId::new(value as u128).expect("evidence ID"),
                    RecordKind::Packet,
                    Cursor::new([value as u8]),
                )
                .expect("record within budget");
        }

        assert!(matches!(
            batch.append_reader(
                EvidenceId::new((record_limit + 1) as u128).expect("evidence ID"),
                RecordKind::Packet,
                Cursor::new([0]),
            ),
            Err(SegmentWriterError::RecordLimitReached(limit)) if limit == record_limit
        ));
        let committed = batch.commit().expect("bounded commit");
        assert_eq!(committed.records().len(), record_limit as usize);
        committed.mark_published();
    }

    fn writer(durability: DurabilityProfile) -> SegmentWriter {
        SegmentWriter::create(
            tempfile().expect("temporary segment"),
            tempfile().expect("temporary owner lease"),
            tempfile().expect("temporary chunk journal"),
            SegmentHeader::new(
                SegmentId::new(1).expect("segment ID"),
                2,
                KeyReference::new("test/key").expect("key reference"),
            ),
            SegmentKey::new([3; 32]),
            durability,
            Arc::new(StoreOwnerToken),
        )
        .expect("segment writer")
    }
}

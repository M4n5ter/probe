use std::{
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

use evidence::ContentDigest;

use super::{
    crypto::SegmentKey,
    format::{
        AEAD_TAG_LEN, BatchId, FRAME_CHECKSUM_LEN, FRAME_HEADER_LEN, FrameHeader,
        SEGMENT_HEADER_LEN, SegmentFormatError, SegmentHeader, frame_checksum,
    },
    writer::SegmentWatermark,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentRecoveryReport {
    pub header: SegmentHeader,
    pub last_watermark: Option<SegmentWatermark>,
    pub observed_committed_batches: u64,
    pub truncated_uncommitted_bytes: u64,
    pub discarded_committed_orphan_bytes: u64,
}

pub(crate) struct RecoveryState {
    pub report: SegmentRecoveryReport,
    pub logical_len: u64,
    pub file_len: u64,
}

struct PendingBatch {
    id: BatchId,
    first_sequence: u64,
    frame_count: u64,
    hasher: blake3::Hasher,
}

struct OpenRecord {
    evidence: evidence::EvidenceId,
    kind: super::RecordKind,
}

pub(crate) fn recover_file(
    file: &mut File,
    key: &SegmentKey,
) -> Result<RecoveryState, SegmentRecoveryError> {
    file.seek(SeekFrom::Start(0))
        .map_err(SegmentRecoveryError::Seek)?;
    let mut header_bytes = [0_u8; SEGMENT_HEADER_LEN];
    let read = read_fully(file, &mut header_bytes).map_err(SegmentRecoveryError::Read)?;
    if read != SEGMENT_HEADER_LEN {
        return Err(SegmentRecoveryError::TruncatedHeader(read));
    }
    let header = SegmentHeader::decode(&header_bytes)
        .map_err(|source| SegmentRecoveryError::Format { offset: 0, source })?;
    let original_len = file
        .metadata()
        .map_err(SegmentRecoveryError::Inspect)?
        .len();

    let mut offset = SEGMENT_HEADER_LEN as u64;
    let mut last_committed_offset = offset;
    let mut expected_sequence = 1_u64;
    let mut logical_len = 0_u64;
    let mut committed_logical_len = 0_u64;
    let mut pending: Option<PendingBatch> = None;
    let mut open_record: Option<OpenRecord> = None;
    let mut last_watermark = None;
    let mut committed_batches = 0_u64;
    let mut incomplete_tail = false;

    loop {
        let frame_offset = offset;
        let mut frame_bytes = [0_u8; FRAME_HEADER_LEN];
        let read = read_fully(file, &mut frame_bytes).map_err(SegmentRecoveryError::Read)?;
        if read == 0 {
            break;
        }
        if read != FRAME_HEADER_LEN {
            incomplete_tail = true;
            break;
        }
        let frame =
            FrameHeader::decode(&frame_bytes).map_err(|source| SegmentRecoveryError::Format {
                offset: frame_offset,
                source,
            })?;
        if frame.sequence() != expected_sequence {
            return Err(SegmentRecoveryError::SequenceMismatch {
                offset: frame_offset,
                expected: expected_sequence,
                actual: frame.sequence(),
            });
        }

        let payload_len = match frame {
            FrameHeader::Data(data) => data.plaintext_len as usize + AEAD_TAG_LEN,
            FrameHeader::Commit(_) => 0,
        };
        let mut payload = vec![0_u8; payload_len];
        if read_fully(file, &mut payload).map_err(SegmentRecoveryError::Read)? != payload_len {
            incomplete_tail = true;
            break;
        }
        let mut checksum_bytes = [0_u8; FRAME_CHECKSUM_LEN];
        if read_fully(file, &mut checksum_bytes).map_err(SegmentRecoveryError::Read)?
            != FRAME_CHECKSUM_LEN
        {
            incomplete_tail = true;
            break;
        }
        let expected_checksum = frame_checksum(&frame_bytes, &payload);
        if checksum_bytes != *expected_checksum.as_bytes() {
            return Err(SegmentRecoveryError::FrameChecksumMismatch(frame_offset));
        }
        offset = offset
            .checked_add(FRAME_HEADER_LEN as u64)
            .and_then(|value| value.checked_add(payload_len as u64))
            .and_then(|value| value.checked_add(FRAME_CHECKSUM_LEN as u64))
            .ok_or(SegmentRecoveryError::OffsetOverflow)?;

        match frame {
            FrameHeader::Data(data) => {
                if data.nonce != key.nonce(header.digest(), data.sequence) {
                    return Err(SegmentRecoveryError::NonceMismatch(frame_offset));
                }
                let batch = pending.get_or_insert_with(|| PendingBatch {
                    id: data.batch,
                    first_sequence: data.sequence,
                    frame_count: 0,
                    hasher: batch_hasher(data.batch),
                });
                if batch.id != data.batch {
                    return Err(SegmentRecoveryError::InterleavedBatch(frame_offset));
                }
                validate_record_boundary(&mut open_record, data, frame_offset)?;
                if data.logical_offset != logical_len {
                    return Err(SegmentRecoveryError::LogicalOffsetMismatch {
                        offset: frame_offset,
                        expected: logical_len,
                        actual: data.logical_offset,
                    });
                }
                let plaintext = key
                    .decrypt(header.digest(), data, &payload)
                    .map_err(|_| SegmentRecoveryError::AuthenticationFailed(frame_offset))?;
                if plaintext.len() != data.plaintext_len as usize
                    || ContentDigest::for_bytes(&plaintext) != data.plaintext_digest
                {
                    return Err(SegmentRecoveryError::PlaintextDigestMismatch(frame_offset));
                }
                logical_len = logical_len
                    .checked_add(plaintext.len() as u64)
                    .ok_or(SegmentRecoveryError::OffsetOverflow)?;
                batch.hasher.update(&checksum_bytes);
                batch.frame_count = batch
                    .frame_count
                    .checked_add(1)
                    .ok_or(SegmentRecoveryError::FrameCountOverflow)?;
            }
            FrameHeader::Commit(commit) => {
                if open_record.is_some() {
                    return Err(SegmentRecoveryError::CommitInsideRecord(frame_offset));
                }
                let Some(batch) = pending.take() else {
                    return Err(SegmentRecoveryError::CommitWithoutBatch(frame_offset));
                };
                if commit.batch != batch.id {
                    return Err(SegmentRecoveryError::CommitBatchMismatch(frame_offset));
                }
                if commit.first_sequence != batch.first_sequence
                    || commit.frame_count.get() != batch.frame_count
                {
                    return Err(SegmentRecoveryError::CommitFrameSetMismatch(frame_offset));
                }
                let batch_digest = ContentDigest::new(*batch.hasher.finalize().as_bytes());
                if commit.batch_digest != batch_digest {
                    return Err(SegmentRecoveryError::BatchDigestMismatch(frame_offset));
                }
                last_committed_offset = offset;
                committed_logical_len = logical_len;
                last_watermark = Some(SegmentWatermark::from_metadata(
                    header.segment(),
                    commit.batch,
                    last_committed_offset,
                    commit.sequence,
                    committed_logical_len,
                ));
                committed_batches = committed_batches
                    .checked_add(1)
                    .ok_or(SegmentRecoveryError::BatchCountOverflow)?;
            }
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(SegmentRecoveryError::SequenceOverflow)?;
    }

    let has_uncommitted_tail = incomplete_tail || pending.is_some();
    let truncated_bytes = if has_uncommitted_tail {
        let truncated = original_len
            .checked_sub(last_committed_offset)
            .ok_or(SegmentRecoveryError::OffsetOverflow)?;
        file.set_len(last_committed_offset)
            .map_err(SegmentRecoveryError::Truncate)?;
        file.sync_data().map_err(SegmentRecoveryError::Sync)?;
        truncated
    } else {
        0
    };
    file.seek(SeekFrom::Start(last_committed_offset))
        .map_err(SegmentRecoveryError::Seek)?;

    Ok(RecoveryState {
        report: SegmentRecoveryReport {
            header,
            last_watermark,
            observed_committed_batches: committed_batches,
            truncated_uncommitted_bytes: truncated_bytes,
            discarded_committed_orphan_bytes: 0,
        },
        logical_len: committed_logical_len,
        file_len: last_committed_offset,
    })
}

pub(crate) fn recover_segment_to_published(
    file: &mut File,
    key: &SegmentKey,
    published: Option<SegmentWatermark>,
) -> Result<SegmentRecoveryReport, SegmentRecoveryError> {
    let mut state = recover_file(file, key)?;
    let target = match published {
        Some(watermark) => {
            if watermark.segment() != state.report.header.segment() {
                return Err(SegmentRecoveryError::PublishedSegmentMismatch);
            }
            validate_published_commit(file, state.file_len, watermark)?;
            if watermark.logical_len() > state.logical_len {
                return Err(SegmentRecoveryError::PublishedWatermarkAhead);
            }
            watermark.committed_file_len()
        }
        None => SEGMENT_HEADER_LEN as u64,
    };
    if target > state.file_len {
        return Err(SegmentRecoveryError::PublishedWatermarkAhead);
    }
    let orphaned_committed_bytes = state.file_len - target;
    if orphaned_committed_bytes != 0 {
        file.set_len(target)
            .map_err(SegmentRecoveryError::Truncate)?;
        file.sync_data().map_err(SegmentRecoveryError::Sync)?;
    }
    file.seek(SeekFrom::Start(target))
        .map_err(SegmentRecoveryError::Seek)?;
    state.report.last_watermark = published;
    state.report.discarded_committed_orphan_bytes = orphaned_committed_bytes;
    Ok(state.report)
}

pub(crate) fn validate_committed_segment(
    file: &mut File,
    watermark: SegmentWatermark,
) -> Result<(), SegmentRecoveryError> {
    let file_len = file
        .metadata()
        .map_err(SegmentRecoveryError::Inspect)?
        .len();
    validate_published_commit(file, file_len, watermark)
}

#[derive(Debug)]
pub enum SegmentRecoveryError {
    Inspect(io::Error),
    Read(io::Error),
    Seek(io::Error),
    Truncate(io::Error),
    Sync(io::Error),
    TruncatedHeader(usize),
    Format {
        offset: u64,
        source: SegmentFormatError,
    },
    SequenceMismatch {
        offset: u64,
        expected: u64,
        actual: u64,
    },
    InterleavedBatch(u64),
    RecordBoundary(u64),
    RecordIdentityMismatch(u64),
    LogicalOffsetMismatch {
        offset: u64,
        expected: u64,
        actual: u64,
    },
    FrameChecksumMismatch(u64),
    NonceMismatch(u64),
    AuthenticationFailed(u64),
    PlaintextDigestMismatch(u64),
    CommitWithoutBatch(u64),
    CommitInsideRecord(u64),
    CommitBatchMismatch(u64),
    CommitFrameSetMismatch(u64),
    BatchDigestMismatch(u64),
    OffsetOverflow,
    SequenceOverflow,
    FrameCountOverflow,
    BatchCountOverflow,
    PublishedSegmentMismatch,
    PublishedWatermarkAhead,
    PublishedCommitMismatch,
}

impl fmt::Display for SegmentRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => write!(formatter, "failed to inspect segment: {error}"),
            Self::Read(error) => write!(formatter, "failed to read segment: {error}"),
            Self::Seek(error) => write!(formatter, "failed to seek segment: {error}"),
            Self::Truncate(error) => write!(formatter, "failed to truncate segment tail: {error}"),
            Self::Sync(error) => write!(formatter, "failed to sync recovered segment: {error}"),
            Self::TruncatedHeader(bytes) => {
                write!(
                    formatter,
                    "segment header is truncated after {bytes} byte(s)"
                )
            }
            Self::Format { offset, source } => {
                write!(
                    formatter,
                    "invalid segment format at offset {offset}: {source}"
                )
            }
            Self::SequenceMismatch {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "frame sequence mismatch at offset {offset}: expected {expected}, found {actual}"
            ),
            Self::InterleavedBatch(offset) => {
                write!(formatter, "interleaved batch at offset {offset}")
            }
            Self::RecordBoundary(offset) => {
                write!(formatter, "invalid record boundary at offset {offset}")
            }
            Self::RecordIdentityMismatch(offset) => {
                write!(formatter, "record identity changes at offset {offset}")
            }
            Self::LogicalOffsetMismatch {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "logical offset mismatch at file offset {offset}: expected {expected}, found {actual}"
            ),
            Self::FrameChecksumMismatch(offset) => {
                write!(formatter, "frame checksum mismatch at offset {offset}")
            }
            Self::NonceMismatch(offset) => {
                write!(formatter, "frame nonce mismatch at offset {offset}")
            }
            Self::AuthenticationFailed(offset) => {
                write!(formatter, "frame authentication failed at offset {offset}")
            }
            Self::PlaintextDigestMismatch(offset) => {
                write!(
                    formatter,
                    "frame plaintext digest mismatch at offset {offset}"
                )
            }
            Self::CommitWithoutBatch(offset) => {
                write!(formatter, "commit marker has no batch at offset {offset}")
            }
            Self::CommitInsideRecord(offset) => {
                write!(
                    formatter,
                    "commit marker splits a record at offset {offset}"
                )
            }
            Self::CommitBatchMismatch(offset) => {
                write!(formatter, "commit marker batch mismatch at offset {offset}")
            }
            Self::CommitFrameSetMismatch(offset) => {
                write!(
                    formatter,
                    "commit marker frame set mismatch at offset {offset}"
                )
            }
            Self::BatchDigestMismatch(offset) => {
                write!(formatter, "batch digest mismatch at offset {offset}")
            }
            Self::OffsetOverflow => formatter.write_str("segment offset overflows"),
            Self::SequenceOverflow => formatter.write_str("segment sequence overflows"),
            Self::FrameCountOverflow => formatter.write_str("segment frame count overflows"),
            Self::BatchCountOverflow => formatter.write_str("segment batch count overflows"),
            Self::PublishedSegmentMismatch => {
                formatter.write_str("published watermark references another segment")
            }
            Self::PublishedWatermarkAhead => {
                formatter.write_str("published watermark is ahead of durable segment contents")
            }
            Self::PublishedCommitMismatch => {
                formatter.write_str("published watermark does not match a segment commit marker")
            }
        }
    }
}

impl std::error::Error for SegmentRecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspect(error)
            | Self::Read(error)
            | Self::Seek(error)
            | Self::Truncate(error)
            | Self::Sync(error) => Some(error),
            Self::Format { source, .. } => Some(source),
            Self::TruncatedHeader(_)
            | Self::SequenceMismatch { .. }
            | Self::InterleavedBatch(_)
            | Self::RecordBoundary(_)
            | Self::RecordIdentityMismatch(_)
            | Self::LogicalOffsetMismatch { .. }
            | Self::FrameChecksumMismatch(_)
            | Self::NonceMismatch(_)
            | Self::AuthenticationFailed(_)
            | Self::PlaintextDigestMismatch(_)
            | Self::CommitWithoutBatch(_)
            | Self::CommitInsideRecord(_)
            | Self::CommitBatchMismatch(_)
            | Self::CommitFrameSetMismatch(_)
            | Self::BatchDigestMismatch(_)
            | Self::OffsetOverflow
            | Self::SequenceOverflow
            | Self::FrameCountOverflow
            | Self::BatchCountOverflow
            | Self::PublishedSegmentMismatch
            | Self::PublishedWatermarkAhead
            | Self::PublishedCommitMismatch => None,
        }
    }
}

fn validate_record_boundary(
    open: &mut Option<OpenRecord>,
    frame: super::format::DataFrameHeader,
    offset: u64,
) -> Result<(), SegmentRecoveryError> {
    if frame.starts_record {
        if open.is_some() {
            return Err(SegmentRecoveryError::RecordBoundary(offset));
        }
        *open = Some(OpenRecord {
            evidence: frame.evidence,
            kind: frame.kind,
        });
    }
    let Some(record) = open.as_ref() else {
        return Err(SegmentRecoveryError::RecordBoundary(offset));
    };
    if record.evidence != frame.evidence || record.kind != frame.kind {
        return Err(SegmentRecoveryError::RecordIdentityMismatch(offset));
    }
    if frame.ends_record {
        *open = None;
    }
    Ok(())
}

fn batch_hasher(batch: BatchId) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-segment-batch\0");
    hasher.update(&batch.get().to_be_bytes());
    hasher
}

pub(crate) fn validate_published_commit(
    file: &mut File,
    file_len: u64,
    watermark: SegmentWatermark,
) -> Result<(), SegmentRecoveryError> {
    let commit_len = (FRAME_HEADER_LEN + FRAME_CHECKSUM_LEN) as u64;
    if watermark.committed_file_len() < SEGMENT_HEADER_LEN as u64 + commit_len
        || watermark.committed_file_len() > file_len
    {
        return Err(SegmentRecoveryError::PublishedWatermarkAhead);
    }
    let offset = watermark.committed_file_len() - commit_len;
    file.seek(SeekFrom::Start(offset))
        .map_err(SegmentRecoveryError::Seek)?;
    let mut frame_bytes = [0_u8; FRAME_HEADER_LEN];
    file.read_exact(&mut frame_bytes)
        .map_err(SegmentRecoveryError::Read)?;
    let mut checksum = [0_u8; FRAME_CHECKSUM_LEN];
    file.read_exact(&mut checksum)
        .map_err(SegmentRecoveryError::Read)?;
    if checksum != *frame_checksum(&frame_bytes, &[]).as_bytes() {
        return Err(SegmentRecoveryError::PublishedCommitMismatch);
    }
    let FrameHeader::Commit(commit) = FrameHeader::decode(&frame_bytes)
        .map_err(|source| SegmentRecoveryError::Format { offset, source })?
    else {
        return Err(SegmentRecoveryError::PublishedCommitMismatch);
    };
    if commit.batch != watermark.batch() || commit.sequence != watermark.commit_sequence() {
        return Err(SegmentRecoveryError::PublishedCommitMismatch);
    }
    Ok(())
}

fn read_fully(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Seek, SeekFrom, Write},
        sync::Arc,
    };

    use evidence::{EvidenceId, SegmentId};
    use tempfile::tempfile;

    use super::*;
    use crate::{
        BatchId, DurabilityProfile, KeyReference, RecordKind, SegmentHeader, SegmentWriter,
    };

    #[test]
    fn truncates_only_an_uncommitted_crash_tail() {
        let key_bytes = [7; 32];
        let mut writer = writer(key_bytes);
        let mut first = writer
            .begin_batch(BatchId::new(2).expect("batch ID"))
            .expect("first batch");
        first
            .append_reader(
                EvidenceId::new(3).expect("evidence ID"),
                RecordKind::Packet,
                Cursor::new(b"committed"),
            )
            .expect("first record");
        let committed = first.commit().expect("first commit");
        let watermark = committed.watermark();
        committed.mark_published();
        let mut file = writer.into_file().expect("healthy writer");
        file.seek(SeekFrom::End(0)).expect("tail");
        file.write_all(b"partial frame").expect("crash tail");

        let state = recover_file(&mut file, &SegmentKey::new(key_bytes)).expect("recovery");
        assert_eq!(state.report.truncated_uncommitted_bytes, 13);
        assert_eq!(state.file_len, watermark.committed_file_len());
        assert_eq!(
            file.metadata().expect("metadata").len(),
            watermark.committed_file_len()
        );
        assert_eq!(state.logical_len, b"committed".len() as u64);
    }

    #[test]
    fn checksum_corruption_fails_closed_without_truncation() {
        let key_bytes = [7; 32];
        let mut writer = writer(key_bytes);
        let mut batch = writer
            .begin_batch(BatchId::new(2).expect("batch ID"))
            .expect("batch");
        batch
            .append_reader(
                EvidenceId::new(3).expect("evidence ID"),
                RecordKind::Packet,
                Cursor::new(b"committed"),
            )
            .expect("record");
        batch.commit().expect("commit").mark_published();
        let mut file = writer.into_file().expect("healthy writer");
        let original_len = file.metadata().expect("metadata").len();
        file.seek(SeekFrom::Start(SEGMENT_HEADER_LEN as u64 + 1))
            .expect("frame byte");
        file.write_all(&[0xff]).expect("corrupt frame");

        assert!(matches!(
            recover_file(&mut file, &SegmentKey::new(key_bytes)),
            Err(SegmentRecoveryError::Format { .. })
                | Err(SegmentRecoveryError::FrameChecksumMismatch(_))
        ));
        assert_eq!(file.metadata().expect("metadata").len(), original_len);
    }

    fn writer(key: [u8; 32]) -> SegmentWriter {
        SegmentWriter::create(
            tempfile().expect("temporary segment"),
            tempfile().expect("temporary owner lease"),
            tempfile().expect("temporary chunk journal"),
            SegmentHeader::new(
                SegmentId::new(1).expect("segment ID"),
                1,
                KeyReference::new("test/key").expect("key reference"),
            ),
            SegmentKey::new(key),
            DurabilityProfile::ProcessCrash,
            Arc::new(crate::segment::StoreOwnerToken),
        )
        .expect("segment writer")
    }
}

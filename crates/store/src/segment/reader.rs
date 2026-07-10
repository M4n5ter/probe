use std::{
    cmp::{max, min},
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

use evidence::{ContentDigest, OffsetRange, RangeError, SegmentId};

use super::{
    SegmentWatermark, StoredChunkRef, StoredRecordRef,
    crypto::SegmentKey,
    format::{
        AEAD_TAG_LEN, FRAME_CHECKSUM_LEN, FRAME_HEADER_LEN, FrameHeader, SEGMENT_HEADER_LEN,
        SegmentFormatError, SegmentHeader, frame_checksum,
    },
    recovery::{SegmentRecoveryError, validate_published_commit},
};

pub(crate) struct SegmentReader {
    file: File,
    header: SegmentHeader,
    key: SegmentKey,
    published: SegmentWatermark,
}

impl SegmentReader {
    pub(crate) fn open_locked(
        mut file: File,
        key: SegmentKey,
        published: SegmentWatermark,
    ) -> Result<Self, SegmentReadError> {
        file.seek(SeekFrom::Start(0))
            .map_err(SegmentReadError::Seek)?;
        let mut header_bytes = [0_u8; SEGMENT_HEADER_LEN];
        file.read_exact(&mut header_bytes)
            .map_err(SegmentReadError::Read)?;
        let header = SegmentHeader::decode(&header_bytes)
            .map_err(|source| SegmentReadError::Format { offset: 0, source })?;
        if header.segment() != published.segment() {
            return Err(SegmentReadError::SegmentMismatch {
                expected: header.segment(),
                actual: published.segment(),
            });
        }
        let file_len = file.metadata().map_err(SegmentReadError::Inspect)?.len();
        validate_published_commit(&mut file, file_len, published)
            .map_err(SegmentReadError::PublishedCommit)?;
        Ok(Self {
            file,
            header,
            key,
            published,
        })
    }

    pub(crate) fn read_record_to(
        &mut self,
        record: StoredRecordRef,
        chunks: &[StoredChunkRef],
        output: &mut impl Write,
    ) -> Result<u64, SegmentReadError> {
        self.validate_record(record)?;
        self.stream_chunks(
            record,
            record.bytes().range,
            chunks,
            Some(record.bytes().digest),
            output,
        )
    }

    pub(crate) fn read_record_range_to(
        &mut self,
        record: StoredRecordRef,
        relative: OffsetRange,
        chunks: &[StoredChunkRef],
        output: &mut impl Write,
    ) -> Result<u64, SegmentReadError> {
        self.validate_record(record)?;
        if relative.end() > record.bytes().range.length().get() {
            return Err(SegmentReadError::RangeOutsideRecord);
        }
        let start = record
            .bytes()
            .range
            .start()
            .checked_add(relative.start())
            .ok_or(SegmentReadError::RangeOverflow)?;
        let absolute = OffsetRange::new(start, relative.length().get())
            .map_err(SegmentReadError::InvalidRange)?;
        self.stream_chunks(record, absolute, chunks, None, output)
    }

    fn validate_record(&self, record: StoredRecordRef) -> Result<(), SegmentReadError> {
        if record.bytes().segment != self.header.segment() {
            return Err(SegmentReadError::SegmentMismatch {
                expected: self.header.segment(),
                actual: record.bytes().segment,
            });
        }
        if record.bytes().range.end() > self.published.logical_len() {
            return Err(SegmentReadError::RangeOutsidePublishedWatermark);
        }
        Ok(())
    }

    fn stream_chunks(
        &mut self,
        record: StoredRecordRef,
        query: OffsetRange,
        chunks: &[StoredChunkRef],
        expected_digest: Option<ContentDigest>,
        output: &mut impl Write,
    ) -> Result<u64, SegmentReadError> {
        let mut next_logical = query.start();
        let mut written = 0_u64;
        let mut content_hasher = blake3::Hasher::new();

        for chunk in chunks {
            validate_chunk_index(record, *chunk, self.published)?;
            let chunk_end = chunk.logical.end();
            if chunk_end <= query.start() || chunk.logical.start() >= query.end() {
                continue;
            }
            let intersection_start = max(query.start(), chunk.logical.start());
            let intersection_end = min(query.end(), chunk_end);
            if intersection_start != next_logical {
                return Err(SegmentReadError::ChunkCoverageGap {
                    expected: next_logical,
                    actual: intersection_start,
                });
            }

            let plaintext = self.read_chunk(*chunk)?;
            let from = usize::try_from(intersection_start - chunk.logical.start())
                .map_err(|_| SegmentReadError::RangeOverflow)?;
            let to = usize::try_from(intersection_end - chunk.logical.start())
                .map_err(|_| SegmentReadError::RangeOverflow)?;
            output
                .write_all(&plaintext[from..to])
                .map_err(SegmentReadError::Write)?;
            content_hasher.update(&plaintext[from..to]);
            written = written
                .checked_add((to - from) as u64)
                .ok_or(SegmentReadError::RangeOverflow)?;
            next_logical = intersection_end;
        }

        if next_logical != query.end() {
            return Err(SegmentReadError::ChunkCoverageGap {
                expected: next_logical,
                actual: query.end(),
            });
        }
        if let Some(expected) = expected_digest {
            let actual = ContentDigest::new(*content_hasher.finalize().as_bytes());
            if actual != expected {
                return Err(SegmentReadError::RecordDigestMismatch { expected, actual });
            }
        }
        Ok(written)
    }

    fn read_chunk(&mut self, chunk: StoredChunkRef) -> Result<Vec<u8>, SegmentReadError> {
        self.file
            .seek(SeekFrom::Start(chunk.file_offset))
            .map_err(SegmentReadError::Seek)?;
        let mut frame_bytes = [0_u8; FRAME_HEADER_LEN];
        self.file
            .read_exact(&mut frame_bytes)
            .map_err(SegmentReadError::Read)?;
        let FrameHeader::Data(frame) =
            FrameHeader::decode(&frame_bytes).map_err(|source| SegmentReadError::Format {
                offset: chunk.file_offset,
                source,
            })?
        else {
            return Err(SegmentReadError::ChunkIndexMismatch(chunk.file_offset));
        };
        if frame.sequence != chunk.sequence
            || frame.batch != chunk.batch
            || frame.evidence != chunk.evidence
            || frame.kind != chunk.kind
            || frame.logical_offset != chunk.logical.start()
            || u64::from(frame.plaintext_len) != chunk.logical.length().get()
            || frame.plaintext_digest != chunk.plaintext_digest
        {
            return Err(SegmentReadError::ChunkIndexMismatch(chunk.file_offset));
        }
        let payload_len = frame.plaintext_len as usize + AEAD_TAG_LEN;
        let frame_end = chunk
            .file_offset
            .checked_add(FRAME_HEADER_LEN as u64)
            .and_then(|offset| offset.checked_add(payload_len as u64))
            .and_then(|offset| offset.checked_add(FRAME_CHECKSUM_LEN as u64))
            .ok_or(SegmentReadError::RangeOverflow)?;
        if frame_end > self.published.committed_file_len() {
            return Err(SegmentReadError::ChunkOutsidePublishedWatermark);
        }
        let mut ciphertext = vec![0_u8; payload_len];
        self.file
            .read_exact(&mut ciphertext)
            .map_err(SegmentReadError::Read)?;
        let mut checksum = [0_u8; FRAME_CHECKSUM_LEN];
        self.file
            .read_exact(&mut checksum)
            .map_err(SegmentReadError::Read)?;
        if checksum != *frame_checksum(&frame_bytes, &ciphertext).as_bytes() {
            return Err(SegmentReadError::FrameChecksumMismatch(chunk.file_offset));
        }
        if frame.nonce != self.key.nonce(self.header.digest(), frame.sequence) {
            return Err(SegmentReadError::NonceMismatch(chunk.file_offset));
        }
        let plaintext = self
            .key
            .decrypt(self.header.digest(), frame, &ciphertext)
            .map_err(|_| SegmentReadError::AuthenticationFailed(chunk.file_offset))?;
        if ContentDigest::for_bytes(&plaintext) != chunk.plaintext_digest {
            return Err(SegmentReadError::PlaintextDigestMismatch(chunk.file_offset));
        }
        Ok(plaintext)
    }
}

fn validate_chunk_index(
    record: StoredRecordRef,
    chunk: StoredChunkRef,
    published: SegmentWatermark,
) -> Result<(), SegmentReadError> {
    if chunk.segment != record.bytes().segment
        || chunk.batch != record.batch()
        || chunk.evidence != record.evidence()
        || chunk.kind != record.kind()
        || chunk.logical.start() < record.bytes().range.start()
        || chunk.logical.end() > record.bytes().range.end()
        || chunk.logical.end() > published.logical_len()
    {
        return Err(SegmentReadError::ChunkIndexMismatch(chunk.file_offset));
    }
    Ok(())
}

#[derive(Debug)]
pub enum SegmentReadError {
    Inspect(io::Error),
    Read(io::Error),
    Write(io::Error),
    Seek(io::Error),
    PublishedCommit(SegmentRecoveryError),
    Format {
        offset: u64,
        source: SegmentFormatError,
    },
    InvalidRange(RangeError),
    RangeOutsideRecord,
    RangeOutsidePublishedWatermark,
    RangeOverflow,
    SegmentMismatch {
        expected: SegmentId,
        actual: SegmentId,
    },
    ChunkIndexMismatch(u64),
    ChunkCoverageGap {
        expected: u64,
        actual: u64,
    },
    ChunkOutsidePublishedWatermark,
    FrameChecksumMismatch(u64),
    NonceMismatch(u64),
    AuthenticationFailed(u64),
    PlaintextDigestMismatch(u64),
    RecordDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
}

impl fmt::Display for SegmentReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => write!(formatter, "failed to inspect segment: {error}"),
            Self::Read(error) => write!(formatter, "failed to read segment: {error}"),
            Self::Write(error) => write!(formatter, "failed to write range output: {error}"),
            Self::Seek(error) => write!(formatter, "failed to seek segment: {error}"),
            Self::PublishedCommit(error) => {
                write!(formatter, "published segment commit is invalid: {error}")
            }
            Self::Format { offset, source } => {
                write!(
                    formatter,
                    "invalid segment frame at offset {offset}: {source}"
                )
            }
            Self::InvalidRange(error) => write!(formatter, "invalid segment range: {error}"),
            Self::RangeOutsideRecord => {
                formatter.write_str("requested range lies outside the stored record")
            }
            Self::RangeOutsidePublishedWatermark => {
                formatter.write_str("record lies outside the published segment watermark")
            }
            Self::RangeOverflow => formatter.write_str("requested segment range overflows"),
            Self::SegmentMismatch { expected, actual } => write!(
                formatter,
                "record references segment {}, but reader opened segment {}",
                actual.get(),
                expected.get()
            ),
            Self::ChunkIndexMismatch(offset) => {
                write!(formatter, "chunk index mismatch at file offset {offset}")
            }
            Self::ChunkCoverageGap { expected, actual } => write!(
                formatter,
                "chunk coverage gap: expected logical offset {expected}, found {actual}"
            ),
            Self::ChunkOutsidePublishedWatermark => {
                formatter.write_str("chunk lies outside the published segment watermark")
            }
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
            Self::RecordDigestMismatch { expected, actual } => write!(
                formatter,
                "stored record digest mismatch: expected {expected}, loaded {actual}"
            ),
        }
    }
}

impl std::error::Error for SegmentReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspect(error) | Self::Read(error) | Self::Write(error) | Self::Seek(error) => {
                Some(error)
            }
            Self::PublishedCommit(error) => Some(error),
            Self::Format { source, .. } => Some(source),
            Self::InvalidRange(error) => Some(error),
            Self::RangeOutsideRecord
            | Self::RangeOutsidePublishedWatermark
            | Self::RangeOverflow
            | Self::SegmentMismatch { .. }
            | Self::ChunkIndexMismatch(_)
            | Self::ChunkCoverageGap { .. }
            | Self::ChunkOutsidePublishedWatermark
            | Self::FrameChecksumMismatch(_)
            | Self::NonceMismatch(_)
            | Self::AuthenticationFailed(_)
            | Self::PlaintextDigestMismatch(_)
            | Self::RecordDigestMismatch { .. } => None,
        }
    }
}

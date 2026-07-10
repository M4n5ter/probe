use std::{
    fmt,
    fs::File,
    io::{self, Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
};

use evidence::{ContentDigest, SegmentId};

use super::{
    ChunkCodecError, STORED_CHUNK_VALUE_LEN, StoredChunkRef, decode_chunk_value, encode_chunk_value,
};

const ENTRY_DATA_LEN: usize = 8 + STORED_CHUNK_VALUE_LEN;
const ENTRY_LEN: usize = ENTRY_DATA_LEN + 32;

pub(crate) struct ChunkJournal {
    file: File,
    segment: SegmentId,
    entries: u64,
}

impl ChunkJournal {
    pub(crate) fn new(file: File, segment: SegmentId) -> Result<Self, ChunkJournalError> {
        let length = file.metadata().map_err(ChunkJournalError::Inspect)?.len();
        if length != 0 {
            return Err(ChunkJournalError::NonEmpty(length));
        }
        Ok(Self {
            file,
            segment,
            entries: 0,
        })
    }

    pub(crate) fn reset(&mut self) -> Result<(), ChunkJournalError> {
        self.file.set_len(0).map_err(ChunkJournalError::Truncate)?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(ChunkJournalError::Seek)?;
        self.entries = 0;
        Ok(())
    }

    pub(crate) fn append(&mut self, chunk: StoredChunkRef) -> Result<(), ChunkJournalError> {
        if chunk.segment() != self.segment {
            return Err(ChunkJournalError::SegmentMismatch {
                expected: self.segment,
                actual: chunk.segment(),
            });
        }
        self.file
            .write_all(&encode_entry(chunk))
            .map_err(ChunkJournalError::Write)?;
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(ChunkJournalError::EntryCountOverflow)?;
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Result<ChunkJournalSnapshot, ChunkJournalError> {
        let expected = self
            .entries
            .checked_mul(ENTRY_LEN as u64)
            .ok_or(ChunkJournalError::FileOffsetOverflow)?;
        let actual = self
            .file
            .metadata()
            .map_err(ChunkJournalError::Inspect)?
            .len();
        if actual != expected {
            return Err(ChunkJournalError::LengthMismatch { expected, actual });
        }
        Ok(ChunkJournalSnapshot {
            file: self.file.try_clone().map_err(ChunkJournalError::Clone)?,
            segment: self.segment,
            entries: self.entries,
        })
    }
}

pub(crate) struct ChunkJournalSnapshot {
    file: File,
    segment: SegmentId,
    entries: u64,
}

impl ChunkJournalSnapshot {
    pub(crate) const fn len(&self) -> u64 {
        self.entries
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.entries == 0
    }

    pub(crate) fn iter(&self) -> ChunkJournalIter<'_> {
        ChunkJournalIter {
            journal: self,
            index: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_chunks(
        file: File,
        segment: SegmentId,
        chunks: &[StoredChunkRef],
    ) -> Result<Self, ChunkJournalError> {
        let mut journal = ChunkJournal::new(file, segment)?;
        for chunk in chunks {
            journal.append(*chunk)?;
        }
        journal.snapshot()
    }
}

pub(crate) struct ChunkJournalIter<'journal> {
    journal: &'journal ChunkJournalSnapshot,
    index: u64,
}

impl Iterator for ChunkJournalIter<'_> {
    type Item = Result<StoredChunkRef, ChunkJournalError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.journal.entries {
            return None;
        }
        let index = self.index;
        self.index += 1;
        Some(read_entry(self.journal, index))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.journal.entries - self.index;
        match usize::try_from(remaining) {
            Ok(remaining) => (remaining, Some(remaining)),
            Err(_) => (usize::MAX, None),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ChunkJournalError {
    Inspect(io::Error),
    Truncate(io::Error),
    Seek(io::Error),
    Write(io::Error),
    Clone(io::Error),
    Read(io::Error),
    NonEmpty(u64),
    SegmentMismatch {
        expected: SegmentId,
        actual: SegmentId,
    },
    EntryCountOverflow,
    FileOffsetOverflow,
    LengthMismatch {
        expected: u64,
        actual: u64,
    },
    ChecksumMismatch(u64),
    Codec(ChunkCodecError),
}

impl fmt::Display for ChunkJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => write!(formatter, "failed to inspect chunk journal: {error}"),
            Self::Truncate(error) => write!(formatter, "failed to reset chunk journal: {error}"),
            Self::Seek(error) => write!(formatter, "failed to seek chunk journal: {error}"),
            Self::Write(error) => write!(formatter, "failed to append chunk journal: {error}"),
            Self::Clone(error) => write!(formatter, "failed to snapshot chunk journal: {error}"),
            Self::Read(error) => write!(formatter, "failed to read chunk journal: {error}"),
            Self::NonEmpty(length) => {
                write!(formatter, "new chunk journal contains {length} byte(s)")
            }
            Self::SegmentMismatch { expected, actual } => write!(
                formatter,
                "chunk journal belongs to segment {}, not segment {}",
                expected.get(),
                actual.get()
            ),
            Self::EntryCountOverflow => formatter.write_str("chunk journal entry count overflows"),
            Self::FileOffsetOverflow => formatter.write_str("chunk journal file offset overflows"),
            Self::LengthMismatch { expected, actual } => write!(
                formatter,
                "chunk journal length is {actual}, expected {expected}"
            ),
            Self::ChecksumMismatch(index) => {
                write!(formatter, "chunk journal entry {index} checksum mismatch")
            }
            Self::Codec(error) => write!(formatter, "invalid chunk journal entry: {error}"),
        }
    }
}

impl std::error::Error for ChunkJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspect(error)
            | Self::Truncate(error)
            | Self::Seek(error)
            | Self::Write(error)
            | Self::Clone(error)
            | Self::Read(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::NonEmpty(_)
            | Self::SegmentMismatch { .. }
            | Self::EntryCountOverflow
            | Self::FileOffsetOverflow
            | Self::LengthMismatch { .. }
            | Self::ChecksumMismatch(_) => None,
        }
    }
}

fn encode_entry(chunk: StoredChunkRef) -> [u8; ENTRY_LEN] {
    let mut bytes = [0_u8; ENTRY_LEN];
    bytes[..8].copy_from_slice(&chunk.logical().start().to_be_bytes());
    bytes[8..ENTRY_DATA_LEN].copy_from_slice(&encode_chunk_value(chunk));
    let checksum = entry_checksum(&bytes[..ENTRY_DATA_LEN]);
    bytes[ENTRY_DATA_LEN..].copy_from_slice(checksum.as_bytes());
    bytes
}

fn read_entry(
    journal: &ChunkJournalSnapshot,
    index: u64,
) -> Result<StoredChunkRef, ChunkJournalError> {
    let offset = index
        .checked_mul(ENTRY_LEN as u64)
        .ok_or(ChunkJournalError::FileOffsetOverflow)?;
    let mut bytes = [0_u8; ENTRY_LEN];
    journal
        .file
        .read_exact_at(&mut bytes, offset)
        .map_err(ChunkJournalError::Read)?;
    if bytes[ENTRY_DATA_LEN..] != *entry_checksum(&bytes[..ENTRY_DATA_LEN]).as_bytes() {
        return Err(ChunkJournalError::ChecksumMismatch(index));
    }
    decode_chunk_value(
        journal.segment,
        read_u64(&bytes, 0),
        &bytes[8..ENTRY_DATA_LEN],
    )
    .map_err(ChunkJournalError::Codec)
}

fn entry_checksum(bytes: &[u8]) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-chunk-journal-entry\0");
    hasher.update(bytes);
    ContentDigest::new(*hasher.finalize().as_bytes())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("fixed range"))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use evidence::{EvidenceId, OffsetRange};
    use tempfile::tempfile;

    use super::*;
    use crate::{BatchId, RecordKind};

    #[test]
    fn snapshots_replay_fixed_checked_entries_and_reject_tampering() {
        let segment = SegmentId::new(1).expect("segment ID");
        let mut journal =
            ChunkJournal::new(tempfile().expect("journal"), segment).expect("journal");
        let chunk = StoredChunkRef {
            segment,
            evidence: EvidenceId::new(2).expect("evidence ID"),
            batch: BatchId::new(3).expect("batch ID"),
            kind: RecordKind::Plaintext,
            logical: OffsetRange::new(4, 5).expect("range"),
            file_offset: 192,
            sequence: 1,
            plaintext_digest: ContentDigest::for_bytes(b"chunk"),
        };
        journal.append(chunk).expect("append");
        let snapshot = journal.snapshot().expect("snapshot");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(
            snapshot
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .expect("replay"),
            [chunk]
        );

        journal.file.seek(SeekFrom::Start(0)).expect("seek");
        journal.file.write_all(&[0xff]).expect("tamper");
        assert!(matches!(
            snapshot.iter().next(),
            Some(Err(ChunkJournalError::ChecksumMismatch(0)))
        ));
    }
}

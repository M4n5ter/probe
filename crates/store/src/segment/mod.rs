mod chunk;
mod chunk_journal;
mod crypto;
mod format;
mod lock;
mod reader;
mod recovery;
mod writer;

pub(crate) use chunk::{
    ChunkCodecError, STORED_CHUNK_VALUE_LEN, StoredChunkRef, decode_chunk_value, encode_chunk_value,
};
pub(crate) use chunk_journal::{ChunkJournalError, ChunkJournalSnapshot};
pub use crypto::{SegmentCryptoError, SegmentKey};
pub(crate) use format::{AEAD_TAG_LEN, FRAME_CHECKSUM_LEN, FRAME_HEADER_LEN, SEGMENT_HEADER_LEN};
pub use format::{
    BatchId, ChecksumAlgorithm, CipherAlgorithm, KeyReference, RecordKind, SegmentFormatError,
    SegmentHeader,
};
pub use lock::SegmentLockError;
pub(crate) use lock::{lock_exclusive, lock_shared};
pub use reader::SegmentReadError;
pub(crate) use reader::SegmentReader;
pub use recovery::{SegmentRecoveryError, SegmentRecoveryReport};
pub(crate) use recovery::{recover_segment_to_published, validate_committed_segment};
pub(crate) use writer::StoreOwnerToken;
pub use writer::{
    CommittedBatch, DurabilityProfile, PublishedBatch, SegmentBatch, SegmentWatermark,
    SegmentWriter, SegmentWriterError, StoredRecordRef,
};

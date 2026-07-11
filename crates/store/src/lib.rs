mod durable;
mod layout;
mod metadata;
mod runtime;
mod segment;

pub use durable::{DurableDirectory, DurableFileError, PreallocatedFile};
pub(crate) use layout::StoreLayout;
pub use layout::StoreLayoutError;
pub(crate) use metadata::MetadataStore;
pub use metadata::{MetadataError, MetadataSnapshot, PublishOutcome};
pub use runtime::{EvidenceStore, EvidenceStoreError};
pub(crate) use segment::{
    AEAD_TAG_LEN, ChunkJournalSnapshot, FRAME_CHECKSUM_LEN, FRAME_HEADER_LEN, SEGMENT_HEADER_LEN,
    SegmentReader, StoreOwnerToken, lock_exclusive, lock_shared, recover_segment_to_published,
    validate_committed_segment,
};
pub use segment::{
    BatchId, ChecksumAlgorithm, CipherAlgorithm, CommittedBatch, DurabilityProfile, KeyReference,
    PublishedBatch, RecordKind, SegmentBatch, SegmentCryptoError, SegmentFormatError,
    SegmentHeader, SegmentKey, SegmentLockError, SegmentReadError, SegmentRecoveryError,
    SegmentRecoveryReport, SegmentWatermark, SegmentWriter, SegmentWriterError, StoredRecordRef,
};

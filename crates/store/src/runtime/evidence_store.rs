use std::{fmt, io::Write, path::Path, sync::Arc};

use evidence::{OffsetRange, RangeError, SegmentId};

use crate::{
    CommittedBatch, DurabilityProfile, MetadataError, MetadataSnapshot, MetadataStore,
    PublishOutcome, PublishedBatch, SegmentHeader, SegmentKey, SegmentLockError, SegmentReadError,
    SegmentReader, SegmentRecoveryError, SegmentRecoveryReport, SegmentWriter, SegmentWriterError,
    StoreLayout, StoreLayoutError, StoreOwnerToken, StoredRecordRef, lock_exclusive, lock_shared,
    recover_segment_to_published, validate_committed_segment,
};

pub struct EvidenceStore {
    layout: StoreLayout,
    metadata: MetadataStore,
    durability: DurabilityProfile,
    owner: Arc<StoreOwnerToken>,
}

impl EvidenceStore {
    pub fn open(path: &Path, durability: DurabilityProfile) -> Result<Self, EvidenceStoreError> {
        let layout = StoreLayout::ensure(path).map_err(EvidenceStoreError::Layout)?;
        let metadata_file = layout
            .open_or_create_metadata()
            .map_err(EvidenceStoreError::Layout)?;
        let metadata =
            MetadataStore::open(metadata_file, durability).map_err(EvidenceStoreError::Metadata)?;
        Ok(Self {
            layout,
            metadata,
            durability,
            owner: Arc::new(StoreOwnerToken),
        })
    }

    pub fn create_segment(
        &self,
        header: SegmentHeader,
        key: SegmentKey,
    ) -> Result<SegmentWriter, EvidenceStoreError> {
        let owner_lease = self
            .layout
            .open_or_create_segment_owner(header.segment())
            .map_err(EvidenceStoreError::Layout)?;
        let chunk_journal = self
            .layout
            .create_chunk_journal()
            .map_err(EvidenceStoreError::Layout)?;
        let file = self
            .layout
            .create_segment(header.segment())
            .map_err(EvidenceStoreError::Layout)?;
        SegmentWriter::create(
            file,
            owner_lease,
            chunk_journal,
            header,
            key,
            self.durability,
            Arc::clone(&self.owner),
        )
        .map_err(EvidenceStoreError::SegmentWrite)
    }

    pub fn recover_segment(
        &self,
        segment: SegmentId,
        key: SegmentKey,
    ) -> Result<SegmentRecoveryReport, EvidenceStoreError> {
        let owner_lease = self
            .layout
            .open_segment_owner(segment)
            .map_err(EvidenceStoreError::Layout)?;
        lock_exclusive(&owner_lease).map_err(EvidenceStoreError::SegmentLock)?;
        let mut file = self
            .layout
            .open_segment_read_write(segment)
            .map_err(EvidenceStoreError::Layout)?;
        lock_exclusive(&file).map_err(EvidenceStoreError::SegmentLock)?;
        let published = self
            .metadata
            .snapshot()
            .map_err(EvidenceStoreError::Metadata)?
            .watermark(segment)
            .map_err(EvidenceStoreError::Metadata)?;
        recover_segment_to_published(&mut file, &key, published)
            .map_err(EvidenceStoreError::SegmentRecovery)
    }

    pub fn publish_batch(
        &self,
        committed: CommittedBatch,
    ) -> Result<(PublishOutcome, PublishedBatch), EvidenceStoreError> {
        if !committed.belongs_to(&self.owner) {
            return Err(EvidenceStoreError::ForeignCommittedBatch);
        }
        let mut segment = self
            .layout
            .open_segment_read(committed.watermark().segment())
            .map_err(EvidenceStoreError::Layout)?;
        lock_shared(&segment).map_err(EvidenceStoreError::SegmentLock)?;
        validate_committed_segment(&mut segment, committed.watermark())
            .map_err(EvidenceStoreError::SegmentRecovery)?;
        let outcome = self
            .metadata
            .publish_batch(
                committed.watermark(),
                committed.records(),
                committed.chunks(),
            )
            .map_err(EvidenceStoreError::Metadata)?;
        Ok((outcome, committed.mark_published()))
    }

    pub fn read_record_to(
        &self,
        record: StoredRecordRef,
        key: SegmentKey,
        output: &mut impl Write,
    ) -> Result<u64, EvidenceStoreError> {
        self.read_record(record, record.bytes().range, None, key, output)
    }

    pub fn read_record_range_to(
        &self,
        record: StoredRecordRef,
        relative: OffsetRange,
        key: SegmentKey,
        output: &mut impl Write,
    ) -> Result<u64, EvidenceStoreError> {
        if relative.end() > record.bytes().range.length().get() {
            return Err(EvidenceStoreError::RangeOutsideRecord);
        }
        let absolute_start = record
            .bytes()
            .range
            .start()
            .checked_add(relative.start())
            .ok_or(EvidenceStoreError::RangeOverflow)?;
        let absolute = OffsetRange::new(absolute_start, relative.length().get())
            .map_err(EvidenceStoreError::InvalidRange)?;
        self.read_record(record, absolute, Some(relative), key, output)
    }

    pub fn snapshot(&self) -> Result<MetadataSnapshot, EvidenceStoreError> {
        self.metadata
            .snapshot()
            .map_err(EvidenceStoreError::Metadata)
    }

    fn read_record(
        &self,
        record: StoredRecordRef,
        absolute: OffsetRange,
        relative: Option<OffsetRange>,
        key: SegmentKey,
        output: &mut impl Write,
    ) -> Result<u64, EvidenceStoreError> {
        let segment = record.bytes().segment;
        let file = self
            .layout
            .open_segment_read(segment)
            .map_err(EvidenceStoreError::Layout)?;
        lock_shared(&file).map_err(EvidenceStoreError::SegmentLock)?;

        let snapshot = self
            .metadata
            .snapshot()
            .map_err(EvidenceStoreError::Metadata)?;
        let published_record = snapshot
            .record(record.evidence())
            .map_err(EvidenceStoreError::Metadata)?
            .ok_or(EvidenceStoreError::RecordNotPublished(record.evidence()))?;
        if published_record != record {
            return Err(EvidenceStoreError::StaleRecordReference(record.evidence()));
        }
        let watermark = snapshot
            .watermark(segment)
            .map_err(EvidenceStoreError::Metadata)?
            .ok_or(EvidenceStoreError::MissingWatermark(segment))?;
        let chunks = snapshot
            .chunks_for_record(record, absolute)
            .map_err(EvidenceStoreError::Metadata)?;
        let mut reader = SegmentReader::open_locked(file, key, watermark)
            .map_err(EvidenceStoreError::SegmentRead)?;
        match relative {
            Some(range) => reader
                .read_record_range_to(record, range, &chunks, output)
                .map_err(EvidenceStoreError::SegmentRead),
            None => reader
                .read_record_to(record, &chunks, output)
                .map_err(EvidenceStoreError::SegmentRead),
        }
    }
}

#[derive(Debug)]
pub enum EvidenceStoreError {
    Layout(StoreLayoutError),
    Metadata(MetadataError),
    SegmentLock(SegmentLockError),
    SegmentWrite(SegmentWriterError),
    SegmentRead(SegmentReadError),
    SegmentRecovery(SegmentRecoveryError),
    ForeignCommittedBatch,
    RecordNotPublished(evidence::EvidenceId),
    StaleRecordReference(evidence::EvidenceId),
    MissingWatermark(SegmentId),
    InvalidRange(RangeError),
    RangeOutsideRecord,
    RangeOverflow,
}

impl fmt::Display for EvidenceStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Layout(error) => write!(formatter, "store layout failed: {error}"),
            Self::Metadata(error) => write!(formatter, "store metadata failed: {error}"),
            Self::SegmentLock(error) => write!(formatter, "segment ownership failed: {error}"),
            Self::SegmentWrite(error) => write!(formatter, "segment write failed: {error}"),
            Self::SegmentRead(error) => write!(formatter, "segment read failed: {error}"),
            Self::SegmentRecovery(error) => write!(formatter, "segment recovery failed: {error}"),
            Self::ForeignCommittedBatch => {
                formatter.write_str("committed batch belongs to another evidence store")
            }
            Self::RecordNotPublished(evidence) => write!(
                formatter,
                "evidence {} is not present in published metadata",
                evidence.get()
            ),
            Self::StaleRecordReference(evidence) => write!(
                formatter,
                "evidence {} does not match published metadata",
                evidence.get()
            ),
            Self::MissingWatermark(segment) => write!(
                formatter,
                "segment {} has no published watermark",
                segment.get()
            ),
            Self::InvalidRange(error) => write!(formatter, "invalid record range: {error}"),
            Self::RangeOutsideRecord => {
                formatter.write_str("requested range lies outside the stored record")
            }
            Self::RangeOverflow => formatter.write_str("requested record range overflows"),
        }
    }
}

impl std::error::Error for EvidenceStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Layout(error) => Some(error),
            Self::Metadata(error) => Some(error),
            Self::SegmentLock(error) => Some(error),
            Self::SegmentWrite(error) => Some(error),
            Self::SegmentRead(error) => Some(error),
            Self::SegmentRecovery(error) => Some(error),
            Self::InvalidRange(error) => Some(error),
            Self::ForeignCommittedBatch
            | Self::RecordNotPublished(_)
            | Self::StaleRecordReference(_)
            | Self::MissingWatermark(_)
            | Self::RangeOutsideRecord
            | Self::RangeOverflow => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, io::Cursor};

    use evidence::{EvidenceId, SegmentId};
    use tempfile::tempdir;

    use super::*;
    use crate::{BatchId, KeyReference, RecordKind};

    #[test]
    fn persists_queries_and_reads_a_record_through_the_public_store_path() {
        let temp = tempdir().expect("temporary directory");
        let store = EvidenceStore::open(
            &temp.path().join("probe-store"),
            DurabilityProfile::PowerLoss,
        )
        .expect("evidence store");
        let segment = SegmentId::new(1).expect("segment ID");
        let key_bytes = [7; 32];
        let mut writer = store
            .create_segment(
                SegmentHeader::new(
                    segment,
                    1,
                    KeyReference::new("test/key").expect("key reference"),
                ),
                SegmentKey::new(key_bytes),
            )
            .expect("segment writer");
        let mut batch = writer
            .begin_batch(BatchId::new(2).expect("batch ID"))
            .expect("batch");
        let payload = b"persisted evidence body";
        batch
            .append_reader(
                EvidenceId::new(3).expect("evidence ID"),
                RecordKind::Plaintext,
                Cursor::new(payload),
            )
            .expect("record");
        let committed = batch.commit().expect("segment commit");
        let watermark = committed.watermark();
        let (outcome, published) = store.publish_batch(committed).expect("metadata publish");
        assert_eq!(outcome, PublishOutcome::Published);
        let record = published.records()[0];
        drop(writer);

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot.record(record.evidence()).expect("record"),
            Some(record)
        );
        assert_eq!(
            snapshot.watermark(segment).expect("watermark"),
            Some(watermark)
        );
        drop(snapshot);

        assert!(matches!(
            store.read_record_to(record, SegmentKey::new([8; 32]), &mut Vec::new()),
            Err(EvidenceStoreError::SegmentRead(
                SegmentReadError::NonceMismatch(_) | SegmentReadError::AuthenticationFailed(_)
            ))
        ));
        let mut loaded = Vec::new();
        assert_eq!(
            store
                .read_record_to(record, SegmentKey::new(key_bytes), &mut loaded)
                .expect("record bytes"),
            payload.len() as u64
        );
        assert_eq!(loaded, payload);
    }

    #[test]
    fn refuses_to_hide_a_segment_that_falls_behind_published_metadata() {
        let temp = tempdir().expect("temporary directory");
        let path = temp.path().join("probe-store");
        let store =
            EvidenceStore::open(&path, DurabilityProfile::PowerLoss).expect("evidence store");
        let segment = SegmentId::new(1).expect("segment ID");
        let mut writer = store
            .create_segment(
                SegmentHeader::new(
                    segment,
                    1,
                    KeyReference::new("test/key").expect("key reference"),
                ),
                SegmentKey::new([7; 32]),
            )
            .expect("segment writer");
        let mut batch = writer
            .begin_batch(BatchId::new(2).expect("batch ID"))
            .expect("batch");
        batch
            .append_reader(
                EvidenceId::new(3).expect("evidence ID"),
                RecordKind::Plaintext,
                Cursor::new(b"published"),
            )
            .expect("record");
        let committed = batch.commit().expect("segment commit");
        let watermark = committed.watermark();
        let (_, published) = store.publish_batch(committed).expect("metadata publish");
        let record = published.records()[0];
        drop(writer);

        let segment_path = path
            .join("segments")
            .join(format!("{:032x}.segment", segment.get()));
        OpenOptions::new()
            .write(true)
            .open(segment_path)
            .expect("segment file")
            .set_len(watermark.committed_file_len() - 1)
            .expect("truncate published commit");

        assert!(matches!(
            store.read_record_to(record, SegmentKey::new([7; 32]), &mut Vec::new()),
            Err(EvidenceStoreError::SegmentRead(
                SegmentReadError::PublishedCommit(SegmentRecoveryError::PublishedWatermarkAhead)
            ))
        ));
    }

    #[test]
    fn live_writer_fences_recovery_while_idle_reader_sees_published_data() {
        let temp = tempdir().expect("temporary directory");
        let store = EvidenceStore::open(
            &temp.path().join("probe-store"),
            DurabilityProfile::ProcessCrash,
        )
        .expect("evidence store");
        let segment = SegmentId::new(1).expect("segment ID");
        let key = [9; 32];
        let mut writer = store
            .create_segment(
                SegmentHeader::new(
                    segment,
                    1,
                    KeyReference::new("test/key").expect("key reference"),
                ),
                SegmentKey::new(key),
            )
            .expect("segment writer");
        let mut batch = writer
            .begin_batch(BatchId::new(1).expect("batch ID"))
            .expect("batch");
        batch
            .append_reader(
                EvidenceId::new(1).expect("evidence ID"),
                RecordKind::Plaintext,
                Cursor::new(b"published"),
            )
            .expect("record");
        let (_, published) = store
            .publish_batch(batch.commit().expect("commit"))
            .expect("publish");
        let record = published.records()[0];

        assert!(matches!(
            store.recover_segment(segment, SegmentKey::new(key)),
            Err(EvidenceStoreError::SegmentLock(SegmentLockError::Busy))
        ));

        let mut loaded = Vec::new();
        store
            .read_record_to(record, SegmentKey::new(key), &mut loaded)
            .expect("read from idle active segment");
        assert_eq!(loaded, b"published");

        let active_batch = writer
            .begin_batch(BatchId::new(2).expect("active batch ID"))
            .expect("active batch");
        assert!(matches!(
            store.read_record_to(record, SegmentKey::new(key), &mut Vec::new()),
            Err(EvidenceStoreError::SegmentLock(SegmentLockError::Busy))
        ));
        drop(active_batch);
        loaded.clear();
        store
            .read_record_to(record, SegmentKey::new(key), &mut loaded)
            .expect("read after active batch release");
        assert_eq!(loaded, b"published");
    }

    #[test]
    fn committed_batch_retains_the_recovery_fence_after_writer_drop() {
        let temp = tempdir().expect("temporary directory");
        let store = EvidenceStore::open(
            &temp.path().join("probe-store"),
            DurabilityProfile::ProcessCrash,
        )
        .expect("evidence store");
        let segment = SegmentId::new(1).expect("segment ID");
        let key = [8; 32];
        let mut writer = store
            .create_segment(
                SegmentHeader::new(
                    segment,
                    1,
                    KeyReference::new("test/key").expect("key reference"),
                ),
                SegmentKey::new(key),
            )
            .expect("segment writer");
        let mut batch = writer
            .begin_batch(BatchId::new(1).expect("batch ID"))
            .expect("batch");
        batch
            .append_reader(
                EvidenceId::new(1).expect("evidence ID"),
                RecordKind::Plaintext,
                Cursor::new(b"pending publication"),
            )
            .expect("record");
        let committed = batch.commit().expect("commit");
        let watermark = committed.watermark();
        drop(writer);

        assert!(matches!(
            store.recover_segment(segment, SegmentKey::new(key)),
            Err(EvidenceStoreError::SegmentLock(SegmentLockError::Busy))
        ));
        store.publish_batch(committed).expect("publish");
        let report = store
            .recover_segment(segment, SegmentKey::new(key))
            .expect("recovery after publication");
        assert_eq!(report.last_watermark, Some(watermark));
        assert_eq!(report.discarded_committed_orphan_bytes, 0);
    }

    #[test]
    fn foreign_store_cannot_consume_a_committed_batch() {
        let temp = tempdir().expect("temporary directory");
        let origin =
            EvidenceStore::open(&temp.path().join("origin"), DurabilityProfile::ProcessCrash)
                .expect("origin store");
        let foreign = EvidenceStore::open(
            &temp.path().join("foreign"),
            DurabilityProfile::ProcessCrash,
        )
        .expect("foreign store");
        let mut writer = origin
            .create_segment(
                SegmentHeader::new(
                    SegmentId::new(1).expect("segment ID"),
                    1,
                    KeyReference::new("test/key").expect("key reference"),
                ),
                SegmentKey::new([3; 32]),
            )
            .expect("segment writer");
        let mut batch = writer
            .begin_batch(BatchId::new(1).expect("batch ID"))
            .expect("batch");
        batch
            .append_reader(
                EvidenceId::new(1).expect("evidence ID"),
                RecordKind::Packet,
                Cursor::new(b"packet"),
            )
            .expect("record");

        assert!(matches!(
            foreign.publish_batch(batch.commit().expect("commit")),
            Err(EvidenceStoreError::ForeignCommittedBatch)
        ));
        assert!(matches!(
            writer.begin_batch(BatchId::new(2).expect("next batch ID")),
            Err(SegmentWriterError::Poisoned)
        ));
    }

    #[test]
    fn reads_a_narrow_range_from_a_multi_chunk_record() {
        let temp = tempdir().expect("temporary directory");
        let store = EvidenceStore::open(
            &temp.path().join("probe-store"),
            DurabilityProfile::ProcessCrash,
        )
        .expect("evidence store");
        let segment = SegmentId::new(1).expect("segment ID");
        let key = [4; 32];
        let mut writer = store
            .create_segment(
                SegmentHeader::new(
                    segment,
                    1,
                    KeyReference::new("test/key").expect("key reference"),
                ),
                SegmentKey::new(key),
            )
            .expect("segment writer");
        let payload = (0..3 * 1024 * 1024 + 17)
            .map(|offset| (offset % 251) as u8)
            .collect::<Vec<_>>();
        let mut batch = writer
            .begin_batch(BatchId::new(1).expect("batch ID"))
            .expect("batch");
        batch
            .append_reader(
                EvidenceId::new(1).expect("evidence ID"),
                RecordKind::Plaintext,
                Cursor::new(&payload),
            )
            .expect("record");
        let (_, published) = store
            .publish_batch(batch.commit().expect("commit"))
            .expect("publish");
        let record = published.records()[0];
        drop(writer);

        let relative = OffsetRange::new(1_500_000, 137).expect("range");
        let mut loaded = Vec::new();
        assert_eq!(
            store
                .read_record_range_to(record, relative, SegmentKey::new(key), &mut loaded)
                .expect("range read"),
            relative.length().get()
        );
        assert_eq!(loaded, payload[1_500_000..1_500_137]);
    }
}

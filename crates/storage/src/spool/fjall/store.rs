use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

use fjall::{Database, Keyspace, KeyspaceCreateOptions};

use crate::spool::{
    DurableSpool, ExportSpool, IngressCursorOwner, SpoolSnapshot, StorageError,
    lane::{
        LAST_EXPORT_SEQUENCE, LAST_INGRESS_SEQUENCE, LIVE_EXPORT_RECORDS, LIVE_INGRESS_RECORDS,
        SpoolLane,
    },
    marker::{ensure_spool_markers, validate_existing_spool_markers},
    record::{AppendOutcome, RetentionPrune, SpoolPayload, StoredEvent},
};

const INGRESS_JOURNAL: &str = "ingress_journal";
const EXPORT_QUEUE: &str = "export_queue";
const INGRESS_CURSORS: &str = "ingress_cursors";
const EXPORT_CURSORS: &str = "export_cursors";
const EXPORT_DEDUP: &str = "export_dedup";
const EXPORT_DEDUP_BY_SEQUENCE: &str = "export_dedup_by_sequence";
const METADATA: &str = "metadata";
pub struct FjallSpool {
    pub(super) database: Database,
    ingress_journal: Keyspace,
    pub(super) export_queue: Keyspace,
    ingress_cursors: Keyspace,
    pub(super) export_cursors: Keyspace,
    pub(super) export_dedup: Keyspace,
    pub(super) export_dedup_by_sequence: Keyspace,
    pub(super) metadata: Keyspace,
    last_ingress_sequence: Mutex<u64>,
    last_export_sequence: Mutex<u64>,
    live_ingress_records: Mutex<u64>,
    live_export_records: Mutex<u64>,
}

impl FjallSpool {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        validate_existing_spool_markers(path)?;
        let database = Database::builder(path).open()?;
        let ingress_journal = database.keyspace(INGRESS_JOURNAL, KeyspaceCreateOptions::default)?;
        let export_queue = database.keyspace(EXPORT_QUEUE, KeyspaceCreateOptions::default)?;
        let ingress_cursors = database.keyspace(INGRESS_CURSORS, KeyspaceCreateOptions::default)?;
        let export_cursors = database.keyspace(EXPORT_CURSORS, KeyspaceCreateOptions::default)?;
        let export_dedup = database.keyspace(EXPORT_DEDUP, KeyspaceCreateOptions::default)?;
        let export_dedup_by_sequence =
            database.keyspace(EXPORT_DEDUP_BY_SEQUENCE, KeyspaceCreateOptions::default)?;
        let metadata = database.keyspace(METADATA, KeyspaceCreateOptions::default)?;
        let last_ingress_sequence =
            read_last_sequence(&ingress_journal, &metadata, LAST_INGRESS_SEQUENCE)?;
        let last_export_sequence =
            read_last_sequence(&export_queue, &metadata, LAST_EXPORT_SEQUENCE)?;
        let live_ingress_records = read_live_records(
            &ingress_journal,
            &metadata,
            LIVE_INGRESS_RECORDS,
            last_ingress_sequence,
        )?;
        let live_export_records = read_live_records(
            &export_queue,
            &metadata,
            LIVE_EXPORT_RECORDS,
            last_export_sequence,
        )?;
        let spool = Self {
            database,
            ingress_journal,
            export_queue,
            ingress_cursors,
            export_cursors,
            export_dedup,
            export_dedup_by_sequence,
            metadata,
            last_ingress_sequence: Mutex::new(last_ingress_sequence),
            last_export_sequence: Mutex::new(last_export_sequence),
            live_ingress_records: Mutex::new(live_ingress_records),
            live_export_records: Mutex::new(live_export_records),
        };
        ensure_spool_markers(path)?;
        Ok(spool)
    }

    pub fn snapshot(&self) -> Result<SpoolSnapshot, StorageError> {
        Ok(SpoolSnapshot {
            last_ingress_sequence: *self.lock_last_sequence(SpoolLane::Ingress)?,
            last_export_sequence: *self.lock_last_sequence(SpoolLane::Export)?,
        })
    }

    pub(super) fn queue(&self, lane: SpoolLane) -> &Keyspace {
        match lane {
            SpoolLane::Ingress => &self.ingress_journal,
            SpoolLane::Export => &self.export_queue,
        }
    }

    pub(super) fn cursors(&self, lane: SpoolLane) -> &Keyspace {
        match lane {
            SpoolLane::Ingress => &self.ingress_cursors,
            SpoolLane::Export => &self.export_cursors,
        }
    }

    pub(super) fn lock_last_sequence(
        &self,
        lane: SpoolLane,
    ) -> Result<MutexGuard<'_, u64>, StorageError> {
        match lane {
            SpoolLane::Ingress => self
                .last_ingress_sequence
                .lock()
                .map_err(|_| StorageError::SequenceLockPoisoned { lane: lane.name() }),
            SpoolLane::Export => self
                .last_export_sequence
                .lock()
                .map_err(|_| StorageError::SequenceLockPoisoned { lane: lane.name() }),
        }
    }

    pub(super) fn lock_live_records(
        &self,
        lane: SpoolLane,
    ) -> Result<MutexGuard<'_, u64>, StorageError> {
        match lane {
            SpoolLane::Ingress => self
                .live_ingress_records
                .lock()
                .map_err(|_| StorageError::LiveRecordCountLockPoisoned { lane: lane.name() }),
            SpoolLane::Export => self
                .live_export_records
                .lock()
                .map_err(|_| StorageError::LiveRecordCountLockPoisoned { lane: lane.name() }),
        }
    }
}

impl ExportSpool for FjallSpool {
    fn read_export_batch(
        &self,
        sink: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        FjallSpool::read_export_batch(self, sink, limit)
    }

    fn ack_export(&self, sink: &str, sequence: u64) -> Result<(), StorageError> {
        FjallSpool::ack_export(self, sink, sequence)
    }

    fn export_cursor(&self, sink: &str) -> Result<u64, StorageError> {
        FjallSpool::export_cursor(self, sink)
    }

    fn prune_export_through(&self, sequence: u64, limit: usize) -> Result<u64, StorageError> {
        FjallSpool::prune_export_through(self, sequence, limit)
    }

    fn prune_expired_export_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<RetentionPrune, StorageError> {
        FjallSpool::prune_expired_export_prefix(self, cutoff_unix_ns, limit, cursor_owners)
    }

    fn prune_export_to_max_records(
        &self,
        max_records: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<RetentionPrune, StorageError> {
        FjallSpool::prune_export_to_max_records(self, max_records, limit, cursor_owners)
    }
}

impl DurableSpool for FjallSpool {
    fn append_ingress(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        FjallSpool::append_ingress(self, payload)
    }

    fn read_ingress_batch(
        &self,
        consumer: IngressCursorOwner,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        FjallSpool::read_ingress_batch(self, consumer, limit)
    }

    fn read_ingress_batch_after(
        &self,
        sequence: u64,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        FjallSpool::read_ingress_batch_after(self, sequence, limit)
    }

    fn ack_ingress(&self, consumer: IngressCursorOwner, sequence: u64) -> Result<(), StorageError> {
        FjallSpool::ack_ingress(self, consumer, sequence)
    }

    fn ingress_cursor(&self, consumer: IngressCursorOwner) -> Result<u64, StorageError> {
        FjallSpool::ingress_cursor(self, consumer)
    }

    fn append_export(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        FjallSpool::append_export(self, payload)
    }

    fn append_export_once(
        &self,
        dedup_key: &str,
        payload: SpoolPayload,
    ) -> Result<AppendOutcome, StorageError> {
        FjallSpool::append_export_once(self, dedup_key, payload)
    }

    fn prune_expired_ingress_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        consumers: &[IngressCursorOwner],
    ) -> Result<RetentionPrune, StorageError> {
        FjallSpool::prune_expired_ingress_prefix(self, cutoff_unix_ns, limit, consumers)
    }

    fn prune_ingress_to_max_records(
        &self,
        max_records: u64,
        limit: usize,
        consumers: &[IngressCursorOwner],
    ) -> Result<RetentionPrune, StorageError> {
        FjallSpool::prune_ingress_to_max_records(self, max_records, limit, consumers)
    }
}

fn read_last_sequence(
    queue: &Keyspace,
    metadata: &Keyspace,
    metadata_key: &[u8],
) -> Result<u64, StorageError> {
    if let Some(value) = metadata.get(metadata_key)? {
        return decode_exact_sequence_key(metadata_key, &value);
    }
    Ok(queue
        .range::<[u8; 8], _>(..)
        .next_back()
        .map(|item| {
            let (key, _) = item.into_inner()?;
            Ok::<_, fjall::Error>(decode_sequence_key(key.as_ref()))
        })
        .transpose()?
        .unwrap_or(0))
}

fn read_live_records(
    queue: &Keyspace,
    metadata: &Keyspace,
    metadata_key: &[u8],
    durable_last_sequence: u64,
) -> Result<u64, StorageError> {
    if let Some(value) = metadata.get(metadata_key)? {
        return decode_exact_sequence_key(metadata_key, &value);
    }
    queue
        .range(..=sequence_key(durable_last_sequence))
        .try_fold(0_u64, |count, item| {
            item.into_inner()?;
            count.checked_add(1).ok_or(StorageError::SequenceOverflow)
        })
}

pub(super) fn sequence_key(sequence: u64) -> [u8; 8] {
    sequence.to_be_bytes()
}

pub(super) fn decode_sequence_key(bytes: &[u8]) -> u64 {
    let mut key = [0_u8; 8];
    key.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(key)
}

fn decode_exact_sequence_key(key: &[u8], bytes: &[u8]) -> Result<u64, StorageError> {
    if bytes.len() != 8 {
        return Err(StorageError::InvalidMetadata {
            key: String::from_utf8_lossy(key).into_owned(),
            len: bytes.len(),
        });
    }
    Ok(decode_sequence_key(bytes))
}

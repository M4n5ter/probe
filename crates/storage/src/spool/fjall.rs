use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};

use super::{
    DurableSpool, ExportSpool, SpoolProbe, SpoolSnapshot, StorageError,
    lane::{LAST_EXPORT_SEQUENCE, LAST_INGRESS_SEQUENCE, SpoolLane},
    marker::{
        ensure_spool_markers, read_spool_marker, read_spool_ready_marker,
        validate_existing_spool_markers,
    },
    record::{
        ExportRetentionPrune, SpoolPayload, StoredEvent, decode_spool_record, encode_spool_record,
    },
};

const INGRESS_JOURNAL: &str = "ingress_journal";
const EXPORT_QUEUE: &str = "export_queue";
const INGRESS_CURSORS: &str = "ingress_cursors";
const EXPORT_CURSORS: &str = "export_cursors";
const METADATA: &str = "metadata";
pub struct FjallSpool {
    database: Database,
    ingress_journal: Keyspace,
    export_queue: Keyspace,
    ingress_cursors: Keyspace,
    export_cursors: Keyspace,
    metadata: Keyspace,
    last_ingress_sequence: Mutex<u64>,
    last_export_sequence: Mutex<u64>,
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
        let metadata = database.keyspace(METADATA, KeyspaceCreateOptions::default)?;
        let last_ingress_sequence =
            read_last_sequence(&ingress_journal, &metadata, LAST_INGRESS_SEQUENCE)?;
        let last_export_sequence =
            read_last_sequence(&export_queue, &metadata, LAST_EXPORT_SEQUENCE)?;
        let spool = Self {
            database,
            ingress_journal,
            export_queue,
            ingress_cursors,
            export_cursors,
            metadata,
            last_ingress_sequence: Mutex::new(last_ingress_sequence),
            last_export_sequence: Mutex::new(last_export_sequence),
        };
        ensure_spool_markers(path)?;
        Ok(spool)
    }

    pub fn probe(path: impl AsRef<Path>) -> Result<SpoolProbe, StorageError> {
        let path = path.as_ref();
        if !path.try_exists()? {
            return Ok(SpoolProbe::Missing);
        }
        if !read_spool_marker(path)? {
            return Ok(SpoolProbe::Incomplete {
                reason: "spool marker is missing".to_string(),
            });
        }
        if !read_spool_ready_marker(path)? {
            return Ok(SpoolProbe::Incomplete {
                reason: "spool ready marker is missing".to_string(),
            });
        }

        match Self::open(path) {
            Ok(spool) => Ok(SpoolProbe::Available {
                snapshot: spool.snapshot()?,
                export_cursors: spool.export_cursor_snapshot()?,
            }),
            Err(StorageError::Fjall(fjall::Error::Locked)) => Ok(SpoolProbe::Busy {
                reason: "spool database is locked by another process".to_string(),
            }),
            Err(error) => Err(error),
        }
    }

    pub fn is_initialized(path: impl AsRef<Path>) -> Result<bool, StorageError> {
        Ok(matches!(
            Self::probe(path)?,
            SpoolProbe::Available { .. } | SpoolProbe::Busy { .. }
        ))
    }

    pub fn append_ingress(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        self.append_payload(SpoolLane::Ingress, payload)
    }

    pub fn read_ingress_batch(
        &self,
        consumer: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        self.read_batch_from_lane(SpoolLane::Ingress, consumer, limit)
    }

    pub fn read_ingress_batch_after(
        &self,
        sequence: u64,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        self.read_batch_from_lane_after(SpoolLane::Ingress, sequence, limit)
    }

    pub fn ack_ingress(&self, consumer: &str, sequence: u64) -> Result<(), StorageError> {
        self.ack_lane(SpoolLane::Ingress, consumer, sequence)
    }

    pub fn ingress_cursor(&self, consumer: &str) -> Result<u64, StorageError> {
        self.cursor_for_lane(SpoolLane::Ingress, consumer)
    }

    pub fn append_export(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        self.append_payload(SpoolLane::Export, payload)
    }

    pub fn read_export_batch(
        &self,
        sink: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        self.read_batch_from_lane(SpoolLane::Export, sink, limit)
    }

    pub fn ack_export(&self, sink: &str, sequence: u64) -> Result<(), StorageError> {
        self.ack_lane(SpoolLane::Export, sink, sequence)
    }

    pub fn export_cursor(&self, sink: &str) -> Result<u64, StorageError> {
        self.cursor_for_lane(SpoolLane::Export, sink)
    }

    pub fn prune_export_through(&self, sequence: u64, limit: usize) -> Result<u64, StorageError> {
        self.prune_lane_through(SpoolLane::Export, sequence, limit)
    }

    pub fn prune_expired_export_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<ExportRetentionPrune, StorageError> {
        self.prune_expired_lane_prefix(SpoolLane::Export, cutoff_unix_ns, limit, cursor_owners)
    }

    pub fn snapshot(&self) -> Result<SpoolSnapshot, StorageError> {
        Ok(SpoolSnapshot {
            last_ingress_sequence: *self.lock_last_sequence(SpoolLane::Ingress)?,
            last_export_sequence: *self.lock_last_sequence(SpoolLane::Export)?,
        })
    }

    fn export_cursor_snapshot(&self) -> Result<BTreeMap<String, u64>, StorageError> {
        let mut cursors = BTreeMap::new();
        for item in self.export_cursors.iter() {
            let (key, value) = item.into_inner()?;
            let sink = String::from_utf8(key.as_ref().to_vec())
                .map_err(|source| StorageError::InvalidCursorSinkName { source })?;
            if value.len() != 8 {
                return Err(StorageError::InvalidCursor {
                    sink,
                    len: value.len(),
                });
            }
            cursors.insert(sink, decode_sequence_key(value.as_ref()));
        }
        Ok(cursors)
    }

    fn append_payload(
        &self,
        lane: SpoolLane,
        payload: SpoolPayload,
    ) -> Result<StoredEvent, StorageError> {
        self.append_payload_at(lane, payload, current_unix_time_ns())
    }

    fn append_payload_at(
        &self,
        lane: SpoolLane,
        payload: SpoolPayload,
        stored_at_unix_ns: u64,
    ) -> Result<StoredEvent, StorageError> {
        let mut last_sequence = self.lock_last_sequence(lane)?;
        let sequence = last_sequence
            .checked_add(1)
            .ok_or(StorageError::SequenceOverflow)?;
        let key = sequence_key(sequence);
        let encoded = encode_spool_record(stored_at_unix_ns, &payload)?;
        let mut batch = self.database.batch();
        batch.insert(self.queue(lane), key, encoded);
        batch.insert(&self.metadata, lane.last_sequence_key(), key);
        batch.commit()?;
        self.database.persist(PersistMode::SyncAll)?;
        *last_sequence = sequence;
        Ok(StoredEvent {
            sequence,
            stored_at_unix_ns,
            payload,
        })
    }

    fn read_batch_from_lane(
        &self,
        lane: SpoolLane,
        consumer: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        let cursor = self.cursor_for_lane(lane, consumer)?;
        self.read_batch_from_lane_after(lane, cursor, limit)
    }

    fn read_batch_from_lane_after(
        &self,
        lane: SpoolLane,
        sequence: u64,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let Some(start) = sequence.checked_add(1) else {
            return Ok(Vec::new());
        };
        let durable_last_sequence = *self.lock_last_sequence(lane)?;
        let mut events = Vec::new();

        for item in self.queue(lane).range(sequence_key(start)..) {
            let (key, value) = item.into_inner()?;
            let sequence = decode_sequence_key(key.as_ref());
            if sequence > durable_last_sequence {
                break;
            }
            let record = decode_spool_record(value.as_ref())?;
            events.push(StoredEvent {
                sequence,
                stored_at_unix_ns: record.stored_at_unix_ns,
                payload: record.payload,
            });
            if events.len() >= limit {
                break;
            }
        }

        Ok(events)
    }

    fn ack_lane(&self, lane: SpoolLane, consumer: &str, sequence: u64) -> Result<(), StorageError> {
        let last_sequence = self.lock_last_sequence(lane)?;
        let durable_last_sequence = *last_sequence;
        let current = self.cursor_for_lane(lane, consumer)?;
        if sequence > current {
            if sequence > durable_last_sequence {
                return Err(StorageError::AckBeyondLastSequence {
                    sink: consumer.to_string(),
                    sequence,
                    last_sequence: durable_last_sequence,
                });
            }
            let mut batch = self.database.batch();
            batch.insert(
                self.cursors(lane),
                consumer.as_bytes(),
                sequence_key(sequence),
            );
            batch.commit()?;
            self.database.persist(PersistMode::SyncAll)?;
        }
        drop(last_sequence);
        Ok(())
    }

    fn cursor_for_lane(&self, lane: SpoolLane, consumer: &str) -> Result<u64, StorageError> {
        let Some(value) = self.cursors(lane).get(consumer.as_bytes())? else {
            return Ok(0);
        };
        if value.len() != 8 {
            return Err(StorageError::InvalidCursor {
                sink: consumer.to_string(),
                len: value.len(),
            });
        }
        Ok(decode_sequence_key(&value))
    }

    fn prune_lane_through(
        &self,
        lane: SpoolLane,
        sequence: u64,
        limit: usize,
    ) -> Result<u64, StorageError> {
        if sequence == 0 || limit == 0 {
            return Ok(0);
        }
        // Keep this guard through commit so cleanup cannot overwrite high-water
        // metadata written by a concurrent append with this older value.
        let last_sequence = self.lock_last_sequence(lane)?;
        let durable_last_sequence = *last_sequence;
        let cutoff = sequence.min(durable_last_sequence);
        if cutoff == 0 {
            return Ok(0);
        }
        let keys = self
            .queue(lane)
            .range(..=sequence_key(cutoff))
            .take(limit)
            .map(|item| {
                let (key, _) = item.into_inner()?;
                Ok::<_, fjall::Error>(key.as_ref().to_vec())
            })
            .collect::<Result<Vec<_>, fjall::Error>>()?;
        if keys.is_empty() {
            return Ok(0);
        }

        let mut batch = self.database.batch();
        batch.insert(
            &self.metadata,
            lane.last_sequence_key(),
            sequence_key(durable_last_sequence),
        );
        for key in &keys {
            batch.remove(self.queue(lane), key.as_slice());
        }
        batch.commit()?;
        self.database.persist(PersistMode::SyncAll)?;
        drop(last_sequence);
        Ok(keys.len() as u64)
    }

    fn prune_expired_lane_prefix(
        &self,
        lane: SpoolLane,
        cutoff_unix_ns: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<ExportRetentionPrune, StorageError> {
        if limit == 0 {
            return Ok(ExportRetentionPrune::default());
        }
        let last_sequence = self.lock_last_sequence(lane)?;
        let durable_last_sequence = *last_sequence;
        if durable_last_sequence == 0 {
            return Ok(ExportRetentionPrune::default());
        }

        let mut keys = Vec::new();
        let mut retired_through = None;
        for item in self.queue(lane).range::<[u8; 8], _>(..) {
            let (key, value) = item.into_inner()?;
            let sequence = decode_sequence_key(key.as_ref());
            if sequence > durable_last_sequence {
                break;
            }
            let record = decode_spool_record(value.as_ref())?;
            if record.stored_at_unix_ns > cutoff_unix_ns {
                break;
            }
            retired_through = Some(sequence);
            keys.push(key.as_ref().to_vec());
            if keys.len() >= limit {
                break;
            }
        }
        if keys.is_empty() {
            return Ok(ExportRetentionPrune::default());
        }
        let retired_through = retired_through.expect("non-empty retention keys have a sequence");
        let cursor_updates = cursor_owners
            .iter()
            .map(|owner| {
                let current = self.cursor_for_lane(lane, owner)?;
                Ok((*owner, current))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        let mut batch = self.database.batch();
        batch.insert(
            &self.metadata,
            lane.last_sequence_key(),
            sequence_key(durable_last_sequence),
        );
        for key in &keys {
            batch.remove(self.queue(lane), key.as_slice());
        }
        for (owner, current) in cursor_updates {
            if current < retired_through {
                batch.insert(
                    self.cursors(lane),
                    owner.as_bytes(),
                    sequence_key(retired_through),
                );
            }
        }
        batch.commit()?;
        self.database.persist(PersistMode::SyncAll)?;
        drop(last_sequence);
        Ok(ExportRetentionPrune {
            pruned_count: keys.len() as u64,
            retired_through: Some(retired_through),
        })
    }

    fn queue(&self, lane: SpoolLane) -> &Keyspace {
        match lane {
            SpoolLane::Ingress => &self.ingress_journal,
            SpoolLane::Export => &self.export_queue,
        }
    }

    fn cursors(&self, lane: SpoolLane) -> &Keyspace {
        match lane {
            SpoolLane::Ingress => &self.ingress_cursors,
            SpoolLane::Export => &self.export_cursors,
        }
    }

    fn lock_last_sequence(&self, lane: SpoolLane) -> Result<MutexGuard<'_, u64>, StorageError> {
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
    ) -> Result<ExportRetentionPrune, StorageError> {
        FjallSpool::prune_expired_export_prefix(self, cutoff_unix_ns, limit, cursor_owners)
    }
}

impl DurableSpool for FjallSpool {
    fn append_ingress(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        FjallSpool::append_ingress(self, payload)
    }

    fn read_ingress_batch(
        &self,
        consumer: &str,
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

    fn ack_ingress(&self, consumer: &str, sequence: u64) -> Result<(), StorageError> {
        FjallSpool::ack_ingress(self, consumer, sequence)
    }

    fn ingress_cursor(&self, consumer: &str) -> Result<u64, StorageError> {
        FjallSpool::ingress_cursor(self, consumer)
    }

    fn append_export(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        FjallSpool::append_export(self, payload)
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

fn sequence_key(sequence: u64) -> [u8; 8] {
    sequence.to_be_bytes()
}

fn decode_sequence_key(bytes: &[u8]) -> u64 {
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

fn current_unix_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use fjall::PersistMode;
    use probe_core::SpoolPayloadSchema;
    use tempfile::tempdir;

    use crate::spool::{
        lane::SpoolLane,
        marker::{SPOOL_MARKER_CONTENT, SPOOL_MARKER_FILE, SPOOL_READY_FILE},
        record::encode_spool_record,
    };

    use super::{FjallSpool, SpoolPayload, SpoolProbe, StorageError, sequence_key};

    #[test]
    fn spool_tracks_per_sink_cursors() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;

        let one = spool.append_export(test_payload(b"one"))?;
        let two = spool.append_export(test_payload(b"two"))?;
        assert_eq!(one.sequence, 1);
        assert_eq!(two.sequence, 2);
        assert_eq!(one.payload.schema_wire(), "test.schema");
        assert_eq!(one.payload.bytes(), b"one");

        let first = spool.read_export_batch("primary", 10)?;
        assert_eq!(first.len(), 2);
        spool.ack_export("primary", 1)?;

        let remaining = spool.read_export_batch("primary", 10)?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].sequence, 2);

        let secondary = spool.read_export_batch("secondary", 10)?;
        assert_eq!(secondary.len(), 2);
        Ok(())
    }

    #[test]
    fn ingress_and_export_sequences_are_independent() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;

        let ingress_one = spool.append_ingress(test_payload(b"raw-one"))?;
        let export_one = spool.append_export(test_payload(b"event-one"))?;
        let ingress_two = spool.append_ingress(test_payload(b"raw-two"))?;

        assert_eq!(ingress_one.sequence, 1);
        assert_eq!(export_one.sequence, 1);
        assert_eq!(ingress_two.sequence, 2);
        assert_eq!(spool.read_ingress_batch("parser", 10)?.len(), 2);
        assert_eq!(spool.read_export_batch("webhook", 10)?.len(), 1);

        spool.ack_ingress("parser", 1)?;
        assert_eq!(spool.ingress_cursor("parser")?, 1);
        assert_eq!(spool.export_cursor("webhook")?, 0);
        Ok(())
    }

    #[test]
    fn read_ingress_batch_after_scans_without_advancing_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;

        spool.append_ingress(test_payload(b"raw-one"))?;
        spool.append_ingress(test_payload(b"raw-two"))?;
        spool.append_ingress(test_payload(b"raw-three"))?;
        spool.ack_ingress("parser", 2)?;

        let replay = spool.read_ingress_batch_after(0, 10)?;
        let suffix = spool.read_ingress_batch_after(1, 10)?;

        assert_eq!(
            replay
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            suffix
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(spool.ingress_cursor("parser")?, 2);
        Ok(())
    }

    #[test]
    fn read_ingress_batch_after_max_sequence_returns_empty_batch()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;

        spool.append_ingress(test_payload(b"raw"))?;

        assert!(spool.read_ingress_batch_after(u64::MAX, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn spool_recovers_sequences_after_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        assert_eq!(
            spool
                .append_payload_at(SpoolLane::Ingress, test_payload(b"raw-one"), 10)?
                .sequence,
            1
        );
        assert_eq!(
            spool
                .append_payload_at(SpoolLane::Export, test_payload(b"event-one"), 20)?
                .sequence,
            1
        );
        drop(spool);

        let reopened = FjallSpool::open(temp.path())?;
        assert_eq!(
            reopened.append_ingress(test_payload(b"raw-two"))?.sequence,
            2
        );
        assert_eq!(
            reopened.append_export(test_payload(b"event-two"))?.sequence,
            2
        );
        let ingress = reopened.read_ingress_batch("parser", 10)?;
        let events = reopened.read_export_batch("primary", 10)?;
        assert_eq!(
            ingress
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(ingress[0].payload.bytes(), b"raw-one");
        assert_eq!(events[0].payload.bytes(), b"event-one");
        assert_eq!(ingress[0].stored_at_unix_ns, 10);
        assert_eq!(events[0].stored_at_unix_ns, 20);
        Ok(())
    }

    #[test]
    fn spool_rejects_future_ack() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(test_payload(b"one"))?;

        let result = spool.ack_export("primary", 2);

        assert!(result.is_err());
        assert_eq!(spool.export_cursor("primary")?, 0);
        Ok(())
    }

    #[test]
    fn read_batch_ignores_queue_entries_above_durable_high_water()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let payload = test_payload(b"not-yet-durable");
        let mut batch = spool.database.batch();
        batch.insert(
            &spool.export_queue,
            sequence_key(1),
            encode_spool_record(42, &payload)?,
        );
        batch.commit()?;

        assert!(spool.read_export_batch("primary", 10)?.is_empty());
        assert!(spool.ack_export("primary", 1).is_err());
        Ok(())
    }

    #[test]
    fn read_batch_with_zero_limit_returns_no_events() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(test_payload(b"one"))?;

        assert!(spool.read_export_batch("primary", 0)?.is_empty());
        Ok(())
    }

    #[test]
    fn prune_export_through_removes_bounded_prefix_without_moving_high_water()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.append_export(test_payload(b"three"))?;

        assert_eq!(spool.prune_export_through(3, 2)?, 2);

        let remaining = spool.read_export_batch("late", 10)?;
        assert_eq!(
            remaining
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(spool.snapshot()?.last_export_sequence, 3);
        drop(spool);

        let reopened = FjallSpool::open(temp.path())?;
        assert_eq!(reopened.snapshot()?.last_export_sequence, 3);
        assert_eq!(
            reopened
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(reopened.prune_export_through(3, 2)?, 1);
        assert!(reopened.read_export_batch("late", 10)?.is_empty());
        reopened.ack_export("primary", 3)?;
        assert_eq!(reopened.export_cursor("primary")?, 3);
        Ok(())
    }

    #[test]
    fn prune_export_through_materializes_high_water_for_metadata_less_spool()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let mut batch = spool.database.batch();
        batch.insert(
            &spool.export_queue,
            sequence_key(1),
            encode_spool_record(1, &test_payload(b"one"))?,
        );
        batch.insert(
            &spool.export_queue,
            sequence_key(2),
            encode_spool_record(2, &test_payload(b"two"))?,
        );
        batch.commit()?;
        spool.database.persist(PersistMode::SyncAll)?;
        drop(spool);

        let recovered = FjallSpool::open(temp.path())?;
        assert_eq!(recovered.snapshot()?.last_export_sequence, 2);
        assert_eq!(recovered.prune_export_through(2, 10)?, 2);
        assert!(recovered.read_export_batch("late", 10)?.is_empty());
        drop(recovered);

        let reopened = FjallSpool::open(temp.path())?;
        assert_eq!(reopened.snapshot()?.last_export_sequence, 2);
        assert_eq!(reopened.append_export(test_payload(b"three"))?.sequence, 3);
        Ok(())
    }

    #[test]
    fn prune_expired_export_prefix_removes_only_expired_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"old-one"), 10)?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"new"), 30)?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"old-after-clock-skew"), 5)?;

        let pruned = spool.prune_expired_export_prefix(20, 10, &["slow"])?;

        assert_eq!(pruned.pruned_count, 1);
        assert_eq!(pruned.retired_through, Some(1));
        assert_eq!(spool.export_cursor("slow")?, 1);
        assert_eq!(
            spool
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        Ok(())
    }

    #[test]
    fn prune_expired_export_prefix_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"old-one"), 10)?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"old-two"), 11)?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"old-three"), 12)?;

        let first = spool.prune_expired_export_prefix(20, 2, &[])?;
        let second = spool.prune_expired_export_prefix(20, 2, &[])?;

        assert_eq!(first.pruned_count, 2);
        assert_eq!(first.retired_through, Some(2));
        assert_eq!(second.pruned_count, 1);
        assert_eq!(second.retired_through, Some(3));
        assert!(spool.read_export_batch("late", 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn prune_expired_export_prefix_does_not_regress_cursor_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"old-one"), 10)?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"new"), 30)?;
        spool.ack_export("ahead", 2)?;

        let pruned = spool.prune_expired_export_prefix(20, 10, &["behind", "ahead"])?;

        assert_eq!(pruned.pruned_count, 1);
        assert_eq!(spool.export_cursor("behind")?, 1);
        assert_eq!(spool.export_cursor("ahead")?, 2);
        Ok(())
    }

    #[test]
    fn ack_export_does_not_regress_retired_cursor() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"old-one"), 10)?;
        spool.append_payload_at(SpoolLane::Export, test_payload(b"old-two"), 11)?;
        spool.prune_expired_export_prefix(20, 10, &["sink"])?;

        spool.ack_export("sink", 1)?;

        assert_eq!(spool.export_cursor("sink")?, 2);
        Ok(())
    }

    #[test]
    fn initialization_probe_does_not_create_spool() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;

        assert!(!FjallSpool::is_initialized(temp.path())?);
        assert!(temp.path().read_dir()?.next().is_none());
        Ok(())
    }

    #[test]
    fn initialization_probe_rejects_marker_without_ready_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        fs::write(temp.path().join(SPOOL_MARKER_FILE), SPOOL_MARKER_CONTENT)?;

        assert!(!FjallSpool::is_initialized(temp.path())?);
        assert!(!temp.path().join(SPOOL_READY_FILE).try_exists()?);
        Ok(())
    }

    #[test]
    fn initialization_probe_rejects_older_spool_marker() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        fs::write(
            temp.path().join(SPOOL_MARKER_FILE),
            b"sssa-probe-spool-v1\n",
        )?;

        let error = FjallSpool::probe(temp.path()).expect_err("old marker must fail fast");

        assert!(matches!(error, StorageError::InvalidSpoolMarker { .. }));
        Ok(())
    }

    #[test]
    fn open_rejects_older_spool_marker_without_initializing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        fs::write(
            temp.path().join(SPOOL_MARKER_FILE),
            b"sssa-probe-spool-v1\n",
        )?;

        let error = match FjallSpool::open(temp.path()) {
            Ok(_) => panic!("old marker must fail before DB open"),
            Err(error) => error,
        };

        assert!(matches!(error, StorageError::InvalidSpoolMarker { .. }));
        assert!(!temp.path().join(SPOOL_READY_FILE).try_exists()?);
        Ok(())
    }

    #[test]
    fn open_writes_spool_markers() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;

        let _spool = FjallSpool::open(temp.path())?;

        assert!(FjallSpool::is_initialized(temp.path())?);
        Ok(())
    }

    #[test]
    fn status_probe_reports_snapshot_and_export_cursors() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_ingress(test_payload(b"raw-one"))?;
        spool.append_export(test_payload(b"event-one"))?;
        spool.append_export(test_payload(b"event-two"))?;
        spool.ack_export("primary", 1)?;
        drop(spool);

        let probe = FjallSpool::probe(temp.path())?;

        let SpoolProbe::Available {
            snapshot,
            export_cursors,
        } = probe
        else {
            panic!("expected available spool probe");
        };
        assert_eq!(snapshot.last_ingress_sequence, 1);
        assert_eq!(snapshot.last_export_sequence, 2);
        assert_eq!(export_cursors.get("primary"), Some(&1));
        Ok(())
    }

    #[test]
    fn snapshot_reports_durable_lane_high_water() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_ingress(test_payload(b"raw-one"))?;
        spool.append_ingress(test_payload(b"raw-two"))?;
        spool.append_export(test_payload(b"event-one"))?;

        let snapshot = spool.snapshot()?;

        assert_eq!(snapshot.last_ingress_sequence, 2);
        assert_eq!(snapshot.last_export_sequence, 1);
        Ok(())
    }

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new(SpoolPayloadSchema::from_wire("test.schema"), bytes)
    }
}

use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

use bytes::Bytes;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use thiserror::Error;

const INGRESS_JOURNAL: &str = "ingress_journal";
const EXPORT_QUEUE: &str = "export_queue";
const INGRESS_CURSORS: &str = "ingress_cursors";
const EXPORT_CURSORS: &str = "export_cursors";
const METADATA: &str = "metadata";
const LAST_INGRESS_SEQUENCE: &[u8] = b"last_ingress_sequence";
const LAST_EXPORT_SEQUENCE: &[u8] = b"last_export_sequence";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("fjall storage error: {0}")]
    Fjall(#[from] fjall::Error),
    #[error("invalid cursor value for sink {sink}: expected 8 bytes, got {len}")]
    InvalidCursor { sink: String, len: usize },
    #[error("invalid metadata value for key {key}: expected 8 bytes, got {len}")]
    InvalidMetadata { key: String, len: usize },
    #[error("spool sequence overflow")]
    SequenceOverflow,
    #[error("{lane} sequence lock poisoned")]
    SequenceLockPoisoned { lane: &'static str },
    #[error(
        "sink {sink} tried to ack sequence {sequence} beyond last stored sequence {last_sequence}"
    )]
    AckBeyondLastSequence {
        sink: String,
        sequence: u64,
        last_sequence: u64,
    },
    #[error("spool payload schema is too large: {len} bytes")]
    PayloadSchemaTooLarge { len: usize },
    #[error("invalid stored payload: expected at least 4 bytes, got {len}")]
    InvalidStoredPayload { len: usize },
    #[error("invalid stored payload schema utf-8: {0}")]
    InvalidStoredPayloadSchema(#[from] std::string::FromUtf8Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolPayload {
    schema: String,
    bytes: Bytes,
}

impl SpoolPayload {
    pub fn new(schema: impl Into<String>, bytes: impl AsRef<[u8]>) -> Self {
        Self {
            schema: schema.into(),
            bytes: Bytes::copy_from_slice(bytes.as_ref()),
        }
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub sequence: u64,
    pub payload: SpoolPayload,
}

pub trait DurableSpool {
    fn append_ingress(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError>;

    fn read_ingress_batch(
        &self,
        consumer: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError>;

    fn ack_ingress(&self, consumer: &str, sequence: u64) -> Result<(), StorageError>;

    fn ingress_cursor(&self, consumer: &str) -> Result<u64, StorageError>;

    fn append_export(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError>;

    fn read_export_batch(&self, sink: &str, limit: usize)
    -> Result<Vec<StoredEvent>, StorageError>;

    fn ack_export(&self, sink: &str, sequence: u64) -> Result<(), StorageError>;

    fn export_cursor(&self, sink: &str) -> Result<u64, StorageError>;
}

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
        let database = Database::builder(path.as_ref()).open()?;
        let ingress_journal = database.keyspace(INGRESS_JOURNAL, KeyspaceCreateOptions::default)?;
        let export_queue = database.keyspace(EXPORT_QUEUE, KeyspaceCreateOptions::default)?;
        let ingress_cursors = database.keyspace(INGRESS_CURSORS, KeyspaceCreateOptions::default)?;
        let export_cursors = database.keyspace(EXPORT_CURSORS, KeyspaceCreateOptions::default)?;
        let metadata = database.keyspace(METADATA, KeyspaceCreateOptions::default)?;
        let last_ingress_sequence =
            read_last_sequence(&ingress_journal, &metadata, LAST_INGRESS_SEQUENCE)?;
        let last_export_sequence =
            read_last_sequence(&export_queue, &metadata, LAST_EXPORT_SEQUENCE)?;
        Ok(Self {
            database,
            ingress_journal,
            export_queue,
            ingress_cursors,
            export_cursors,
            metadata,
            last_ingress_sequence: Mutex::new(last_ingress_sequence),
            last_export_sequence: Mutex::new(last_export_sequence),
        })
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

    fn append_payload(
        &self,
        lane: SpoolLane,
        payload: SpoolPayload,
    ) -> Result<StoredEvent, StorageError> {
        let mut last_sequence = self.lock_last_sequence(lane)?;
        let sequence = last_sequence
            .checked_add(1)
            .ok_or(StorageError::SequenceOverflow)?;
        let key = sequence_key(sequence);
        let encoded = encode_spool_payload(&payload)?;
        let mut batch = self.database.batch();
        batch.insert(self.queue(lane), key, encoded);
        batch.insert(&self.metadata, lane.last_sequence_key(), key);
        batch.commit()?;
        self.database.persist(PersistMode::SyncAll)?;
        *last_sequence = sequence;
        Ok(StoredEvent { sequence, payload })
    }

    fn read_batch_from_lane(
        &self,
        lane: SpoolLane,
        consumer: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        let cursor = self.cursor_for_lane(lane, consumer)?;
        let start = cursor.saturating_add(1);
        let mut events = Vec::new();

        for item in self.queue(lane).range(sequence_key(start)..) {
            let (key, value) = item.into_inner()?;
            let sequence = decode_sequence_key(key.as_ref());
            events.push(StoredEvent {
                sequence,
                payload: decode_spool_payload(value.as_ref())?,
            });
            if events.len() >= limit {
                break;
            }
        }

        Ok(events)
    }

    fn ack_lane(&self, lane: SpoolLane, consumer: &str, sequence: u64) -> Result<(), StorageError> {
        let current = self.cursor_for_lane(lane, consumer)?;
        if sequence > current {
            let last_sequence = *self.lock_last_sequence(lane)?;
            if sequence > last_sequence {
                return Err(StorageError::AckBeyondLastSequence {
                    sink: consumer.to_string(),
                    sequence,
                    last_sequence,
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

    fn ack_ingress(&self, consumer: &str, sequence: u64) -> Result<(), StorageError> {
        FjallSpool::ack_ingress(self, consumer, sequence)
    }

    fn ingress_cursor(&self, consumer: &str) -> Result<u64, StorageError> {
        FjallSpool::ingress_cursor(self, consumer)
    }

    fn append_export(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        FjallSpool::append_export(self, payload)
    }

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpoolLane {
    Ingress,
    Export,
}

impl SpoolLane {
    fn name(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Export => "export",
        }
    }

    fn last_sequence_key(self) -> &'static [u8] {
        match self {
            Self::Ingress => LAST_INGRESS_SEQUENCE,
            Self::Export => LAST_EXPORT_SEQUENCE,
        }
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

fn encode_spool_payload(payload: &SpoolPayload) -> Result<Vec<u8>, StorageError> {
    let schema = payload.schema.as_bytes();
    let schema_len = u32::try_from(schema.len())
        .map_err(|_| StorageError::PayloadSchemaTooLarge { len: schema.len() })?;
    let mut encoded = Vec::with_capacity(4 + schema.len() + payload.bytes.len());
    encoded.extend_from_slice(&schema_len.to_be_bytes());
    encoded.extend_from_slice(schema);
    encoded.extend_from_slice(&payload.bytes);
    Ok(encoded)
}

fn decode_spool_payload(bytes: &[u8]) -> Result<SpoolPayload, StorageError> {
    if bytes.len() < 4 {
        return Err(StorageError::InvalidStoredPayload { len: bytes.len() });
    }
    let mut len = [0_u8; 4];
    len.copy_from_slice(&bytes[..4]);
    let schema_len = u32::from_be_bytes(len) as usize;
    let expected_min_len = 4 + schema_len;
    if bytes.len() < expected_min_len {
        return Err(StorageError::InvalidStoredPayload { len: bytes.len() });
    }
    let schema = String::from_utf8(bytes[4..expected_min_len].to_vec())?;
    Ok(SpoolPayload {
        schema,
        bytes: Bytes::copy_from_slice(&bytes[expected_min_len..]),
    })
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::{FjallSpool, SpoolPayload};

    #[test]
    fn spool_tracks_per_sink_cursors() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;

        let one = spool.append_export(test_payload(b"one"))?;
        let two = spool.append_export(test_payload(b"two"))?;
        assert_eq!(one.sequence, 1);
        assert_eq!(two.sequence, 2);
        assert_eq!(one.payload.schema(), "test.schema");
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
    fn spool_recovers_sequences_after_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        assert_eq!(spool.append_ingress(test_payload(b"raw-one"))?.sequence, 1);
        assert_eq!(spool.append_export(test_payload(b"event-one"))?.sequence, 1);
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

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new("test.schema", bytes)
    }
}

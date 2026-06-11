use std::{path::Path, sync::Mutex};

use bytes::Bytes;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use thiserror::Error;

const EXPORT_QUEUE: &str = "export_queue";
const SINK_CURSORS: &str = "sink_cursors";
const METADATA: &str = "metadata";
const LAST_SEQUENCE: &[u8] = b"last_sequence";

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
    #[error("spool sequence lock poisoned")]
    SequenceLockPoisoned,
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
    fn append(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError>;

    fn read_batch(&self, sink: &str, limit: usize) -> Result<Vec<StoredEvent>, StorageError>;

    fn ack(&self, sink: &str, sequence: u64) -> Result<(), StorageError>;

    fn cursor(&self, sink: &str) -> Result<u64, StorageError>;
}

pub struct FjallSpool {
    database: Database,
    queue: Keyspace,
    cursors: Keyspace,
    metadata: Keyspace,
    last_sequence: Mutex<u64>,
}

impl FjallSpool {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let database = Database::builder(path.as_ref()).open()?;
        let queue = database.keyspace(EXPORT_QUEUE, KeyspaceCreateOptions::default)?;
        let cursors = database.keyspace(SINK_CURSORS, KeyspaceCreateOptions::default)?;
        let metadata = database.keyspace(METADATA, KeyspaceCreateOptions::default)?;
        let last_sequence = read_last_sequence(&queue, &metadata)?;
        Ok(Self {
            database,
            queue,
            cursors,
            metadata,
            last_sequence: Mutex::new(last_sequence),
        })
    }

    pub fn append(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        self.append_payload(payload)
    }

    fn append_payload(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        let mut last_sequence = self
            .last_sequence
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned)?;
        let sequence = last_sequence
            .checked_add(1)
            .ok_or(StorageError::SequenceOverflow)?;
        let key = sequence_key(sequence);
        let encoded = encode_spool_payload(&payload)?;
        let mut batch = self.database.batch();
        batch.insert(&self.queue, key, encoded);
        batch.insert(&self.metadata, LAST_SEQUENCE, key);
        batch.commit()?;
        self.database.persist(PersistMode::SyncAll)?;
        *last_sequence = sequence;
        Ok(StoredEvent { sequence, payload })
    }

    pub fn read_batch(&self, sink: &str, limit: usize) -> Result<Vec<StoredEvent>, StorageError> {
        let cursor = self.cursor(sink)?;
        let start = cursor.saturating_add(1);
        let mut events = Vec::new();

        for item in self.queue.range(sequence_key(start)..) {
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

    pub fn ack(&self, sink: &str, sequence: u64) -> Result<(), StorageError> {
        let current = self.cursor(sink)?;
        if sequence > current {
            let last_sequence = *self
                .last_sequence
                .lock()
                .map_err(|_| StorageError::SequenceLockPoisoned)?;
            if sequence > last_sequence {
                return Err(StorageError::AckBeyondLastSequence {
                    sink: sink.to_string(),
                    sequence,
                    last_sequence,
                });
            }
            let mut batch = self.database.batch();
            batch.insert(&self.cursors, sink.as_bytes(), sequence_key(sequence));
            batch.commit()?;
            self.database.persist(PersistMode::SyncAll)?;
        }
        Ok(())
    }

    pub fn cursor(&self, sink: &str) -> Result<u64, StorageError> {
        let Some(value) = self.cursors.get(sink.as_bytes())? else {
            return Ok(0);
        };
        if value.len() != 8 {
            return Err(StorageError::InvalidCursor {
                sink: sink.to_string(),
                len: value.len(),
            });
        }
        Ok(decode_sequence_key(&value))
    }
}

impl DurableSpool for FjallSpool {
    fn append(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        self.append_payload(payload)
    }

    fn read_batch(&self, sink: &str, limit: usize) -> Result<Vec<StoredEvent>, StorageError> {
        FjallSpool::read_batch(self, sink, limit)
    }

    fn ack(&self, sink: &str, sequence: u64) -> Result<(), StorageError> {
        FjallSpool::ack(self, sink, sequence)
    }

    fn cursor(&self, sink: &str) -> Result<u64, StorageError> {
        FjallSpool::cursor(self, sink)
    }
}

fn read_last_sequence(queue: &Keyspace, metadata: &Keyspace) -> Result<u64, StorageError> {
    if let Some(value) = metadata.get(LAST_SEQUENCE)? {
        return decode_exact_sequence_key(LAST_SEQUENCE, &value);
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

        let one = spool.append(test_payload(b"one"))?;
        let two = spool.append(test_payload(b"two"))?;
        assert_eq!(one.sequence, 1);
        assert_eq!(two.sequence, 2);
        assert_eq!(one.payload.schema(), "test.schema");
        assert_eq!(one.payload.bytes(), b"one");

        let first = spool.read_batch("primary", 10)?;
        assert_eq!(first.len(), 2);
        spool.ack("primary", 1)?;

        let remaining = spool.read_batch("primary", 10)?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].sequence, 2);

        let secondary = spool.read_batch("secondary", 10)?;
        assert_eq!(secondary.len(), 2);
        Ok(())
    }

    #[test]
    fn spool_recovers_sequence_after_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        assert_eq!(spool.append(test_payload(b"one"))?.sequence, 1);
        drop(spool);

        let reopened = FjallSpool::open(temp.path())?;
        assert_eq!(reopened.append(test_payload(b"two"))?.sequence, 2);
        let events = reopened.read_batch("primary", 10)?;
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(events[0].payload.schema(), "test.schema");
        assert_eq!(events[0].payload.bytes(), b"one");
        Ok(())
    }

    #[test]
    fn spool_rejects_future_ack() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append(test_payload(b"one"))?;

        let result = spool.ack("primary", 2);

        assert!(result.is_err());
        assert_eq!(spool.cursor("primary")?, 0);
        Ok(())
    }

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new("test.schema", bytes)
    }
}

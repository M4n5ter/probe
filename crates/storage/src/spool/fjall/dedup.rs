use fjall::OwnedWriteBatch;

use crate::spool::StorageError;

use super::store::{FjallSpool, decode_sequence_key, sequence_key};

pub(super) enum ExportDedupLookup {
    None,
    DurableDuplicate { sequence: u64 },
    Stale { sequence: u64 },
}

impl FjallSpool {
    pub(super) fn lookup_export_dedup(
        &self,
        dedup_key: &str,
        durable_last_sequence: u64,
    ) -> Result<ExportDedupLookup, StorageError> {
        let Some(value) = self.export_dedup.get(dedup_key.as_bytes())? else {
            return Ok(ExportDedupLookup::None);
        };
        let sequence = decode_export_dedup_sequence(dedup_key, value.as_ref())?;
        let key = sequence_key(sequence);
        if sequence <= durable_last_sequence
            && self.export_queue.get(key)?.is_some()
            && self.export_dedup_by_sequence.get(key)?.as_deref() == Some(dedup_key.as_bytes())
        {
            return Ok(ExportDedupLookup::DurableDuplicate { sequence });
        }
        Ok(ExportDedupLookup::Stale { sequence })
    }

    pub(super) fn insert_export_dedup_indexes(
        &self,
        batch: &mut OwnedWriteBatch,
        dedup_key: &str,
        key: [u8; 8],
    ) {
        batch.insert(&self.export_dedup, dedup_key.as_bytes(), key);
        batch.insert(&self.export_dedup_by_sequence, key, dedup_key.as_bytes());
    }

    pub(super) fn remove_export_dedup_entry(
        &self,
        batch: &mut OwnedWriteBatch,
        dedup_key: &str,
        sequence: u64,
    ) -> Result<(), StorageError> {
        batch.remove(&self.export_dedup, dedup_key.as_bytes());
        let key = sequence_key(sequence);
        if self.export_dedup_by_sequence.get(key)?.as_deref() == Some(dedup_key.as_bytes()) {
            batch.remove(&self.export_dedup_by_sequence, key);
        }
        Ok(())
    }

    pub(super) fn remove_export_dedup_for_sequence_key(
        &self,
        batch: &mut OwnedWriteBatch,
        key: &[u8],
    ) -> Result<(), StorageError> {
        if let Some(dedup_key) = self.export_dedup_by_sequence.get(key)? {
            batch.remove(&self.export_dedup, dedup_key.as_ref());
            batch.remove(&self.export_dedup_by_sequence, key);
        }
        Ok(())
    }
}

fn decode_export_dedup_sequence(dedup_key: &str, bytes: &[u8]) -> Result<u64, StorageError> {
    if bytes.len() != 8 {
        return Err(StorageError::InvalidExportDedupIndex {
            key: dedup_key.to_string(),
            len: bytes.len(),
        });
    }
    Ok(decode_sequence_key(bytes))
}

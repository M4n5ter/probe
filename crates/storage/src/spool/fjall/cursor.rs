use std::time::{SystemTime, UNIX_EPOCH};

use fjall::PersistMode;

use crate::spool::{
    IngressCursorOwner, SpoolPayload, StorageError, StoredEvent,
    lane::SpoolLane,
    record::{decode_spool_record, encode_spool_record},
};

use super::{FjallSpool, decode_sequence_key, sequence_key};

impl FjallSpool {
    pub fn append_ingress(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        self.append_payload(SpoolLane::Ingress, payload)
    }

    pub fn read_ingress_batch(
        &self,
        consumer: IngressCursorOwner,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        self.read_batch_from_lane(SpoolLane::Ingress, consumer.as_str(), limit)
    }

    pub fn read_ingress_batch_after(
        &self,
        sequence: u64,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        self.read_batch_from_lane_after(SpoolLane::Ingress, sequence, limit)
    }

    pub fn ack_ingress(
        &self,
        consumer: IngressCursorOwner,
        sequence: u64,
    ) -> Result<(), StorageError> {
        self.ack_lane(SpoolLane::Ingress, consumer.as_str(), sequence)
    }

    pub fn ingress_cursor(&self, consumer: IngressCursorOwner) -> Result<u64, StorageError> {
        self.cursor_for_lane(SpoolLane::Ingress, consumer.as_str())
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

    pub(super) fn append_payload(
        &self,
        lane: SpoolLane,
        payload: SpoolPayload,
    ) -> Result<StoredEvent, StorageError> {
        self.append_payload_at(lane, payload, current_unix_time_ns())
    }

    pub(super) fn append_payload_at(
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

    pub(super) fn cursor_for_lane(
        &self,
        lane: SpoolLane,
        consumer: &str,
    ) -> Result<u64, StorageError> {
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
    use probe_core::SpoolPayloadSchema;
    use tempfile::tempdir;

    use crate::spool::{
        IngressCursorOwner, SpoolPayload, lane::SpoolLane, record::encode_spool_record,
    };

    use super::*;

    const TEST_INGRESS_CURSOR_OWNER: IngressCursorOwner = IngressCursorOwner::new("test");

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
        assert_eq!(
            spool
                .read_ingress_batch(TEST_INGRESS_CURSOR_OWNER, 10)?
                .len(),
            2
        );
        assert_eq!(spool.read_export_batch("webhook", 10)?.len(), 1);

        spool.ack_ingress(TEST_INGRESS_CURSOR_OWNER, 1)?;
        assert_eq!(spool.ingress_cursor(TEST_INGRESS_CURSOR_OWNER)?, 1);
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
        spool.ack_ingress(TEST_INGRESS_CURSOR_OWNER, 2)?;

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
        assert_eq!(spool.ingress_cursor(TEST_INGRESS_CURSOR_OWNER)?, 2);
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
        let ingress = reopened.read_ingress_batch(TEST_INGRESS_CURSOR_OWNER, 10)?;
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

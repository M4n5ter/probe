use fjall::PersistMode;

use crate::spool::{
    IngressCursorOwner, RetentionPrune, StorageError, lane::SpoolLane, record::decode_spool_record,
};

use super::store::{FjallSpool, decode_sequence_key, sequence_key};

impl FjallSpool {
    pub fn prune_export_through(&self, sequence: u64, limit: usize) -> Result<u64, StorageError> {
        self.prune_lane_through(SpoolLane::Export, sequence, limit)
    }

    pub fn prune_expired_export_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<RetentionPrune, StorageError> {
        self.prune_expired_lane_prefix(SpoolLane::Export, cutoff_unix_ns, limit, cursor_owners)
    }

    pub fn prune_expired_ingress_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        consumers: &[IngressCursorOwner],
    ) -> Result<RetentionPrune, StorageError> {
        let consumers = consumers
            .iter()
            .map(|consumer| consumer.as_str())
            .collect::<Vec<_>>();
        self.prune_expired_lane_prefix(SpoolLane::Ingress, cutoff_unix_ns, limit, &consumers)
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
    ) -> Result<RetentionPrune, StorageError> {
        if limit == 0 {
            return Ok(RetentionPrune::default());
        }
        let last_sequence = self.lock_last_sequence(lane)?;
        let durable_last_sequence = *last_sequence;
        if durable_last_sequence == 0 {
            return Ok(RetentionPrune::default());
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
            return Ok(RetentionPrune::default());
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
        Ok(RetentionPrune {
            pruned_count: keys.len() as u64,
            retired_through: Some(retired_through),
        })
    }
}

#[cfg(test)]
mod tests {
    use fjall::PersistMode;
    use probe_core::SpoolPayloadSchema;
    use tempfile::tempdir;

    use crate::spool::{
        IngressCursorOwner, SpoolPayload, lane::SpoolLane, record::encode_spool_record,
    };

    use super::*;

    const TEST_INGRESS_CURSOR_OWNER: IngressCursorOwner = IngressCursorOwner::new("test");

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
    fn prune_expired_ingress_prefix_retires_consumer_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_payload_at(SpoolLane::Ingress, test_payload(b"old-one"), 10)?;
        spool.append_payload_at(SpoolLane::Ingress, test_payload(b"old-two"), 11)?;
        spool.append_payload_at(SpoolLane::Ingress, test_payload(b"new"), 30)?;

        let pruned = spool.prune_expired_ingress_prefix(20, 10, &[TEST_INGRESS_CURSOR_OWNER])?;

        assert_eq!(pruned.pruned_count, 2);
        assert_eq!(pruned.retired_through, Some(2));
        assert_eq!(spool.ingress_cursor(TEST_INGRESS_CURSOR_OWNER)?, 2);
        assert_eq!(spool.snapshot()?.last_ingress_sequence, 3);
        assert_eq!(
            spool
                .read_ingress_batch_after(2, 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
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

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new(SpoolPayloadSchema::from_wire("test.schema"), bytes)
    }
}

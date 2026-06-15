use fjall::PersistMode;

use crate::spool::{
    IngressCursorOwner, RetentionPrune, StorageError, lane::SpoolLane, record::decode_spool_record,
};

use super::store::{FjallSpool, decode_sequence_key, sequence_key};

struct CursorRetirement<'a> {
    retired_through: u64,
    owners: &'a [&'a str],
}

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

    pub fn prune_export_to_max_records(
        &self,
        max_records: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<RetentionPrune, StorageError> {
        self.prune_lane_to_max_records(SpoolLane::Export, max_records, limit, cursor_owners)
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

    pub fn prune_ingress_to_max_records(
        &self,
        max_records: u64,
        limit: usize,
        consumers: &[IngressCursorOwner],
    ) -> Result<RetentionPrune, StorageError> {
        let consumers = consumers
            .iter()
            .map(|consumer| consumer.as_str())
            .collect::<Vec<_>>();
        self.prune_lane_to_max_records(SpoolLane::Ingress, max_records, limit, &consumers)
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
        let keys = self.prefix_keys_through(lane, cutoff, limit)?;
        if keys.is_empty() {
            return Ok(0);
        }
        Ok(self
            .commit_prefix_delete(lane, last_sequence, keys, None)?
            .pruned_count)
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
        self.commit_retention_prune(lane, last_sequence, keys, retired_through, cursor_owners)
    }

    fn prune_lane_to_max_records(
        &self,
        lane: SpoolLane,
        max_records: u64,
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
        let live_records = *self.lock_live_records(lane)?;
        let overflow = live_records.saturating_sub(max_records);
        let delete_limit = usize::try_from(overflow).unwrap_or(usize::MAX).min(limit);
        if delete_limit == 0 {
            return Ok(RetentionPrune::default());
        }
        let keys = self.prefix_keys_through(lane, durable_last_sequence, delete_limit)?;
        if keys.is_empty() {
            return Ok(RetentionPrune::default());
        }
        let retired_through = keys
            .last()
            .map(|key| decode_sequence_key(key))
            .expect("non-empty retention keys have a sequence");

        self.commit_retention_prune(lane, last_sequence, keys, retired_through, cursor_owners)
    }

    fn prefix_keys_through(
        &self,
        lane: SpoolLane,
        cutoff_sequence: u64,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        self.queue(lane)
            .range(..=sequence_key(cutoff_sequence))
            .take(limit)
            .map(|item| {
                let (key, _) = item.into_inner()?;
                Ok::<_, fjall::Error>(key.as_ref().to_vec())
            })
            .collect::<Result<Vec<_>, fjall::Error>>()
            .map_err(StorageError::from)
    }

    fn commit_retention_prune(
        &self,
        lane: SpoolLane,
        last_sequence: std::sync::MutexGuard<'_, u64>,
        keys: Vec<Vec<u8>>,
        retired_through: u64,
        cursor_owners: &[&str],
    ) -> Result<RetentionPrune, StorageError> {
        self.commit_prefix_delete(
            lane,
            last_sequence,
            keys,
            Some(CursorRetirement {
                retired_through,
                owners: cursor_owners,
            }),
        )
    }

    fn commit_prefix_delete(
        &self,
        lane: SpoolLane,
        last_sequence: std::sync::MutexGuard<'_, u64>,
        keys: Vec<Vec<u8>>,
        cursor_retirement: Option<CursorRetirement<'_>>,
    ) -> Result<RetentionPrune, StorageError> {
        let durable_last_sequence = *last_sequence;
        let mut live_records = self.lock_live_records(lane)?;
        let pruned_count = keys.len() as u64;
        let next_live_records = live_records.checked_sub(pruned_count).ok_or(
            StorageError::LiveRecordCountUnderflow {
                lane: lane.name(),
                live_records: *live_records,
                pruned_count,
            },
        )?;
        let cursor_retirement = cursor_retirement
            .map(|retirement| {
                let cursor_updates = retirement
                    .owners
                    .iter()
                    .map(|owner| {
                        let current = self.cursor_for_lane(lane, owner)?;
                        Ok((*owner, current))
                    })
                    .collect::<Result<Vec<_>, StorageError>>()?;
                Ok::<_, StorageError>((retirement.retired_through, cursor_updates))
            })
            .transpose()?;

        let mut batch = self.database.batch();
        batch.insert(
            &self.metadata,
            lane.last_sequence_key(),
            sequence_key(durable_last_sequence),
        );
        batch.insert(
            &self.metadata,
            lane.live_records_key(),
            sequence_key(next_live_records),
        );
        for key in &keys {
            batch.remove(self.queue(lane), key.as_slice());
        }
        if let Some((retired_through, cursor_updates)) = &cursor_retirement {
            for (owner, current) in cursor_updates {
                if current < retired_through {
                    batch.insert(
                        self.cursors(lane),
                        owner.as_bytes(),
                        sequence_key(*retired_through),
                    );
                }
            }
        }
        batch.commit()?;
        self.database.persist(PersistMode::SyncAll)?;
        *live_records = next_live_records;
        drop(live_records);
        drop(last_sequence);
        Ok(RetentionPrune {
            pruned_count,
            retired_through: cursor_retirement.map(|(retired_through, _)| retired_through),
        })
    }
}

#[cfg(test)]
mod tests {
    use fjall::PersistMode;
    use probe_core::SpoolPayloadSchema;
    use tempfile::tempdir;

    use crate::spool::{
        IngressCursorOwner, SpoolPayload,
        lane::{LAST_EXPORT_SEQUENCE, LIVE_EXPORT_RECORDS, SpoolLane},
        record::encode_spool_record,
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
    fn prune_export_to_max_records_ignores_records_above_durable_high_water_when_counting_live_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let mut batch = spool.database.batch();
        batch.insert(
            &spool.export_queue,
            sequence_key(1),
            encode_spool_record(1, &test_payload(b"durable"))?,
        );
        batch.insert(
            &spool.export_queue,
            sequence_key(2),
            encode_spool_record(2, &test_payload(b"future-one"))?,
        );
        batch.insert(
            &spool.export_queue,
            sequence_key(3),
            encode_spool_record(3, &test_payload(b"future-two"))?,
        );
        batch.insert(&spool.metadata, LAST_EXPORT_SEQUENCE, sequence_key(1));
        batch.commit()?;
        spool.database.persist(PersistMode::SyncAll)?;
        drop(spool);

        let recovered = FjallSpool::open(temp.path())?;
        let pruned = recovered.prune_export_to_max_records(1, 10, &["sink"])?;

        assert_eq!(recovered.snapshot()?.last_export_sequence, 1);
        assert_eq!(pruned, RetentionPrune::default());
        assert_eq!(recovered.export_cursor("sink")?, 0);
        assert_eq!(
            recovered
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1]
        );
        Ok(())
    }

    #[test]
    fn prune_export_through_rejects_live_record_count_underflow()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        let mut batch = spool.database.batch();
        batch.insert(&spool.metadata, LIVE_EXPORT_RECORDS, sequence_key(1));
        batch.commit()?;
        spool.database.persist(PersistMode::SyncAll)?;
        drop(spool);

        let recovered = FjallSpool::open(temp.path())?;
        let error = recovered
            .prune_export_through(2, 10)
            .expect_err("corrupt live-record metadata should fail retention prune");

        assert!(matches!(
            error,
            StorageError::LiveRecordCountUnderflow {
                lane: "export",
                live_records: 1,
                pruned_count: 2,
            }
        ));
        assert_eq!(
            recovered
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
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
    fn prune_export_to_max_records_keeps_newest_suffix() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.append_export(test_payload(b"three"))?;
        spool.append_export(test_payload(b"four"))?;

        let pruned = spool.prune_export_to_max_records(2, 10, &["sink"])?;

        assert_eq!(pruned.pruned_count, 2);
        assert_eq!(pruned.retired_through, Some(2));
        assert_eq!(spool.export_cursor("sink")?, 2);
        assert_eq!(
            spool
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(spool.snapshot()?.last_export_sequence, 4);
        Ok(())
    }

    #[test]
    fn prune_export_to_max_records_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.append_export(test_payload(b"three"))?;
        spool.append_export(test_payload(b"four"))?;

        let first = spool.prune_export_to_max_records(1, 2, &[])?;
        let second = spool.prune_export_to_max_records(1, 2, &[])?;

        assert_eq!(first.pruned_count, 2);
        assert_eq!(first.retired_through, Some(2));
        assert_eq!(second.pruned_count, 1);
        assert_eq!(second.retired_through, Some(3));
        assert_eq!(
            spool
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![4]
        );
        Ok(())
    }

    #[test]
    fn prune_export_to_max_records_does_not_regress_cursor_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.append_export(test_payload(b"three"))?;
        spool.ack_export("ahead", 3)?;

        spool.prune_export_to_max_records(1, 10, &["behind", "ahead"])?;

        assert_eq!(spool.export_cursor("behind")?, 2);
        assert_eq!(spool.export_cursor("ahead")?, 3);
        Ok(())
    }

    #[test]
    fn prune_export_to_max_records_counts_live_records_not_sequence_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.append_export(test_payload(b"three"))?;
        spool.append_export(test_payload(b"four"))?;
        spool.append_export(test_payload(b"five"))?;
        spool.prune_export_through(3, 10)?;

        let no_prune = spool.prune_export_to_max_records(2, 10, &["sink"])?;

        assert_eq!(no_prune, RetentionPrune::default());
        assert_eq!(
            spool
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![4, 5]
        );

        spool.append_export(test_payload(b"six"))?;
        let pruned = spool.prune_export_to_max_records(2, 10, &["sink"])?;

        assert_eq!(pruned.pruned_count, 1);
        assert_eq!(pruned.retired_through, Some(4));
        assert_eq!(
            spool
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![5, 6]
        );
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

    #[test]
    fn prune_ingress_to_max_records_retires_consumer_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_ingress(test_payload(b"one"))?;
        spool.append_ingress(test_payload(b"two"))?;
        spool.append_ingress(test_payload(b"three"))?;

        let pruned = spool.prune_ingress_to_max_records(1, 10, &[TEST_INGRESS_CURSOR_OWNER])?;

        assert_eq!(pruned.pruned_count, 2);
        assert_eq!(pruned.retired_through, Some(2));
        assert_eq!(spool.ingress_cursor(TEST_INGRESS_CURSOR_OWNER)?, 2);
        assert_eq!(
            spool
                .read_ingress_batch(TEST_INGRESS_CURSOR_OWNER, 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        Ok(())
    }

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new(SpoolPayloadSchema::EventEnvelopeJson, bytes)
    }
}

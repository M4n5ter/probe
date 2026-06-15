use std::collections::BTreeMap;

use super::{
    error::StorageError,
    record::{AppendOutcome, RetentionPrune, SpoolPayload, StoredEvent},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressCursorOwner {
    name: &'static str,
}

impl IngressCursorOwner {
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    pub fn as_str(self) -> &'static str {
        self.name
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolSnapshot {
    pub last_ingress_sequence: u64,
    pub last_export_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpoolProbe {
    Missing,
    Incomplete {
        reason: String,
    },
    Busy {
        reason: String,
    },
    Available {
        snapshot: SpoolSnapshot,
        export_cursors: BTreeMap<String, u64>,
    },
}

pub trait ExportSpool {
    fn read_export_batch(&self, sink: &str, limit: usize)
    -> Result<Vec<StoredEvent>, StorageError>;

    fn ack_export(&self, sink: &str, sequence: u64) -> Result<(), StorageError>;

    fn export_cursor(&self, sink: &str) -> Result<u64, StorageError>;

    /// Removes up to `limit` export events with sequence <= `sequence`.
    ///
    /// This does not change export cursors or the durable high-water mark. Callers
    /// must pass a sequence already confirmed by every cursor-owning sink whose
    /// at-least-once delivery must be preserved.
    fn prune_export_through(&self, sequence: u64, limit: usize) -> Result<u64, StorageError>;

    /// Removes expired export events from the durable prefix and retires cursor owners.
    ///
    /// Only a contiguous prefix older than `cutoff_unix_ns` is removed. This
    /// keeps cursor retirement from jumping over a newer event if wall time moves
    /// backwards between appends. Cursor retirement is committed in the same
    /// storage batch as the prefix deletion.
    fn prune_expired_export_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<RetentionPrune, StorageError>;

    /// Prunes toward `max_records` newest export events.
    ///
    /// Removes up to `limit` durable records older than the newest
    /// `max_records` record suffix. Cursor retirement is committed in the same
    /// storage batch as the prefix deletion, so one call is not guaranteed to
    /// reach the configured record count when more than `limit` records are
    /// eligible.
    fn prune_export_to_max_records(
        &self,
        max_records: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<RetentionPrune, StorageError>;
}

pub trait DurableSpool: ExportSpool {
    fn append_ingress(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError>;

    fn read_ingress_batch(
        &self,
        consumer: IngressCursorOwner,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError>;

    fn read_ingress_batch_after(
        &self,
        sequence: u64,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError>;

    fn ack_ingress(&self, consumer: IngressCursorOwner, sequence: u64) -> Result<(), StorageError>;

    fn ingress_cursor(&self, consumer: IngressCursorOwner) -> Result<u64, StorageError>;

    /// Appends a new export record without idempotency.
    ///
    /// Callers that own stable semantic event IDs should prefer
    /// [`Self::append_export_once`].
    fn append_export(&self, payload: SpoolPayload) -> Result<StoredEvent, StorageError>;

    /// Appends an export record unless `dedup_key` already points to a retained
    /// durable export record.
    ///
    /// The dedup key lives with the export queue record. Pruning or retention
    /// removes the key, making a later append with the same key valid again.
    fn append_export_once(
        &self,
        dedup_key: &str,
        payload: SpoolPayload,
    ) -> Result<AppendOutcome, StorageError>;

    /// Removes expired ingress journal records from the durable prefix.
    ///
    /// The typed cursor owners are advanced through the retired prefix in the same
    /// storage batch. This is an explicit retention tradeoff: records older than
    /// the deadline are no longer recoverable.
    fn prune_expired_ingress_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        consumers: &[IngressCursorOwner],
    ) -> Result<RetentionPrune, StorageError>;

    /// Prunes toward `max_records` newest ingress journal records.
    ///
    /// Removes up to `limit` durable records older than the newest
    /// `max_records` record suffix. The typed cursor owners are advanced through
    /// the retired prefix in the same storage batch. This is an explicit
    /// retention tradeoff: retired records are no longer available for startup
    /// recovery.
    fn prune_ingress_to_max_records(
        &self,
        max_records: u64,
        limit: usize,
        consumers: &[IngressCursorOwner],
    ) -> Result<RetentionPrune, StorageError>;
}

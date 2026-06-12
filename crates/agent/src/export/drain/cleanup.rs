use std::time::{SystemTime, UNIX_EPOCH};

use runtime::{ExportRetentionPlan, ExportSinkPlan};
use storage::ExportSpool;

use super::ExportDrainError;

const EXPORT_PRUNE_BATCH_LIMIT: usize = 1024;

pub(super) fn prune_export_queue_for_sinks(
    spool: &impl ExportSpool,
    sinks: &[ExportSinkPlan],
    retention: &ExportRetentionPlan,
) -> Result<(), ExportDrainError> {
    let sink_ids = sinks
        .iter()
        .map(|sink| sink.id.as_str())
        .collect::<Vec<_>>();
    prune_export_queue_for_sink_ids_at(spool, &sink_ids, retention, current_unix_time_ns())
}

pub(super) fn prune_export_queue_for_sink_ids_at(
    spool: &impl ExportSpool,
    sink_ids: &[&str],
    retention: &ExportRetentionPlan,
    now_unix_ns: u64,
) -> Result<(), ExportDrainError> {
    prune_export_acknowledged_prefix(spool, sink_ids)?;
    prune_export_retention_deadline(spool, sink_ids, retention, now_unix_ns)
}

fn prune_export_acknowledged_prefix(
    spool: &impl ExportSpool,
    sink_ids: &[&str],
) -> Result<(), ExportDrainError> {
    let mut retire_through = None;
    for sink_id in sink_ids {
        let cursor = spool.export_cursor(sink_id)?;
        retire_through = Some(retire_through.map_or(cursor, |sequence: u64| sequence.min(cursor)));
    }
    if let Some(sequence) = retire_through {
        spool.prune_export_through(sequence, EXPORT_PRUNE_BATCH_LIMIT)?;
    }
    Ok(())
}

fn prune_export_retention_deadline(
    spool: &impl ExportSpool,
    sink_ids: &[&str],
    retention: &ExportRetentionPlan,
    now_unix_ns: u64,
) -> Result<(), ExportDrainError> {
    let Some(max_age_ms) = retention.max_age_ms else {
        return Ok(());
    };
    let cutoff_unix_ns = retention_cutoff_unix_ns(now_unix_ns, max_age_ms);
    let limit = usize::try_from(retention.prune_batch_limit.get()).unwrap_or(usize::MAX);
    let pruned = spool.prune_expired_export_prefix(cutoff_unix_ns, limit, sink_ids)?;
    let Some(retired_through) = pruned.retired_through else {
        return Ok(());
    };
    eprintln!(
        "export retention retired {} expired events through sequence {} for {} planned sinks",
        pruned.pruned_count,
        retired_through,
        sink_ids.len()
    );
    Ok(())
}

fn retention_cutoff_unix_ns(now_unix_ns: u64, max_age_ms: u64) -> u64 {
    now_unix_ns.saturating_sub(max_age_ms.saturating_mul(1_000_000))
}

pub(super) fn current_unix_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

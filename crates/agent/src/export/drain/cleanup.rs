use runtime::ExportSinkPlan;
use storage::ExportSpool;

use super::ExportDrainError;

const EXPORT_PRUNE_BATCH_LIMIT: usize = 1024;

pub(super) fn prune_export_acknowledged_prefix_for_sinks(
    spool: &impl ExportSpool,
    sinks: &[ExportSinkPlan],
) -> Result<(), ExportDrainError> {
    let sink_ids = sinks
        .iter()
        .map(|sink| sink.id.as_str())
        .collect::<Vec<_>>();
    prune_export_acknowledged_prefix(spool, &sink_ids)
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

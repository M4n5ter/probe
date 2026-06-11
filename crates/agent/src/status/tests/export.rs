use serde_json::json;

use super::*;

#[test]
fn status_snapshot_reports_per_sink_exporter_worker_quota() -> Result<(), Box<dyn std::error::Error>>
{
    let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
    config.exporters[0].worker.batches_per_tick = Some(2);
    let plan = runtime_plan_from_config(
        config,
        vec![CapabilityState::available(
            CapabilityKind::DryRunEnforcement,
        )],
    )?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert_eq!(
        snapshot.exporters[0].sink_worker.batches_per_tick_override,
        Some(2)
    );
    assert_eq!(
        snapshot.exporters[0]
            .sink_worker
            .effective_batches_per_tick
            .get(),
        2
    );
    let value = serde_json::to_value(&snapshot)?;
    assert_eq!(
        value["exporters"][0]["sink_worker"]["batches_per_tick_override"],
        json!(2)
    );
    assert_eq!(
        value["exporters"][0]["sink_worker"]["effective_batches_per_tick"],
        json!(2)
    );
    Ok(())
}

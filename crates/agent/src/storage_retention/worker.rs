use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pipeline::PARSER_INGRESS_CURSOR_OWNER;
use runtime::{ExportRetentionPlan, IngressRetentionPlan, RuntimePlan, StoragePlan};
use storage::{DurableSpool, IngressCursorOwner};

use crate::{
    periodic_worker::{WorkerHandle, spawn_worker},
    runtime_plan::RuntimePlanHandle,
};

pub(crate) struct StorageRetentionWorkerHandle {
    ingress: WorkerHandle,
    export: WorkerHandle,
}

struct IngressRetentionLaneConfig {
    cursor_owners: Vec<IngressCursorOwner>,
    retention: IngressRetentionPlan,
}

#[derive(Clone)]
struct ExportRetentionLaneSnapshot {
    cursor_owners: Vec<String>,
    retention: ExportRetentionPlan,
}

#[derive(Clone, Copy)]
struct RetentionLimits {
    max_age_ms: Option<u64>,
    max_records: Option<u64>,
    prune_batch_limit: u64,
}

impl StorageRetentionWorkerHandle {
    pub(crate) async fn stop(self) {
        self.ingress.stop().await;
        self.export.stop().await;
    }
}

impl IngressRetentionLaneConfig {
    fn from_storage_plan(plan: &StoragePlan) -> Option<Self> {
        let retention = &plan.retention.ingress;
        retention.enabled().then(|| Self {
            cursor_owners: vec![PARSER_INGRESS_CURSOR_OWNER],
            retention: retention.clone(),
        })
    }
}

pub(crate) fn spawn_storage_retention_workers<S>(
    spool: Arc<S>,
    plan_handle: RuntimePlanHandle,
) -> StorageRetentionWorkerHandle
where
    S: DurableSpool + Send + Sync + 'static,
{
    let ingress = spawn_ingress_retention_worker(Arc::clone(&spool), plan_handle.clone());
    let export = spawn_export_retention_worker(spool, plan_handle);
    StorageRetentionWorkerHandle { ingress, export }
}

fn spawn_ingress_retention_worker<S>(spool: Arc<S>, plan_handle: RuntimePlanHandle) -> WorkerHandle
where
    S: DurableSpool + Send + Sync + 'static,
{
    spawn_retention_lane_worker(
        "ingress retention",
        spool,
        plan_handle,
        |plan| IngressRetentionLaneConfig::from_storage_plan(&plan.storage),
        |config| Duration::from_millis(config.retention.sweep_interval_ms.get()),
        |spool, config| prune_ingress_retention_once(spool, config),
    )
}

fn spawn_export_retention_worker<S>(spool: Arc<S>, plan_handle: RuntimePlanHandle) -> WorkerHandle
where
    S: DurableSpool + Send + Sync + 'static,
{
    spawn_retention_lane_worker(
        "export retention",
        spool,
        plan_handle,
        export_retention_lane_snapshot,
        |snapshot| Duration::from_millis(snapshot.retention.sweep_interval_ms.get()),
        |spool, snapshot| prune_export_retention_once(spool, snapshot),
    )
}

fn spawn_retention_lane_worker<S, C, Snapshot, Interval, Prune>(
    label: &'static str,
    spool: Arc<S>,
    plan_handle: RuntimePlanHandle,
    snapshot: Snapshot,
    interval: Interval,
    prune: Prune,
) -> WorkerHandle
where
    S: DurableSpool + Send + Sync + 'static,
    C: Send + 'static,
    Snapshot: Fn(&RuntimePlan) -> Option<C> + Send + 'static,
    Interval: Fn(&C) -> Duration + Send + 'static,
    Prune: Fn(&S, &C) -> Result<(), storage::StorageError> + Send + 'static,
{
    spawn_worker(label, move |context| async move {
        let mut plan_changes = plan_handle.subscribe_changes();
        loop {
            if context.stop_requested() {
                break;
            }
            let Some(config) = snapshot(plan_handle.snapshot().as_ref()) else {
                if !context.wait_or_stop(plan_changes.changed()).await {
                    break;
                }
                continue;
            };
            if let Err(error) = prune(spool.as_ref(), &config) {
                eprintln!("{label} worker iteration failed: {error}");
            }
            if !context
                .sleep_or_wait_or_stop(interval(&config), plan_changes.changed())
                .await
            {
                break;
            }
        }
    })
}

fn prune_ingress_retention_once(
    spool: &impl DurableSpool,
    config: &IngressRetentionLaneConfig,
) -> Result<(), storage::StorageError> {
    prune_ingress_retention_once_at(spool, config, current_unix_time_ns())
}

fn prune_ingress_retention_once_at(
    spool: &impl DurableSpool,
    config: &IngressRetentionLaneConfig,
    now_unix_ns: u64,
) -> Result<(), storage::StorageError> {
    prune_retention_limits(
        RetentionLimits::from(&config.retention),
        now_unix_ns,
        |cutoff_unix_ns, limit| {
            spool.prune_expired_ingress_prefix(cutoff_unix_ns, limit, &config.cursor_owners)
        },
        |max_records, limit| {
            spool.prune_ingress_to_max_records(max_records, limit, &config.cursor_owners)
        },
        |kind, pruned| {
            log_retention(
                "ingress",
                "records",
                kind,
                pruned,
                config.cursor_owners.len(),
            )
        },
    )
}

fn prune_export_retention_once(
    spool: &impl DurableSpool,
    snapshot: &ExportRetentionLaneSnapshot,
) -> Result<(), storage::StorageError> {
    prune_export_retention_once_at(spool, snapshot, current_unix_time_ns())
}

fn prune_export_retention_once_at(
    spool: &impl DurableSpool,
    snapshot: &ExportRetentionLaneSnapshot,
    now_unix_ns: u64,
) -> Result<(), storage::StorageError> {
    let cursor_owners = snapshot
        .cursor_owners
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    prune_retention_limits(
        RetentionLimits::from(&snapshot.retention),
        now_unix_ns,
        |cutoff_unix_ns, limit| {
            spool.prune_expired_export_prefix(cutoff_unix_ns, limit, &cursor_owners)
        },
        |max_records, limit| spool.prune_export_to_max_records(max_records, limit, &cursor_owners),
        |kind, pruned| log_retention("export", "events", kind, pruned, cursor_owners.len()),
    )
}

fn export_retention_lane_snapshot(plan: &RuntimePlan) -> Option<ExportRetentionLaneSnapshot> {
    let retention = &plan.storage.retention.export;
    retention.enabled().then(|| ExportRetentionLaneSnapshot {
        cursor_owners: plan
            .export
            .sinks
            .iter()
            .map(|sink| sink.id().to_string())
            .collect(),
        retention: retention.clone(),
    })
}

fn prune_retention_limits(
    retention: RetentionLimits,
    now_unix_ns: u64,
    mut prune_expired: impl FnMut(u64, usize) -> Result<storage::RetentionPrune, storage::StorageError>,
    mut prune_capacity: impl FnMut(u64, usize) -> Result<storage::RetentionPrune, storage::StorageError>,
    log_prune: impl Fn(&str, storage::RetentionPrune),
) -> Result<(), storage::StorageError> {
    let mut remaining_limit = usize::try_from(retention.prune_batch_limit).unwrap_or(usize::MAX);
    if let Some(max_age_ms) = retention.max_age_ms {
        let cutoff_unix_ns = retention_cutoff_unix_ns(now_unix_ns, max_age_ms);
        let pruned = prune_expired(cutoff_unix_ns, remaining_limit)?;
        remaining_limit = remaining_after_prune(remaining_limit, pruned.pruned_count);
        log_prune("expired", pruned);
    }
    if remaining_limit > 0
        && let Some(max_records) = retention.max_records
    {
        let pruned = prune_capacity(max_records, remaining_limit)?;
        log_prune("capacity", pruned);
    }
    Ok(())
}

fn log_retention(
    lane: &str,
    record_noun: &str,
    kind: &str,
    pruned: storage::RetentionPrune,
    cursor_owner_count: usize,
) {
    let Some(retired_through) = pruned.retired_through else {
        return;
    };
    eprintln!(
        "{} retention retired {} {} {} through sequence {} for {} cursor owners",
        lane, pruned.pruned_count, kind, record_noun, retired_through, cursor_owner_count
    );
}

fn remaining_after_prune(limit: usize, pruned_count: u64) -> usize {
    limit.saturating_sub(usize::try_from(pruned_count).unwrap_or(usize::MAX))
}

fn retention_cutoff_unix_ns(now_unix_ns: u64, max_age_ms: u64) -> u64 {
    now_unix_ns.saturating_sub(max_age_ms.saturating_mul(1_000_000))
}

fn current_unix_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

impl From<&IngressRetentionPlan> for RetentionLimits {
    fn from(retention: &IngressRetentionPlan) -> Self {
        Self {
            max_age_ms: retention.max_age_ms,
            max_records: retention.max_records,
            prune_batch_limit: retention.prune_batch_limit.get(),
        }
    }
}

impl From<&ExportRetentionPlan> for RetentionLimits {
    fn from(retention: &ExportRetentionPlan) -> Self {
        Self {
            max_age_ms: retention.max_age_ms,
            max_records: retention.max_records,
            prune_batch_limit: retention.prune_batch_limit.get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, num::NonZeroU64, path::PathBuf, sync::Arc};

    use probe_config::{
        AgentConfig, CaptureBackend, CaptureConfig, CaptureSelection, ExportQueueRetentionConfig,
        ExporterConfig, ExporterTransportConfig, IngressJournalRetentionConfig, StorageConfig,
        StorageRetentionConfig,
    };
    use probe_core::{CapabilityKind, CapabilityState, SpoolPayloadSchema};
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, OnlineExportConfigUpdate,
        OnlineReloadConfigUpdate, ProviderRegistry, RuntimePlan,
    };
    use storage::{FjallSpool, RetentionPrune, SpoolPayload};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn storage_retention_lane_snapshot_uses_storage_plan() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let plan = runtime_plan(
            temp.path().join("spool"),
            StorageRetentionConfig {
                ingress: IngressJournalRetentionConfig {
                    max_age_ms: Some(60_000),
                    max_records: Some(10_000),
                    sweep_interval_ms: 5_000,
                    prune_batch_limit: 128,
                },
                export: ExportQueueRetentionConfig {
                    max_age_ms: Some(120_000),
                    max_records: Some(50_000),
                    sweep_interval_ms: 7_000,
                    prune_batch_limit: 256,
                },
            },
            vec![webhook_exporter("collector")],
        )?;

        let ingress = IngressRetentionLaneConfig::from_storage_plan(&plan.storage)
            .expect("ingress retention should be enabled");
        let export =
            export_retention_lane_snapshot(&plan).expect("export retention should be enabled");

        assert_eq!(ingress.cursor_owners, [PARSER_INGRESS_CURSOR_OWNER]);
        assert_eq!(ingress.retention.max_age_ms, Some(60_000));
        assert_eq!(ingress.retention.max_records, Some(10_000));
        assert_eq!(export.cursor_owners, ["collector"]);
        assert_eq!(
            export.retention.sweep_interval_ms,
            NonZeroU64::new(7_000).expect("positive sweep interval")
        );
        assert_eq!(export.retention.max_age_ms, Some(120_000));
        assert_eq!(export.retention.max_records, Some(50_000));
        Ok(())
    }

    #[test]
    fn storage_retention_lane_snapshot_is_disabled_without_retention_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let plan = runtime_plan(
            temp.path().join("spool"),
            StorageRetentionConfig::default(),
            Vec::new(),
        )?;

        assert!(IngressRetentionLaneConfig::from_storage_plan(&plan.storage).is_none());
        assert!(export_retention_lane_snapshot(&plan).is_none());
        Ok(())
    }

    #[test]
    fn storage_retention_lane_snapshot_is_enabled_by_max_records_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let plan = runtime_plan(
            temp.path().join("spool"),
            StorageRetentionConfig {
                ingress: IngressJournalRetentionConfig {
                    max_age_ms: None,
                    max_records: Some(10),
                    sweep_interval_ms: 5_000,
                    prune_batch_limit: 128,
                },
                export: ExportQueueRetentionConfig {
                    max_age_ms: None,
                    max_records: Some(20),
                    sweep_interval_ms: 7_000,
                    prune_batch_limit: 256,
                },
            },
            vec![webhook_exporter("collector")],
        )?;

        assert_eq!(
            IngressRetentionLaneConfig::from_storage_plan(&plan.storage)
                .expect("ingress retention should be enabled")
                .retention
                .max_records,
            Some(10)
        );
        let export =
            export_retention_lane_snapshot(&plan).expect("export retention should be enabled");
        assert_eq!(export.cursor_owners, ["collector"]);
        assert_eq!(export.retention.max_records, Some(20));
        Ok(())
    }

    #[test]
    fn export_retention_uses_active_export_plan_for_cursor_retirement()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path().join("spool-data"))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"one",
        ))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"two",
        ))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"three",
        ))?;
        let plan = runtime_plan(
            temp.path().join("spool"),
            StorageRetentionConfig {
                export: ExportQueueRetentionConfig {
                    max_age_ms: None,
                    max_records: Some(1),
                    sweep_interval_ms: 7_000,
                    prune_batch_limit: 256,
                },
                ..StorageRetentionConfig::default()
            },
            vec![webhook_exporter("primary")],
        )?;
        let plan_handle = RuntimePlanHandle::new(Arc::new(plan.clone()));

        let updated_plan = plan.with_online_reload_update(OnlineReloadConfigUpdate {
            export: Some(OnlineExportConfigUpdate {
                export: plan.config.export.clone(),
                exporters: vec![webhook_exporter("primary"), webhook_exporter("secondary")],
            }),
            ..OnlineReloadConfigUpdate::default()
        });
        plan_handle.replace(updated_plan);
        let export = export_retention_lane_snapshot(plan_handle.snapshot().as_ref())
            .expect("export retention should be enabled");

        prune_export_retention_once(&spool, &export)?;

        assert_eq!(spool.export_cursor("primary")?, 2);
        assert_eq!(spool.export_cursor("secondary")?, 2);
        assert_eq!(
            spool
                .read_export_batch("secondary", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        Ok(())
    }

    #[tokio::test]
    async fn storage_retention_worker_enables_ingress_retention_after_plan_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = Arc::new(FjallSpool::open(temp.path().join("spool-data"))?);
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            b"one",
        ))?;
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            b"two",
        ))?;
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            b"three",
        ))?;
        let plan = runtime_plan(
            temp.path().join("spool"),
            StorageRetentionConfig::default(),
            Vec::new(),
        )?;
        let plan_handle = RuntimePlanHandle::new(Arc::new(plan));
        let worker = spawn_storage_retention_workers(Arc::clone(&spool), plan_handle.clone());

        plan_handle.replace(plan_handle.snapshot().with_online_reload_update(
            OnlineReloadConfigUpdate {
                storage_retention: Some(StorageRetentionConfig {
                    ingress: IngressJournalRetentionConfig {
                        max_age_ms: None,
                        max_records: Some(1),
                        sweep_interval_ms: 50,
                        prune_batch_limit: 10,
                    },
                    ..StorageRetentionConfig::default()
                }),
                ..OnlineReloadConfigUpdate::default()
            },
        ));

        let result =
            wait_until_storage(|| Ok(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)? == 2))
                .await;
        worker.stop().await;
        result?;
        assert_eq!(
            spool
                .read_ingress_batch(PARSER_INGRESS_CURSOR_OWNER, 10)?
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        Ok(())
    }

    #[tokio::test]
    async fn storage_retention_worker_idles_ingress_lane_after_plan_disables_retention()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = Arc::new(FjallSpool::open(temp.path().join("spool-data"))?);
        for payload in ["one", "two", "three"] {
            spool.append_ingress(SpoolPayload::new(
                SpoolPayloadSchema::CaptureEventOriginJson,
                payload.as_bytes(),
            ))?;
        }
        let plan = runtime_plan(
            temp.path().join("spool"),
            StorageRetentionConfig {
                ingress: IngressJournalRetentionConfig {
                    max_age_ms: None,
                    max_records: Some(1),
                    sweep_interval_ms: 50,
                    prune_batch_limit: 10,
                },
                ..StorageRetentionConfig::default()
            },
            Vec::new(),
        )?;
        let plan_handle = RuntimePlanHandle::new(Arc::new(plan));
        let worker = spawn_storage_retention_workers(Arc::clone(&spool), plan_handle.clone());

        let result =
            wait_until_storage(|| Ok(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)? == 2))
                .await;
        result?;
        plan_handle.replace(plan_handle.snapshot().with_online_reload_update(
            OnlineReloadConfigUpdate {
                storage_retention: Some(StorageRetentionConfig::default()),
                ..OnlineReloadConfigUpdate::default()
            },
        ));
        for payload in ["four", "five"] {
            spool.append_ingress(SpoolPayload::new(
                SpoolPayloadSchema::CaptureEventOriginJson,
                payload.as_bytes(),
            ))?;
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
        worker.stop().await;

        assert_eq!(
            spool
                .read_ingress_batch(PARSER_INGRESS_CURSOR_OWNER, 10)?
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        Ok(())
    }

    #[tokio::test]
    async fn storage_retention_worker_enables_export_retention_after_plan_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = Arc::new(FjallSpool::open(temp.path().join("spool-data"))?);
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"one",
        ))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"two",
        ))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"three",
        ))?;
        let plan = runtime_plan(
            temp.path().join("spool"),
            StorageRetentionConfig::default(),
            vec![webhook_exporter("collector")],
        )?;
        let plan_handle = RuntimePlanHandle::new(Arc::new(plan));
        let worker = spawn_storage_retention_workers(Arc::clone(&spool), plan_handle.clone());

        plan_handle.replace(plan_handle.snapshot().with_online_reload_update(
            OnlineReloadConfigUpdate {
                storage_retention: Some(StorageRetentionConfig {
                    export: ExportQueueRetentionConfig {
                        max_age_ms: None,
                        max_records: Some(1),
                        sweep_interval_ms: 50,
                        prune_batch_limit: 10,
                    },
                    ..StorageRetentionConfig::default()
                }),
                ..OnlineReloadConfigUpdate::default()
            },
        ));

        let result = wait_until_storage(|| Ok(spool.export_cursor("collector")? == 2)).await;
        worker.stop().await;
        result?;
        assert_eq!(
            spool
                .read_export_batch("collector", 10)?
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        Ok(())
    }

    #[test]
    fn retention_limits_prunes_age_first_then_capacity_with_remaining_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let calls = RefCell::new(Vec::new());
        let logs = RefCell::new(Vec::new());

        prune_retention_limits(
            RetentionLimits {
                max_age_ms: Some(5),
                max_records: Some(10),
                prune_batch_limit: 3,
            },
            20_000_000,
            |cutoff_unix_ns, limit| {
                assert_eq!(cutoff_unix_ns, 15_000_000);
                assert_eq!(limit, 3);
                calls.borrow_mut().push(format!("expired:{limit}"));
                Ok(RetentionPrune {
                    pruned_count: 2,
                    retired_through: Some(2),
                })
            },
            |max_records, limit| {
                assert_eq!(max_records, 10);
                assert_eq!(limit, 1);
                calls.borrow_mut().push(format!("capacity:{limit}"));
                Ok(RetentionPrune {
                    pruned_count: 1,
                    retired_through: Some(3),
                })
            },
            |kind, pruned| {
                logs.borrow_mut()
                    .push(format!("{kind}:{}", pruned.pruned_count));
            },
        )?;

        assert_eq!(calls.into_inner(), ["expired:3", "capacity:1"]);
        assert_eq!(logs.into_inner(), ["expired:2", "capacity:1"]);
        Ok(())
    }

    #[test]
    fn retention_limits_skips_capacity_when_age_exhausts_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let calls = RefCell::new(Vec::new());

        prune_retention_limits(
            RetentionLimits {
                max_age_ms: Some(5),
                max_records: Some(10),
                prune_batch_limit: 2,
            },
            20_000_000,
            |_, limit| {
                calls.borrow_mut().push(format!("expired:{limit}"));
                Ok(RetentionPrune {
                    pruned_count: 2,
                    retired_through: Some(2),
                })
            },
            |_, _| panic!("capacity prune should not run after age exhausts the batch budget"),
            |_, _| {},
        )?;

        assert_eq!(calls.into_inner(), ["expired:2"]);
        Ok(())
    }

    #[test]
    fn ingress_retention_retires_expired_parser_cursor() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            b"one",
        ))?;
        let config = IngressRetentionLaneConfig {
            cursor_owners: vec![PARSER_INGRESS_CURSOR_OWNER],
            retention: IngressRetentionPlan {
                max_age_ms: Some(1),
                max_records: None,
                sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                prune_batch_limit: NonZeroU64::new(10).expect("positive prune limit"),
            },
        };

        prune_ingress_retention_once_at(&spool, &config, u64::MAX)?;

        assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 1);
        assert!(spool.read_ingress_batch_after(0, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn export_retention_retires_expired_sink_cursor() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"one",
        ))?;
        let snapshot = ExportRetentionLaneSnapshot {
            cursor_owners: vec!["collector".to_string()],
            retention: ExportRetentionPlan {
                max_age_ms: Some(1),
                max_records: None,
                sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                prune_batch_limit: NonZeroU64::new(10).expect("positive prune limit"),
            },
        };

        prune_export_retention_once_at(&spool, &snapshot, u64::MAX)?;

        assert_eq!(spool.export_cursor("collector")?, 1);
        assert!(spool.read_export_batch("collector", 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn ingress_capacity_retention_retires_parser_cursor() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            b"one",
        ))?;
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            b"two",
        ))?;
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            b"three",
        ))?;
        let config = IngressRetentionLaneConfig {
            cursor_owners: vec![PARSER_INGRESS_CURSOR_OWNER],
            retention: IngressRetentionPlan {
                max_age_ms: None,
                max_records: Some(1),
                sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                prune_batch_limit: NonZeroU64::new(10).expect("positive prune limit"),
            },
        };

        prune_ingress_retention_once_at(&spool, &config, 42)?;

        assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 2);
        assert_eq!(
            spool
                .read_ingress_batch(PARSER_INGRESS_CURSOR_OWNER, 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        Ok(())
    }

    #[test]
    fn export_capacity_retention_retires_sink_cursor() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"one",
        ))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"two",
        ))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"three",
        ))?;
        let snapshot = ExportRetentionLaneSnapshot {
            cursor_owners: vec!["collector".to_string()],
            retention: ExportRetentionPlan {
                max_age_ms: None,
                max_records: Some(1),
                sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                prune_batch_limit: NonZeroU64::new(10).expect("positive prune limit"),
            },
        };

        prune_export_retention_once_at(&spool, &snapshot, 42)?;

        assert_eq!(spool.export_cursor("collector")?, 2);
        assert_eq!(
            spool
                .read_export_batch("collector", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        Ok(())
    }

    async fn wait_until_storage(
        mut condition: impl FnMut() -> Result<bool, storage::StorageError>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if condition()? {
                    return Ok::<(), storage::StorageError>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "timed out waiting for storage retention worker")??;
        Ok(())
    }

    fn runtime_plan(
        storage_path: PathBuf,
        retention: StorageRetentionConfig,
        exporters: Vec<ExporterConfig>,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(
            AgentConfig {
                capture: CaptureConfig {
                    selection: CaptureSelection::Replay,
                    ..CaptureConfig::default()
                },
                storage: StorageConfig {
                    path: storage_path,
                    retention,
                },
                exporters,
                ..AgentConfig::default()
            },
            &registry(),
        )
    }

    fn registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            vec![
                CapabilityState::available(CapabilityKind::Http1),
                CapabilityState::available(CapabilityKind::Sse),
                CapabilityState::available(CapabilityKind::WebSocketHandoff),
                CapabilityState::available(CapabilityKind::WebSocketFrame),
                CapabilityState::available(CapabilityKind::DryRunEnforcement),
                CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
                CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
            ],
        )
    }

    fn webhook_exporter(id: &str) -> ExporterConfig {
        ExporterConfig {
            id: id.to_string(),
            transport: ExporterTransportConfig::Webhook {
                endpoint: format!("https://{id}.example/probe/batches"),
                headers: Default::default(),
                tls: Default::default(),
            },
            ..ExporterConfig::default()
        }
    }
}

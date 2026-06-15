use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pipeline::PARSER_INGRESS_CURSOR_OWNER;
use runtime::{ExportPlan, ExportRetentionPlan, IngressRetentionPlan, StoragePlan};
use storage::{DurableSpool, IngressCursorOwner};

use crate::periodic_worker::{PeriodicWorkerHandle, spawn_periodic_worker};

pub(crate) struct StorageRetentionWorkerHandle {
    ingress: Option<PeriodicWorkerHandle>,
    export: Option<PeriodicWorkerHandle>,
}

pub(crate) struct StorageRetentionWorkerConfig {
    ingress: Option<IngressRetentionLaneConfig>,
    export: Option<ExportRetentionLaneConfig>,
}

struct IngressRetentionLaneConfig {
    cursor_owners: Vec<IngressCursorOwner>,
    retention: IngressRetentionPlan,
    interval: Duration,
}

struct ExportRetentionLaneConfig {
    cursor_owners: Vec<String>,
    retention: ExportRetentionPlan,
    interval: Duration,
}

#[derive(Clone, Copy)]
struct RetentionLimits {
    max_age_ms: Option<u64>,
    max_records: Option<u64>,
    prune_batch_limit: u64,
}

impl StorageRetentionWorkerHandle {
    pub(crate) async fn stop(self) {
        if let Some(worker) = self.ingress {
            worker.stop().await;
        }
        if let Some(worker) = self.export {
            worker.stop().await;
        }
    }
}

impl StorageRetentionWorkerConfig {
    pub(crate) fn from_plans(export: &ExportPlan, storage: &StoragePlan) -> Option<Self> {
        let ingress = IngressRetentionLaneConfig::from_storage_plan(storage);
        let export = ExportRetentionLaneConfig::from_plans(export, storage);
        (ingress.is_some() || export.is_some()).then_some(Self { ingress, export })
    }
}

impl IngressRetentionLaneConfig {
    fn from_storage_plan(plan: &StoragePlan) -> Option<Self> {
        let retention = &plan.retention.ingress;
        retention.enabled().then(|| Self {
            cursor_owners: vec![PARSER_INGRESS_CURSOR_OWNER],
            interval: Duration::from_millis(retention.sweep_interval_ms.get()),
            retention: retention.clone(),
        })
    }
}

impl ExportRetentionLaneConfig {
    fn from_plans(export: &ExportPlan, storage: &StoragePlan) -> Option<Self> {
        let retention = &storage.retention.export;
        retention.enabled().then(|| Self {
            cursor_owners: export.sinks.iter().map(|sink| sink.id.clone()).collect(),
            interval: Duration::from_millis(retention.sweep_interval_ms.get()),
            retention: retention.clone(),
        })
    }
}

pub(crate) fn spawn_storage_retention_workers<S>(
    spool: Arc<S>,
    config: StorageRetentionWorkerConfig,
) -> StorageRetentionWorkerHandle
where
    S: DurableSpool + Send + Sync + 'static,
{
    let StorageRetentionWorkerConfig { ingress, export } = config;
    let ingress = ingress.map(|config| {
        let spool = Arc::clone(&spool);
        spawn_periodic_worker("ingress retention", config.interval, move || {
            prune_ingress_retention_once(spool.as_ref(), &config)
        })
    });
    let export = export.map(|config| {
        let spool = Arc::clone(&spool);
        spawn_periodic_worker("export retention", config.interval, move || {
            prune_export_retention_once(spool.as_ref(), &config)
        })
    });
    StorageRetentionWorkerHandle { ingress, export }
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
    config: &ExportRetentionLaneConfig,
) -> Result<(), storage::StorageError> {
    prune_export_retention_once_at(spool, config, current_unix_time_ns())
}

fn prune_export_retention_once_at(
    spool: &impl DurableSpool,
    config: &ExportRetentionLaneConfig,
    now_unix_ns: u64,
) -> Result<(), storage::StorageError> {
    let cursor_owners = config
        .cursor_owners
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    prune_retention_limits(
        RetentionLimits::from(&config.retention),
        now_unix_ns,
        |cutoff_unix_ns, limit| {
            spool.prune_expired_export_prefix(cutoff_unix_ns, limit, &cursor_owners)
        },
        |max_records, limit| spool.prune_export_to_max_records(max_records, limit, &cursor_owners),
        |kind, pruned| log_retention("export", "events", kind, pruned, cursor_owners.len()),
    )
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
    use std::{cell::RefCell, num::NonZeroU64};

    use probe_config::CompressionCodecName;
    use probe_core::SpoolPayloadSchema;
    use runtime::{
        ExportPlan, ExportSinkTlsPlan, ExportWorkerPlan, StorageRetentionPlan,
        WebhookExportSinkPlan,
    };
    use storage::{FjallSpool, RetentionPrune, SpoolPayload};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn storage_retention_worker_config_uses_storage_plan() {
        let export = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: vec![WebhookExportSinkPlan {
                id: "collector".to_string(),
                endpoint: "https://collector.example/batches".to_string(),
                codec: CompressionCodecName::None,
                headers: Default::default(),
                tls: ExportSinkTlsPlan::default(),
                worker: runtime::ExportSinkWorkerPlan {
                    batches_per_tick_override: None,
                    effective_batches_per_tick: NonZeroU64::new(1).expect("positive quota"),
                },
            }],
        };
        let storage = StoragePlan {
            retention: StorageRetentionPlan {
                ingress: IngressRetentionPlan {
                    max_age_ms: Some(60_000),
                    max_records: Some(10_000),
                    sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                    prune_batch_limit: NonZeroU64::new(128).expect("positive prune limit"),
                },
                export: ExportRetentionPlan {
                    max_age_ms: Some(120_000),
                    max_records: Some(50_000),
                    sweep_interval_ms: NonZeroU64::new(7_000).expect("positive sweep interval"),
                    prune_batch_limit: NonZeroU64::new(256).expect("positive prune limit"),
                },
            },
        };

        let config = StorageRetentionWorkerConfig::from_plans(&export, &storage)
            .expect("configured max age should enable storage retention");
        let ingress = config.ingress.expect("ingress retention should be enabled");
        let export = config.export.expect("export retention should be enabled");

        assert_eq!(ingress.cursor_owners, [PARSER_INGRESS_CURSOR_OWNER]);
        assert_eq!(ingress.interval, Duration::from_millis(5_000));
        assert_eq!(ingress.retention.max_age_ms, Some(60_000));
        assert_eq!(ingress.retention.max_records, Some(10_000));
        assert_eq!(export.cursor_owners, ["collector"]);
        assert_eq!(export.interval, Duration::from_millis(7_000));
        assert_eq!(export.retention.max_age_ms, Some(120_000));
        assert_eq!(export.retention.max_records, Some(50_000));
    }

    #[test]
    fn storage_retention_worker_config_is_disabled_without_retention_limit() {
        let export = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: Vec::new(),
        };

        assert!(
            StorageRetentionWorkerConfig::from_plans(&export, &StoragePlan::default()).is_none()
        );
    }

    #[test]
    fn storage_retention_worker_config_is_enabled_by_max_records_only() {
        let export = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: vec![WebhookExportSinkPlan {
                id: "collector".to_string(),
                endpoint: "https://collector.example/batches".to_string(),
                codec: CompressionCodecName::None,
                headers: Default::default(),
                tls: ExportSinkTlsPlan::default(),
                worker: runtime::ExportSinkWorkerPlan {
                    batches_per_tick_override: None,
                    effective_batches_per_tick: NonZeroU64::new(1).expect("positive quota"),
                },
            }],
        };
        let storage = StoragePlan {
            retention: StorageRetentionPlan {
                ingress: IngressRetentionPlan {
                    max_age_ms: None,
                    max_records: Some(10),
                    sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                    prune_batch_limit: NonZeroU64::new(128).expect("positive prune limit"),
                },
                export: ExportRetentionPlan {
                    max_age_ms: None,
                    max_records: Some(20),
                    sweep_interval_ms: NonZeroU64::new(7_000).expect("positive sweep interval"),
                    prune_batch_limit: NonZeroU64::new(256).expect("positive prune limit"),
                },
            },
        };

        let config = StorageRetentionWorkerConfig::from_plans(&export, &storage)
            .expect("max-records retention should enable storage retention");

        assert_eq!(
            config
                .ingress
                .expect("ingress retention should be enabled")
                .retention
                .max_records,
            Some(10)
        );
        assert_eq!(
            config
                .export
                .expect("export retention should be enabled")
                .retention
                .max_records,
            Some(20)
        );
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
            SpoolPayloadSchema::CaptureEventJson,
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
            interval: Duration::from_millis(5_000),
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
            SpoolPayloadSchema::EventEnvelopeJson,
            b"one",
        ))?;
        let config = ExportRetentionLaneConfig {
            cursor_owners: vec!["collector".to_string()],
            retention: ExportRetentionPlan {
                max_age_ms: Some(1),
                max_records: None,
                sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                prune_batch_limit: NonZeroU64::new(10).expect("positive prune limit"),
            },
            interval: Duration::from_millis(5_000),
        };

        prune_export_retention_once_at(&spool, &config, u64::MAX)?;

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
            SpoolPayloadSchema::CaptureEventJson,
            b"one",
        ))?;
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventJson,
            b"two",
        ))?;
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventJson,
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
            interval: Duration::from_millis(5_000),
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
            SpoolPayloadSchema::EventEnvelopeJson,
            b"one",
        ))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeJson,
            b"two",
        ))?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeJson,
            b"three",
        ))?;
        let config = ExportRetentionLaneConfig {
            cursor_owners: vec!["collector".to_string()],
            retention: ExportRetentionPlan {
                max_age_ms: None,
                max_records: Some(1),
                sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                prune_batch_limit: NonZeroU64::new(10).expect("positive prune limit"),
            },
            interval: Duration::from_millis(5_000),
        };

        prune_export_retention_once_at(&spool, &config, 42)?;

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
}

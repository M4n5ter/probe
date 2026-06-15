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
    let Some(max_age_ms) = config.retention.max_age_ms else {
        return Ok(());
    };
    let cutoff_unix_ns = retention_cutoff_unix_ns(now_unix_ns, max_age_ms);
    let limit = usize::try_from(config.retention.prune_batch_limit.get()).unwrap_or(usize::MAX);
    let pruned =
        spool.prune_expired_ingress_prefix(cutoff_unix_ns, limit, &config.cursor_owners)?;
    let Some(retired_through) = pruned.retired_through else {
        return Ok(());
    };
    eprintln!(
        "ingress retention retired {} expired records through sequence {} for {} cursor owners",
        pruned.pruned_count,
        retired_through,
        config.cursor_owners.len()
    );
    Ok(())
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
    let Some(max_age_ms) = config.retention.max_age_ms else {
        return Ok(());
    };
    let cutoff_unix_ns = retention_cutoff_unix_ns(now_unix_ns, max_age_ms);
    let limit = usize::try_from(config.retention.prune_batch_limit.get()).unwrap_or(usize::MAX);
    let cursor_owners = config
        .cursor_owners
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let pruned = spool.prune_expired_export_prefix(cutoff_unix_ns, limit, &cursor_owners)?;
    let Some(retired_through) = pruned.retired_through else {
        return Ok(());
    };
    eprintln!(
        "export retention retired {} expired events through sequence {} for {} cursor owners",
        pruned.pruned_count,
        retired_through,
        cursor_owners.len()
    );
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use probe_config::{CompressionCodecName, ExporterTransport};
    use probe_core::SpoolPayloadSchema;
    use runtime::{
        ExportPlan, ExportSinkPlan, ExportSinkTlsPlan, ExportWorkerPlan, StorageRetentionPlan,
    };
    use storage::{FjallSpool, SpoolPayload};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn storage_retention_worker_config_uses_storage_plan() {
        let export = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: vec![ExportSinkPlan {
                id: "collector".to_string(),
                transport: ExporterTransport::Webhook,
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
                    sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                    prune_batch_limit: NonZeroU64::new(128).expect("positive prune limit"),
                },
                export: ExportRetentionPlan {
                    max_age_ms: Some(120_000),
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
        assert_eq!(export.cursor_owners, ["collector"]);
        assert_eq!(export.interval, Duration::from_millis(7_000));
        assert_eq!(export.retention.max_age_ms, Some(120_000));
    }

    #[test]
    fn storage_retention_worker_config_is_disabled_without_max_age() {
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
}

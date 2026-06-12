use std::{
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use runtime::{ExportPlan, ExportRetentionPlan};
use storage::ExportSpool;
use tokio::sync::Notify;

use super::{
    ExportDrainError,
    cleanup::{current_unix_time_ns, prune_export_queue_for_sink_ids_at},
};

const EXPORT_RETENTION_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ExportRetentionWorkerHandle {
    stop_requested: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

pub struct ExportRetentionWorkerConfig {
    sink_ids: Vec<String>,
    retention: ExportRetentionPlan,
    interval: Duration,
}

impl ExportRetentionWorkerConfig {
    pub fn from_export_plan(plan: &ExportPlan) -> Option<Self> {
        plan.retention.enabled().then(|| Self {
            sink_ids: plan.sinks.iter().map(|sink| sink.id.clone()).collect(),
            interval: Duration::from_millis(plan.retention.sweep_interval_ms.get()),
            retention: plan.retention.clone(),
        })
    }
}

impl ExportRetentionWorkerHandle {
    pub async fn stop(mut self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        self.stop_notify.notify_one();
        match tokio::time::timeout(EXPORT_RETENTION_WORKER_SHUTDOWN_TIMEOUT, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if !error.is_cancelled() => {
                eprintln!("export retention worker stopped with error: {error}");
            }
            Ok(Err(_)) => {}
            Err(_) => {
                self.task.abort();
                if let Err(error) = self.task.await
                    && !error.is_cancelled()
                {
                    eprintln!("export retention worker stopped with error: {error}");
                }
            }
        }
    }
}

pub fn spawn_export_retention_worker<S>(
    spool: Arc<S>,
    config: ExportRetentionWorkerConfig,
) -> ExportRetentionWorkerHandle
where
    S: ExportSpool + Send + Sync + 'static,
{
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_notify = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_stop_notify = Arc::clone(&stop_notify);
    let task = tokio::spawn(async move {
        while !task_stop_requested.load(Ordering::Relaxed) {
            if let Err(error) = prune_export_retention_once(spool.as_ref(), &config) {
                eprintln!("export retention worker cleanup failed: {error}");
            }
            if task_stop_requested.load(Ordering::Relaxed) {
                break;
            }
            tokio::select! {
                () = tokio::time::sleep(config.interval) => {}
                () = task_stop_notify.notified() => {}
            }
        }
    });
    ExportRetentionWorkerHandle {
        stop_requested,
        stop_notify,
        task,
    }
}

fn prune_export_retention_once(
    spool: &impl ExportSpool,
    config: &ExportRetentionWorkerConfig,
) -> Result<(), ExportDrainError> {
    let sink_ids = config
        .sink_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    prune_export_queue_for_sink_ids_at(spool, &sink_ids, &config.retention, current_unix_time_ns())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use runtime::{ExportPlan, ExportRetentionPlan, ExportWorkerPlan};

    use super::*;

    #[test]
    fn export_retention_worker_config_uses_storage_retention_without_sinks() {
        let plan = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "export worker disabled by config".to_string(),
            },
            retention: ExportRetentionPlan {
                max_age_ms: Some(60_000),
                sweep_interval_ms: NonZeroU64::new(5_000).expect("positive sweep interval"),
                prune_batch_limit: NonZeroU64::new(128).expect("positive prune limit"),
            },
            sinks: Vec::new(),
        };

        let config = ExportRetentionWorkerConfig::from_export_plan(&plan)
            .expect("retention worker should not depend on planned sinks");

        assert!(config.sink_ids.is_empty());
        assert_eq!(config.interval, Duration::from_millis(5_000));
        assert_eq!(config.retention.max_age_ms, Some(60_000));
    }
}

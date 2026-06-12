use std::{
    collections::HashMap,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use runtime::{ExportPlan, ExportSinkPlan, ExportWorkerPlan};
use storage::ExportSpool;
use tokio::sync::Notify;

use super::{ExportDrainError, mode::SinkDrainMode, target::drain_export_sink_with_mode};

const EXPORT_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ExportWorkerHandle {
    stop_requested: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

pub struct ExportWorkerConfig {
    agent_id: String,
    sinks: Vec<ExportSinkPlan>,
    interval: Duration,
    sink_timeout: Duration,
    failure_backoff: Duration,
}

impl ExportWorkerConfig {
    fn fixed_interval_bounded(
        agent_id: String,
        sinks: Vec<ExportSinkPlan>,
        interval: Duration,
        sink_timeout: Duration,
        failure_backoff: Duration,
    ) -> Self {
        Self {
            agent_id,
            sinks,
            interval,
            sink_timeout,
            failure_backoff,
        }
    }

    pub fn from_export_plan(agent_id: String, plan: &ExportPlan) -> Option<Self> {
        match &plan.worker {
            ExportWorkerPlan::Disabled { .. } => None,
            ExportWorkerPlan::FixedIntervalBounded {
                interval_ms,
                sink_timeout_ms,
                failure_backoff_ms,
                ..
            } => Some(Self::fixed_interval_bounded(
                agent_id,
                plan.sinks.clone(),
                Duration::from_millis(*interval_ms),
                Duration::from_millis(*sink_timeout_ms),
                Duration::from_millis(*failure_backoff_ms),
            )),
        }
    }
}

impl ExportWorkerHandle {
    pub async fn stop(mut self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        self.stop_notify.notify_one();
        match tokio::time::timeout(EXPORT_WORKER_SHUTDOWN_TIMEOUT, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if !error.is_cancelled() => {
                eprintln!("export worker stopped with error: {error}");
            }
            Ok(Err(_)) => {}
            Err(_) => {
                self.task.abort();
                if let Err(error) = self.task.await
                    && !error.is_cancelled()
                {
                    eprintln!("export worker stopped with error: {error}");
                }
            }
        }
    }
}

pub fn spawn_export_worker<S>(spool: Arc<S>, config: ExportWorkerConfig) -> ExportWorkerHandle
where
    S: ExportSpool + Send + Sync + 'static,
{
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_notify = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_stop_notify = Arc::clone(&stop_notify);
    let task = tokio::spawn(async move {
        let mut backoff = ExportWorkerBackoff::new(config.failure_backoff);
        while !task_stop_requested.load(Ordering::Relaxed) {
            if let Err(error) = drain_export_sinks_once(spool.as_ref(), &config, &mut backoff).await
            {
                eprintln!("export worker drain failed: {error}");
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
    ExportWorkerHandle {
        stop_requested,
        stop_notify,
        task,
    }
}

async fn drain_export_sinks_once(
    spool: &impl ExportSpool,
    config: &ExportWorkerConfig,
    backoff: &mut ExportWorkerBackoff,
) -> Result<(), ExportDrainError> {
    let mut failures = Vec::new();
    for sink in &config.sinks {
        let now = Instant::now();
        if backoff.should_skip(&sink.id, now) {
            continue;
        }
        let mode = SinkDrainMode::MaxBatches {
            max_batches: sink.worker.effective_batches_per_tick.get(),
            sink_timeout: config.sink_timeout,
        };
        let result = drain_export_sink_with_mode(spool, &config.agent_id, sink, mode).await;
        match result {
            Ok(()) => backoff.record_success(&sink.id),
            Err(error) => {
                eprintln!("exporter sink {} failed: {error}", sink.id);
                backoff.record_failure(&sink.id);
                failures.push(format!("{}: {error}", sink.id));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ExportDrainError::MultipleSinksFailed {
            failures: failures.join("; "),
        })
    }
}

#[derive(Debug)]
struct ExportWorkerBackoff {
    failure_backoff: Duration,
    retry_after: HashMap<String, Option<Instant>>,
}

impl ExportWorkerBackoff {
    fn new(failure_backoff: Duration) -> Self {
        Self {
            failure_backoff,
            retry_after: HashMap::new(),
        }
    }

    fn should_skip(&mut self, sink: &str, now: Instant) -> bool {
        match self.retry_after.get(sink).copied() {
            Some(None) => true,
            Some(Some(retry_after)) if retry_after > now => true,
            Some(Some(_)) => {
                self.retry_after.remove(sink);
                false
            }
            None => false,
        }
    }

    fn record_failure(&mut self, sink: &str) {
        self.record_failure_at(sink, Instant::now());
    }

    fn record_failure_at(&mut self, sink: &str, failed_at: Instant) {
        self.retry_after.insert(
            sink.to_string(),
            failed_at.checked_add(self.failure_backoff),
        );
    }

    fn record_success(&mut self, sink: &str) {
        self.retry_after.remove(sink);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::PathBuf,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use probe_config::{
        AgentConfig, CompressionCodecName, ExportWorkerScheduleConfig, ExporterConfig,
        ExporterTransport, TlsMaterialKind,
    };
    use runtime::{ExportPlan, ExportSinkPlan, ExportSinkTlsPlan, ExportWorkerPlan};
    use storage::{ExportSpool, FjallSpool};

    use super::*;
    use crate::export::drain::fixture::{
        plan::{inherited_worker_quota, overridden_worker_quota, runtime_plan, tls_material},
        spool::{
            SingleEventBatchSpool, append_export_event, wait_for_export_cursor,
            wait_for_memory_export_cursor,
        },
        webhook::{TestWebhookServer, request_header},
    };

    #[test]
    fn export_worker_backoff_counts_from_failure_completion() {
        let tick_started_at = Instant::now();
        let failure_completed_at = tick_started_at + Duration::from_millis(750);
        let mut backoff = ExportWorkerBackoff::new(Duration::from_millis(1_000));

        backoff.record_failure_at("slow", failure_completed_at);

        assert!(backoff.should_skip("slow", failure_completed_at + Duration::from_millis(999)));
        assert!(!backoff.should_skip("slow", failure_completed_at + Duration::from_millis(1_000)));
    }

    #[test]
    fn export_worker_config_does_not_read_tls_materials_without_webhook_sinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let tls = ExportSinkTlsPlan {
            trust_anchors: vec![tls_material(
                "collector-ca",
                TlsMaterialKind::TrustAnchor,
                PathBuf::from("/missing/ca.pem"),
            )],
            client_certificates: vec![tls_material(
                "client-cert",
                TlsMaterialKind::ClientCertificate,
                PathBuf::from("/missing/client.pem"),
            )],
            client_private_key: Some(tls_material(
                "client-key",
                TlsMaterialKind::ClientPrivateKey,
                PathBuf::from("/missing/client.key"),
            )),
        };
        let disabled = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: Vec::new(),
        };
        assert!(ExportWorkerConfig::from_export_plan("agent-1".to_string(), &disabled).is_none());
        let non_webhook = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 10,
                batches_per_sink_per_tick: 1,
                sink_timeout_ms: 5_000,
                failure_backoff_ms: 30_000,
            },
            sinks: vec![ExportSinkPlan {
                id: "grpc".to_string(),
                transport: ExporterTransport::Grpc,
                endpoint: "https://collector.example".to_string(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls,
                worker: inherited_worker_quota(1),
            }],
        };

        assert!(
            ExportWorkerConfig::from_export_plan("agent-1".to_string(), &non_webhook).is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn export_worker_drains_until_stopped() -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("planned-export-worker");
        let spool = Arc::new(FjallSpool::open(&temp)?);
        append_export_event(spool.as_ref(), 1)?;
        let server = TestWebhookServer::spawn_accepting(true, 2)?;
        let mut config = AgentConfig {
            agent_id: "agent-1".to_string(),
            exporters: vec![ExporterConfig {
                id: "worker".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: server.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: Default::default(),
                worker: Default::default(),
            }],
            ..AgentConfig::default()
        };
        config.export.worker.schedule = ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 10,
            batches_per_sink_per_tick: 1,
            sink_timeout_ms: 5_000,
            failure_backoff_ms: 30_000,
        };
        config.validate_basic()?;
        let plan = runtime_plan(config)?;
        let config =
            ExportWorkerConfig::from_export_plan(plan.config.agent_id.clone(), &plan.export)
                .expect("worker should be enabled for planned webhook sink");

        let worker = spawn_export_worker(Arc::clone(&spool), config);
        wait_for_export_cursor(spool.as_ref(), "worker", 1).await?;
        append_export_event(spool.as_ref(), 2)?;
        wait_for_export_cursor(spool.as_ref(), "worker", 2).await?;
        worker.stop().await;

        let requests = server.join_requests()?;
        assert_eq!(requests.len(), 2);
        assert_eq!(
            request_header(&requests[0], "x-sssa-codec").as_deref(),
            Some("none")
        );
        assert_eq!(
            request_header(&requests[0], "idempotency-key").as_deref(),
            Some("agent-1:worker:1")
        );
        assert_eq!(
            request_header(&requests[1], "idempotency-key").as_deref(),
            Some("agent-1:worker:2")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn export_worker_uses_configured_per_tick_batch_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let spool = Arc::new(SingleEventBatchSpool::with_export_events(2)?);
        let server = TestWebhookServer::spawn_accepting(true, 2)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 60_000,
                batches_per_sink_per_tick: 2,
                sink_timeout_ms: 5_000,
                failure_backoff_ms: 30_000,
            },
            sinks: vec![ExportSinkPlan {
                id: "budget".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: server.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: ExportSinkTlsPlan::default(),
                worker: inherited_worker_quota(2),
            }],
        };
        let config = ExportWorkerConfig::from_export_plan("agent-1".to_string(), &plan)
            .expect("worker should be enabled");

        let worker = spawn_export_worker(Arc::clone(&spool), config);
        wait_for_memory_export_cursor(spool.as_ref(), "budget", 2).await?;
        worker.stop().await;

        let requests = server.join_requests()?;
        assert_eq!(requests.len(), 2);
        assert_eq!(
            request_header(&requests[0], "idempotency-key").as_deref(),
            Some("agent-1:budget:1")
        );
        assert_eq!(
            request_header(&requests[1], "idempotency-key").as_deref(),
            Some("agent-1:budget:2")
        );
        Ok(())
    }

    #[tokio::test]
    async fn export_worker_uses_per_sink_batch_quota() -> Result<(), Box<dyn std::error::Error>> {
        let spool = Arc::new(SingleEventBatchSpool::with_export_events(2)?);
        let server = TestWebhookServer::spawn_recording(true)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 60_000,
                batches_per_sink_per_tick: 2,
                sink_timeout_ms: 5_000,
                failure_backoff_ms: 30_000,
            },
            sinks: vec![ExportSinkPlan {
                id: "limited".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: server.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: ExportSinkTlsPlan::default(),
                worker: overridden_worker_quota(1),
            }],
        };
        let config = ExportWorkerConfig::from_export_plan("agent-1".to_string(), &plan)
            .expect("worker should be enabled");

        let worker = spawn_export_worker(Arc::clone(&spool), config);
        wait_for_memory_export_cursor(spool.as_ref(), "limited", 1).await?;
        worker.stop().await;

        assert_eq!(spool.export_cursor("limited")?, 1);
        let requests = server.join_requests()?;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            request_header(&requests[0], "idempotency-key").as_deref(),
            Some("agent-1:limited:1")
        );
        Ok(())
    }

    #[tokio::test]
    async fn export_worker_backs_off_failing_sink_without_blocking_healthy_sink()
    -> Result<(), Box<dyn std::error::Error>> {
        let spool = Arc::new(SingleEventBatchSpool::with_export_events(2)?);
        let failing = TestWebhookServer::spawn_recording(false)?;
        let successful = TestWebhookServer::spawn_accepting(true, 2)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 10,
                batches_per_sink_per_tick: 1,
                sink_timeout_ms: 5_000,
                failure_backoff_ms: 60_000,
            },
            sinks: vec![
                ExportSinkPlan {
                    id: "failing".to_string(),
                    transport: ExporterTransport::Webhook,
                    endpoint: failing.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::new(),
                    tls: ExportSinkTlsPlan::default(),
                    worker: inherited_worker_quota(1),
                },
                ExportSinkPlan {
                    id: "successful".to_string(),
                    transport: ExporterTransport::Webhook,
                    endpoint: successful.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::new(),
                    tls: ExportSinkTlsPlan::default(),
                    worker: inherited_worker_quota(1),
                },
            ],
        };
        let config = ExportWorkerConfig::from_export_plan("agent-1".to_string(), &plan)
            .expect("worker should be enabled");

        let worker = spawn_export_worker(Arc::clone(&spool), config);
        wait_for_memory_export_cursor(spool.as_ref(), "successful", 2).await?;
        worker.stop().await;

        let successful_requests = successful.join_requests()?;
        assert_eq!(successful_requests.len(), 2);
        let failing_requests = failing.join_requests()?;
        assert_eq!(failing_requests.len(), 1);
        assert_eq!(
            request_header(&failing_requests[0], "idempotency-key").as_deref(),
            Some("agent-1:failing:1")
        );
        Ok(())
    }

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("sssa-probe-{name}-{}-{nanos}", std::process::id()))
    }
}

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use runtime::{ExportFailureBackoffPlan, ExportPlan, ExportWorkerPlan, WebhookExportSinkPlan};
use serde::Serialize;
use storage::ExportSpool;
use tokio::sync::Notify;

use super::{
    ExportDrainError, ExportDrainFailureReason,
    cleanup::prune_export_acknowledged_prefix_for_sinks,
    mode::SinkDrainMode,
    target::{drain_export_sink_with_mode, finish_export_sink_drain},
};

const EXPORT_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ExportWorkerHandle {
    stop_requested: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

pub struct ExportWorker {
    config: ExportWorkerConfig,
    runtime_state: ExportWorkerRuntimeState,
}

pub struct ExportWorkerConfig {
    agent_id: String,
    sinks: Vec<WebhookExportSinkPlan>,
    interval: Duration,
    sink_timeout: Duration,
    failure_backoff: ExportWorkerBackoffPolicy,
}

#[derive(Debug, Clone)]
pub struct ExportWorkerRuntimeState {
    inner: Arc<Mutex<ExportWorkerRuntimeInner>>,
}

#[derive(Debug)]
struct ExportWorkerRuntimeInner {
    failure_backoff: ExportWorkerBackoffPolicy,
    sinks: BTreeMap<String, ExportSinkWorkerRuntime>,
}

#[derive(Debug)]
enum ExportSinkWorkerRuntime {
    Idle,
    BackingOff {
        failures: u64,
        delay: Duration,
        retry_after: Option<Instant>,
        last_failure_reason: ExportDrainFailureReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportWorkerRuntimeSnapshot {
    pub sinks: BTreeMap<String, ExportSinkWorkerRuntimeSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportSinkWorkerRuntimeSnapshot {
    pub mode: ExportSinkWorkerRuntimeMode,
    pub consecutive_failures: u64,
    pub backoff_delay_ms: Option<u64>,
    pub backoff_remaining_ms: Option<u64>,
    pub last_failure_reason: Option<ExportDrainFailureReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportSinkWorkerRuntimeMode {
    Idle,
    BackingOff,
}

impl ExportWorker {
    pub fn new(config: ExportWorkerConfig) -> Self {
        let runtime_state = ExportWorkerRuntimeState::from_config(&config);
        Self {
            config,
            runtime_state,
        }
    }

    pub fn runtime_state(&self) -> ExportWorkerRuntimeState {
        self.runtime_state.clone()
    }

    pub fn spawn<S>(self, spool: Arc<S>) -> ExportWorkerHandle
    where
        S: ExportSpool + Send + Sync + 'static,
    {
        spawn_export_worker_with_state(spool, self.config, self.runtime_state)
    }
}

impl ExportWorkerConfig {
    fn fixed_interval_bounded(
        agent_id: String,
        sinks: Vec<WebhookExportSinkPlan>,
        interval: Duration,
        sink_timeout: Duration,
        failure_backoff: ExportWorkerBackoffPolicy,
    ) -> Self {
        Self {
            agent_id,
            sinks,
            interval,
            sink_timeout,
            failure_backoff,
        }
    }

    pub fn from_plans(agent_id: String, export: &ExportPlan) -> Option<Self> {
        match &export.worker {
            ExportWorkerPlan::Disabled { .. } => None,
            ExportWorkerPlan::FixedIntervalBounded {
                interval_ms,
                sink_timeout_ms,
                failure_backoff,
                ..
            } => Some(Self::fixed_interval_bounded(
                agent_id,
                export.sinks.clone(),
                Duration::from_millis(*interval_ms),
                Duration::from_millis(*sink_timeout_ms),
                ExportWorkerBackoffPolicy::from(*failure_backoff),
            )),
        }
    }
}

impl ExportWorkerRuntimeState {
    fn from_config(config: &ExportWorkerConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ExportWorkerRuntimeInner {
                failure_backoff: config.failure_backoff,
                sinks: config
                    .sinks
                    .iter()
                    .map(|sink| (sink.id.clone(), ExportSinkWorkerRuntime::Idle))
                    .collect(),
            })),
        }
    }

    fn should_skip(&self, sink: &str, now: Instant) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match inner.sinks.get(sink) {
            Some(ExportSinkWorkerRuntime::BackingOff {
                retry_after: None, ..
            }) => true,
            Some(ExportSinkWorkerRuntime::BackingOff {
                retry_after: Some(retry_after),
                ..
            }) => *retry_after > now,
            Some(ExportSinkWorkerRuntime::Idle) | None => false,
        }
    }

    pub fn snapshot(&self) -> ExportWorkerRuntimeSnapshot {
        let now = Instant::now();
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ExportWorkerRuntimeSnapshot {
            sinks: inner
                .sinks
                .iter()
                .map(|(sink, state)| (sink.clone(), state.snapshot(now)))
                .collect(),
        }
    }

    fn record_success(&self, sink: &str) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner
            .sinks
            .insert(sink.to_string(), ExportSinkWorkerRuntime::Idle);
    }

    fn record_failure(&self, sink: &str, reason: ExportDrainFailureReason) {
        self.record_failure_at(sink, Instant::now(), reason);
    }

    fn record_failure_at(&self, sink: &str, failed_at: Instant, reason: ExportDrainFailureReason) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let policy = inner.failure_backoff;
        let current = inner
            .sinks
            .entry(sink.to_string())
            .or_insert(ExportSinkWorkerRuntime::Idle);
        let (delay, failures) = match current {
            ExportSinkWorkerRuntime::Idle => (policy.initial, 1),
            ExportSinkWorkerRuntime::BackingOff {
                delay, failures, ..
            } => (policy.next_delay(*delay), failures.saturating_add(1)),
        };
        *current = ExportSinkWorkerRuntime::BackingOff {
            failures,
            delay,
            retry_after: failed_at.checked_add(delay),
            last_failure_reason: reason,
        };
    }
}

impl ExportSinkWorkerRuntime {
    fn snapshot(&self, now: Instant) -> ExportSinkWorkerRuntimeSnapshot {
        match self {
            Self::Idle => ExportSinkWorkerRuntimeSnapshot {
                mode: ExportSinkWorkerRuntimeMode::Idle,
                consecutive_failures: 0,
                backoff_delay_ms: None,
                backoff_remaining_ms: None,
                last_failure_reason: None,
            },
            Self::BackingOff {
                failures,
                delay,
                retry_after,
                last_failure_reason,
            } => ExportSinkWorkerRuntimeSnapshot {
                mode: ExportSinkWorkerRuntimeMode::BackingOff,
                consecutive_failures: *failures,
                backoff_delay_ms: Some(duration_millis(*delay)),
                backoff_remaining_ms: retry_after
                    .map(|retry_after| duration_millis(retry_after.saturating_duration_since(now))),
                last_failure_reason: Some(*last_failure_reason),
            },
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

fn spawn_export_worker_with_state<S>(
    spool: Arc<S>,
    config: ExportWorkerConfig,
    runtime_state: ExportWorkerRuntimeState,
) -> ExportWorkerHandle
where
    S: ExportSpool + Send + Sync + 'static,
{
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_notify = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_stop_notify = Arc::clone(&stop_notify);
    let task_runtime_state = runtime_state.clone();
    let task = tokio::spawn(async move {
        while !task_stop_requested.load(Ordering::Relaxed) {
            if let Err(error) =
                drain_export_sinks_once(spool.as_ref(), &config, &task_runtime_state).await
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
    runtime_state: &ExportWorkerRuntimeState,
) -> Result<(), ExportDrainError> {
    let mut failures = Vec::new();
    for sink in &config.sinks {
        let now = Instant::now();
        if runtime_state.should_skip(&sink.id, now) {
            continue;
        }
        let mode = SinkDrainMode::MaxBatches {
            max_batches: sink.worker.effective_batches_per_tick.get(),
            sink_timeout: config.sink_timeout,
        };
        let result = drain_export_sink_with_mode(spool, &config.agent_id, sink, mode).await;
        match result {
            Ok(()) => {
                runtime_state.record_success(&sink.id);
            }
            Err(error) => {
                eprintln!("exporter sink {} failed: {error}", sink.id);
                runtime_state.record_failure(&sink.id, error.runtime_failure_reason());
                failures.push(format!("{}: {error}", sink.id));
            }
        }
    }
    let drain_result = if failures.is_empty() {
        Ok(())
    } else {
        Err(ExportDrainError::MultipleSinksFailed {
            failures: failures.join("; "),
        })
    };
    finish_export_sink_drain(
        drain_result,
        prune_export_acknowledged_prefix_for_sinks(spool, &config.sinks),
    )
}

#[derive(Debug, Clone, Copy)]
struct ExportWorkerBackoffPolicy {
    initial: Duration,
    max: Duration,
    multiplier: u32,
}

impl ExportWorkerBackoffPolicy {
    fn next_delay(self, current: Duration) -> Duration {
        current
            .checked_mul(self.multiplier)
            .unwrap_or(self.max)
            .min(self.max)
    }
}

impl From<ExportFailureBackoffPlan> for ExportWorkerBackoffPolicy {
    fn from(value: ExportFailureBackoffPlan) -> Self {
        Self {
            initial: Duration::from_millis(value.initial_ms),
            max: Duration::from_millis(value.max_ms),
            multiplier: value.multiplier,
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        num::NonZeroU64,
        path::PathBuf,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use probe_config::{
        AgentConfig, CompressionCodecName, ExportWorkerScheduleConfig, ExporterConfig,
        ExporterTransport,
    };
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{
        self, ExportFailureBackoffPlan, ExportPlan, ExportSinkTlsPlan, ExportSinkWorkerPlan,
        ExportWorkerPlan, ProviderRegistry, RuntimePlan, WebhookExportSinkPlan,
    };
    use storage::FjallSpool;

    use super::*;
    use crate::export::drain::{
        batch::EXPORT_BATCH_LIMIT,
        spooled_event::{append_export_event, append_export_events},
        webhook_server::{WebhookAckServer, request_header},
    };

    #[test]
    fn export_worker_backoff_counts_from_failure_completion() {
        let tick_started_at = Instant::now();
        let failure_completed_at = tick_started_at + Duration::from_millis(750);
        let runtime_state = worker_runtime_from_plan(fixed_failure_backoff(1_000));

        runtime_state.record_failure_at(
            "slow",
            failure_completed_at,
            ExportDrainFailureReason::HttpTransportError,
        );

        assert!(
            runtime_state.should_skip("slow", failure_completed_at + Duration::from_millis(999))
        );
        assert!(
            !runtime_state.should_skip("slow", failure_completed_at + Duration::from_millis(1_000))
        );
    }

    #[test]
    fn export_worker_backoff_grows_until_max_and_resets_after_success() {
        let started_at = Instant::now();
        let runtime_state = worker_runtime_from_plan(ExportFailureBackoffPlan {
            initial_ms: 100,
            max_ms: 250,
            multiplier: 2,
        });

        runtime_state.record_failure_at(
            "sink",
            started_at,
            ExportDrainFailureReason::HttpTransportError,
        );
        assert!(runtime_state.should_skip("sink", started_at + Duration::from_millis(99)));
        assert!(!runtime_state.should_skip("sink", started_at + Duration::from_millis(100)));

        let second_failure = started_at + Duration::from_millis(100);
        runtime_state.record_failure_at(
            "sink",
            second_failure,
            ExportDrainFailureReason::HttpTransportError,
        );
        assert!(runtime_state.should_skip("sink", second_failure + Duration::from_millis(199)));
        assert!(!runtime_state.should_skip("sink", second_failure + Duration::from_millis(200)));

        let third_failure = second_failure + Duration::from_millis(200);
        runtime_state.record_failure_at(
            "sink",
            third_failure,
            ExportDrainFailureReason::HttpTransportError,
        );
        assert!(runtime_state.should_skip("sink", third_failure + Duration::from_millis(249)));
        assert!(!runtime_state.should_skip("sink", third_failure + Duration::from_millis(250)));

        runtime_state.record_success("sink");
        let reset_failure = third_failure + Duration::from_millis(250);
        runtime_state.record_failure_at(
            "sink",
            reset_failure,
            ExportDrainFailureReason::HttpTransportError,
        );
        assert!(runtime_state.should_skip("sink", reset_failure + Duration::from_millis(99)));
        assert!(!runtime_state.should_skip("sink", reset_failure + Duration::from_millis(100)));
    }

    #[tokio::test]
    async fn export_worker_drains_until_stopped() -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("planned-export-worker");
        let spool = Arc::new(FjallSpool::open(&temp)?);
        append_export_event(spool.as_ref(), 1)?;
        let server = WebhookAckServer::accepting(2)?;
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
            failure_backoff: probe_config::ExportFailureBackoffConfig {
                initial_ms: 30_000,
                max_ms: 30_000,
                multiplier: 1,
            },
        };
        config.validate_basic()?;
        let plan = runtime_plan(config)?;
        let config = ExportWorkerConfig::from_plans(plan.config.agent_id.clone(), &plan.export)
            .expect("worker should be enabled for planned webhook sink");

        let (worker, _) = spawn_test_export_worker(Arc::clone(&spool), config);
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
        assert!(spool.read_export_batch("late", 10)?.is_empty());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn export_worker_uses_configured_per_tick_batch_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("configured-worker-budget");
        let spool = Arc::new(FjallSpool::open(&temp)?);
        let event_count = (EXPORT_BATCH_LIMIT + 1) as u64;
        append_export_events(spool.as_ref(), event_count)?;
        let server = WebhookAckServer::accepting(2)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 60_000,
                batches_per_sink_per_tick: 2,
                sink_timeout_ms: 5_000,
                failure_backoff: fixed_failure_backoff(30_000),
            },
            sinks: vec![WebhookExportSinkPlan {
                id: "budget".to_string(),
                endpoint: server.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: ExportSinkTlsPlan::default(),
                worker: inherited_worker_quota(2),
            }],
        };
        let config = ExportWorkerConfig::from_plans("agent-1".to_string(), &plan)
            .expect("worker should be enabled");

        let (worker, _) = spawn_test_export_worker(Arc::clone(&spool), config);
        wait_for_export_cursor(spool.as_ref(), "budget", event_count).await?;
        worker.stop().await;

        let requests = server.join_requests()?;
        assert_eq!(requests.len(), 2);
        assert_eq!(
            request_header(&requests[0], "idempotency-key"),
            Some(batch_id("agent-1", "budget", EXPORT_BATCH_LIMIT as u64))
        );
        assert_eq!(
            request_header(&requests[1], "idempotency-key"),
            Some(batch_id("agent-1", "budget", event_count))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn export_worker_uses_per_sink_batch_quota() -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("per-sink-worker-budget");
        let spool = Arc::new(FjallSpool::open(&temp)?);
        append_export_events(spool.as_ref(), (EXPORT_BATCH_LIMIT + 1) as u64)?;
        let server = WebhookAckServer::recording_accepting()?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 60_000,
                batches_per_sink_per_tick: 2,
                sink_timeout_ms: 5_000,
                failure_backoff: fixed_failure_backoff(30_000),
            },
            sinks: vec![WebhookExportSinkPlan {
                id: "limited".to_string(),
                endpoint: server.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: ExportSinkTlsPlan::default(),
                worker: overridden_worker_quota(1),
            }],
        };
        let config = ExportWorkerConfig::from_plans("agent-1".to_string(), &plan)
            .expect("worker should be enabled");

        let (worker, _) = spawn_test_export_worker(Arc::clone(&spool), config);
        wait_for_export_cursor(spool.as_ref(), "limited", EXPORT_BATCH_LIMIT as u64).await?;
        worker.stop().await;

        assert_eq!(spool.export_cursor("limited")?, EXPORT_BATCH_LIMIT as u64);
        let requests = server.join_requests()?;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            request_header(&requests[0], "idempotency-key"),
            Some(batch_id("agent-1", "limited", EXPORT_BATCH_LIMIT as u64))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn export_worker_backs_off_failing_sink_without_blocking_healthy_sink()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("failing-sink-backoff");
        let spool = Arc::new(FjallSpool::open(&temp)?);
        let event_count = (EXPORT_BATCH_LIMIT + 1) as u64;
        append_export_events(spool.as_ref(), event_count)?;
        let failing = WebhookAckServer::recording_rejecting()?;
        let successful = WebhookAckServer::accepting(2)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 10,
                batches_per_sink_per_tick: 1,
                sink_timeout_ms: 5_000,
                failure_backoff: fixed_failure_backoff(60_000),
            },
            sinks: vec![
                WebhookExportSinkPlan {
                    id: "failing".to_string(),
                    endpoint: failing.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::new(),
                    tls: ExportSinkTlsPlan::default(),
                    worker: inherited_worker_quota(1),
                },
                WebhookExportSinkPlan {
                    id: "successful".to_string(),
                    endpoint: successful.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::new(),
                    tls: ExportSinkTlsPlan::default(),
                    worker: inherited_worker_quota(1),
                },
            ],
        };
        let config = ExportWorkerConfig::from_plans("agent-1".to_string(), &plan)
            .expect("worker should be enabled");

        let (worker, runtime_state) = spawn_test_export_worker(Arc::clone(&spool), config);
        wait_for_export_cursor(spool.as_ref(), "successful", event_count).await?;
        let runtime_snapshot = runtime_state.snapshot();
        worker.stop().await;

        let successful_requests = successful.join_requests()?;
        assert_eq!(successful_requests.len(), 2);
        assert_eq!(
            request_header(&successful_requests[0], "idempotency-key"),
            Some(batch_id("agent-1", "successful", EXPORT_BATCH_LIMIT as u64))
        );
        assert_eq!(
            request_header(&successful_requests[1], "idempotency-key"),
            Some(batch_id("agent-1", "successful", event_count))
        );
        let failing_requests = failing.join_requests()?;
        assert_eq!(failing_requests.len(), 1);
        let failing_runtime = runtime_snapshot
            .sinks
            .get("failing")
            .expect("failing sink should have runtime state");
        assert_eq!(
            failing_runtime.mode,
            ExportSinkWorkerRuntimeMode::BackingOff
        );
        assert_eq!(failing_runtime.consecutive_failures, 1);
        assert_eq!(failing_runtime.backoff_delay_ms, Some(60_000));
        assert!(
            failing_runtime
                .backoff_remaining_ms
                .is_some_and(|remaining| remaining <= 60_000)
        );
        assert_eq!(
            failing_runtime.last_failure_reason,
            Some(ExportDrainFailureReason::RemoteRejectedBatch)
        );
        let successful_runtime = runtime_snapshot
            .sinks
            .get("successful")
            .expect("successful sink should have runtime state");
        assert_eq!(successful_runtime.mode, ExportSinkWorkerRuntimeMode::Idle);
        assert_eq!(successful_runtime.consecutive_failures, 0);
        assert_eq!(successful_runtime.last_failure_reason, None);
        assert_eq!(
            request_header(&failing_requests[0], "idempotency-key"),
            Some(batch_id("agent-1", "failing", EXPORT_BATCH_LIMIT as u64))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("sssa-probe-{name}-{}-{nanos}", std::process::id()))
    }

    fn batch_id(agent_id: &str, sink: &str, sequence: u64) -> String {
        format!("{agent_id}:{sink}:{sequence}")
    }

    async fn wait_for_export_cursor(
        spool: &FjallSpool,
        sink: &str,
        expected_cursor: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for _ in 0..50 {
            let cursor = spool.export_cursor(sink)?;
            if cursor >= expected_cursor {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err(format!(
            "export cursor for sink {sink} did not reach {expected_cursor}; current cursor is {}",
            spool.export_cursor(sink)?
        )
        .into())
    }

    fn inherited_worker_quota(effective_batches_per_tick: u64) -> ExportSinkWorkerPlan {
        ExportSinkWorkerPlan {
            batches_per_tick_override: None,
            effective_batches_per_tick: NonZeroU64::new(effective_batches_per_tick)
                .expect("positive batch quota"),
        }
    }

    fn overridden_worker_quota(effective_batches_per_tick: u64) -> ExportSinkWorkerPlan {
        ExportSinkWorkerPlan {
            batches_per_tick_override: Some(effective_batches_per_tick),
            effective_batches_per_tick: NonZeroU64::new(effective_batches_per_tick)
                .expect("positive batch quota"),
        }
    }

    fn fixed_failure_backoff(backoff_ms: u64) -> ExportFailureBackoffPlan {
        ExportFailureBackoffPlan {
            initial_ms: backoff_ms,
            max_ms: backoff_ms,
            multiplier: 1,
        }
    }

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(
            config,
            &ProviderRegistry::new(Vec::new(), test_capabilities()),
        )
    }

    fn test_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
        ]
    }

    fn worker_runtime_from_plan(
        failure_backoff: ExportFailureBackoffPlan,
    ) -> ExportWorkerRuntimeState {
        let config = export_worker_config_with_failure_backoff("sink", failure_backoff);
        ExportWorkerRuntimeState::from_config(&config)
    }

    fn export_worker_config_with_failure_backoff(
        sink: &str,
        failure_backoff: ExportFailureBackoffPlan,
    ) -> ExportWorkerConfig {
        let plan = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 1_000,
                batches_per_sink_per_tick: 1,
                sink_timeout_ms: 5_000,
                failure_backoff,
            },
            sinks: vec![WebhookExportSinkPlan {
                id: sink.to_string(),
                endpoint: "https://collector.example/batches".to_string(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: ExportSinkTlsPlan::default(),
                worker: inherited_worker_quota(1),
            }],
        };
        ExportWorkerConfig::from_plans("agent-1".to_string(), &plan)
            .expect("fixed interval worker plan should produce worker config")
    }

    fn spawn_test_export_worker(
        spool: Arc<FjallSpool>,
        config: ExportWorkerConfig,
    ) -> (ExportWorkerHandle, ExportWorkerRuntimeState) {
        let worker = ExportWorker::new(config);
        let runtime_state = worker.runtime_state();
        (worker.spawn(spool), runtime_state)
    }
}

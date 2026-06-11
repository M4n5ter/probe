use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashSet, sync::Arc, time::Duration};

use exporter::{CompressionCodec, ReliableExporter, WebhookExporter};
use probe_config::{CompressionCodecName, ExporterTransport};
use proto::{BatchEnvelope, EVENT_ENVELOPE_JSON_SCHEMA};
use runtime::{ExportPlan, ExportSinkPlan, ExportWorkerPlan};
use storage::DurableSpool;
use thiserror::Error;
use tokio::sync::Notify;

const EXPORT_BATCH_LIMIT: usize = 1024;
const EXPORT_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const REPLAY_WEBHOOK_SINK: &str = "replay-webhook";

#[derive(Debug, Error)]
pub enum ExportDrainError {
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("proto error: {0}")]
    Proto(#[from] proto::ProtoError),
    #[error("export error: {0}")]
    Export(#[from] exporter::ExportError),
    #[error("{transport:?} exporter is reserved but not implemented")]
    UnsupportedTransport { transport: ExporterTransport },
    #[error("one or more exporters failed: {failures}")]
    MultipleSinksFailed { failures: String },
    #[error("unsupported spooled payload schema at sequence {sequence}: {schema}")]
    UnsupportedSpoolPayloadSchema { sequence: u64, schema: String },
    #[error("exporter sink {sink} timed out after {timeout_ms} ms")]
    SinkTimedOut { sink: String, timeout_ms: u64 },
}

pub struct ExportWorkerHandle {
    stop_requested: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

pub struct ExportWorkerConfig {
    agent_id: String,
    sinks: Vec<ExportSinkPlan>,
    interval: Duration,
    batches_per_sink_per_tick: u64,
    sink_timeout: Duration,
}

impl ExportWorkerConfig {
    fn fixed_interval_bounded(
        agent_id: String,
        sinks: Vec<ExportSinkPlan>,
        interval: Duration,
        batches_per_sink_per_tick: u64,
        sink_timeout: Duration,
    ) -> Self {
        Self {
            agent_id,
            sinks,
            interval,
            batches_per_sink_per_tick,
            sink_timeout,
        }
    }

    pub fn from_export_plan(agent_id: String, plan: &ExportPlan) -> Option<Self> {
        match &plan.worker {
            ExportWorkerPlan::Disabled { .. } => None,
            ExportWorkerPlan::FixedIntervalBounded {
                interval_ms,
                batches_per_sink_per_tick,
                sink_timeout_ms,
            } => Some(Self::fixed_interval_bounded(
                agent_id,
                plan.sinks.clone(),
                Duration::from_millis(*interval_ms),
                *batches_per_sink_per_tick,
                Duration::from_millis(*sink_timeout_ms),
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
    S: DurableSpool + Send + Sync + 'static,
{
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_notify = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_stop_notify = Arc::clone(&stop_notify);
    let task = tokio::spawn(async move {
        while !task_stop_requested.load(Ordering::Relaxed) {
            if let Err(error) = drain_export_sinks_once(spool.as_ref(), &config).await {
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

pub async fn drain_planned_sinks(
    spool: &impl DurableSpool,
    agent_id: &str,
    plan: &ExportPlan,
) -> Result<(), ExportDrainError> {
    drain_export_sinks_with_mode(spool, agent_id, &plan.sinks, SinkDrainMode::UntilEmpty).await
}

async fn drain_export_sinks_once(
    spool: &impl DurableSpool,
    config: &ExportWorkerConfig,
) -> Result<(), ExportDrainError> {
    drain_export_sinks_with_mode(
        spool,
        &config.agent_id,
        &config.sinks,
        SinkDrainMode::MaxBatches {
            max_batches: config.batches_per_sink_per_tick,
            sink_timeout: config.sink_timeout,
        },
    )
    .await
}

async fn drain_export_sinks_with_mode(
    spool: &impl DurableSpool,
    agent_id: &str,
    sinks: &[ExportSinkPlan],
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let mut failures = Vec::new();
    for sink in sinks {
        let result = match webhook_export_target_from_plan_sink(sink) {
            Ok(target) => drain_webhook_sink_with_mode(spool, agent_id, target, mode).await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            eprintln!("exporter sink {} failed: {error}", sink.id);
            failures.push(format!("{}: {error}", sink.id));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkDrainMode {
    UntilEmpty,
    MaxBatches {
        max_batches: u64,
        sink_timeout: Duration,
    },
}

impl SinkDrainMode {
    fn can_continue_after(self, batches: u64) -> bool {
        match self {
            Self::UntilEmpty => true,
            Self::MaxBatches { max_batches, .. } => batches < max_batches,
        }
    }

    fn sink_timeout(self) -> Option<Duration> {
        match self {
            Self::UntilEmpty => None,
            Self::MaxBatches { sink_timeout, .. } => Some(sink_timeout),
        }
    }
}

pub async fn drain_replay_webhook(
    spool: &impl DurableSpool,
    agent_id: &str,
    endpoint: String,
    codec: CompressionCodec,
) -> Result<(), ExportDrainError> {
    drain_webhook_sink(
        spool,
        agent_id,
        WebhookExportTarget::replay(endpoint, codec),
        SinkDrainMode::UntilEmpty,
    )
    .await
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookExportTarget {
    sink: String,
    endpoint: String,
    codec: CompressionCodec,
    headers: Vec<(String, String)>,
}

impl WebhookExportTarget {
    fn replay(endpoint: String, codec: CompressionCodec) -> Self {
        Self {
            sink: REPLAY_WEBHOOK_SINK.to_string(),
            endpoint,
            codec,
            headers: Vec::new(),
        }
    }
}

fn webhook_export_target_from_plan_sink(
    sink: &ExportSinkPlan,
) -> Result<WebhookExportTarget, ExportDrainError> {
    match sink.transport {
        ExporterTransport::Webhook => Ok(WebhookExportTarget {
            sink: sink.id.clone(),
            endpoint: sink.endpoint.clone(),
            codec: compression_codec_from_config(sink.codec),
            headers: sink
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        }),
        ExporterTransport::Grpc | ExporterTransport::Kafka | ExporterTransport::Otlp => {
            Err(ExportDrainError::UnsupportedTransport {
                transport: sink.transport,
            })
        }
    }
}

fn compression_codec_from_config(codec: CompressionCodecName) -> CompressionCodec {
    match codec {
        CompressionCodecName::None => CompressionCodec::None,
        CompressionCodecName::Zstd => CompressionCodec::Zstd,
        CompressionCodecName::Gzip => CompressionCodec::Gzip,
        CompressionCodecName::Deflate => CompressionCodec::Deflate,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportDrainSummary {
    batches: u64,
    committed_cursor: Option<u64>,
}

async fn drain_webhook_sink_with_mode(
    spool: &impl DurableSpool,
    agent_id: &str,
    target: WebhookExportTarget,
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let sink = target.sink.clone();
    match mode.sink_timeout() {
        Some(timeout) => {
            match tokio::time::timeout(timeout, drain_webhook_sink(spool, agent_id, target, mode))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(ExportDrainError::SinkTimedOut {
                    sink,
                    timeout_ms: duration_millis(timeout),
                }),
            }
        }
        None => drain_webhook_sink(spool, agent_id, target, mode).await,
    }
}

async fn drain_webhook_sink(
    spool: &impl DurableSpool,
    agent_id: &str,
    target: WebhookExportTarget,
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let WebhookExportTarget {
        sink,
        endpoint,
        codec,
        headers,
    } = target;
    let exporter = WebhookExporter::with_headers(endpoint, codec, headers)?;
    drain_export_sink(spool, agent_id, &sink, codec, mode, &exporter)
        .await
        .map(|_| ())
}

async fn drain_export_sink(
    spool: &impl DurableSpool,
    agent_id: &str,
    sink: &str,
    codec: CompressionCodec,
    mode: SinkDrainMode,
    exporter: &(impl ReliableExporter + ?Sized),
) -> Result<ExportDrainSummary, ExportDrainError> {
    let mut summary = ExportDrainSummary {
        batches: 0,
        committed_cursor: None,
    };

    loop {
        let events = spool.read_export_batch(sink, EXPORT_BATCH_LIMIT)?;
        let Some(last_sequence) = events.last().map(|event| event.sequence) else {
            return Ok(summary);
        };
        for event in &events {
            if event.payload.schema() != EVENT_ENVELOPE_JSON_SCHEMA {
                return Err(ExportDrainError::UnsupportedSpoolPayloadSchema {
                    sequence: event.sequence,
                    schema: event.payload.schema().to_string(),
                });
            }
        }

        let batch = BatchEnvelope::from_json_payloads(
            format!("{agent_id}:{sink}:{last_sequence}"),
            agent_id,
            codec.wire_name(),
            events
                .iter()
                .map(|event| (event.sequence, event.payload.bytes())),
        )?;
        let ack = exporter.send(&batch).await?;
        summary.batches = summary.batches.saturating_add(1);
        let committed_cursor = ack
            .committed_cursor
            .or_else(|| contiguous_cursor_from_event_ids(&batch, &ack.acked_event_ids));
        let Some(cursor) = committed_cursor else {
            println!(
                "exported sink {sink} batch {} without committed cursor; spool cursor unchanged",
                ack.batch_id
            );
            return Ok(summary);
        };

        spool.ack_export(sink, cursor)?;
        summary.committed_cursor = Some(cursor);
        println!(
            "exported sink {sink} batch {} and committed cursor {cursor}",
            ack.batch_id
        );
        if !mode.can_continue_after(summary.batches) {
            return Ok(summary);
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn contiguous_cursor_from_event_ids(
    batch: &BatchEnvelope,
    acked_event_ids: &[String],
) -> Option<u64> {
    let acked_event_ids = acked_event_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut cursor = None;
    for event in &batch.events {
        if acked_event_ids.contains(event.event_id.as_str()) {
            cursor = Some(event.sequence);
        } else {
            break;
        }
    }
    cursor
}

#[cfg(test)]
mod tests;

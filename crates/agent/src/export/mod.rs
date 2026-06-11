use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use exporter::{CompressionCodec, ReliableExporter, WebhookExporter, WebhookTlsConfig};
use probe_config::{CompressionCodecName, ExporterTransport, TlsMaterialKind};
use probe_core::SpoolPayloadSchema;
use proto::BatchEnvelope;
use runtime::{
    ExportPlan, ExportSinkPlan, ExportSinkTlsPlan, ExportTlsMaterialPlan, ExportWorkerPlan,
};
use storage::{DurableSpool, StoredEvent};
use thiserror::Error;
use tokio::sync::Notify;

use crate::tls_material::{TlsMaterialFileError, read_tls_material};

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
    #[error("TLS material {id} ({kind:?}) at {path}: {source}")]
    TlsMaterial {
        id: String,
        kind: TlsMaterialKind,
        path: PathBuf,
        source: TlsMaterialFileError,
    },
    #[error("client TLS identity requires at least one client certificate and one private key")]
    IncompleteClientTlsIdentity,
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
    failure_backoff: Duration,
}

impl ExportWorkerConfig {
    fn fixed_interval_bounded(
        agent_id: String,
        sinks: Vec<ExportSinkPlan>,
        interval: Duration,
        batches_per_sink_per_tick: u64,
        sink_timeout: Duration,
        failure_backoff: Duration,
    ) -> Self {
        Self {
            agent_id,
            sinks,
            interval,
            batches_per_sink_per_tick,
            sink_timeout,
            failure_backoff,
        }
    }

    pub fn from_export_plan(agent_id: String, plan: &ExportPlan) -> Option<Self> {
        match &plan.worker {
            ExportWorkerPlan::Disabled { .. } => None,
            ExportWorkerPlan::FixedIntervalBounded {
                interval_ms,
                batches_per_sink_per_tick,
                sink_timeout_ms,
                failure_backoff_ms,
            } => Some(Self::fixed_interval_bounded(
                agent_id,
                plan.sinks.clone(),
                Duration::from_millis(*interval_ms),
                *batches_per_sink_per_tick,
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
    S: DurableSpool + Send + Sync + 'static,
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
    backoff: &mut ExportWorkerBackoff,
) -> Result<(), ExportDrainError> {
    let mode = SinkDrainMode::MaxBatches {
        max_batches: config.batches_per_sink_per_tick,
        sink_timeout: config.sink_timeout,
    };
    let mut failures = Vec::new();
    for sink in &config.sinks {
        let now = Instant::now();
        if backoff.should_skip(&sink.id, now) {
            continue;
        }
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

async fn drain_export_sinks_with_mode(
    spool: &impl DurableSpool,
    agent_id: &str,
    sinks: &[ExportSinkPlan],
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let mut failures = Vec::new();
    for sink in sinks {
        let result = drain_export_sink_with_mode(spool, agent_id, sink, mode).await;
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

async fn drain_export_sink_with_mode(
    spool: &impl DurableSpool,
    agent_id: &str,
    sink: &ExportSinkPlan,
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    match webhook_export_target_from_plan_sink(sink) {
        Ok(target) => drain_webhook_sink_with_mode(spool, agent_id, target, mode).await,
        Err(error) => Err(error),
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
    tls: ExportSinkTlsPlan,
}

impl WebhookExportTarget {
    fn replay(endpoint: String, codec: CompressionCodec) -> Self {
        Self {
            sink: REPLAY_WEBHOOK_SINK.to_string(),
            endpoint,
            codec,
            headers: Vec::new(),
            tls: ExportSinkTlsPlan::default(),
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
            tls: sink.tls.clone(),
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
        tls,
    } = target;
    let first_events = spool.read_export_batch(&sink, EXPORT_BATCH_LIMIT)?;
    if first_events.is_empty() {
        return Ok(());
    }
    let Some(first_batch) = export_batch_from_events(agent_id, &sink, codec, first_events)? else {
        return Ok(());
    };
    let tls = webhook_tls_config_from_plan(&tls)?;
    let exporter = WebhookExporter::with_tls_config(endpoint, codec, headers, tls)?;
    drain_export_sink_from_batch(spool, agent_id, &sink, codec, mode, &exporter, first_batch)
        .await
        .map(|_| ())
}

fn webhook_tls_config_from_plan(
    plan: &ExportSinkTlsPlan,
) -> Result<WebhookTlsConfig, ExportDrainError> {
    let trust_anchor_pems = plan
        .trust_anchors
        .iter()
        .map(read_tls_material_for_export)
        .collect::<Result<Vec<_>, _>>()?;
    let identity_pem = match (
        plan.client_certificates.is_empty(),
        plan.client_private_key.as_ref(),
    ) {
        (true, None) => None,
        (false, Some(private_key)) => {
            let mut pem = Vec::new();
            for certificate in &plan.client_certificates {
                pem.extend(read_tls_material_for_export(certificate)?);
                pem.push(b'\n');
            }
            pem.extend(read_tls_material_for_export(private_key)?);
            Some(pem)
        }
        (true, Some(_)) | (false, None) => {
            return Err(ExportDrainError::IncompleteClientTlsIdentity);
        }
    };
    Ok(WebhookTlsConfig {
        trust_anchor_pems,
        identity_pem,
    })
}

fn read_tls_material_for_export(
    material: &ExportTlsMaterialPlan,
) -> Result<Vec<u8>, ExportDrainError> {
    read_tls_material(&material.path).map_err(|source| ExportDrainError::TlsMaterial {
        id: material.id.clone(),
        kind: material.kind,
        path: material.path.clone(),
        source,
    })
}

async fn drain_export_sink_from_batch(
    spool: &impl DurableSpool,
    agent_id: &str,
    sink: &str,
    codec: CompressionCodec,
    mode: SinkDrainMode,
    exporter: &(impl ReliableExporter + ?Sized),
    first_batch: BatchEnvelope,
) -> Result<ExportDrainSummary, ExportDrainError> {
    let mut summary = ExportDrainSummary {
        batches: 0,
        committed_cursor: None,
    };
    let mut next_batch = Some(first_batch);

    loop {
        let batch = match next_batch.take() {
            Some(batch) => batch,
            None => {
                let events = spool.read_export_batch(sink, EXPORT_BATCH_LIMIT)?;
                let Some(batch) = export_batch_from_events(agent_id, sink, codec, events)? else {
                    return Ok(summary);
                };
                batch
            }
        };
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

fn export_batch_from_events(
    agent_id: &str,
    sink: &str,
    codec: CompressionCodec,
    events: Vec<StoredEvent>,
) -> Result<Option<BatchEnvelope>, ExportDrainError> {
    let Some(last_sequence) = events.last().map(|event| event.sequence) else {
        return Ok(None);
    };
    for event in &events {
        if event.payload.schema() != &SpoolPayloadSchema::EventEnvelopeJsonV1 {
            return Err(ExportDrainError::UnsupportedSpoolPayloadSchema {
                sequence: event.sequence,
                schema: event.payload.schema_wire().to_string(),
            });
        }
    }

    BatchEnvelope::from_json_payloads(
        format!("{agent_id}:{sink}:{last_sequence}"),
        agent_id,
        codec.wire_name(),
        events
            .iter()
            .map(|event| (event.sequence, event.payload.bytes())),
    )
    .map(Some)
    .map_err(ExportDrainError::Proto)
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

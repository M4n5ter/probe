use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashSet, sync::Arc, time::Duration};

use exporter::{CompressionCodec, ReliableExporter, WebhookExporter};
use probe_config::{AgentConfig, CompressionCodecName, ExporterConfig, ExporterTransport};
use proto::{BatchEnvelope, EVENT_ENVELOPE_JSON_SCHEMA};
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
    exporters: Vec<ExporterConfig>,
    interval: Duration,
    batches_per_sink_per_tick: u64,
    sink_timeout: Duration,
}

impl ExportWorkerConfig {
    pub fn fixed_interval_bounded(
        agent_id: String,
        exporters: Vec<ExporterConfig>,
        interval: Duration,
        batches_per_sink_per_tick: u64,
        sink_timeout: Duration,
    ) -> Self {
        Self {
            agent_id,
            exporters,
            interval,
            batches_per_sink_per_tick,
            sink_timeout,
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

pub fn spawn_configured_export_worker<S>(
    spool: Arc<S>,
    config: ExportWorkerConfig,
) -> ExportWorkerHandle
where
    S: DurableSpool + Send + Sync + 'static,
{
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_notify = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_stop_notify = Arc::clone(&stop_notify);
    let task = tokio::spawn(async move {
        while !task_stop_requested.load(Ordering::Relaxed) {
            if let Err(error) = drain_configured_sinks_once(spool.as_ref(), &config).await {
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

pub async fn drain_configured_sinks(
    spool: &impl DurableSpool,
    config: &AgentConfig,
) -> Result<(), ExportDrainError> {
    drain_configured_sinks_with_mode(
        spool,
        &config.agent_id,
        &config.exporters,
        SinkDrainMode::UntilEmpty,
    )
    .await
}

async fn drain_configured_sinks_once(
    spool: &impl DurableSpool,
    config: &ExportWorkerConfig,
) -> Result<(), ExportDrainError> {
    drain_configured_sinks_with_mode(
        spool,
        &config.agent_id,
        &config.exporters,
        SinkDrainMode::MaxBatches {
            max_batches: config.batches_per_sink_per_tick,
            sink_timeout: config.sink_timeout,
        },
    )
    .await
}

async fn drain_configured_sinks_with_mode(
    spool: &impl DurableSpool,
    agent_id: &str,
    exporters: &[ExporterConfig],
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let mut failures = Vec::new();
    for exporter in exporters {
        let result = match webhook_export_target_from_config(exporter) {
            Ok(target) => drain_webhook_sink_with_mode(spool, agent_id, target, mode).await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            eprintln!("exporter sink {} failed: {error}", exporter.id);
            failures.push(format!("{}: {error}", exporter.id));
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

fn webhook_export_target_from_config(
    exporter: &ExporterConfig,
) -> Result<WebhookExportTarget, ExportDrainError> {
    match exporter.transport {
        ExporterTransport::Webhook => Ok(WebhookExportTarget {
            sink: exporter.id.clone(),
            endpoint: exporter.endpoint.clone(),
            codec: compression_codec_from_config(exporter.codec),
            headers: exporter
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        }),
        ExporterTransport::Grpc | ExporterTransport::Kafka | ExporterTransport::Otlp => {
            Err(ExportDrainError::UnsupportedTransport {
                transport: exporter.transport,
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
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::TcpListener,
        path::PathBuf,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use probe_core::{
        AddressPort, CaptureSource, EventEnvelope, EventKind, FlowContext, FlowIdentity,
        ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };
    use proto::{BATCH_SCHEMA_VERSION, EventRecord, PayloadFormat};
    use storage::FjallSpool;

    use super::*;

    #[test]
    fn acked_event_ids_advance_only_contiguous_cursor_prefix() {
        let batch = batch_with_events(["one", "two", "three"]);

        assert_eq!(
            contiguous_cursor_from_event_ids(&batch, &["one".to_string(), "two".to_string()]),
            Some(2)
        );
        assert_eq!(
            contiguous_cursor_from_event_ids(&batch, &["two".to_string(), "three".to_string()]),
            None
        );
    }

    #[tokio::test]
    async fn configured_exporters_use_independent_sinks_and_attempt_all()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-exporters");
        let spool = FjallSpool::open(&temp)?;
        append_export_event(&spool, 1)?;
        let failing = TestWebhookServer::spawn(false)?;
        let successful = TestWebhookServer::spawn(true)?;
        let config = AgentConfig {
            agent_id: "agent-1".to_string(),
            exporters: vec![
                ExporterConfig {
                    id: "failing".to_string(),
                    transport: ExporterTransport::Webhook,
                    endpoint: failing.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::new(),
                },
                ExporterConfig {
                    id: "successful".to_string(),
                    transport: ExporterTransport::Webhook,
                    endpoint: successful.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
                },
            ],
            ..AgentConfig::default()
        };
        config.validate_basic()?;

        let result = drain_configured_sinks(&spool, &config).await;

        assert!(matches!(
            result,
            Err(ExportDrainError::MultipleSinksFailed { .. })
        ));
        assert_eq!(spool.export_cursor("failing")?, 0);
        assert_eq!(spool.export_cursor("successful")?, 1);

        let request = successful.join()?;
        assert_eq!(
            request_header(&request, "x-probe-node").as_deref(),
            Some("node-a")
        );
        assert_eq!(
            request_header(&request, "x-sssa-codec").as_deref(),
            Some("none")
        );
        assert_eq!(
            request_header(&request, "idempotency-key").as_deref(),
            Some("agent-1:successful:1")
        );
        let _ = failing.join()?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn configured_export_worker_drains_until_stopped()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-export-worker");
        let spool = Arc::new(FjallSpool::open(&temp)?);
        append_export_event(spool.as_ref(), 1)?;
        let server = TestWebhookServer::spawn_accepting(true, 2)?;
        let config = ExportWorkerConfig::fixed_interval_bounded(
            "agent-1".to_string(),
            vec![ExporterConfig {
                id: "worker".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: server.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
            }],
            Duration::from_millis(10),
            1,
            Duration::from_secs(10),
        );

        let worker = spawn_configured_export_worker(Arc::clone(&spool), config);
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

    fn batch_with_events<const N: usize>(event_ids: [&str; N]) -> BatchEnvelope {
        BatchEnvelope {
            batch_id: "batch-1".to_string(),
            agent_id: "agent-1".to_string(),
            codec: "none".to_string(),
            events: event_ids
                .into_iter()
                .enumerate()
                .map(|(index, event_id)| EventRecord {
                    event_id: event_id.to_string(),
                    sequence: (index + 1) as u64,
                    payload_format: PayloadFormat::Json as i32,
                    payload: Vec::new(),
                    payload_schema: "test.schema".to_string(),
                })
                .collect(),
            schema_version: BATCH_SCHEMA_VERSION,
        }
    }

    fn append_export_event(
        spool: &FjallSpool,
        monotonic_ns: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let envelope = EventEnvelope::new(
            current_timestamp(monotonic_ns),
            replay_flow(),
            CaptureSource::Replay,
            "test",
            EventKind::ConnectionOpened,
        );
        let payload = serde_json::to_vec(&envelope)?;
        spool.append_export(storage::SpoolPayload::new(
            EVENT_ENVELOPE_JSON_SCHEMA,
            payload,
        ))?;
        Ok(())
    }

    fn current_timestamp(monotonic_ns: u64) -> Timestamp {
        Timestamp {
            monotonic_ns,
            wall_time_unix_ns: 1,
        }
    }

    fn replay_flow() -> FlowContext {
        let process = synthetic_replay_process();
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process.identity,
                &local,
                &remote,
                TransportProtocol::Tcp,
                0,
                None,
            ),
            process,
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 0,
            socket_cookie: None,
            attribution_confidence: 0,
        }
    }

    fn synthetic_replay_process() -> ProcessContext {
        let identity = ProcessIdentity {
            pid: 0,
            tgid: 0,
            start_time_ticks: 0,
            boot_id: "replay".to_string(),
            exe_path: "replay".to_string(),
            cmdline_hash: "replay".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        ProcessContext {
            identity,
            name: "replay".to_string(),
            cmdline: vec!["replay".to_string()],
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("sssa-probe-{name}-{}-{nanos}", std::process::id()))
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

    struct TestWebhookServer {
        endpoint: String,
        requests: Arc<Mutex<Vec<String>>>,
        handle: thread::JoinHandle<Result<(), String>>,
    }

    impl TestWebhookServer {
        fn spawn(accepted: bool) -> Result<Self, Box<dyn std::error::Error>> {
            Self::spawn_accepting(accepted, 1)
        }

        fn spawn_accepting(
            accepted: bool,
            request_count: usize,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let endpoint = format!("http://{}/batches", listener.local_addr()?);
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                for _ in 0..request_count {
                    let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
                    let mut bytes = Vec::new();
                    loop {
                        let mut buffer = [0; 1024];
                        let read = stream
                            .read(&mut buffer)
                            .map_err(|error| error.to_string())?;
                        if read == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&buffer[..read]);
                        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request_text = String::from_utf8_lossy(&bytes).into_owned();
                    let batch_id = request_header(&request_text, "idempotency-key")
                        .unwrap_or_else(|| "missing-batch".to_string());
                    let acked_cursor = accepted.then(|| cursor_from_batch_id(&batch_id));
                    let body = serde_json::json!({
                        "batch_id": batch_id,
                        "accepted": accepted,
                        "acked_cursor": acked_cursor,
                        "acked_event_ids": [],
                        "retryable_event_ids": [],
                        "reason": if accepted { None::<String> } else { Some("failed".to_string()) },
                    })
                    .to_string();
                    let status = if accepted {
                        "200 OK"
                    } else {
                        "500 Internal Server Error"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .map_err(|error| error.to_string())?;
                    requests_for_thread
                        .lock()
                        .map_err(|_| "request lock poisoned".to_string())?
                        .push(request_text);
                }
                Ok(())
            });
            Ok(Self {
                endpoint,
                requests,
                handle,
            })
        }

        fn endpoint(&self) -> String {
            self.endpoint.clone()
        }

        fn join(self) -> Result<String, Box<dyn std::error::Error>> {
            let mut requests = self.join_requests()?;
            if requests.len() != 1 {
                return Err(format!(
                    "webhook server captured {} requests; expected 1",
                    requests.len()
                )
                .into());
            }
            Ok(requests.remove(0))
        }

        fn join_requests(self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
            self.handle
                .join()
                .map_err(|_| "webhook server thread panicked")?
                .map_err(|error| format!("webhook server failed: {error}"))?;
            let requests = self
                .requests
                .lock()
                .map_err(|_| "request lock poisoned")?
                .clone();
            if requests.is_empty() {
                Err("webhook server did not capture a request".into())
            } else {
                Ok(requests)
            }
        }
    }

    fn cursor_from_batch_id(batch_id: &str) -> u64 {
        batch_id
            .rsplit(':')
            .next()
            .and_then(|sequence| sequence.parse().ok())
            .unwrap_or(0)
    }

    fn request_header(request: &str, name: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }
}

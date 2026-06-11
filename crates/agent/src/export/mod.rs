use std::collections::HashSet;

use exporter::{CompressionCodec, ReliableExporter, WebhookExporter};
use probe_config::{AgentConfig, CompressionCodecName, ExporterConfig, ExporterTransport};
use proto::{BatchEnvelope, EVENT_ENVELOPE_JSON_SCHEMA};
use storage::DurableSpool;
use thiserror::Error;

const EXPORT_BATCH_LIMIT: usize = 1024;
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
}

pub async fn drain_configured_sinks(
    spool: &impl DurableSpool,
    config: &AgentConfig,
) -> Result<(), ExportDrainError> {
    let mut failures = Vec::new();
    for exporter in &config.exporters {
        let result = match webhook_export_target_from_config(exporter) {
            Ok(target) => drain_webhook_sink(spool, &config.agent_id, target).await,
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

async fn drain_webhook_sink(
    spool: &impl DurableSpool,
    agent_id: &str,
    target: WebhookExportTarget,
) -> Result<(), ExportDrainError> {
    let WebhookExportTarget {
        sink,
        endpoint,
        codec,
        headers,
    } = target;
    let exporter = WebhookExporter::with_headers(endpoint, codec, headers)?;
    drain_export_sink(spool, agent_id, &sink, codec, &exporter)
        .await
        .map(|_| ())
}

async fn drain_export_sink(
    spool: &impl DurableSpool,
    agent_id: &str,
    sink: &str,
    codec: CompressionCodec,
    exporter: &(impl ReliableExporter + ?Sized),
) -> Result<ExportDrainSummary, ExportDrainError> {
    let mut summary = ExportDrainSummary {
        batches: 0,
        committed_cursor: None,
    };

    loop {
        let events = spool.read_export_batch(sink, EXPORT_BATCH_LIMIT)?;
        let Some(last_sequence) = events.last().map(|event| event.sequence) else {
            if summary.batches == 0 {
                println!("no spooled events to export for sink {sink}");
            }
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
    }
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
        time::{SystemTime, UNIX_EPOCH},
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

    struct TestWebhookServer {
        endpoint: String,
        request: Arc<Mutex<Option<String>>>,
        handle: thread::JoinHandle<Result<(), String>>,
    }

    impl TestWebhookServer {
        fn spawn(accepted: bool) -> Result<Self, Box<dyn std::error::Error>> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let endpoint = format!("http://{}/batches", listener.local_addr()?);
            let request = Arc::new(Mutex::new(None));
            let request_for_thread = Arc::clone(&request);
            let handle = thread::spawn(move || {
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
                let body = serde_json::json!({
                    "batch_id": batch_id,
                    "accepted": accepted,
                    "acked_cursor": if accepted { Some(1_u64) } else { None },
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
                *request_for_thread
                    .lock()
                    .map_err(|_| "request lock poisoned".to_string())? = Some(request_text);
                Ok(())
            });
            Ok(Self {
                endpoint,
                request,
                handle,
            })
        }

        fn endpoint(&self) -> String {
            self.endpoint.clone()
        }

        fn join(self) -> Result<String, Box<dyn std::error::Error>> {
            self.handle
                .join()
                .map_err(|_| "webhook server thread panicked")?
                .map_err(|error| format!("webhook server failed: {error}"))?;
            self.request
                .lock()
                .map_err(|_| "request lock poisoned")?
                .clone()
                .ok_or_else(|| "webhook server did not capture a request".into())
        }
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

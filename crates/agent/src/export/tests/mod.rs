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

use probe_config::{AgentConfig, ExportWorkerScheduleConfig, ExporterConfig};
use probe_core::{
    AddressPort, CapabilityKind, CapabilityState, CaptureSource, EventEnvelope, EventKind,
    FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
};
use proto::{BATCH_SCHEMA_VERSION, EventRecord, PayloadFormat};
use runtime::{ProviderRegistry, RuntimePlan};
use storage::{DurableSpool, FjallSpool, SpoolPayload, StorageError, StoredEvent};

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
async fn planned_export_sinks_use_independent_cursors_and_attempt_all()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("planned-export-sinks");
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
    let plan = runtime_plan(config)?;

    let result = drain_planned_sinks(&spool, &plan.config.agent_id, &plan.export).await;

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
async fn export_worker_drains_until_stopped() -> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("planned-export-worker");
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
        }],
        ..AgentConfig::default()
    };
    config.export.worker.schedule = ExportWorkerScheduleConfig::FixedIntervalBounded {
        interval_ms: 10,
        batches_per_sink_per_tick: 1,
        sink_timeout_ms: 5_000,
    };
    config.validate_basic()?;
    let plan = runtime_plan(config)?;
    let config = ExportWorkerConfig::from_export_plan(plan.config.agent_id.clone(), &plan.export)
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
        },
        sinks: vec![ExportSinkPlan {
            id: "budget".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: server.endpoint(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
        }],
    };
    let config = ExportWorkerConfig::from_export_plan("agent-1".to_string(), &plan)
        .expect("worker should be enabled");

    let worker = spawn_export_worker(Arc::clone(&spool), config);
    wait_for_memory_export_cursor(spool.as_ref(), 2).await?;
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
        CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
        CapabilityState::available(CapabilityKind::DryRunEnforcement),
    ]
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

async fn wait_for_memory_export_cursor(
    spool: &SingleEventBatchSpool,
    expected_cursor: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..50 {
        let cursor = spool.export_cursor("budget")?;
        if cursor >= expected_cursor {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!(
        "memory export cursor did not reach {expected_cursor}; current cursor is {}",
        spool.export_cursor("budget")?
    )
    .into())
}

struct SingleEventBatchSpool {
    events: Mutex<Vec<StoredEvent>>,
    cursor: Mutex<u64>,
}

impl SingleEventBatchSpool {
    fn with_export_events(count: u64) -> Result<Self, serde_json::Error> {
        let events = (1..=count)
            .map(|sequence| {
                let payload = export_event_payload(sequence)?;
                Ok(StoredEvent { sequence, payload })
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()?;
        Ok(Self {
            events: Mutex::new(events),
            cursor: Mutex::new(0),
        })
    }
}

impl DurableSpool for SingleEventBatchSpool {
    fn append_ingress(&self, _payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        unimplemented!("export worker tests do not append ingress events")
    }

    fn read_ingress_batch(
        &self,
        _consumer: &str,
        _limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        unimplemented!("export worker tests do not read ingress events")
    }

    fn ack_ingress(&self, _consumer: &str, _sequence: u64) -> Result<(), StorageError> {
        unimplemented!("export worker tests do not ack ingress events")
    }

    fn ingress_cursor(&self, _consumer: &str) -> Result<u64, StorageError> {
        unimplemented!("export worker tests do not inspect ingress cursors")
    }

    fn append_export(&self, _payload: SpoolPayload) -> Result<StoredEvent, StorageError> {
        unimplemented!("export worker tests seed export events directly")
    }

    fn read_export_batch(
        &self,
        _sink: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let cursor = *self
            .cursor
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })?;
        let events = self
            .events
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })?;
        Ok(events
            .iter()
            .find(|event| event.sequence > cursor)
            .cloned()
            .into_iter()
            .collect())
    }

    fn ack_export(&self, _sink: &str, sequence: u64) -> Result<(), StorageError> {
        let last_sequence = self
            .events
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })?
            .last()
            .map_or(0, |event| event.sequence);
        if sequence > last_sequence {
            return Err(StorageError::AckBeyondLastSequence {
                sink: "budget".to_string(),
                sequence,
                last_sequence,
            });
        }
        let mut cursor = self
            .cursor
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })?;
        *cursor = (*cursor).max(sequence);
        Ok(())
    }

    fn export_cursor(&self, _sink: &str) -> Result<u64, StorageError> {
        self.cursor
            .lock()
            .map(|cursor| *cursor)
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })
    }
}

fn export_event_payload(sequence: u64) -> Result<SpoolPayload, serde_json::Error> {
    let envelope = EventEnvelope::new(
        current_timestamp(sequence),
        replay_flow(),
        CaptureSource::Replay,
        "test",
        EventKind::ConnectionOpened,
    );
    serde_json::to_vec(&envelope)
        .map(|payload| SpoolPayload::new(EVENT_ENVELOPE_JSON_SCHEMA, payload))
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

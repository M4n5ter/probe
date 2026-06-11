use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use probe_config::AgentConfig;
use probe_core::{
    AddressPort, CapabilityKind, CapabilityState, CaptureSource, EventEnvelope, EventKind,
    FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
};
use proto::{
    BATCH_SCHEMA_VERSION, BatchEnvelope, EVENT_ENVELOPE_JSON_SCHEMA, EventRecord, PayloadFormat,
};
use runtime::{self, ProviderRegistry, RuntimePlan};
use storage::{DurableSpool, FjallSpool, SpoolPayload, StorageError, StoredEvent};

pub(super) fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
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

pub(super) fn batch_with_events<const N: usize>(event_ids: [&str; N]) -> BatchEnvelope {
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

pub(super) fn append_export_event(
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

pub(super) fn test_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("sssa-probe-{name}-{}-{nanos}", std::process::id()))
}

pub(super) async fn wait_for_export_cursor(
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

pub(super) async fn wait_for_memory_export_cursor(
    spool: &SingleEventBatchSpool,
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
        "memory export cursor for {sink} did not reach {expected_cursor}; current cursor is {}",
        spool.export_cursor(sink)?
    )
    .into())
}

pub(super) struct SingleEventBatchSpool {
    events: Mutex<Vec<StoredEvent>>,
    cursors: Mutex<BTreeMap<String, u64>>,
}

impl SingleEventBatchSpool {
    pub(super) fn with_export_events(count: u64) -> Result<Self, serde_json::Error> {
        let events = (1..=count)
            .map(|sequence| {
                let payload = export_event_payload(sequence)?;
                Ok(StoredEvent { sequence, payload })
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()?;
        Ok(Self {
            events: Mutex::new(events),
            cursors: Mutex::new(BTreeMap::new()),
        })
    }

    pub(super) fn with_export_payload(payload: SpoolPayload) -> Self {
        Self {
            events: Mutex::new(vec![StoredEvent {
                sequence: 1,
                payload,
            }]),
            cursors: Mutex::new(BTreeMap::new()),
        }
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
        sink: &str,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let cursor = self
            .cursors
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })?
            .get(sink)
            .copied()
            .unwrap_or(0);
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

    fn ack_export(&self, sink: &str, sequence: u64) -> Result<(), StorageError> {
        let last_sequence = self
            .events
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })?
            .last()
            .map_or(0, |event| event.sequence);
        if sequence > last_sequence {
            return Err(StorageError::AckBeyondLastSequence {
                sink: sink.to_string(),
                sequence,
                last_sequence,
            });
        }
        let mut cursors = self
            .cursors
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })?;
        let cursor = cursors.entry(sink.to_string()).or_default();
        *cursor = (*cursor).max(sequence);
        Ok(())
    }

    fn export_cursor(&self, sink: &str) -> Result<u64, StorageError> {
        self.cursors
            .lock()
            .map(|cursors| cursors.get(sink).copied().unwrap_or(0))
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

pub(super) struct TestWebhookServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop_requested: Arc<AtomicBool>,
    handle: thread::JoinHandle<Result<(), String>>,
}

impl TestWebhookServer {
    pub(super) fn spawn(accepted: bool) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_accepting(accepted, 1)
    }

    pub(super) fn spawn_accepting(
        accepted: bool,
        request_count: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_limit(accepted, request_count)
    }

    pub(super) fn spawn_recording(accepted: bool) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_limit(accepted, usize::MAX)
    }

    fn spawn_with_limit(
        accepted: bool,
        request_count: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}/batches", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_requested_for_thread = Arc::clone(&stop_requested);
        let handle = thread::spawn(move || {
            while requests_for_thread
                .lock()
                .map_err(|_| "request lock poisoned".to_string())?
                .len()
                < request_count
            {
                if stop_requested_for_thread.load(Ordering::Relaxed) {
                    break;
                }
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
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
            stop_requested,
            handle,
        })
    }

    pub(super) fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    pub(super) fn join(self) -> Result<String, Box<dyn std::error::Error>> {
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

    pub(super) fn join_requests(self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        self.stop_requested.store(true, Ordering::Relaxed);
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

pub(super) fn request_header(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

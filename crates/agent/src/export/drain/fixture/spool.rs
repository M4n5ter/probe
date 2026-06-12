use std::{collections::BTreeMap, sync::Mutex, time::Duration};

use probe_core::{
    AddressPort, CaptureSource, EventEnvelope, EventKind, FlowContext, FlowIdentity,
    ProcessContext, ProcessIdentity, SpoolPayloadSchema, Timestamp, TransportProtocol,
};
use storage::{ExportSpool, FjallSpool, SpoolPayload, StorageError, StoredEvent};

pub(in crate::export::drain) fn append_export_event(
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
        SpoolPayloadSchema::EventEnvelopeJson,
        payload,
    ))?;
    Ok(())
}

pub(in crate::export::drain) async fn wait_for_export_cursor(
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

pub(in crate::export::drain) async fn wait_for_memory_export_cursor(
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

pub(in crate::export::drain) struct SingleEventBatchSpool {
    events: Mutex<Vec<StoredEvent>>,
    cursors: Mutex<BTreeMap<String, u64>>,
    last_sequence: u64,
}

impl SingleEventBatchSpool {
    pub(in crate::export::drain) fn with_export_events(
        count: u64,
    ) -> Result<Self, serde_json::Error> {
        let events = (1..=count)
            .map(|sequence| {
                let payload = export_event_payload(sequence)?;
                Ok(StoredEvent { sequence, payload })
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()?;
        Ok(Self {
            events: Mutex::new(events),
            cursors: Mutex::new(BTreeMap::new()),
            last_sequence: count,
        })
    }

    pub(in crate::export::drain) fn with_export_payload(payload: SpoolPayload) -> Self {
        Self {
            events: Mutex::new(vec![StoredEvent {
                sequence: 1,
                payload,
            }]),
            cursors: Mutex::new(BTreeMap::new()),
            last_sequence: 1,
        }
    }
}

impl ExportSpool for SingleEventBatchSpool {
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
        if sequence > self.last_sequence {
            return Err(StorageError::AckBeyondLastSequence {
                sink: sink.to_string(),
                sequence,
                last_sequence: self.last_sequence,
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

    fn prune_export_through(&self, sequence: u64, limit: usize) -> Result<u64, StorageError> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| StorageError::SequenceLockPoisoned { lane: "export" })?;
        let mut removed = 0;
        events.retain(|event| {
            if event.sequence <= sequence && removed < limit {
                removed += 1;
                false
            } else {
                true
            }
        });
        Ok(removed as u64)
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
        .map(|payload| SpoolPayload::new(SpoolPayloadSchema::EventEnvelopeJson, payload))
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

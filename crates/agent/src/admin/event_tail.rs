use probe_core::{EventEnvelope, Selector, SpoolPayloadSchema};
use serde::{Deserialize, Serialize};
use storage::{FjallSpool, StoredEvent};
use thiserror::Error;

const MAX_TAIL_LIMIT: usize = 256;
const MAX_TAIL_SCAN: usize = 2_048;
const MAX_TAIL_EVENT_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_TAIL_RESPONSE_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const SELECTOR_SCAN_MULTIPLIER: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EventTailRequest {
    pub(super) after_sequence: u64,
    pub(super) limit: usize,
    pub(super) selector: Option<Selector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailSnapshot {
    pub after_sequence: u64,
    pub next_after_sequence: u64,
    pub last_export_sequence: u64,
    pub limit: usize,
    pub scanned: usize,
    pub budget: EventTailBudgetSnapshot,
    pub events: Vec<EventTailRecord>,
    pub omissions: Vec<EventTailOmission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailRecord {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub event: EventEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailBudgetSnapshot {
    pub max_event_payload_bytes: usize,
    pub max_response_payload_bytes: usize,
    pub included_payload_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailOmission {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub payload_schema: String,
    pub payload_bytes: usize,
    pub reason: EventTailOmissionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventTailOmissionReason {
    EventTooLarge,
    ResponseBudgetExceeded,
}

impl EventTailOmissionReason {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::EventTooLarge => "event too large",
            Self::ResponseBudgetExceeded => "response budget exceeded",
        }
    }
}

pub(super) fn read_event_tail(
    spool: &FjallSpool,
    request: EventTailRequest,
) -> Result<EventTailSnapshot, EventTailError> {
    let limit = normalize_limit(request.limit);
    let scan_limit = scan_limit(limit, request.selector.is_some());
    let selector = request
        .selector
        .as_ref()
        .map(Selector::compile)
        .transpose()
        .map_err(EventTailError::Selector)?;
    let stored = spool.read_export_batch_after(request.after_sequence, scan_limit)?;
    let last_export_sequence = spool.snapshot()?.last_export_sequence;
    let mut next_after_sequence = request.after_sequence;
    let mut events = Vec::new();
    let mut omissions = Vec::new();
    let mut included_payload_bytes = 0_usize;
    let mut truncated = false;
    let mut scanned = 0;

    for stored_event in stored {
        scanned += 1;
        next_after_sequence = stored_event.sequence;
        let payload_bytes = stored_event.payload.bytes().len();
        if payload_bytes > MAX_TAIL_EVENT_PAYLOAD_BYTES {
            if selector.is_none() {
                omissions.push(omission_for(
                    &stored_event,
                    EventTailOmissionReason::EventTooLarge,
                ));
            }
            continue;
        }
        let record = decode_tail_record(stored_event)?;
        if selector
            .as_ref()
            .is_none_or(|selector| selector.matches_event(&record.event))
        {
            if included_payload_bytes.saturating_add(payload_bytes)
                > MAX_TAIL_RESPONSE_PAYLOAD_BYTES
            {
                omissions.push(EventTailOmission {
                    sequence: record.sequence,
                    stored_at_unix_ns: record.stored_at_unix_ns,
                    payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON
                        .to_string(),
                    payload_bytes,
                    reason: EventTailOmissionReason::ResponseBudgetExceeded,
                });
                truncated = true;
                break;
            }
            included_payload_bytes = included_payload_bytes.saturating_add(payload_bytes);
            events.push(record);
        }
        if events.len() >= limit {
            break;
        }
    }

    Ok(EventTailSnapshot {
        after_sequence: request.after_sequence,
        next_after_sequence,
        last_export_sequence,
        limit,
        scanned,
        budget: EventTailBudgetSnapshot {
            max_event_payload_bytes: MAX_TAIL_EVENT_PAYLOAD_BYTES,
            max_response_payload_bytes: MAX_TAIL_RESPONSE_PAYLOAD_BYTES,
            included_payload_bytes,
            truncated,
        },
        events,
        omissions,
    })
}

fn normalize_limit(limit: usize) -> usize {
    limit.clamp(1, MAX_TAIL_LIMIT)
}

fn scan_limit(limit: usize, filtered: bool) -> usize {
    if filtered {
        limit
            .saturating_mul(SELECTOR_SCAN_MULTIPLIER)
            .clamp(limit, MAX_TAIL_SCAN)
    } else {
        limit
    }
}

fn decode_tail_record(stored: StoredEvent) -> Result<EventTailRecord, EventTailError> {
    let schema = stored.payload.schema();
    if schema != &SpoolPayloadSchema::EventEnvelopeSubjectOriginJson {
        return Err(EventTailError::UnexpectedSchema {
            sequence: stored.sequence,
            expected: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON,
            actual: schema.to_string(),
        });
    }
    let event = serde_json::from_slice(stored.payload.bytes())?;
    Ok(EventTailRecord {
        sequence: stored.sequence,
        stored_at_unix_ns: stored.stored_at_unix_ns,
        event,
    })
}

fn omission_for(stored: &StoredEvent, reason: EventTailOmissionReason) -> EventTailOmission {
    EventTailOmission {
        sequence: stored.sequence,
        stored_at_unix_ns: stored.stored_at_unix_ns,
        payload_schema: stored.payload.schema().to_string(),
        payload_bytes: stored.payload.bytes().len(),
        reason,
    }
}

#[derive(Debug, Error)]
pub(super) enum EventTailError {
    #[error("invalid event tail selector: {0}")]
    Selector(probe_core::SelectorError),
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
    #[error(
        "unexpected export payload schema at sequence {sequence}: expected {expected}, got {actual}"
    )]
    UnexpectedSchema {
        sequence: u64,
        expected: &'static str,
        actual: String,
    },
    #[error("failed to decode event envelope: {0}")]
    EventJson(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use pipeline::ExportEventWriter;
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity, ProcessSelector,
        SelectorTerm, Timestamp, TrafficSelector, TransportProtocol,
    };
    use storage::SpoolPayload;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn tail_events_filters_by_process_selector_without_advancing_export_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;
        ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/nginx"))?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                limit: 16,
                selector: Some(exe_selector("/usr/bin/nginx")),
            },
        )?;

        assert_eq!(tail.scanned, 2);
        assert_eq!(tail.next_after_sequence, 2);
        assert_eq!(tail.events.len(), 1);
        assert_eq!(
            tail.events[0]
                .event
                .flow()
                .expect("flow event")
                .process
                .identity
                .exe_path,
            "/usr/bin/nginx"
        );
        assert_eq!(spool.export_cursor("webhook")?, 0);
        Ok(())
    }

    #[test]
    fn tail_events_clamps_zero_limit_to_one() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;
        ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/nginx"))?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                limit: 0,
                selector: None,
            },
        )?;

        assert_eq!(tail.limit, 1);
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.next_after_sequence, 1);
        Ok(())
    }

    #[test]
    fn tail_events_omits_oversized_event_without_decoding_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let oversized = vec![b'x'; MAX_TAIL_EVENT_PAYLOAD_BYTES + 1];
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            oversized,
        ))?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                limit: 16,
                selector: None,
            },
        )?;

        assert_eq!(tail.next_after_sequence, 1);
        assert!(tail.events.is_empty());
        assert_eq!(tail.omissions.len(), 1);
        assert_eq!(
            tail.omissions[0].reason,
            EventTailOmissionReason::EventTooLarge
        );
        assert_eq!(
            tail.omissions[0].payload_bytes,
            MAX_TAIL_EVENT_PAYLOAD_BYTES + 1
        );
        Ok(())
    }

    #[test]
    fn filtered_tail_skips_oversized_event_without_leaking_omission_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let oversized = vec![b'x'; MAX_TAIL_EVENT_PAYLOAD_BYTES + 1];
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            oversized,
        ))?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                limit: 16,
                selector: Some(exe_selector("/usr/bin/curl")),
            },
        )?;

        assert_eq!(tail.next_after_sequence, 1);
        assert!(tail.events.is_empty());
        assert!(tail.omissions.is_empty());
        Ok(())
    }

    fn exe_selector(exe_path: &str) -> Selector {
        Selector::Match {
            term: Box::new(SelectorTerm {
                process: ProcessSelector {
                    exe_path_globs: vec![exe_path.to_string()],
                    ..ProcessSelector::default()
                },
                traffic: TrafficSelector::default(),
            }),
        }
    }

    fn event_for_exe(exe_path: &str) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow_for_exe(exe_path),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn flow_for_exe(exe_path: &str) -> FlowContext {
        let process = ProcessContext {
            identity: ProcessIdentity {
                pid: 42,
                tgid: 42,
                start_time_ticks: 7,
                boot_id: "boot".to_string(),
                exe_path: exe_path.to_string(),
                cmdline_hash: "hash".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: exe_path.rsplit('/').next().unwrap_or("process").to_string(),
            cmdline: Vec::new(),
        };
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
                1,
                None,
            ),
            process,
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

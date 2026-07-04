use probe_core::{
    CaptureSource, CompiledSelector, EventEnvelope, EventType, Selector, SpoolPayloadSchema,
};
use serde::{Deserialize, Serialize};
use storage::{FjallSpool, StoredEvent};
use thiserror::Error;

const MAX_TAIL_LIMIT: usize = 256;
const MAX_TAIL_SCAN: usize = 2_048;
const MAX_TAIL_EVENT_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_TAIL_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENT_DETAIL_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const SELECTOR_SCAN_MULTIPLIER: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EventTailRequest {
    pub(super) after_sequence: u64,
    pub(super) latest: bool,
    pub(super) limit: usize,
    pub(super) selector: Option<Selector>,
    pub(super) attribution_mode: EventTailAttributionMode,
    pub(super) event_types: Vec<EventType>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventTailAttributionMode {
    #[default]
    Strict,
    IncludeUnknownProcess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailSnapshot {
    pub after_sequence: u64,
    pub next_after_sequence: u64,
    pub last_export_sequence: u64,
    pub attribution_mode: EventTailAttributionMode,
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
pub(crate) struct EventDetailSnapshot {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub payload_schema: String,
    pub payload_bytes: usize,
    pub event: EventEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventDetailTooLargeSnapshot {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub payload_schema: String,
    pub payload_bytes: usize,
    pub max_payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventTailBudgetSnapshot {
    pub max_event_payload_bytes: usize,
    pub max_record_bytes: usize,
    pub included_record_bytes: usize,
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
    let filtered = request.selector.is_some() || !request.event_types.is_empty();
    let scan_limit = scan_limit(limit, filtered);
    let selector = request
        .selector
        .as_ref()
        .map(Selector::compile)
        .transpose()
        .map_err(EventTailError::Selector)?;
    let event_type_filter = EventTypeFilter::new(&request.event_types);
    let last_export_sequence = spool.snapshot()?.last_export_sequence;
    let after_sequence = effective_after_sequence(&request, scan_limit, last_export_sequence);
    let stored = spool.read_export_batch_after(after_sequence, scan_limit)?;
    let mut next_after_sequence = after_sequence;
    let mut events = Vec::new();
    let mut omissions = Vec::new();
    let mut included_record_bytes = 0_usize;
    let mut truncated = false;
    let mut scanned = 0;

    for stored_event in stored {
        scanned += 1;
        next_after_sequence = stored_event.sequence;
        let payload_bytes = stored_event.payload.bytes().len();
        if payload_bytes > MAX_TAIL_EVENT_PAYLOAD_BYTES {
            if !filtered {
                omissions.push(omission_for(
                    &stored_event,
                    EventTailOmissionReason::EventTooLarge,
                ));
            }
            continue;
        }
        let payload_schema = stored_event.payload.schema().to_string();
        let record = decode_tail_record(stored_event)?;
        if event_type_filter.matches(&record.event)
            && selector.as_ref().is_none_or(|selector| {
                selector_matches_event(selector, &record.event, request.attribution_mode)
            })
        {
            let record_bytes = tail_record_budget_bytes(&record)?;
            if included_record_bytes.saturating_add(record_bytes) > MAX_TAIL_RECORD_BYTES {
                omissions.push(EventTailOmission {
                    sequence: record.sequence,
                    stored_at_unix_ns: record.stored_at_unix_ns,
                    payload_schema,
                    payload_bytes,
                    reason: EventTailOmissionReason::ResponseBudgetExceeded,
                });
                truncated = true;
                break;
            }
            included_record_bytes = included_record_bytes.saturating_add(record_bytes);
            events.push(record);
        }
        if events.len() >= limit {
            break;
        }
    }

    Ok(EventTailSnapshot {
        after_sequence,
        next_after_sequence,
        last_export_sequence,
        attribution_mode: request.attribution_mode,
        limit,
        scanned,
        budget: EventTailBudgetSnapshot {
            max_event_payload_bytes: MAX_TAIL_EVENT_PAYLOAD_BYTES,
            max_record_bytes: MAX_TAIL_RECORD_BYTES,
            included_record_bytes,
            truncated,
        },
        events,
        omissions,
    })
}

fn tail_record_budget_bytes(record: &EventTailRecord) -> Result<usize, EventTailError> {
    Ok(serde_json::to_vec(record)?.len())
}

fn selector_matches_event(
    selector: &CompiledSelector,
    event: &EventEnvelope,
    mode: EventTailAttributionMode,
) -> bool {
    selector.matches_event(event)
        || (mode == EventTailAttributionMode::IncludeUnknownProcess
            && is_libpcap_unknown_process_event(event)
            && selector.matches_event_with_unknown_process(event))
}

fn is_libpcap_unknown_process_event(event: &EventEnvelope) -> bool {
    event.origin().source() == CaptureSource::Libpcap
        && event.flow().is_some_and(|flow| {
            flow.attribution_confidence == 0
                && flow.process.identity.pid == 0
                && flow.process.identity.exe_path == "unknown"
                && flow.process.identity.runtime_hint.as_deref() == Some("libpcap_fallback")
        })
}

fn effective_after_sequence(
    request: &EventTailRequest,
    scan_limit: usize,
    last_export_sequence: u64,
) -> u64 {
    if request.latest {
        last_export_sequence.saturating_sub(scan_limit as u64)
    } else {
        request.after_sequence
    }
}

struct EventTypeFilter<'a> {
    event_types: &'a [EventType],
}

impl<'a> EventTypeFilter<'a> {
    fn new(event_types: &'a [EventType]) -> Self {
        Self { event_types }
    }

    fn matches(&self, event: &EventEnvelope) -> bool {
        self.event_types.is_empty() || self.event_types.contains(&event.kind().event_type())
    }
}

pub(super) fn read_event_detail(
    spool: &FjallSpool,
    sequence: u64,
) -> Result<EventDetailSnapshot, EventTailError> {
    let stored = spool
        .read_export_record(sequence)?
        .ok_or(EventTailError::EventNotFound { sequence })?;
    let payload_schema = stored.payload.schema().to_string();
    let payload_bytes = stored.payload.bytes().len();
    if payload_bytes > MAX_EVENT_DETAIL_PAYLOAD_BYTES {
        return Err(EventTailError::EventDetailTooLarge {
            sequence: stored.sequence,
            stored_at_unix_ns: stored.stored_at_unix_ns,
            payload_schema,
            payload_bytes,
            max_payload_bytes: MAX_EVENT_DETAIL_PAYLOAD_BYTES,
        });
    }
    let record = decode_tail_record(stored)?;
    Ok(EventDetailSnapshot {
        sequence: record.sequence,
        stored_at_unix_ns: record.stored_at_unix_ns,
        payload_schema,
        payload_bytes,
        event: record.event,
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
    #[error("export event sequence {sequence} was not found")]
    EventNotFound { sequence: u64 },
    #[error(
        "export event sequence {sequence} payload has {payload_bytes} bytes, exceeding event_detail limit {max_payload_bytes} bytes"
    )]
    EventDetailTooLarge {
        sequence: u64,
        stored_at_unix_ns: u64,
        payload_schema: String,
        payload_bytes: usize,
        max_payload_bytes: usize,
    },
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

impl EventTailError {
    pub(super) fn event_detail_too_large_snapshot(&self) -> Option<EventDetailTooLargeSnapshot> {
        match self {
            Self::EventDetailTooLarge {
                sequence,
                stored_at_unix_ns,
                payload_schema,
                payload_bytes,
                max_payload_bytes,
            } => Some(EventDetailTooLargeSnapshot {
                sequence: *sequence,
                stored_at_unix_ns: *stored_at_unix_ns,
                payload_schema: payload_schema.clone(),
                payload_bytes: *payload_bytes,
                max_payload_bytes: *max_payload_bytes,
            }),
            _ => None,
        }
    }
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
                latest: false,
                limit: 16,
                selector: Some(exe_selector("/usr/bin/nginx")),
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: Vec::new(),
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
    fn relaxed_tail_includes_libpcap_unknown_process_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        ExportEventWriter::new(&spool).append_occurrence(&libpcap_unknown_process_event())?;
        let selector = exe_selector("/app/backend");

        let strict = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                latest: false,
                limit: 16,
                selector: Some(selector.clone()),
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: vec![EventType::HttpRequestHeaders],
            },
        )?;
        let relaxed = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                latest: false,
                limit: 16,
                selector: Some(selector),
                attribution_mode: EventTailAttributionMode::IncludeUnknownProcess,
                event_types: vec![EventType::HttpRequestHeaders],
            },
        )?;

        assert!(strict.events.is_empty());
        assert_eq!(relaxed.events.len(), 1);
        assert_eq!(relaxed.events[0].sequence, 1);
        assert_eq!(spool.export_cursor("webhook")?, 0);
        Ok(())
    }

    #[test]
    fn tail_events_filters_by_event_type() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        ExportEventWriter::new(&spool).append_occurrence(&event_with_kind(
            "/usr/bin/curl",
            EventKind::ConnectionOpened,
        ))?;
        ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                latest: false,
                limit: 16,
                selector: None,
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: vec![EventType::HttpRequestHeaders],
            },
        )?;

        assert_eq!(tail.scanned, 2);
        assert_eq!(tail.next_after_sequence, 2);
        assert_eq!(tail.events.len(), 1);
        assert_eq!(
            tail.events[0].event.kind().event_type(),
            EventType::HttpRequestHeaders
        );
        Ok(())
    }

    #[test]
    fn tail_record_budget_omits_large_batches_before_response_can_grow()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let event = large_body_event_for_exe("/usr/bin/curl", 16 * 1024);
        let payload_bytes = serde_json::to_vec(&event)?.len();
        assert!(payload_bytes < MAX_TAIL_EVENT_PAYLOAD_BYTES);
        let sample_record_bytes = tail_record_budget_bytes(&EventTailRecord {
            sequence: 1,
            stored_at_unix_ns: 1,
            event: event.clone(),
        })?;
        let event_count = MAX_TAIL_RECORD_BYTES
            .checked_div(sample_record_bytes)
            .unwrap_or_default()
            + 2;
        assert!(event_count <= MAX_TAIL_LIMIT);
        for _ in 0..event_count {
            ExportEventWriter::new(&spool).append_occurrence(&event)?;
        }

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                latest: false,
                limit: MAX_TAIL_LIMIT,
                selector: None,
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: Vec::new(),
            },
        )?;

        assert!(tail.events.len() < event_count);
        assert!(tail.budget.truncated);
        assert!(tail.budget.included_record_bytes <= tail.budget.max_record_bytes);
        assert_eq!(tail.omissions.len(), 1);
        assert_eq!(
            tail.omissions[0].reason,
            EventTailOmissionReason::ResponseBudgetExceeded
        );
        Ok(())
    }

    #[test]
    fn latest_tail_starts_from_recent_export_window() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        for _ in 0..32 {
            ExportEventWriter::new(&spool).append_occurrence(&event_with_kind(
                "/usr/bin/curl",
                EventKind::ConnectionOpened,
            ))?;
        }
        ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                latest: true,
                limit: 4,
                selector: None,
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: vec![EventType::HttpRequestHeaders],
            },
        )?;

        assert_eq!(tail.after_sequence, 1);
        assert_eq!(tail.next_after_sequence, 33);
        assert_eq!(tail.last_export_sequence, 33);
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].sequence, 33);
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
                latest: false,
                limit: 0,
                selector: None,
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: Vec::new(),
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
                latest: false,
                limit: 16,
                selector: None,
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: Vec::new(),
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
                latest: false,
                limit: 16,
                selector: Some(exe_selector("/usr/bin/curl")),
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: Vec::new(),
            },
        )?;

        assert_eq!(tail.next_after_sequence, 1);
        assert!(tail.events.is_empty());
        assert!(tail.omissions.is_empty());
        Ok(())
    }

    #[test]
    fn event_detail_reads_single_event_ignored_by_tail_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let event = large_body_event_for_exe("/usr/bin/curl", MAX_TAIL_EVENT_PAYLOAD_BYTES);
        ExportEventWriter::new(&spool).append_occurrence(&event)?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                after_sequence: 0,
                latest: false,
                limit: 16,
                selector: None,
                attribution_mode: EventTailAttributionMode::Strict,
                event_types: Vec::new(),
            },
        )?;
        assert!(tail.events.is_empty());
        assert_eq!(tail.omissions.len(), 1);

        let detail = read_event_detail(&spool, 1)?;

        assert_eq!(detail.sequence, 1);
        assert!(detail.payload_bytes > MAX_TAIL_EVENT_PAYLOAD_BYTES);
        assert_eq!(detail.event, event);
        assert_eq!(spool.export_cursor("primary")?, 0);
        Ok(())
    }

    #[test]
    fn event_detail_reports_retained_event_too_large_for_single_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let stored = spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            vec![b' '; MAX_EVENT_DETAIL_PAYLOAD_BYTES + 1],
        ))?;

        let error =
            read_event_detail(&spool, stored.sequence).expect_err("detail should be capped");
        let snapshot = error
            .event_detail_too_large_snapshot()
            .expect("too large error should expose structured metadata");

        assert_eq!(snapshot.sequence, stored.sequence);
        assert_eq!(snapshot.payload_bytes, MAX_EVENT_DETAIL_PAYLOAD_BYTES + 1);
        assert_eq!(snapshot.max_payload_bytes, MAX_EVENT_DETAIL_PAYLOAD_BYTES);
        assert_eq!(spool.export_cursor("primary")?, 0);
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
        event_with_kind(
            exe_path,
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

    fn libpcap_unknown_process_event() -> EventEnvelope {
        let mut flow = flow_for_exe("unknown");
        flow.process.identity.pid = 0;
        flow.process.identity.tgid = 0;
        flow.process.identity.start_time_ticks = 0;
        flow.process.identity.boot_id = "libpcap".to_string();
        flow.process.identity.cmdline_hash = "unknown".to_string();
        flow.process.identity.runtime_hint = Some("libpcap_fallback".to_string());
        flow.process.name = "unknown".to_string();
        flow.process.cmdline.clear();
        flow.attribution_confidence = 0;
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Libpcap),
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

    fn event_with_kind(exe_path: &str, kind: EventKind) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow_for_exe(exe_path),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            kind,
        )
    }

    fn large_body_event_for_exe(exe_path: &str, min_body_len: usize) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow_for_exe(exe_path),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpBodyChunk(probe_core::BodyChunk {
                direction: Direction::Outbound,
                stream_sequence: 1,
                offset: 0,
                data: vec![b'a'; min_body_len].into(),
                end_stream: true,
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

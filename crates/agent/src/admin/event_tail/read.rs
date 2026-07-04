use std::collections::VecDeque;

use probe_core::{
    CompiledSelector, Direction, EventType, FlowContext, Selector,
    is_libpcap_unknown_process_candidate,
};
use storage::{FjallSpool, StoredEvent};

use super::{
    decode::{decode_stored_event, decode_tail_record},
    error::EventTailError,
    model::{
        EventDetailSnapshot, EventTailAttributionMode, EventTailBudgetSnapshot, EventTailEvent,
        EventTailOmission, EventTailOmissionReason, EventTailRecord, EventTailSnapshot,
    },
};

const MAX_TAIL_LIMIT: usize = 256;
const MAX_TAIL_LIVE_SCAN: usize = 4_096;
const MAX_TAIL_LATEST_SCAN: usize = 16_384;
const MAX_TAIL_EVENT_PAYLOAD_BYTES: usize = MAX_EVENT_DETAIL_PAYLOAD_BYTES;
const MAX_TAIL_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENT_DETAIL_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const LIVE_SELECTOR_SCAN_MULTIPLIER: usize = 16;
const LATEST_SELECTOR_SCAN_MULTIPLIER: usize = 64;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::admin) struct EventTailRequest {
    pub(in crate::admin) after_sequence: u64,
    pub(in crate::admin) latest: bool,
    pub(in crate::admin) limit: usize,
    pub(in crate::admin) selector: Option<Selector>,
    pub(in crate::admin) attribution_mode: EventTailAttributionMode,
    pub(in crate::admin) event_types: Vec<EventType>,
}
pub(in crate::admin) fn read_event_tail(
    spool: &FjallSpool,
    request: EventTailRequest,
) -> Result<EventTailSnapshot, EventTailError> {
    let limit = normalize_limit(request.limit);
    let filtered = request.selector.is_some() || !request.event_types.is_empty();
    let scan_limit = scan_limit(limit, filtered, request.latest);
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
    let mut tail = TailRecordAccumulator::new(limit, request.latest && filtered);

    for stored_event in stored {
        tail.observe_scanned();
        next_after_sequence = stored_event.sequence;
        let payload_bytes = stored_event.payload.bytes().len();
        if payload_bytes > MAX_TAIL_EVENT_PAYLOAD_BYTES {
            if !filtered {
                tail.push_omission(omission_for(
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
            && tail.push_record(record, payload_schema, payload_bytes)?
        {
            break;
        }
    }
    let tail = tail.into_response()?;
    if let Some(sequence) = tail.truncated_at_sequence {
        next_after_sequence = sequence;
    }

    Ok(EventTailSnapshot {
        after_sequence,
        next_after_sequence,
        last_export_sequence,
        attribution_mode: request.attribution_mode,
        limit,
        scanned: tail.scanned,
        budget: EventTailBudgetSnapshot {
            max_event_payload_bytes: MAX_TAIL_EVENT_PAYLOAD_BYTES,
            max_record_bytes: MAX_TAIL_RECORD_BYTES,
            included_record_bytes: tail.included_record_bytes,
            truncated: tail.truncated,
        },
        events: tail.events,
        omissions: tail.omissions,
    })
}

fn tail_record_budget_bytes(record: &EventTailRecord) -> Result<usize, EventTailError> {
    Ok(serde_json::to_vec(record)?.len())
}

struct TailRecordAccumulator {
    limit: usize,
    latest_filtered: bool,
    scanned: usize,
    included_record_bytes: usize,
    truncated: bool,
    truncated_at_sequence: Option<u64>,
    events: Vec<EventTailRecord>,
    latest_candidates: VecDeque<TailRecordCandidate>,
    omissions: Vec<EventTailOmission>,
}

impl TailRecordAccumulator {
    fn new(limit: usize, latest_filtered: bool) -> Self {
        Self {
            limit,
            latest_filtered,
            scanned: 0,
            included_record_bytes: 0,
            truncated: false,
            truncated_at_sequence: None,
            events: Vec::new(),
            latest_candidates: VecDeque::new(),
            omissions: Vec::new(),
        }
    }

    fn observe_scanned(&mut self) {
        self.scanned = self.scanned.saturating_add(1);
    }

    fn push_omission(&mut self, omission: EventTailOmission) {
        self.omissions.push(omission);
    }

    fn push_record(
        &mut self,
        record: EventTailRecord,
        payload_schema: String,
        payload_bytes: usize,
    ) -> Result<bool, EventTailError> {
        let candidate = TailRecordCandidate {
            record,
            payload_schema,
            payload_bytes,
        };
        if self.latest_filtered {
            if self.latest_candidates.len() >= self.limit {
                self.latest_candidates.pop_front();
            }
            self.latest_candidates.push_back(candidate);
            return Ok(false);
        }
        self.push_response_candidate(candidate)
    }

    fn into_response(mut self) -> Result<Self, EventTailError> {
        if self.latest_filtered {
            let latest_candidates = std::mem::take(&mut self.latest_candidates);
            for candidate in latest_candidates {
                if self.push_response_candidate(candidate)? {
                    break;
                }
            }
        }
        Ok(self)
    }

    fn push_response_candidate(
        &mut self,
        candidate: TailRecordCandidate,
    ) -> Result<bool, EventTailError> {
        let record_bytes = tail_record_budget_bytes(&candidate.record)?;
        if self.included_record_bytes.saturating_add(record_bytes) > MAX_TAIL_RECORD_BYTES {
            self.omissions.push(EventTailOmission {
                sequence: candidate.record.sequence,
                stored_at_unix_ns: candidate.record.stored_at_unix_ns,
                payload_schema: candidate.payload_schema,
                payload_bytes: candidate.payload_bytes,
                reason: EventTailOmissionReason::ResponseBudgetExceeded,
            });
            self.truncated = true;
            self.truncated_at_sequence = Some(candidate.record.sequence);
            return Ok(true);
        }
        self.included_record_bytes = self.included_record_bytes.saturating_add(record_bytes);
        self.events.push(candidate.record);
        Ok(self.events.len() >= self.limit)
    }
}

struct TailRecordCandidate {
    record: EventTailRecord,
    payload_schema: String,
    payload_bytes: usize,
}

fn selector_matches_event(
    selector: &CompiledSelector,
    event: &EventTailEvent,
    mode: EventTailAttributionMode,
) -> bool {
    let Some(flow) = event.flow.as_ref() else {
        return false;
    };
    let direction = event.kind.direction();
    selector_matches_tail_flow(selector, flow, direction)
        || (mode == EventTailAttributionMode::IncludeUnknownProcess
            && is_libpcap_unknown_process_event(event)
            && selector.matches_flow_with_unknown_process(flow, direction))
}

fn selector_matches_tail_flow(
    selector: &CompiledSelector,
    flow: &FlowContext,
    direction: Option<Direction>,
) -> bool {
    direction.map_or_else(
        || selector.matches_flow_without_direction(flow),
        |direction| selector.matches_flow(flow, direction),
    )
}

fn is_libpcap_unknown_process_event(event: &EventTailEvent) -> bool {
    event
        .flow
        .as_ref()
        .is_some_and(|flow| is_libpcap_unknown_process_candidate(event.origin.source(), flow))
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

    fn matches(&self, event: &EventTailEvent) -> bool {
        self.event_types.is_empty() || self.event_types.contains(&event.kind.event_type())
    }
}

pub(in crate::admin) fn read_event_detail(
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
    let record = decode_stored_event(stored)?;
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

fn scan_limit(limit: usize, filtered: bool, latest: bool) -> usize {
    if !filtered {
        return limit;
    }
    let (multiplier, max_scan) = if latest {
        (LATEST_SELECTOR_SCAN_MULTIPLIER, MAX_TAIL_LATEST_SCAN)
    } else {
        (LIVE_SELECTOR_SCAN_MULTIPLIER, MAX_TAIL_LIVE_SCAN)
    };
    limit.saturating_mul(multiplier).clamp(limit, max_scan)
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
#[cfg(test)]
mod tests {
    use pipeline::ExportEventWriter;
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, HttpHeaders, LIBPCAP_FALLBACK_RUNTIME_HINT, ProcessContext,
        ProcessIdentity, ProcessSelector, SelectorTerm, SpoolPayloadSchema, Timestamp,
        TrafficSelector, TransportProtocol, UNKNOWN_PROCESS_LABEL,
    };
    use storage::SpoolPayload;
    use tempfile::tempdir;

    use super::super::model::EventTailKind;
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
                .flow
                .as_ref()
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
            tail.events[0].event.kind.event_type(),
            EventType::HttpRequestHeaders
        );
        Ok(())
    }

    #[test]
    fn tail_record_budget_uses_compact_records_for_large_body_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let event = large_body_event_for_exe("/usr/bin/curl", 16 * 1024);
        let payload_bytes = serde_json::to_vec(&event)?.len();
        assert!(payload_bytes < MAX_TAIL_EVENT_PAYLOAD_BYTES);
        let sample_record_bytes = tail_record_budget_bytes(&EventTailRecord {
            sequence: 1,
            stored_at_unix_ns: 1,
            event: EventTailEvent::from_envelope(&event),
        })?;
        assert!(sample_record_bytes < payload_bytes / 4);
        let event_count = MAX_TAIL_LIMIT;
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

        assert_eq!(tail.events.len(), event_count);
        assert!(!tail.budget.truncated);
        assert!(tail.budget.included_record_bytes <= tail.budget.max_record_bytes);
        assert!(tail.omissions.is_empty());
        assert!(
            matches!(
                &tail.events[0].event.kind,
                EventTailKind::HttpBodyChunk(chunk) if chunk.data_len >= 16 * 1024
            ),
            "tail should preserve body length metadata without serializing body bytes"
        );
        Ok(())
    }

    #[test]
    fn latest_filtered_tail_uses_wider_backfill_window() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        for _ in 0..79 {
            ExportEventWriter::new(&spool).append_occurrence(&event_with_kind(
                "/usr/bin/curl",
                EventKind::ConnectionOpened,
            ))?;
        }
        ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;
        for _ in 0..220 {
            ExportEventWriter::new(&spool).append_occurrence(&event_with_kind(
                "/usr/bin/curl",
                EventKind::ConnectionOpened,
            ))?;
        }

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

        assert_eq!(tail.after_sequence, 44);
        assert_eq!(tail.next_after_sequence, 300);
        assert_eq!(tail.last_export_sequence, 300);
        assert_eq!(tail.scanned, 256);
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].sequence, 80);
        Ok(())
    }

    #[test]
    fn latest_filtered_tail_returns_newest_matches_from_backfill_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        for _ in 0..300 {
            ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;
        }

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

        assert_eq!(tail.after_sequence, 44);
        assert_eq!(tail.next_after_sequence, 300);
        assert_eq!(tail.scanned, 256);
        assert_eq!(
            tail.events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![297, 298, 299, 300]
        );
        Ok(())
    }

    #[test]
    fn latest_filtered_tail_budget_truncation_advances_to_omitted_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        for _ in 0..296 {
            ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;
        }
        ExportEventWriter::new(&spool).append_occurrence(&large_header_event_for_exe(
            "/usr/bin/curl",
            MAX_TAIL_RECORD_BYTES + 1024,
        ))?;
        for _ in 0..3 {
            ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;
        }

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

        assert_eq!(tail.after_sequence, 44);
        assert_eq!(tail.next_after_sequence, 297);
        assert!(tail.events.is_empty());
        assert!(tail.budget.truncated);
        assert_eq!(tail.omissions.len(), 1);
        assert_eq!(tail.omissions[0].sequence, 297);
        assert_eq!(
            tail.omissions[0].reason,
            EventTailOmissionReason::ResponseBudgetExceeded
        );
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
    fn event_detail_reads_full_payload_for_compact_tail_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let event = large_body_event_for_exe("/usr/bin/curl", 512 * 1024);
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
        assert_eq!(tail.events.len(), 1);
        assert!(tail.omissions.is_empty());
        assert!(
            matches!(
                &tail.events[0].event.kind,
                EventTailKind::HttpBodyChunk(chunk) if chunk.data_len >= 512 * 1024
            ),
            "tail should carry body metadata"
        );

        let detail = read_event_detail(&spool, 1)?;

        assert_eq!(detail.sequence, 1);
        assert!(detail.payload_bytes > tail.budget.included_record_bytes);
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

    fn large_header_event_for_exe(exe_path: &str, header_value_len: usize) -> EventEnvelope {
        event_with_kind(
            exe_path,
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/large".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: vec![("x-large".to_string(), "a".repeat(header_value_len))],
            }),
        )
    }

    fn libpcap_unknown_process_event() -> EventEnvelope {
        let mut flow = flow_for_exe(UNKNOWN_PROCESS_LABEL);
        flow.process.identity.pid = 0;
        flow.process.identity.tgid = 0;
        flow.process.identity.start_time_ticks = 0;
        flow.process.identity.boot_id = "libpcap".to_string();
        flow.process.identity.cmdline_hash = UNKNOWN_PROCESS_LABEL.to_string();
        flow.process.identity.runtime_hint = Some(LIBPCAP_FALLBACK_RUNTIME_HINT.to_string());
        flow.process.name = UNKNOWN_PROCESS_LABEL.to_string();
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

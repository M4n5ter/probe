use std::collections::VecDeque;

use probe_core::{EventType, Selector};
use storage::{FjallSpool, StoredEvent};

use super::{
    decode::{decode_stored_event, decode_tail_record},
    error::EventTailError,
    model::{
        EventDetailSnapshot, EventTailAttributionMode, EventTailBudgetSnapshot, EventTailOmission,
        EventTailOmissionReason, EventTailRecord, EventTailSnapshot,
    },
    selector::{EventTypeFilter, TailEventSelectorFilter, UnknownProcessCandidateSelector},
};

const MAX_TAIL_LIMIT: usize = 1_024;
const MAX_TAIL_EVENT_PAYLOAD_BYTES: usize = MAX_EVENT_DETAIL_PAYLOAD_BYTES;
const MAX_TAIL_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_EVENT_DETAIL_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

const TAIL_SCAN_LIMIT_POLICY: TailScanLimitPolicy = TailScanLimitPolicy {
    live_default: 16_384,
    live_max: 16_384,
    latest_default: 65_536,
    latest_max: 65_536,
};

#[derive(Debug, Clone, Copy)]
struct TailScanLimitPolicy {
    live_default: usize,
    live_max: usize,
    latest_default: usize,
    latest_max: usize,
}

impl TailScanLimitPolicy {
    fn default_for(self, latest: bool) -> usize {
        if latest {
            self.latest_default
        } else {
            self.live_default
        }
    }

    fn max_for(self, latest: bool) -> usize {
        if latest {
            self.latest_max
        } else {
            self.live_max
        }
    }
}

pub(crate) fn default_tail_scan_limit(latest: bool) -> usize {
    TAIL_SCAN_LIMIT_POLICY.default_for(latest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::admin) struct EventTailRequest {
    pub(in crate::admin) after_sequence: u64,
    pub(in crate::admin) latest: bool,
    pub(in crate::admin) limit: usize,
    pub(in crate::admin) scan_limit: usize,
    pub(in crate::admin) selector: Option<Selector>,
    pub(in crate::admin) unknown_process_candidate_selector:
        Option<UnknownProcessCandidateSelector>,
    pub(in crate::admin) attribution_mode: EventTailAttributionMode,
    pub(in crate::admin) event_types: Vec<EventType>,
}

pub(in crate::admin) fn read_event_tail(
    spool: &FjallSpool,
    request: EventTailRequest,
) -> Result<EventTailSnapshot, EventTailError> {
    let limit = normalize_limit(request.limit);
    let selector_filter = TailEventSelectorFilter::compile(
        request.selector.as_ref(),
        request.unknown_process_candidate_selector.clone(),
    )
    .map_err(EventTailError::Selector)?;
    let filtered = selector_filter.is_filtered() || !request.event_types.is_empty();
    let scan_limit = normalize_scan_limit(request.scan_limit, limit, filtered, request.latest);
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
            && selector_filter.matches(&record.event, request.attribution_mode)
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
        scan_limit,
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
    latest_candidates: VecDeque<TailResponseCandidate>,
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
        let candidate =
            TailResponseCandidate::from_matched_record(record, payload_schema, payload_bytes);
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
        candidate: TailResponseCandidate,
    ) -> Result<bool, EventTailError> {
        let record = candidate.record;
        let record_bytes = tail_record_budget_bytes(&record)?;
        if self.included_record_bytes.saturating_add(record_bytes) > MAX_TAIL_RECORD_BYTES {
            self.omissions.push(EventTailOmission {
                sequence: record.sequence,
                stored_at_unix_ns: record.stored_at_unix_ns,
                payload_schema: candidate.payload_schema,
                payload_bytes: candidate.payload_bytes,
                reason: EventTailOmissionReason::ResponseBudgetExceeded,
            });
            self.truncated = true;
            self.truncated_at_sequence = Some(record.sequence);
            return Ok(true);
        }
        self.included_record_bytes = self.included_record_bytes.saturating_add(record_bytes);
        self.events.push(record);
        Ok(self.events.len() >= self.limit)
    }
}

struct TailResponseCandidate {
    record: EventTailRecord,
    payload_schema: String,
    payload_bytes: usize,
}

impl TailResponseCandidate {
    fn from_matched_record(
        record: EventTailRecord,
        payload_schema: String,
        payload_bytes: usize,
    ) -> Self {
        Self {
            record: record.into_compact_response(),
            payload_schema,
            payload_bytes,
        }
    }
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

fn normalize_scan_limit(scan_limit: usize, limit: usize, filtered: bool, latest: bool) -> usize {
    if !filtered {
        return limit;
    }
    let max_scan = TAIL_SCAN_LIMIT_POLICY.max_for(latest);
    scan_limit.clamp(limit, max_scan)
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
        AddressPort, CaptureLoss, CaptureOrigin, CaptureSource, Direction, EventEnvelope,
        EventKind, FlowContext, FlowIdentity, HttpHeaders, LIBPCAP_FALLBACK_RUNTIME_HINT,
        ProcessContext, ProcessIdentity, ProcessSelector, SelectorTerm, SpoolPayloadSchema,
        Timestamp, TrafficSelector, TransportProtocol, UNKNOWN_PROCESS_LABEL,
    };
    use storage::SpoolPayload;
    use tempfile::tempdir;

    use super::super::model::{EventTailEvent, EventTailKind};
    use super::*;

    fn tail_request() -> EventTailRequest {
        EventTailRequest {
            after_sequence: 0,
            latest: false,
            limit: 16,
            scan_limit: 16,
            selector: None,
            unknown_process_candidate_selector: None,
            attribution_mode: EventTailAttributionMode::Strict,
            event_types: Vec::new(),
        }
    }

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
                selector: Some(exe_selector("/usr/bin/nginx")),
                ..tail_request()
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
    fn relaxed_tail_includes_explicit_libpcap_unknown_process_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        ExportEventWriter::new(&spool).append_occurrence(&libpcap_unknown_process_event())?;
        let selector = exe_selector("/app/backend");
        let unknown_process_candidate_selector =
            UnknownProcessCandidateSelector::from_listener_ports([80])
                .expect("listener port should produce candidate selector");

        let strict = read_event_tail(
            &spool,
            EventTailRequest {
                selector: Some(selector.clone()),
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
            },
        )?;
        let relaxed_without_candidate = read_event_tail(
            &spool,
            EventTailRequest {
                selector: Some(selector.clone()),
                attribution_mode: EventTailAttributionMode::IncludeUnknownProcess,
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
            },
        )?;
        let relaxed = read_event_tail(
            &spool,
            EventTailRequest {
                selector: Some(selector),
                unknown_process_candidate_selector: Some(unknown_process_candidate_selector),
                attribution_mode: EventTailAttributionMode::IncludeUnknownProcess,
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
            },
        )?;

        assert!(strict.events.is_empty());
        assert!(relaxed_without_candidate.events.is_empty());
        assert_eq!(relaxed.events.len(), 1);
        assert_eq!(relaxed.events[0].sequence, 1);
        assert_eq!(spool.export_cursor("webhook")?, 0);
        Ok(())
    }

    #[test]
    fn unknown_process_candidate_selector_does_not_match_strongly_attributed_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;
        ExportEventWriter::new(&spool).append_occurrence(&libpcap_unknown_process_event())?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                unknown_process_candidate_selector:
                    UnknownProcessCandidateSelector::from_listener_ports([80]),
                attribution_mode: EventTailAttributionMode::IncludeUnknownProcess,
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
            },
        )?;

        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].sequence, 2);
        assert_eq!(spool.export_cursor("webhook")?, 0);
        Ok(())
    }

    #[test]
    fn event_type_only_tail_includes_provider_events_without_flow()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        ExportEventWriter::new(&spool).append_occurrence(&provider_capture_loss_event())?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                event_types: vec![EventType::CaptureLoss],
                ..tail_request()
            },
        )?;

        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].sequence, 1);
        assert!(tail.events[0].event.flow.is_none());
        assert!(matches!(
            tail.events[0].event.kind,
            EventTailKind::CaptureLoss(_)
        ));
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
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
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
    fn filtered_tail_scan_limit_can_exceed_response_limit() -> Result<(), Box<dyn std::error::Error>>
    {
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
                limit: 1,
                scan_limit: 2,
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
            },
        )?;

        assert_eq!(tail.limit, 1);
        assert_eq!(tail.scan_limit, 2);
        assert_eq!(tail.scanned, 2);
        assert_eq!(tail.next_after_sequence, 2);
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].sequence, 2);
        Ok(())
    }

    #[test]
    fn unfiltered_latest_tail_keeps_latest_window_tied_to_response_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        for _ in 0..3 {
            ExportEventWriter::new(&spool).append_occurrence(&event_for_exe("/usr/bin/curl"))?;
        }

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                latest: true,
                limit: 1,
                scan_limit: 3,
                ..tail_request()
            },
        )?;

        assert_eq!(tail.limit, 1);
        assert_eq!(tail.scan_limit, 1);
        assert_eq!(tail.after_sequence, 2);
        assert_eq!(tail.scanned, 1);
        assert_eq!(
            tail.events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3]
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
                limit: MAX_TAIL_LIMIT,
                scan_limit: MAX_TAIL_LIMIT,
                ..tail_request()
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
    fn tail_events_compact_process_cmdline_after_selector_matching()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let spool = FjallSpool::open(temp.path())?;
        let cmdline = vec![
            "/usr/bin/python3".to_string(),
            "--tenant".to_string(),
            "managed".to_string(),
            "x".repeat(128 * 1024),
        ];
        let event = event_with_cmdline(
            "/usr/bin/python3",
            cmdline.clone(),
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
        );
        ExportEventWriter::new(&spool).append_occurrence(&event)?;

        let tail = read_event_tail(
            &spool,
            EventTailRequest {
                selector: Some(Selector::term(
                    ProcessSelector {
                        cmdline_regexes: vec!["--tenant managed".to_string()],
                        ..ProcessSelector::default()
                    },
                    TrafficSelector::default(),
                )),
                ..tail_request()
            },
        )?;

        assert_eq!(tail.events.len(), 1);
        let tail_flow = tail.events[0]
            .event
            .flow
            .as_ref()
            .expect("tail event should keep flow identity");
        assert!(
            tail_flow.process.cmdline.is_empty(),
            "tail response should not repeat raw argv"
        );
        assert!(
            tail.budget.included_record_bytes < 4096,
            "tail response should budget the compact record"
        );

        let detail = read_event_detail(&spool, 1)?;
        assert_eq!(
            detail
                .event
                .flow()
                .expect("detail should keep flow identity")
                .process
                .cmdline,
            cmdline
        );
        Ok(())
    }

    #[test]
    fn latest_filtered_accumulator_keeps_compact_response_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let cmdline = vec![
            "/usr/bin/python3".to_string(),
            "--tenant".to_string(),
            "managed".to_string(),
            "x".repeat(128 * 1024),
        ];
        let event = event_with_cmdline(
            "/usr/bin/python3",
            cmdline,
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
        );
        let mut tail = TailRecordAccumulator::new(16, true);

        tail.push_record(
            EventTailRecord {
                sequence: 1,
                stored_at_unix_ns: 1,
                event: EventTailEvent::from_envelope(&event),
            },
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson
                .as_str()
                .to_string(),
            0,
        )?;

        let candidate = tail
            .latest_candidates
            .front()
            .expect("latest-filtered tail should retain the matched candidate");
        assert!(
            candidate
                .record
                .event
                .flow
                .as_ref()
                .expect("candidate should keep flow identity")
                .process
                .cmdline
                .is_empty(),
            "latest-filtered accumulator must not retain raw argv"
        );

        let tail = tail.into_response()?;
        assert_eq!(tail.events.len(), 1);
        assert!(
            tail.events[0]
                .event
                .flow
                .as_ref()
                .expect("response should keep flow identity")
                .process
                .cmdline
                .is_empty()
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
                latest: true,
                limit: 4,
                scan_limit: 256,
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
            },
        )?;

        assert_eq!(tail.after_sequence, 44);
        assert_eq!(tail.scan_limit, 256);
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
                latest: true,
                limit: 4,
                scan_limit: 256,
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
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
                latest: true,
                limit: 4,
                scan_limit: 256,
                event_types: vec![EventType::HttpRequestHeaders],
                ..tail_request()
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
                limit: 0,
                scan_limit: 0,
                ..tail_request()
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

        let tail = read_event_tail(&spool, tail_request())?;

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
                selector: Some(exe_selector("/usr/bin/curl")),
                ..tail_request()
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

        let tail = read_event_tail(&spool, tail_request())?;
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

    fn provider_capture_loss_event() -> EventEnvelope {
        EventEnvelope::from_provider(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            CaptureOrigin::from_source(CaptureSource::Libpcap),
            "test",
            EventKind::CaptureLoss(CaptureLoss {
                lost_events: 7,
                reason: "provider ring overflow".to_string(),
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

    fn event_with_cmdline(exe_path: &str, cmdline: Vec<String>, kind: EventKind) -> EventEnvelope {
        let mut flow = flow_for_exe(exe_path);
        flow.process.cmdline = cmdline;
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            kind,
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

use std::fmt;

use probe_core::EventEnvelope;

use crate::admin::{
    EventDetailSnapshot, EventTailBudgetSnapshot, EventTailEvent, EventTailOmission,
    EventTailRecord,
};

use super::{
    attribution::TrafficAttribution,
    event_display::{capture_path_short_label, event_detail_lines, event_kind_display},
    event_ref::TrafficEventRef,
    text::{direction_label, fit_preview_lines},
};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TrafficRow {
    pub(crate) sequence: u64,
    pub(crate) process: String,
    pub(crate) capture_path: &'static str,
    pub(crate) event_type: String,
    pub(crate) direction: String,
    pub(crate) endpoint: String,
    pub(crate) summary: String,
    pub(crate) attribution: TrafficAttribution,
    payload: TrafficRowPayload,
}

impl TrafficRow {
    pub(super) fn from_record(record: EventTailRecord) -> Self {
        Self::from_tail_event(record.sequence, record.event)
    }

    pub(super) fn from_detail(detail: EventDetailSnapshot) -> Self {
        Self::from_event(detail.sequence, detail.event)
    }

    pub(super) fn from_omission(
        omission: EventTailOmission,
        scanned: usize,
        budget: EventTailBudgetSnapshot,
    ) -> Self {
        let reason = omission.reason.label();
        let payload_bytes = omission.payload_bytes;
        Self {
            sequence: omission.sequence,
            process: "tail".to_string(),
            capture_path: "tail",
            event_type: "tail omission".to_string(),
            direction: "-".to_string(),
            endpoint: "-".to_string(),
            summary: format!("{reason}, payload {payload_bytes} bytes"),
            attribution: TrafficAttribution::from_eventless_provider(),
            payload: TrafficRowPayload::Omission(TrafficOmissionRow {
                omission,
                scanned,
                budget,
            }),
        }
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        match &self.payload {
            TrafficRowPayload::FullEvent(event) => {
                event_detail_lines(self.sequence, TrafficEventRef::Full(event))
            }
            TrafficRowPayload::TailEvent(event) => {
                event_detail_lines(self.sequence, TrafficEventRef::Tail(event))
            }
            TrafficRowPayload::Omission(omission) => omission_detail_lines(self.sequence, omission),
        }
    }

    pub(crate) fn preview_lines(&self, max_lines: usize) -> Vec<String> {
        match &self.payload {
            TrafficRowPayload::FullEvent(_) | TrafficRowPayload::TailEvent(_) => {
                event_preview_lines(self, max_lines)
            }
            TrafficRowPayload::Omission(omission) => {
                omission_preview_lines(self.sequence, omission, max_lines)
            }
        }
    }

    pub(crate) fn detail_fetch_sequence(&self) -> Option<u64> {
        matches!(
            self.payload,
            TrafficRowPayload::TailEvent(_) | TrafficRowPayload::Omission(_)
        )
        .then_some(self.sequence)
    }

    pub(super) fn event_ref(&self) -> Option<TrafficEventRef<'_>> {
        match &self.payload {
            TrafficRowPayload::FullEvent(event) => Some(TrafficEventRef::Full(event)),
            TrafficRowPayload::TailEvent(event) => Some(TrafficEventRef::Tail(event)),
            TrafficRowPayload::Omission(_) => None,
        }
    }

    pub(super) fn from_event(sequence: u64, event: EventEnvelope) -> Self {
        let event_ref = TrafficEventRef::Full(&event);
        let flow = event_ref.flow();
        let event_kind = event_kind_display(event_ref.kind(), false);
        let attribution = TrafficAttribution::from_event(event_ref);
        Self {
            sequence,
            process: attribution.process_label(),
            capture_path: capture_path_short_label(event_ref.origin()),
            event_type: event_ref.event_type().as_str().to_string(),
            direction: event_ref
                .direction()
                .map(direction_label)
                .unwrap_or("-")
                .to_string(),
            endpoint: flow
                .map(|flow| format!("{}:{}", flow.remote.address, flow.remote.port))
                .unwrap_or_else(|| "-".to_string()),
            summary: event_kind.summary,
            attribution,
            payload: TrafficRowPayload::FullEvent(Box::new(event)),
        }
    }

    fn from_tail_event(sequence: u64, event: EventTailEvent) -> Self {
        let event_ref = TrafficEventRef::Tail(&event);
        let flow = event_ref.flow();
        let event_kind = event_kind_display(event_ref.kind(), false);
        let attribution = TrafficAttribution::from_event(event_ref);
        Self {
            sequence,
            process: attribution.process_label(),
            capture_path: capture_path_short_label(event_ref.origin()),
            event_type: event_ref.event_type().as_str().to_string(),
            direction: event_ref
                .direction()
                .map(direction_label)
                .unwrap_or("-")
                .to_string(),
            endpoint: flow
                .map(|flow| format!("{}:{}", flow.remote.address, flow.remote.port))
                .unwrap_or_else(|| "-".to_string()),
            summary: event_kind.summary,
            attribution,
            payload: TrafficRowPayload::TailEvent(Box::new(event)),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum TrafficRowPayload {
    FullEvent(Box<EventEnvelope>),
    TailEvent(Box<EventTailEvent>),
    Omission(TrafficOmissionRow),
}

#[derive(Clone, PartialEq, Eq)]
struct TrafficOmissionRow {
    omission: EventTailOmission,
    scanned: usize,
    budget: EventTailBudgetSnapshot,
}

fn event_preview_lines(row: &TrafficRow, max_lines: usize) -> Vec<String> {
    let mut lines = vec![
        format!("Sequence: {}", row.sequence),
        format!("Event type: {} via {}", row.event_type, row.capture_path),
        format!("Direction: {}", row.direction),
        format!("Remote: {}", row.endpoint),
        format!("Summary: {}", row.summary),
    ];
    lines.splice(2..2, row.attribution.preview_lines());
    lines.push("Open detail for full payload".to_string());
    fit_preview_lines(lines, max_lines)
}

fn omission_preview_lines(
    sequence: u64,
    row: &TrafficOmissionRow,
    max_lines: usize,
) -> Vec<String> {
    let lines = vec![
        format!("Sequence: {sequence}"),
        "Event type: tail omission".to_string(),
        format!("Reason: {}", row.omission.reason.label()),
        format!("Payload bytes: {}", row.omission.payload_bytes),
        format!("Payload schema: {}", row.omission.payload_schema),
        "Open detail for tail budget".to_string(),
    ];
    fit_preview_lines(lines, max_lines)
}

impl fmt::Debug for TrafficRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrafficRow")
            .field("sequence", &self.sequence)
            .field("process", &self.process)
            .field("capture_path", &self.capture_path)
            .field("event_type", &self.event_type)
            .field("direction", &self.direction)
            .field("endpoint", &self.endpoint)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

fn omission_detail_lines(sequence: u64, row: &TrafficOmissionRow) -> Vec<String> {
    vec![
        format!("Sequence: {sequence}"),
        "Event type: tail omission".to_string(),
        format!("Stored at unix ns: {}", row.omission.stored_at_unix_ns),
        format!("Reason: {}", row.omission.reason.label()),
        format!("Payload bytes: {}", row.omission.payload_bytes),
        format!("Payload schema: {}", row.omission.payload_schema),
        "Tail diagnostics".to_string(),
        format!("scanned records: {}", row.scanned),
        format!(
            "record budget: {}/{} bytes{}",
            row.budget.included_record_bytes,
            row.budget.max_record_bytes,
            if row.budget.truncated {
                " (truncated)"
            } else {
                ""
            }
        ),
        format!(
            "per-event payload limit: {} bytes",
            row.budget.max_event_payload_bytes
        ),
    ]
}
#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, BodyChunk, CaptureOrigin, CaptureSource, CaptureTrafficSecurity, Direction,
        EventKind, FlowContext, FlowIdentity, HttpHeaders, LIBPCAP_FALLBACK_RUNTIME_HINT,
        ProcessContext, ProcessIdentity, Timestamp, TransportProtocol, UNKNOWN_PROCESS_LABEL,
    };

    use super::*;

    #[test]
    fn traffic_row_does_not_retain_raw_argv() {
        let event = EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow_with_raw_argv(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/health".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        );

        let row = TrafficRow::from_event(7, event);

        assert_eq!(row.sequence, 7);
        assert_eq!(row.process, "curl (42)");
        assert_eq!(row.capture_path, "replay");
        assert_eq!(row.summary, "GET /health");
        assert!(!format!("{row:?}").contains("--secret-token"));
        assert!(
            row.detail_lines()
                .iter()
                .any(|line| line == "Executable: /usr/bin/curl")
        );
    }

    #[test]
    fn traffic_row_surfaces_capture_path_in_list_preview_and_detail() {
        let event = mitm_request_event(CaptureTrafficSecurity::TlsDecrypted, "/mitm");
        let row = TrafficRow::from_event(7, event);

        assert_eq!(row.capture_path, "mitm-tls");
        let compact_preview = row.preview_lines(3);
        assert!(
            compact_preview
                .iter()
                .any(|line| line == "Event type: http_request_headers via mitm-tls"),
            "compact preview should preserve the capture path: {compact_preview:?}"
        );
        assert!(
            row.detail_lines()
                .iter()
                .any(|line| line == "Capture path: MITM proxy path (TLS-decrypted HTTP)")
        );
        let expected_origin =
            "Origin: source=l7_mitm_plaintext provider=interception traffic_security=tls_decrypted";
        assert!(
            row.detail_lines()
                .iter()
                .any(|line| line == expected_origin)
        );
    }

    #[test]
    fn traffic_row_distinguishes_mitm_plain_http_capture_path() {
        let event = mitm_request_event(CaptureTrafficSecurity::Cleartext, "/plain");
        let row = TrafficRow::from_event(7, event);

        assert_eq!(row.capture_path, "mitm-http");
        assert!(
            row.detail_lines()
                .iter()
                .any(|line| line == "Capture path: MITM proxy path (plain HTTP)")
        );
    }

    #[test]
    fn traffic_detail_keeps_full_parsed_payload() {
        let payload = "hello ".repeat(200);
        let event = EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow_with_raw_argv(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpBodyChunk(BodyChunk {
                direction: Direction::Outbound,
                stream_sequence: 1,
                offset: 0,
                data: payload.clone().into_bytes().into(),
                end_stream: true,
            }),
        );

        let row = TrafficRow::from_event(7, event);

        assert!(
            row.detail_lines()
                .iter()
                .any(|line| line == &format!("Body payload: {payload}"))
        );
        assert!(
            !row.preview_lines(6)
                .iter()
                .any(|line| line.contains(&payload))
        );
        assert!(
            row.preview_lines(6)
                .iter()
                .any(|line| line == "Open detail for full payload")
        );
    }

    #[test]
    fn traffic_detail_keeps_all_http_headers() {
        let headers = (0..40)
            .map(|index| (format!("x-test-{index}"), format!("value-{index}")))
            .collect::<Vec<_>>();
        let event = EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow_with_raw_argv(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/headers".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers,
            }),
        );

        let row = TrafficRow::from_event(7, event);

        assert!(
            row.detail_lines()
                .iter()
                .any(|line| line == "x-test-39: value-39")
        );
    }

    #[test]
    fn libpcap_unknown_process_candidate_is_explicit() {
        let event = EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            libpcap_unknown_process_flow(),
            CaptureOrigin::from_source(CaptureSource::Libpcap),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/candidate".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        );

        let row = TrafficRow::from_event(7, event);

        assert_eq!(row.process, "unknown candidate");
        assert!(
            row.preview_lines(8)
                .iter()
                .any(|line| line == "Process: unknown libpcap candidate")
        );
        assert!(
            row.detail_lines()
                .iter()
                .any(|line| line == "Process match: libpcap unknown-process candidate")
        );
    }

    fn flow_with_raw_argv() -> FlowContext {
        let process = ProcessContext {
            identity: ProcessIdentity {
                pid: 42,
                tgid: 42,
                start_time_ticks: 7,
                boot_id: "boot".to_string(),
                exe_path: "/usr/bin/curl".to_string(),
                cmdline_hash: "hash".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "curl".to_string(),
            cmdline: vec!["curl".to_string(), "--secret-token".to_string()],
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

    fn libpcap_unknown_process_flow() -> FlowContext {
        let mut flow = flow_with_raw_argv();
        flow.process.identity.pid = 0;
        flow.process.identity.tgid = 0;
        flow.process.identity.exe_path = UNKNOWN_PROCESS_LABEL.to_string();
        flow.process.identity.runtime_hint = Some(LIBPCAP_FALLBACK_RUNTIME_HINT.to_string());
        flow.process.name = UNKNOWN_PROCESS_LABEL.to_string();
        flow.process.cmdline.clear();
        flow.attribution_confidence = 0;
        flow
    }

    fn mitm_request_event(traffic_security: CaptureTrafficSecurity, target: &str) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow_with_raw_argv(),
            CaptureOrigin::from_source(CaptureSource::L7MitmPlaintext)
                .with_traffic_security(traffic_security),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some(target.to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }
}

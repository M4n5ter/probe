use std::fmt;

use probe_core::{
    CaptureOrigin, CaptureSource, CaptureTrafficSecurity, Direction, EventEnvelope, EventKind,
};

use crate::{
    admin::{EventTailBudgetSnapshot, EventTailOmission, EventTailRecord},
    tui::copy::{MITM_HTTP_PATH_LABEL, MITM_TLS_PATH_LABEL},
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
    payload: TrafficRowPayload,
}

impl TrafficRow {
    pub(super) fn from_record(record: EventTailRecord) -> Self {
        Self::from_event(record.sequence, record.event)
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
            payload: TrafficRowPayload::Omission(TrafficOmissionRow {
                omission,
                scanned,
                budget,
            }),
        }
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        match &self.payload {
            TrafficRowPayload::Event(event) => event_detail_lines(self.sequence, event),
            TrafficRowPayload::Omission(omission) => omission_detail_lines(self.sequence, omission),
        }
    }

    pub(crate) fn preview_lines(&self, max_lines: usize) -> Vec<String> {
        match &self.payload {
            TrafficRowPayload::Event(event) => event_preview_lines(self, event, max_lines),
            TrafficRowPayload::Omission(omission) => {
                omission_preview_lines(self.sequence, omission, max_lines)
            }
        }
    }

    fn from_event(sequence: u64, event: EventEnvelope) -> Self {
        let flow = event.flow();
        let event_kind = event_kind_display(event.kind(), false);
        Self {
            sequence,
            process: flow
                .map(|flow| format!("{} ({})", flow.process.name, flow.process.identity.pid))
                .unwrap_or_else(|| "provider".to_string()),
            capture_path: capture_path_short_label(event.origin()),
            event_type: event.kind().event_type().as_str().to_string(),
            direction: event
                .kind()
                .direction()
                .map(direction_label)
                .unwrap_or("-")
                .to_string(),
            endpoint: flow
                .map(|flow| format!("{}:{}", flow.remote.address, flow.remote.port))
                .unwrap_or_else(|| "-".to_string()),
            summary: event_kind.summary,
            payload: TrafficRowPayload::Event(Box::new(event)),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum TrafficRowPayload {
    Event(Box<EventEnvelope>),
    Omission(TrafficOmissionRow),
}

#[derive(Clone, PartialEq, Eq)]
struct TrafficOmissionRow {
    omission: EventTailOmission,
    scanned: usize,
    budget: EventTailBudgetSnapshot,
}

fn event_preview_lines(row: &TrafficRow, event: &EventEnvelope, max_lines: usize) -> Vec<String> {
    let mut lines = vec![
        format!("Sequence: {}", row.sequence),
        format!("Event type: {} via {}", row.event_type, row.capture_path),
        format!("Direction: {}", row.direction),
        format!("Remote: {}", row.endpoint),
        format!("Summary: {}", row.summary),
    ];
    if let Some(flow) = event.flow() {
        lines.insert(
            2,
            format!(
                "Process: {} pid={}",
                flow.process.name, flow.process.identity.pid
            ),
        );
    }
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

fn capture_path_short_label(origin: CaptureOrigin) -> &'static str {
    match origin.source() {
        CaptureSource::L7MitmPlaintext => mitm_capture_path_short_label(origin.traffic_security()),
        source => capture_source_short_label(source),
    }
}

fn mitm_capture_path_short_label(traffic_security: CaptureTrafficSecurity) -> &'static str {
    match traffic_security {
        CaptureTrafficSecurity::Unknown => "mitm-data",
        CaptureTrafficSecurity::Cleartext => MITM_HTTP_PATH_LABEL,
        CaptureTrafficSecurity::TlsDecrypted => MITM_TLS_PATH_LABEL,
    }
}

fn capture_source_short_label(source: CaptureSource) -> &'static str {
    match source {
        CaptureSource::EbpfSyscall => "ebpf",
        CaptureSource::Libpcap => "libpcap",
        CaptureSource::LibsslUprobe => "tls-uprobe",
        CaptureSource::TlsSessionSecret => "tls-secret",
        CaptureSource::ExternalPlaintextFeed => "plaintext",
        CaptureSource::L7MitmPlaintext => "mitm-data",
        CaptureSource::L7MitmControlPlane => "mitm-ctrl",
        CaptureSource::Replay => "replay",
        CaptureSource::Mock => "mock",
    }
}

fn capture_path_detail_label(origin: CaptureOrigin) -> &'static str {
    match origin.source() {
        CaptureSource::L7MitmPlaintext => mitm_capture_path_detail_label(origin.traffic_security()),
        source => capture_source_detail_label(source),
    }
}

fn mitm_capture_path_detail_label(traffic_security: CaptureTrafficSecurity) -> &'static str {
    match traffic_security {
        CaptureTrafficSecurity::Unknown => "MITM proxy path",
        CaptureTrafficSecurity::Cleartext => "MITM proxy path (plain HTTP)",
        CaptureTrafficSecurity::TlsDecrypted => "MITM proxy path (TLS-decrypted HTTP)",
    }
}

fn capture_source_detail_label(source: CaptureSource) -> &'static str {
    match source {
        CaptureSource::EbpfSyscall => "eBPF syscall capture",
        CaptureSource::Libpcap => "libpcap passive capture",
        CaptureSource::LibsslUprobe => "TLS plaintext uprobe",
        CaptureSource::TlsSessionSecret => "TLS session secret decryption",
        CaptureSource::ExternalPlaintextFeed => "external plaintext feed",
        CaptureSource::L7MitmPlaintext => "MITM proxy path",
        CaptureSource::L7MitmControlPlane => "MITM control plane",
        CaptureSource::Replay => "replay",
        CaptureSource::Mock => "mock",
    }
}

fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "in",
        Direction::Outbound => "out",
    }
}

struct EventKindDisplay {
    summary: String,
    details: Vec<String>,
}

fn event_kind_display(kind: &EventKind, include_details: bool) -> EventKindDisplay {
    match kind {
        EventKind::ConnectionOpened => EventKindDisplay {
            summary: "connection opened".to_string(),
            details: detail_if(include_details, || vec!["Connection: opened".to_string()]),
        },
        EventKind::ConnectionClosed => EventKindDisplay {
            summary: "connection closed".to_string(),
            details: detail_if(include_details, || vec!["Connection: closed".to_string()]),
        },
        EventKind::HttpRequestHeaders(headers) => EventKindDisplay {
            summary: format!(
                "{} {}",
                headers.method.as_deref().unwrap_or("-"),
                headers.target.as_deref().unwrap_or("-")
            ),
            details: detail_if(include_details, || http_header_detail_lines(headers)),
        },
        EventKind::HttpResponseHeaders(headers) => EventKindDisplay {
            summary: format!(
                "{} {}",
                headers
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                headers.reason.as_deref().unwrap_or("")
            ),
            details: detail_if(include_details, || http_header_detail_lines(headers)),
        },
        EventKind::HttpBodyChunk(chunk) => EventKindDisplay {
            summary: format!("body {} bytes at {}", chunk.data.len(), chunk.offset),
            details: detail_if(include_details, || {
                vec![
                    format!("HTTP direction: {}", direction_label(chunk.direction)),
                    format!("HTTP stream: {}", chunk.stream_sequence),
                    format!("Body offset: {}", chunk.offset),
                    format!("Body bytes: {}", chunk.data.len()),
                    format!("End stream: {}", chunk.end_stream),
                    format!("Body payload: {}", bytes_detail(chunk.data.as_ref())),
                ]
            }),
        },
        EventKind::SseEvent(event) => EventKindDisplay {
            summary: format!("sse {} bytes", event.data.len()),
            details: detail_if(include_details, || {
                vec![
                    format!("SSE direction: {}", direction_label(event.direction)),
                    format!("SSE stream: {}", event.stream_sequence),
                    format!("SSE event: {}", event.event.as_deref().unwrap_or("-")),
                    format!("SSE id: {}", event.id.as_deref().unwrap_or("-")),
                    format!(
                        "SSE retry ms: {}",
                        event
                            .retry_ms
                            .map(|retry| retry.to_string())
                            .unwrap_or_else(|| "-".to_string())
                    ),
                    format!("SSE data: {}", escape_text(&event.data)),
                ]
            }),
        },
        EventKind::WebSocketHandoff(handoff) => EventKindDisplay {
            summary: format!(
                "websocket {}",
                handoff.target.as_deref().unwrap_or("handoff")
            ),
            details: detail_if(include_details, || {
                vec![
                    format!(
                        "WebSocket direction: {}",
                        direction_label(handoff.direction)
                    ),
                    format!("WebSocket stream: {}", handoff.stream_sequence),
                    format!("Target: {}", handoff.target.as_deref().unwrap_or("-")),
                    format!(
                        "Subprotocol: {}",
                        handoff.subprotocol.as_deref().unwrap_or("-")
                    ),
                    format!("Extensions: {}", handoff.extensions.join(", ")),
                ]
            }),
        },
        EventKind::WebSocketFrame(frame) => EventKindDisplay {
            summary: format!("ws frame {:?} {} bytes", frame.opcode, frame.payload_len),
            details: detail_if(include_details, || {
                vec![
                    format!("WebSocket direction: {}", direction_label(frame.direction)),
                    format!("WebSocket stream: {}", frame.stream_sequence),
                    format!("Frame: {}", frame.frame_sequence),
                    format!("Opcode: {:?}", frame.opcode),
                    format!("FIN: {}", frame.fin),
                    format!("Payload bytes: {}", frame.payload_len),
                    format!("Masked: {}", frame.masked),
                    format!("Fingerprint: {}", hex_preview(&frame.payload_fingerprint)),
                ]
            }),
        },
        EventKind::WebSocketMessage(message) => EventKindDisplay {
            summary: format!(
                "ws message {:?} {} bytes",
                message.opcode, message.payload_len
            ),
            details: detail_if(include_details, || {
                vec![
                    format!(
                        "WebSocket direction: {}",
                        direction_label(message.direction)
                    ),
                    format!("WebSocket stream: {}", message.stream_sequence),
                    format!("Message: {}", message.message_sequence),
                    format!(
                        "Frames: {}..{}",
                        message.first_frame_sequence, message.final_frame_sequence
                    ),
                    format!("Opcode: {:?}", message.opcode),
                    format!("Payload bytes: {}", message.payload_len),
                    format!("Payload: {}", bytes_detail(message.payload.as_ref())),
                    format!("Fingerprint: {}", hex_preview(&message.payload_fingerprint)),
                ]
            }),
        },
        EventKind::OpaqueStream(stream) => EventKindDisplay {
            summary: stream.reason.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Direction: {}", direction_label(stream.direction)),
                    format!("Reason: {}", stream.reason),
                ]
            }),
        },
        EventKind::CaptureLoss(loss) => EventKindDisplay {
            summary: format!("capture loss {} events: {}", loss.lost_events, loss.reason),
            details: detail_if(include_details, || {
                vec![
                    format!("Lost events: {}", loss.lost_events),
                    format!("Reason: {}", loss.reason),
                ]
            }),
        },
        EventKind::Gap(gap) => EventKindDisplay {
            summary: gap.reason.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Direction: {}", direction_label(gap.direction)),
                    format!("Reason: {}", gap.reason),
                ]
            }),
        },
        EventKind::ProtocolError(error) => EventKindDisplay {
            summary: error.reason.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Direction: {}", direction_label(error.direction)),
                    format!("Reason: {}", error.reason),
                ]
            }),
        },
        EventKind::PolicyAlert(alert) => EventKindDisplay {
            summary: alert.message.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Message: {}", alert.message),
                    format!("Metadata: {}", escape_text(&alert.metadata.to_string())),
                ]
            }),
        },
        EventKind::PolicyVerdict(verdict) => EventKindDisplay {
            summary: format!("verdict {:?}: {}", verdict.action, verdict.reason),
            details: detail_if(include_details, || {
                vec![
                    format!("Action: {:?}", verdict.action),
                    format!("Reason: {}", verdict.reason),
                ]
            }),
        },
        EventKind::PolicyRuntimeError(error) => EventKindDisplay {
            summary: error.reason.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Policy event type: {}", error.event_type),
                    format!("Reason: {}", error.reason),
                ]
            }),
        },
        EventKind::EnforcementDecision(decision) => EventKindDisplay {
            summary: format!("{:?}: {}", decision.outcome, decision.reason),
            details: detail_if(include_details, || {
                vec![
                    format!("Outcome: {:?}", decision.outcome),
                    format!("Reason: {}", decision.reason),
                ]
            }),
        },
        EventKind::L7MitmAudit(audit) => EventKindDisplay {
            summary: audit
                .reason()
                .map(str::to_string)
                .unwrap_or_else(|| format!("{:?}", audit.phase())),
            details: detail_if(include_details, || {
                vec![
                    format!("Phase: {:?}", audit.phase()),
                    format!("Reason: {}", audit.reason().unwrap_or("-")),
                ]
            }),
        },
    }
}

fn detail_if(include_details: bool, build: impl FnOnce() -> Vec<String>) -> Vec<String> {
    if include_details { build() } else { Vec::new() }
}

fn http_header_detail_lines(headers: &probe_core::HttpHeaders) -> Vec<String> {
    let mut lines = vec![
        format!("HTTP direction: {}", direction_label(headers.direction)),
        format!("HTTP stream: {}", headers.stream_sequence),
        format!("HTTP version: {}", headers.version),
    ];
    if let Some(method) = &headers.method {
        lines.push(format!("Method: {method}"));
    }
    if let Some(target) = &headers.target {
        lines.push(format!("Target: {target}"));
    }
    if let Some(status) = headers.status {
        lines.push(format!("Status: {status}"));
    }
    if let Some(reason) = &headers.reason {
        lines.push(format!("Reason: {reason}"));
    }
    lines.push(format!("Headers: {}", headers.headers.len()));
    lines.extend(
        headers
            .headers
            .iter()
            .map(|(name, value)| format!("{name}: {}", escape_text(value))),
    );
    lines
}

fn fit_preview_lines(mut lines: Vec<String>, max_lines: usize) -> Vec<String> {
    let max_lines = max_lines.max(1);
    if lines.len() <= max_lines {
        return lines;
    }
    let prompt = lines.pop().unwrap_or_else(|| "Open detail".to_string());
    lines.truncate(max_lines);
    if let Some(last) = lines.last_mut() {
        *last = prompt;
    }
    lines
}

fn event_detail_lines(sequence: u64, event: &EventEnvelope) -> Vec<String> {
    let mut lines = vec![
        format!("Sequence: {sequence}"),
        format!("Event id: {}", event.id().as_str()),
        format!("Event type: {}", event.kind().event_type()),
        format!("Timestamp ns: {}", event.timestamp().wall_time_unix_ns),
        format!(
            "Capture path: {}",
            capture_path_detail_label(event.origin())
        ),
        format!(
            "Origin: source={} provider={} traffic_security={}",
            event.origin().source().wire_name(),
            event.origin().provider().wire_name(),
            event.origin().traffic_security().wire_name()
        ),
        format!("Config version: {}", event.config_version()),
        format!("Degraded: {}", event.degraded()),
    ];
    if let Some(policy_version) = event.policy_version() {
        lines.push(format!("Policy version: {policy_version}"));
    }
    if let Some(flow) = event.flow() {
        lines.extend([
            format!(
                "Process: {} pid={} uid={} gid={}",
                flow.process.name,
                flow.process.identity.pid,
                flow.process.identity.uid,
                flow.process.identity.gid
            ),
            format!("Executable: {}", flow.process.identity.exe_path),
            format!("Local: {}:{}", flow.local.address, flow.local.port),
            format!("Remote: {}:{}", flow.remote.address, flow.remote.port),
            format!("Protocol: {:?}", flow.protocol),
            format!("Attribution confidence: {}", flow.attribution_confidence),
        ]);
    }
    lines.extend(event_kind_display(event.kind(), true).details);
    lines
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
            "response budget: {}/{} bytes{}",
            row.budget.included_payload_bytes,
            row.budget.max_response_payload_bytes,
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

fn hex_preview(bytes: &[u8]) -> String {
    let hex = bytes
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");
    if bytes.len() > 32 {
        format!("{hex}...")
    } else if hex.is_empty() {
        "-".to_string()
    } else {
        hex
    }
}

fn bytes_detail(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => escape_text(text),
        Err(_) => format!("hex: {}", hex_full(bytes)),
    }
}

fn hex_full(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn escape_text(value: &str) -> String {
    if value.is_empty() {
        return "-".to_string();
    }
    let mut output = String::new();
    for character in value.chars() {
        for escaped in character.escape_default() {
            output.push(escaped);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, BodyChunk, CaptureOrigin, CaptureSource, FlowContext, FlowIdentity,
        HttpHeaders, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
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

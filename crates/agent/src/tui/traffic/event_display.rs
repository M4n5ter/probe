use probe_core::{CaptureOrigin, CaptureSource, CaptureTrafficSecurity, HttpHeaders};

use crate::tui::copy::{MITM_HTTP_PATH_LABEL, MITM_TLS_PATH_LABEL};

use super::{
    attribution::TrafficAttribution,
    event_ref::{
        TrafficEventKindRef, TrafficEventRef, TrafficHttpBodyChunk, TrafficSseEvent,
        TrafficWebSocketMessage,
    },
    text::{bytes_detail, direction_label, escape_text},
};

pub(super) struct EventKindDisplay {
    pub(super) summary: String,
    pub(super) details: Vec<String>,
}

pub(super) fn capture_path_short_label(origin: CaptureOrigin) -> &'static str {
    match origin.source() {
        CaptureSource::L7MitmPlaintext => mitm_capture_path_short_label(origin.traffic_security()),
        source => capture_source_short_label(source),
    }
}

pub(super) fn event_kind_display(
    kind: TrafficEventKindRef<'_>,
    include_details: bool,
) -> EventKindDisplay {
    match kind {
        TrafficEventKindRef::ConnectionOpened => EventKindDisplay {
            summary: "connection opened".to_string(),
            details: detail_if(include_details, || vec!["Connection: opened".to_string()]),
        },
        TrafficEventKindRef::ConnectionClosed => EventKindDisplay {
            summary: "connection closed".to_string(),
            details: detail_if(include_details, || vec!["Connection: closed".to_string()]),
        },
        TrafficEventKindRef::HttpRequestHeaders(headers) => EventKindDisplay {
            summary: format!(
                "{} {}",
                headers.method.as_deref().unwrap_or("-"),
                headers.target.as_deref().unwrap_or("-")
            ),
            details: detail_if(include_details, || http_header_detail_lines(headers)),
        },
        TrafficEventKindRef::HttpResponseHeaders(headers) => EventKindDisplay {
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
        TrafficEventKindRef::HttpBodyChunk(chunk) => EventKindDisplay {
            summary: format!("body {} bytes at {}", chunk.data_len, chunk.offset),
            details: detail_if(include_details, || body_chunk_detail_lines(chunk)),
        },
        TrafficEventKindRef::SseEvent(event) => EventKindDisplay {
            summary: format!("sse {} bytes", event.data_len),
            details: detail_if(include_details, || sse_detail_lines(event)),
        },
        TrafficEventKindRef::WebSocketHandoff(handoff) => EventKindDisplay {
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
        TrafficEventKindRef::WebSocketFrame(frame) => EventKindDisplay {
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
        TrafficEventKindRef::WebSocketMessage(message) => EventKindDisplay {
            summary: format!(
                "ws message {:?} {} bytes",
                message.opcode, message.payload_len
            ),
            details: detail_if(include_details, || websocket_message_detail_lines(message)),
        },
        TrafficEventKindRef::OpaqueStream(stream) => EventKindDisplay {
            summary: stream.reason.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Direction: {}", direction_label(stream.direction)),
                    format!("Reason: {}", stream.reason),
                ]
            }),
        },
        TrafficEventKindRef::CaptureLoss(loss) => EventKindDisplay {
            summary: format!("capture loss {} events: {}", loss.lost_events, loss.reason),
            details: detail_if(include_details, || {
                vec![
                    format!("Lost events: {}", loss.lost_events),
                    format!("Reason: {}", loss.reason),
                ]
            }),
        },
        TrafficEventKindRef::Gap(gap) => EventKindDisplay {
            summary: gap.reason.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Direction: {}", direction_label(gap.direction)),
                    format!("Reason: {}", gap.reason),
                ]
            }),
        },
        TrafficEventKindRef::ProtocolError(error) => EventKindDisplay {
            summary: error.reason.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Direction: {}", direction_label(error.direction)),
                    format!("Reason: {}", error.reason),
                ]
            }),
        },
        TrafficEventKindRef::PolicyAlert(alert) => EventKindDisplay {
            summary: alert.message.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Message: {}", alert.message),
                    format!("Metadata: {}", escape_text(&alert.metadata.to_string())),
                ]
            }),
        },
        TrafficEventKindRef::PolicyVerdict(verdict) => EventKindDisplay {
            summary: format!("verdict {:?}: {}", verdict.action, verdict.reason),
            details: detail_if(include_details, || {
                vec![
                    format!("Action: {:?}", verdict.action),
                    format!("Reason: {}", verdict.reason),
                ]
            }),
        },
        TrafficEventKindRef::PolicyRuntimeError(error) => EventKindDisplay {
            summary: error.reason.clone(),
            details: detail_if(include_details, || {
                vec![
                    format!("Policy event type: {}", error.event_type),
                    format!("Reason: {}", error.reason),
                ]
            }),
        },
        TrafficEventKindRef::EnforcementDecision(decision) => EventKindDisplay {
            summary: format!("{:?}: {}", decision.outcome, decision.reason),
            details: detail_if(include_details, || {
                vec![
                    format!("Outcome: {:?}", decision.outcome),
                    format!("Reason: {}", decision.reason),
                ]
            }),
        },
        TrafficEventKindRef::L7MitmAudit(audit) => EventKindDisplay {
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

pub(super) fn event_detail_lines(
    sequence: u64,
    event: TrafficEventRef<'_>,
    attribution: Option<&TrafficAttribution>,
) -> Vec<String> {
    let mut lines = vec![
        format!("Sequence: {sequence}"),
        format!("Event id: {}", event.event_id()),
        format!("Event type: {}", event.event_type()),
        format!("Timestamp ns: {}", event.wall_time_unix_ns()),
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
        let attribution = attribution
            .cloned()
            .unwrap_or_else(|| TrafficAttribution::from_event(event));
        lines.extend(attribution.detail_lines());
    }
    lines.extend(event_kind_display(event.kind(), true).details);
    if event.is_tail() {
        lines.push("Full payload: open raw event detail".to_string());
    }
    lines
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

fn detail_if(include_details: bool, build: impl FnOnce() -> Vec<String>) -> Vec<String> {
    if include_details { build() } else { Vec::new() }
}

fn http_header_detail_lines(headers: &HttpHeaders) -> Vec<String> {
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

fn body_chunk_detail_lines(chunk: TrafficHttpBodyChunk<'_>) -> Vec<String> {
    vec![
        format!("HTTP direction: {}", direction_label(chunk.direction)),
        format!("HTTP stream: {}", chunk.stream_sequence),
        format!("Body offset: {}", chunk.offset),
        format!("Body bytes: {}", chunk.data_len),
        format!("End stream: {}", chunk.end_stream),
        format!(
            "Body payload: {}",
            chunk
                .data
                .map(bytes_detail)
                .unwrap_or_else(|| "open full event detail".to_string())
        ),
    ]
}

fn sse_detail_lines(event: TrafficSseEvent<'_>) -> Vec<String> {
    vec![
        format!("SSE direction: {}", direction_label(event.direction)),
        format!("SSE stream: {}", event.stream_sequence),
        format!("SSE event: {}", event.event.unwrap_or("-")),
        format!("SSE id: {}", event.id.unwrap_or("-")),
        format!(
            "SSE retry ms: {}",
            event
                .retry_ms
                .map(|retry| retry.to_string())
                .unwrap_or_else(|| "-".to_string())
        ),
        format!("SSE data bytes: {}", event.data_len),
        format!(
            "SSE data: {}",
            event
                .data
                .map(escape_text)
                .unwrap_or_else(|| "open full event detail".to_string())
        ),
    ]
}

fn websocket_message_detail_lines(message: TrafficWebSocketMessage<'_>) -> Vec<String> {
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
        format!(
            "Payload: {}",
            message
                .payload
                .map(bytes_detail)
                .unwrap_or_else(|| "open full event detail".to_string())
        ),
        format!("Fingerprint: {}", hex_preview(message.payload_fingerprint)),
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

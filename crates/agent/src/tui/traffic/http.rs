use std::collections::BTreeMap;

use probe_core::{Direction, EventEnvelope, EventKind, HttpHeaders};

use super::rows::TrafficRow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpExchangeRow {
    pub(crate) sequence: u64,
    pub(crate) process: String,
    pub(crate) capture_path: &'static str,
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) status: String,
    pub(crate) direction: String,
    pub(crate) endpoint: String,
    pub(crate) summary: String,
    request: HttpMessage,
    response: HttpMessage,
    raw_sequences: Vec<u64>,
}

impl HttpExchangeRow {
    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Sequence: {}", self.sequence),
            "View: HTTP exchange".to_string(),
            format!("Process: {}", self.process),
            format!("Capture path: {}", self.capture_path),
            format!("Direction: {}", self.direction),
            format!("Remote: {}", self.endpoint),
            format!("Summary: {}", self.summary),
        ];
        lines.extend(self.request.detail_lines("Request"));
        lines.extend(self.response.detail_lines("Response"));
        lines.push(format!(
            "Raw event sequences: {}",
            self.raw_sequences
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        lines
    }

    pub(crate) fn preview_lines(&self, max_lines: usize) -> Vec<String> {
        let mut lines = vec![
            format!("Sequence: {}", self.sequence),
            "View: HTTP exchange".to_string(),
            format!("Process: {}", self.process),
            format!("Remote: {}", self.endpoint),
            format!("Request: {} {}", self.method, self.target),
            format!("Response: {}", self.status),
            format!("Request body: {} bytes", self.request.body_len()),
            format!("Response body: {} bytes", self.response.body_len()),
            "Open detail for headers and full payloads".to_string(),
        ];
        fit_preview_lines(&mut lines, max_lines)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HttpMessage {
    headers: Option<HttpHeaders>,
    body: Vec<BodyChunk>,
}

impl HttpMessage {
    fn body_len(&self) -> usize {
        self.body.iter().map(|chunk| chunk.data.len()).sum()
    }

    fn detail_lines(&self, label: &str) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(label.to_string());
        match &self.headers {
            Some(headers) => {
                lines.push(format!(
                    "  Direction: {}",
                    direction_label(headers.direction)
                ));
                lines.push(format!("  Stream: {}", headers.stream_sequence));
                lines.push(format!("  Version: {}", headers.version));
                if let Some(method) = &headers.method {
                    lines.push(format!("  Method: {method}"));
                }
                if let Some(target) = &headers.target {
                    lines.push(format!("  Target: {target}"));
                }
                if let Some(status) = headers.status {
                    lines.push(format!("  Status: {status}"));
                }
                if let Some(reason) = &headers.reason {
                    lines.push(format!("  Reason: {reason}"));
                }
                lines.push(format!("  Headers: {}", headers.headers.len()));
                lines.extend(
                    headers
                        .headers
                        .iter()
                        .map(|(name, value)| format!("  {name}: {}", escape_text(value))),
                );
            }
            None => lines.push("  Headers: not observed in current window".to_string()),
        }
        lines.push(format!("  Body bytes: {}", self.body_len()));
        if self.body.is_empty() {
            lines.push("  Body payload: -".to_string());
        } else {
            for chunk in sorted_body_chunks(&self.body) {
                lines.push(format!(
                    "  Body chunk offset={} end_stream={}: {}",
                    chunk.offset,
                    chunk.end_stream,
                    bytes_detail(&chunk.data)
                ));
            }
        }
        lines
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BodyChunk {
    offset: u64,
    data: Vec<u8>,
    end_stream: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HttpExchangeKey {
    flow_id: String,
    stream_sequence: u64,
}

#[derive(Debug, Clone)]
struct HttpExchangeBuilder {
    first_sequence: u64,
    process: String,
    capture_path: &'static str,
    endpoint: String,
    request: HttpMessage,
    response: HttpMessage,
    raw_sequences: Vec<u64>,
}

impl HttpExchangeBuilder {
    fn new(row: &TrafficRow) -> Self {
        Self {
            first_sequence: row.sequence,
            process: row.process.clone(),
            capture_path: row.capture_path,
            endpoint: row.endpoint.clone(),
            request: HttpMessage::default(),
            response: HttpMessage::default(),
            raw_sequences: Vec::new(),
        }
    }

    fn observe(&mut self, row: &TrafficRow, event: &EventEnvelope) {
        self.first_sequence = self.first_sequence.min(row.sequence);
        self.raw_sequences.push(row.sequence);
        match event.kind() {
            EventKind::HttpRequestHeaders(headers) => self.request.headers = Some(headers.clone()),
            EventKind::HttpResponseHeaders(headers) => {
                self.response.headers = Some(headers.clone())
            }
            EventKind::HttpBodyChunk(chunk) => {
                let body = BodyChunk {
                    offset: chunk.offset,
                    data: chunk.data.to_vec(),
                    end_stream: chunk.end_stream,
                };
                if self.body_direction_is_response(chunk.direction) {
                    self.response.body.push(body);
                } else {
                    self.request.body.push(body);
                }
            }
            _ => {}
        }
    }

    fn body_direction_is_response(&self, direction: Direction) -> bool {
        self.response
            .headers
            .as_ref()
            .is_some_and(|headers| headers.direction == direction)
            || (self.request.headers.is_none()
                && self
                    .response
                    .headers
                    .as_ref()
                    .is_some_and(|headers| headers.direction == direction))
    }

    fn into_row(mut self) -> HttpExchangeRow {
        self.raw_sequences.sort_unstable();
        self.raw_sequences.dedup();
        let method = self
            .request
            .headers
            .as_ref()
            .and_then(|headers| headers.method.clone())
            .unwrap_or_else(|| "-".to_string());
        let target = self
            .request
            .headers
            .as_ref()
            .and_then(|headers| headers.target.clone())
            .unwrap_or_else(|| "-".to_string());
        let status = self
            .response
            .headers
            .as_ref()
            .and_then(|headers| {
                headers
                    .status
                    .map(|status| format!("{status} {}", headers.reason.as_deref().unwrap_or("")))
            })
            .unwrap_or_else(|| "pending".to_string());
        let direction = self
            .request
            .headers
            .as_ref()
            .map(|headers| direction_label(headers.direction).to_string())
            .or_else(|| {
                self.response
                    .headers
                    .as_ref()
                    .map(|headers| direction_label(headers.direction).to_string())
            })
            .unwrap_or_else(|| "-".to_string());
        let summary = format!(
            "{} {} -> {} (req {} B, resp {} B)",
            method,
            target,
            status,
            self.request.body_len(),
            self.response.body_len()
        );
        HttpExchangeRow {
            sequence: self.first_sequence,
            process: self.process,
            capture_path: self.capture_path,
            method,
            target,
            status,
            direction,
            endpoint: self.endpoint,
            summary,
            request: self.request,
            response: self.response,
            raw_sequences: self.raw_sequences,
        }
    }
}

pub(super) fn build_http_exchange_rows(rows: &[TrafficRow]) -> Vec<HttpExchangeRow> {
    let mut exchanges = BTreeMap::<HttpExchangeKey, HttpExchangeBuilder>::new();
    for row in rows {
        let Some(event) = row.event() else {
            continue;
        };
        let Some(key) = http_exchange_key(event) else {
            continue;
        };
        exchanges
            .entry(key)
            .or_insert_with(|| HttpExchangeBuilder::new(row))
            .observe(row, event);
    }
    exchanges
        .into_values()
        .map(HttpExchangeBuilder::into_row)
        .collect()
}

fn http_exchange_key(event: &EventEnvelope) -> Option<HttpExchangeKey> {
    let flow_id = event.flow()?.id.0.clone();
    let stream_sequence = match event.kind() {
        EventKind::HttpRequestHeaders(headers) | EventKind::HttpResponseHeaders(headers) => {
            headers.stream_sequence
        }
        EventKind::HttpBodyChunk(chunk) => chunk.stream_sequence,
        _ => return None,
    };
    Some(HttpExchangeKey {
        flow_id,
        stream_sequence,
    })
}

fn sorted_body_chunks(chunks: &[BodyChunk]) -> Vec<&BodyChunk> {
    let mut chunks = chunks.iter().collect::<Vec<_>>();
    chunks.sort_by_key(|chunk| chunk.offset);
    chunks
}

fn fit_preview_lines(lines: &mut Vec<String>, max_lines: usize) -> Vec<String> {
    let max_lines = max_lines.max(1);
    if lines.len() <= max_lines {
        return std::mem::take(lines);
    }
    let prompt = lines.pop().unwrap_or_else(|| "Open detail".to_string());
    lines.truncate(max_lines);
    if let Some(last) = lines.last_mut() {
        *last = prompt;
    }
    std::mem::take(lines)
}

fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "in",
        Direction::Outbound => "out",
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
    fn groups_http_request_response_and_bodies_into_exchange() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("POST".to_string()),
                    target: Some("/api/tasks".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("host".to_string(), "example.test".to_string())],
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: b"hello".to_vec().into(),
                    end_stream: true,
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(201),
                    reason: Some("Created".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "2".to_string())],
                })),
            ),
            TrafficRow::from_event(
                4,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: b"ok".to_vec().into(),
                    end_stream: true,
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);

        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange: {exchanges:?}");
        };
        assert_eq!(exchange.sequence, 1);
        assert_eq!(exchange.method, "POST");
        assert_eq!(exchange.target, "/api/tasks");
        assert_eq!(exchange.status, "201 Created");
        assert_eq!(
            exchange.summary,
            "POST /api/tasks -> 201 Created (req 5 B, resp 2 B)"
        );
        let details = exchange.detail_lines();
        assert!(
            details
                .iter()
                .any(|line| line == "  Body chunk offset=0 end_stream=true: hello")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Body chunk offset=0 end_stream=true: ok")
        );
    }

    fn event(kind: EventKind) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            test_flow(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            kind,
        )
    }

    fn test_flow() -> FlowContext {
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
            cmdline: vec!["curl".to_string()],
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

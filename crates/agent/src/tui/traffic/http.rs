use std::collections::BTreeMap;

use probe_core::{Direction, HttpHeaders};

use super::{
    event_ref::TrafficEventRef,
    rows::TrafficRow,
    text::{bytes_detail, direction_label, escape_text, fit_preview_lines},
};

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
    latest_sequence: u64,
    identity: HttpExchangeIdentity,
}

impl HttpExchangeRow {
    pub(crate) fn identity(&self) -> HttpExchangeIdentity {
        self.identity.clone()
    }

    pub(crate) fn matches_identity(&self, identity: &HttpExchangeIdentity) -> bool {
        &self.identity == identity
    }

    pub(crate) fn order_sequence(&self) -> u64 {
        self.latest_sequence
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Sequence: {}", self.sequence),
            format!("Latest event sequence: {}", self.latest_sequence),
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
        let lines = vec![
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
        fit_preview_lines(lines, max_lines)
    }

    pub(crate) fn detail_fetch_sequences(&self) -> Vec<u64> {
        self.request
            .detail_fetch_sequences()
            .into_iter()
            .chain(self.response.detail_fetch_sequences())
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HttpMessage {
    headers: Option<HttpHeaders>,
    body: Vec<BodyChunk>,
}

impl HttpMessage {
    fn body_len(&self) -> usize {
        self.body.iter().map(|chunk| chunk.data_len).sum()
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
        } else if self.body.iter().any(|chunk| chunk.data.is_none()) {
            lines.push("  Body payload: open raw event detail".to_string());
            lines.push(format!("  Body chunks: {}", self.body.len()));
            for chunk in sorted_body_chunks(&self.body) {
                lines.push(format!(
                    "  Body chunk offset={} len={} end_stream={}",
                    chunk.offset, chunk.data_len, chunk.end_stream
                ));
            }
        } else {
            lines.extend(self.body_payload_lines());
            lines.push(format!("  Body chunks: {}", self.body.len()));
            for chunk in sorted_body_chunks(&self.body) {
                let data = chunk
                    .data
                    .as_ref()
                    .expect("body payload was checked before rendering chunks");
                lines.push(format!(
                    "  Body chunk offset={} end_stream={}: {}",
                    chunk.offset,
                    chunk.end_stream,
                    bytes_detail(data)
                ));
            }
        }
        lines
    }

    fn detail_fetch_sequences(&self) -> Vec<u64> {
        self.body
            .iter()
            .filter(|chunk| chunk.data.is_none())
            .map(|chunk| chunk.sequence)
            .collect()
    }

    fn body_payload_lines(&self) -> Vec<String> {
        let Some(payload) = BodyPayloadDetail::from_chunks(&self.body) else {
            return vec!["  Body payload: -".to_string()];
        };
        match payload {
            BodyPayloadDetail::Complete { bytes } => {
                vec![format!("  Body payload: {}", bytes_detail(&bytes))]
            }
            BodyPayloadDetail::Incomplete {
                start_offset,
                observed_bytes,
                reason,
            } => {
                let label = if start_offset == 0 {
                    "  Body payload".to_string()
                } else {
                    format!("  Body payload from offset {start_offset}")
                };
                vec![
                    format!("{label}: incomplete"),
                    format!("  Observed body bytes: {}", bytes_detail(&observed_bytes)),
                    format!("  Incomplete reason: {reason}"),
                    "  Body payload is incomplete; chunk offsets below show the observed ranges"
                        .to_string(),
                ]
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BodyChunk {
    sequence: u64,
    offset: u64,
    data_len: usize,
    data: Option<Vec<u8>>,
    end_stream: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyPayloadDetail {
    Complete {
        bytes: Vec<u8>,
    },
    Incomplete {
        start_offset: u64,
        observed_bytes: Vec<u8>,
        reason: &'static str,
    },
}

impl BodyPayloadDetail {
    fn from_chunks(chunks: &[BodyChunk]) -> Option<Self> {
        let chunks = sorted_body_chunks(chunks);
        let first = chunks.first()?;
        let start_offset = first.offset;
        let mut next_offset = start_offset;
        let mut bytes = Vec::new();
        let mut has_gap = false;
        let mut has_end_stream = false;
        for chunk in chunks {
            has_end_stream |= chunk.end_stream;
            if chunk.offset > next_offset {
                has_gap = true;
                next_offset = chunk.offset;
            }
            let Some(data) = &chunk.data else {
                return None;
            };
            let overlap = next_offset.saturating_sub(chunk.offset) as usize;
            if overlap >= data.len() {
                continue;
            }
            let new_bytes = &data[overlap..];
            bytes.extend_from_slice(new_bytes);
            next_offset = next_offset.saturating_add(new_bytes.len() as u64);
        }
        if start_offset == 0 && !has_gap && has_end_stream {
            return Some(Self::Complete { bytes });
        }
        let reason = if start_offset != 0 {
            "body starts after offset 0"
        } else if has_gap {
            "missing bytes between observed chunks"
        } else {
            "end of stream was not observed"
        };
        Some(Self::Incomplete {
            start_offset,
            observed_bytes: bytes,
            reason,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct HttpExchangeIdentity {
    flow_id: String,
    stream_sequence: u64,
}

#[derive(Debug, Clone)]
struct HttpExchangeBuilder {
    identity: HttpExchangeIdentity,
    first_sequence: u64,
    latest_sequence: u64,
    process: String,
    capture_path: &'static str,
    endpoint: String,
    request: HttpMessage,
    response: HttpMessage,
    raw_sequences: Vec<u64>,
}

impl HttpExchangeBuilder {
    fn new(identity: HttpExchangeIdentity, row: &TrafficRow) -> Self {
        Self {
            identity,
            first_sequence: row.sequence,
            latest_sequence: row.sequence,
            process: row.process.clone(),
            capture_path: row.capture_path,
            endpoint: row.endpoint.clone(),
            request: HttpMessage::default(),
            response: HttpMessage::default(),
            raw_sequences: Vec::new(),
        }
    }

    fn observe(&mut self, row: &TrafficRow, event: TrafficEventRef<'_>) {
        self.first_sequence = self.first_sequence.min(row.sequence);
        self.latest_sequence = self.latest_sequence.max(row.sequence);
        self.raw_sequences.push(row.sequence);
        if let Some(headers) = event.http_request_headers() {
            self.request.headers = Some(headers.clone());
        } else if let Some(headers) = event.http_response_headers() {
            self.response.headers = Some(headers.clone());
        } else if let Some(chunk) = event.http_body_chunk() {
            let body = BodyChunk {
                sequence: row.sequence,
                offset: chunk.offset,
                data_len: chunk.data_len,
                data: chunk.data.map(<[u8]>::to_vec),
                end_stream: chunk.end_stream,
            };
            if self.body_direction_is_response(chunk.direction) {
                self.response.body.push(body);
            } else {
                self.request.body.push(body);
            }
        }
    }

    fn body_direction_is_response(&self, direction: Direction) -> bool {
        if let Some(headers) = &self.response.headers {
            return headers.direction == direction;
        }
        self.request
            .headers
            .as_ref()
            .is_some_and(|headers| headers.direction != direction)
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
            latest_sequence: self.latest_sequence,
            identity: self.identity,
        }
    }
}

pub(super) fn build_http_exchange_rows(rows: &[TrafficRow]) -> Vec<HttpExchangeRow> {
    let mut exchanges = BTreeMap::<HttpExchangeIdentity, HttpExchangeBuilder>::new();
    let mut ordered_rows = rows.iter().collect::<Vec<_>>();
    ordered_rows.sort_by_key(|row| row.sequence);
    for row in ordered_rows {
        let Some(event) = row.event_ref() else {
            continue;
        };
        let Some(key) = http_exchange_key(event) else {
            continue;
        };
        exchanges
            .entry(key.clone())
            .or_insert_with(|| HttpExchangeBuilder::new(key, row))
            .observe(row, event);
    }
    let mut rows = exchanges
        .into_values()
        .map(HttpExchangeBuilder::into_row)
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| std::cmp::Reverse(row.order_sequence()));
    rows
}

fn http_exchange_key(event: TrafficEventRef<'_>) -> Option<HttpExchangeIdentity> {
    let flow_id = event.flow()?.id.0.clone();
    let stream_sequence = event
        .http_request_headers()
        .map(|headers| headers.stream_sequence)
        .or_else(|| {
            event
                .http_response_headers()
                .map(|headers| headers.stream_sequence)
        })
        .or_else(|| event.http_body_chunk().map(|chunk| chunk.stream_sequence))?;
    Some(HttpExchangeIdentity {
        flow_id,
        stream_sequence,
    })
}

fn sorted_body_chunks(chunks: &[BodyChunk]) -> Vec<&BodyChunk> {
    let mut chunks = chunks.iter().collect::<Vec<_>>();
    chunks.sort_by_key(|chunk| chunk.offset);
    chunks
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, BodyChunk, CaptureOrigin, CaptureSource, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity, Timestamp,
        TransportProtocol,
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
        assert!(details.iter().any(|line| line == "  Body payload: hello"));
        assert!(details.iter().any(|line| line == "  Body payload: ok"));
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

    #[test]
    fn http_body_detail_reports_incomplete_payload_with_observed_chunks() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("POST".to_string()),
                    target: Some("/upload".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: b"hello".to_vec().into(),
                    end_stream: false,
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    offset: 8,
                    data: b"world".to_vec().into(),
                    end_stream: true,
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange");
        };
        let details = exchange.detail_lines();

        assert!(
            details
                .iter()
                .any(|line| line == "  Body payload: incomplete")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Observed body bytes: helloworld")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Incomplete reason: missing bytes between observed chunks")
        );
        assert!(
            details
                .iter()
                .any(|line| line.contains("payload is incomplete"))
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Body chunk offset=8 end_stream=true: world")
        );
    }

    #[test]
    fn http_body_detail_reports_unfinished_contiguous_payload_as_incomplete() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("POST".to_string()),
                    target: Some("/stream".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: b"partial".to_vec().into(),
                    end_stream: false,
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange");
        };
        let details = exchange.detail_lines();

        assert!(
            details
                .iter()
                .any(|line| line == "  Body payload: incomplete")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Incomplete reason: end of stream was not observed")
        );
    }

    #[test]
    fn response_body_without_response_headers_uses_opposite_request_direction() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("GET".to_string()),
                    target: Some("/windowed".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
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
            panic!("expected one exchange");
        };

        assert_eq!(
            exchange.summary,
            "GET /windowed -> pending (req 0 B, resp 2 B)"
        );
        let details = exchange.detail_lines();
        assert!(details.iter().any(|line| line == "  Body payload: ok"));
        assert!(
            details
                .iter()
                .any(|line| line == "  Headers: not observed in current window")
        );
    }

    #[test]
    fn groups_http_exchange_from_newest_first_rows_without_swapping_bodies() {
        let rows = vec![
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
            TrafficRow::from_event(
                3,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
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
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("POST".to_string()),
                    target: Some("/api/tasks".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange");
        };

        assert_eq!(
            exchange.summary,
            "POST /api/tasks -> 200 OK (req 5 B, resp 2 B)"
        );
        let details = exchange.detail_lines();
        assert!(details.iter().any(|line| line == "  Body payload: hello"));
        assert!(details.iter().any(|line| line == "  Body payload: ok"));
    }

    #[test]
    fn http_body_detail_reports_nonzero_start_offset_as_incomplete() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("POST".to_string()),
                    target: Some("/partial".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    offset: 5,
                    data: b"tail".to_vec().into(),
                    end_stream: true,
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange");
        };
        let details = exchange.detail_lines();

        assert!(
            details
                .iter()
                .any(|line| line == "  Body payload from offset 5: incomplete")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Incomplete reason: body starts after offset 0")
        );
    }

    #[test]
    fn http_body_detail_accepts_empty_terminal_chunk_as_complete() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("POST".to_string()),
                    target: Some("/chunked".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: b"hello".to_vec().into(),
                    end_stream: false,
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    offset: 5,
                    data: Vec::new().into(),
                    end_stream: true,
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange");
        };
        let details = exchange.detail_lines();

        assert!(details.iter().any(|line| line == "  Body payload: hello"));
        assert!(
            !details
                .iter()
                .any(|line| line.contains("Body payload is incomplete"))
        );
    }

    #[test]
    fn http_body_detail_accepts_zero_length_complete_body() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("POST".to_string()),
                    target: Some("/empty".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: Vec::new().into(),
                    end_stream: true,
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange");
        };
        let details = exchange.detail_lines();

        assert!(details.iter().any(|line| line == "  Body payload: -"));
        assert!(
            !details
                .iter()
                .any(|line| line.contains("Body payload is incomplete"))
        );
    }

    #[test]
    fn orders_http_exchanges_newest_first() {
        let rows = vec![
            TrafficRow::from_event(
                10,
                event_with_flow_id(
                    "z-late-flow",
                    EventKind::HttpRequestHeaders(HttpHeaders {
                        direction: Direction::Outbound,
                        stream_sequence: 1,
                        method: Some("GET".to_string()),
                        target: Some("/late".to_string()),
                        status: None,
                        reason: None,
                        version: "HTTP/1.1".to_string(),
                        headers: Vec::new(),
                    }),
                ),
            ),
            TrafficRow::from_event(
                1,
                event_with_flow_id(
                    "a-early-flow",
                    EventKind::HttpRequestHeaders(HttpHeaders {
                        direction: Direction::Outbound,
                        stream_sequence: 1,
                        method: Some("GET".to_string()),
                        target: Some("/early".to_string()),
                        status: None,
                        reason: None,
                        version: "HTTP/1.1".to_string(),
                        headers: Vec::new(),
                    }),
                ),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);

        assert_eq!(
            exchanges
                .iter()
                .map(|exchange| exchange.target.as_str())
                .collect::<Vec<_>>(),
            vec!["/late", "/early"]
        );
    }

    #[test]
    fn orders_http_exchanges_by_latest_activity_without_changing_identity_sequence() {
        let rows = vec![
            TrafficRow::from_event(
                10,
                event_with_flow_id(
                    "z-long-flow",
                    EventKind::HttpRequestHeaders(HttpHeaders {
                        direction: Direction::Outbound,
                        stream_sequence: 1,
                        method: Some("GET".to_string()),
                        target: Some("/long".to_string()),
                        status: None,
                        reason: None,
                        version: "HTTP/1.1".to_string(),
                        headers: Vec::new(),
                    }),
                ),
            ),
            TrafficRow::from_event(
                30,
                event_with_flow_id(
                    "a-new-flow",
                    EventKind::HttpRequestHeaders(HttpHeaders {
                        direction: Direction::Outbound,
                        stream_sequence: 1,
                        method: Some("GET".to_string()),
                        target: Some("/new".to_string()),
                        status: None,
                        reason: None,
                        version: "HTTP/1.1".to_string(),
                        headers: Vec::new(),
                    }),
                ),
            ),
            TrafficRow::from_event(
                40,
                event_with_flow_id(
                    "z-long-flow",
                    EventKind::HttpResponseHeaders(HttpHeaders {
                        direction: Direction::Inbound,
                        stream_sequence: 1,
                        method: None,
                        target: None,
                        status: Some(200),
                        reason: Some("OK".to_string()),
                        version: "HTTP/1.1".to_string(),
                        headers: Vec::new(),
                    }),
                ),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);

        assert_eq!(
            exchanges
                .iter()
                .map(|exchange| exchange.target.as_str())
                .collect::<Vec<_>>(),
            vec!["/long", "/new"]
        );
        assert_eq!(exchanges[0].sequence, 10);
        assert_eq!(exchanges[0].order_sequence(), 40);
    }

    fn event(kind: EventKind) -> EventEnvelope {
        event_with_flow_id("flow-a", kind)
    }

    fn event_with_flow_id(flow_id: &str, kind: EventKind) -> EventEnvelope {
        let mut flow = test_flow();
        flow.id = FlowIdentity(flow_id.to_string());
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

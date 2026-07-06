use std::collections::BTreeMap;

use probe_core::{Direction, HttpHeaders};

use super::{
    attribution::TrafficAttribution,
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
    pub(crate) request_body: String,
    pub(crate) response_body: String,
    pub(crate) direction: String,
    pub(crate) endpoint: String,
    pub(crate) summary: String,
    request: HttpMessage,
    response: HttpMessage,
    raw_sequences: Vec<u64>,
    latest_sequence: u64,
    identity: HttpExchangeIdentity,
    attribution: TrafficAttribution,
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
            "Overview".to_string(),
            format!("  Sequence: {}", self.sequence),
            format!("  Latest event sequence: {}", self.latest_sequence),
            "  View: HTTP exchange".to_string(),
            format!("  Process: {}", self.process),
        ];
        lines.extend(
            self.attribution
                .detail_lines()
                .into_iter()
                .map(|line| format!("  {line}")),
        );
        lines.extend([
            format!("  Capture path: {}", self.capture_path),
            format!("  Direction: {}", self.direction),
            format!("  Remote: {}", self.endpoint),
            format!("  Summary: {}", self.summary),
        ]);
        lines.push(String::new());
        lines.extend(self.request.start_lines(HttpMessageRole::Request));
        lines.extend(self.request.body_lines(HttpMessageRole::Request));
        lines.extend(self.request.header_lines(HttpMessageRole::Request));
        lines.push(String::new());
        lines.extend(self.response.start_lines(HttpMessageRole::Response));
        lines.extend(self.response.body_lines(HttpMessageRole::Response));
        lines.extend(self.response.header_lines(HttpMessageRole::Response));
        lines.push(String::new());
        lines.push("Raw events".to_string());
        lines.push(format!(
            "  Sequences: {}",
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
            format!("Request body: {}", self.request.body_preview()),
            format!("Response body: {}", self.response.body_preview()),
            "Full detail: request, response, headers, payloads".to_string(),
        ];
        fit_preview_lines(lines, max_lines)
    }

    pub(crate) fn detail_lines_with_loaded_rows<'a>(
        &self,
        loaded_rows: impl IntoIterator<Item = &'a TrafficRow>,
    ) -> Vec<String> {
        let mut hydrated = self.clone();
        for row in loaded_rows {
            hydrated.apply_loaded_row(row);
        }
        hydrated.detail_lines()
    }

    pub(crate) fn detail_fetch_sequences(&self) -> Vec<u64> {
        self.request
            .detail_fetch_sequences()
            .into_iter()
            .chain(self.response.detail_fetch_sequences())
            .collect()
    }

    fn apply_loaded_row(&mut self, row: &TrafficRow) {
        let Some(event) = row.event_ref() else {
            return;
        };
        if http_exchange_key(event).as_ref() != Some(&self.identity) {
            return;
        }
        let Some(chunk) = event.http_body_chunk() else {
            return;
        };
        let body = if body_direction_is_response(&self.request, &self.response, chunk.direction) {
            &mut self.response.body
        } else {
            &mut self.request.body
        };
        let Some(existing) = body
            .iter_mut()
            .find(|existing| existing.sequence == row.sequence)
        else {
            return;
        };
        existing.offset = chunk.offset;
        existing.data_len = chunk.data_len;
        existing.data = chunk.data.map(<[u8]>::to_vec);
        existing.end_stream = chunk.end_stream;
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

    fn body_preview(&self) -> String {
        let bytes = self.body_len();
        let status = self.body_payload_status();
        format!("{} bytes ({})", bytes, status.preview_label())
    }

    fn body_table_label(&self) -> String {
        let bytes = self.body_len();
        let status = self.body_payload_status();
        format!("{bytes}B {}", status.preview_label())
    }

    fn body_payload_status(&self) -> BodyPayloadStatus {
        if self.body.is_empty() {
            return BodyPayloadStatus::None;
        }
        let missing_chunks = self
            .body
            .iter()
            .filter(|chunk| chunk.data.is_none())
            .count();
        if missing_chunks == self.body.len() {
            return BodyPayloadStatus::NotLoaded { missing_chunks };
        }
        if missing_chunks > 0 {
            return BodyPayloadStatus::Partial { missing_chunks };
        }
        match BodyPayloadScan::scan(&self.body, false)
            .expect("non-empty loaded body chunks must classify")
            .coverage
        {
            BodyPayloadCoverage::Complete => BodyPayloadStatus::Loaded,
            BodyPayloadCoverage::Incomplete { .. } => BodyPayloadStatus::Incomplete,
        }
    }

    fn body_payload_state(&self) -> BodyPayloadState {
        match self.body_payload_status() {
            BodyPayloadStatus::None => BodyPayloadState::None,
            BodyPayloadStatus::NotLoaded { missing_chunks } => {
                BodyPayloadState::NotLoaded { missing_chunks }
            }
            BodyPayloadStatus::Partial { missing_chunks } => {
                let loaded = sorted_body_chunks(&self.body)
                    .into_iter()
                    .filter_map(|chunk| chunk.data.as_ref())
                    .flat_map(|data| data.iter().copied())
                    .collect::<Vec<_>>();
                BodyPayloadState::Partial {
                    loaded,
                    missing_chunks,
                }
            }
            BodyPayloadStatus::Loaded | BodyPayloadStatus::Incomplete => {
                match BodyPayloadDetail::from_chunks(&self.body)
                    .expect("non-empty loaded body chunks must classify")
                {
                    BodyPayloadDetail::Complete { bytes } => BodyPayloadState::Loaded { bytes },
                    BodyPayloadDetail::Incomplete {
                        start_offset,
                        observed_bytes,
                        reason,
                    } => BodyPayloadState::Incomplete {
                        start_offset,
                        observed_bytes,
                        reason,
                    },
                }
            }
        }
    }

    fn start_lines(&self, role: HttpMessageRole) -> Vec<String> {
        let label = role.label();
        let mut lines = vec![label.to_string()];
        match &self.headers {
            Some(headers) => lines.push(format!("  {}", role.start_line(headers))),
            None => lines.push("  Start line: not observed in current window".to_string()),
        }
        lines
    }

    fn header_lines(&self, role: HttpMessageRole) -> Vec<String> {
        let label = role.label();
        let mut lines = Vec::new();
        lines.push(format!("{label} headers"));
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
            None => {
                lines.push("  Headers: not observed in current window".to_string());
            }
        }
        lines
    }

    fn body_lines(&self, role: HttpMessageRole) -> Vec<String> {
        let label = role.label();
        let mut lines = Vec::new();
        lines.push(format!("{label} body"));
        lines.push(format!("  Body bytes: {}", self.body_len()));
        let state = self.body_payload_state();
        lines.extend(state.detail_lines());
        if state.has_chunks() {
            lines.push(format!("  Body chunks: {}", self.body.len()));
            for chunk in sorted_body_chunks(&self.body) {
                match &chunk.data {
                    Some(data) => lines.push(format!(
                        "  Body chunk offset={} end_stream={}: {}",
                        chunk.offset,
                        chunk.end_stream,
                        bytes_detail(data)
                    )),
                    None => lines.push(format!(
                        "  Body chunk offset={} len={} end_stream={} not_loaded=true",
                        chunk.offset, chunk.data_len, chunk.end_stream
                    )),
                }
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpMessageRole {
    Request,
    Response,
}

impl HttpMessageRole {
    fn label(self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::Response => "Response",
        }
    }

    fn start_line(self, headers: &HttpHeaders) -> String {
        match self {
            Self::Request => format!(
                "{} {} {}",
                headers.method.as_deref().unwrap_or("-"),
                headers.target.as_deref().unwrap_or("-"),
                headers.version
            ),
            Self::Response => format!(
                "{} {} {}",
                headers.version,
                headers
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                headers.reason.as_deref().unwrap_or("")
            )
            .trim_end()
            .to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyPayloadStatus {
    None,
    NotLoaded { missing_chunks: usize },
    Partial { missing_chunks: usize },
    Loaded,
    Incomplete,
}

impl BodyPayloadStatus {
    fn preview_label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::NotLoaded { .. } => "not loaded",
            Self::Partial { .. } => "partial",
            Self::Loaded => "loaded",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyPayloadState {
    None,
    NotLoaded {
        missing_chunks: usize,
    },
    Partial {
        loaded: Vec<u8>,
        missing_chunks: usize,
    },
    Loaded {
        bytes: Vec<u8>,
    },
    Incomplete {
        start_offset: u64,
        observed_bytes: Vec<u8>,
        reason: &'static str,
    },
}

impl BodyPayloadState {
    fn detail_lines(&self) -> Vec<String> {
        match self {
            Self::None => vec!["  Body payload: -".to_string()],
            Self::NotLoaded { missing_chunks } => vec![
                "  Body payload: not loaded in tail response".to_string(),
                format!("  Missing body chunks: {missing_chunks}"),
            ],
            Self::Partial {
                loaded,
                missing_chunks,
            } => vec![
                "  Body payload: partially loaded".to_string(),
                format!("  Observed loaded body bytes: {}", bytes_detail(loaded)),
                format!("  Missing body chunks: {missing_chunks}"),
            ],
            Self::Loaded { bytes } => vec![format!("  Body payload: {}", bytes_detail(bytes))],
            Self::Incomplete {
                start_offset,
                observed_bytes,
                reason,
            } => {
                let label = if *start_offset == 0 {
                    "  Body payload".to_string()
                } else {
                    format!("  Body payload from offset {start_offset}")
                };
                vec![
                    format!("{label}: incomplete"),
                    format!("  Observed body bytes: {}", bytes_detail(observed_bytes)),
                    format!("  Incomplete reason: {reason}"),
                    "  Body payload is incomplete; chunk offsets below show the observed ranges"
                        .to_string(),
                ]
            }
        }
    }

    fn has_chunks(&self) -> bool {
        !matches!(self, Self::None)
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
struct BodyPayloadScan {
    coverage: BodyPayloadCoverage,
    observed_bytes: Vec<u8>,
}

impl BodyPayloadScan {
    fn scan(chunks: &[BodyChunk], collect_bytes: bool) -> Option<Self> {
        let chunks = sorted_body_chunks(chunks);
        let first = chunks.first()?;
        let start_offset = first.offset;
        let mut next_offset = start_offset;
        let mut observed_bytes = Vec::new();
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
            if collect_bytes {
                observed_bytes.extend_from_slice(new_bytes);
            }
            next_offset = next_offset.saturating_add(new_bytes.len() as u64);
        }
        let coverage = if start_offset == 0 && !has_gap && has_end_stream {
            BodyPayloadCoverage::Complete
        } else {
            BodyPayloadCoverage::Incomplete {
                start_offset,
                reason: incomplete_body_reason(start_offset, has_gap),
            }
        };
        Some(Self {
            coverage,
            observed_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyPayloadCoverage {
    Complete,
    Incomplete {
        start_offset: u64,
        reason: &'static str,
    },
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
        let scan = BodyPayloadScan::scan(chunks, true)?;
        match scan.coverage {
            BodyPayloadCoverage::Complete => Some(Self::Complete {
                bytes: scan.observed_bytes,
            }),
            BodyPayloadCoverage::Incomplete {
                start_offset,
                reason,
            } => Some(Self::Incomplete {
                start_offset,
                observed_bytes: scan.observed_bytes,
                reason,
            }),
        }
    }
}

fn incomplete_body_reason(start_offset: u64, has_gap: bool) -> &'static str {
    if start_offset != 0 {
        "body starts after offset 0"
    } else if has_gap {
        "missing bytes between observed chunks"
    } else {
        "end of stream was not observed"
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
    attribution: TrafficAttribution,
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
            attribution: row.attribution.clone(),
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
            if body_direction_is_response(&self.request, &self.response, chunk.direction) {
                self.response.body.push(body);
            } else {
                self.request.body.push(body);
            }
        }
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
        let request_body = self.request.body_table_label();
        let response_body = self.response.body_table_label();
        HttpExchangeRow {
            sequence: self.first_sequence,
            process: self.process,
            capture_path: self.capture_path,
            method,
            target,
            status,
            request_body,
            response_body,
            direction,
            endpoint: self.endpoint,
            summary,
            request: self.request,
            response: self.response,
            raw_sequences: self.raw_sequences,
            latest_sequence: self.latest_sequence,
            identity: self.identity,
            attribution: self.attribution,
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
    rows.sort_by_key(HttpExchangeRow::order_sequence);
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

fn body_direction_is_response(
    request: &HttpMessage,
    response: &HttpMessage,
    direction: Direction,
) -> bool {
    if let Some(headers) = &response.headers {
        return headers.direction == direction;
    }
    request
        .headers
        .as_ref()
        .is_some_and(|headers| headers.direction != direction)
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, BodyChunk, CaptureOrigin, CaptureSource, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, HttpHeaders, LIBPCAP_FALLBACK_RUNTIME_HINT, ProcessContext,
        ProcessIdentity, Timestamp, TransportProtocol, UNKNOWN_PROCESS_LABEL,
    };

    use crate::admin::{EventTailEvent, EventTailRecord};

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
        assert_eq!(exchange.request_body, "5B loaded");
        assert_eq!(exchange.response_body, "2B loaded");
        let details = exchange.detail_lines();
        assert_section_order(
            &details,
            &[
                "Overview",
                "Request",
                "  POST /api/tasks HTTP/1.1",
                "Request body",
                "Request headers",
                "Response",
                "  HTTP/1.1 201 Created",
                "Response body",
                "Response headers",
                "Raw events",
            ],
        );
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
    fn body_payload_state_feeds_preview_and_table_label() {
        let cases = [
            BodyPreviewCase::loaded("Request body: 5 bytes (loaded)", "5B loaded"),
            BodyPreviewCase::none("Request body: 0 bytes (none)", "0B none"),
            BodyPreviewCase::not_loaded("Request body: 5 bytes (not loaded)", "5B not loaded"),
            BodyPreviewCase::partial("Request body: 10 bytes (partial)", "10B partial"),
            BodyPreviewCase::incomplete("Request body: 5 bytes (incomplete)", "5B incomplete"),
        ];

        for case in cases {
            let expected_preview = case.expected_preview;
            let expected_payload = case.expected_payload;
            let exchange = single_exchange(case.rows());
            let preview = exchange.preview_lines(16);

            assert!(
                preview.iter().any(|line| line == expected_preview),
                "missing {expected_preview} in {preview:?}"
            );
            assert_eq!(exchange.request_body, expected_payload);
            assert_eq!(exchange.response_body, "0B none");
        }
    }

    #[test]
    fn exchange_detail_preserves_libpcap_candidate_attribution() {
        let rows = vec![TrafficRow::from_event(
            1,
            libpcap_unknown_process_event(EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/candidate".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            })),
        )];

        let exchanges = build_http_exchange_rows(&rows);

        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange: {exchanges:?}");
        };
        assert_eq!(exchange.process, "unknown candidate");
        assert!(
            exchange
                .detail_lines()
                .iter()
                .any(|line| line == "  Process match: libpcap unknown-process candidate")
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
    fn http_body_detail_keeps_loaded_chunks_visible_when_other_chunks_are_missing() {
        let loaded_body_chunk = event(EventKind::HttpBodyChunk(BodyChunk {
            direction: Direction::Outbound,
            stream_sequence: 1,
            offset: 0,
            data: b"hello".to_vec().into(),
            end_stream: false,
        }));
        let missing_body_chunk = event(EventKind::HttpBodyChunk(BodyChunk {
            direction: Direction::Outbound,
            stream_sequence: 1,
            offset: 5,
            data: b"world".to_vec().into(),
            end_stream: true,
        }));
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
            TrafficRow::from_record(EventTailRecord {
                sequence: 2,
                stored_at_unix_ns: 2,
                event: EventTailEvent::from_envelope(&loaded_body_chunk),
            }),
            TrafficRow::from_record(EventTailRecord {
                sequence: 3,
                stored_at_unix_ns: 3,
                event: EventTailEvent::from_envelope(&missing_body_chunk),
            }),
        ];
        let loaded_rows = [TrafficRow::from_event(2, loaded_body_chunk)];

        let exchanges = build_http_exchange_rows(&rows);
        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange");
        };
        let details = exchange.detail_lines_with_loaded_rows(loaded_rows.iter());

        assert!(
            details
                .iter()
                .any(|line| line == "  Body payload: partially loaded")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Observed loaded body bytes: hello")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Missing body chunks: 1")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Body chunk offset=0 end_stream=false: hello")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Body chunk offset=5 len=5 end_stream=true not_loaded=true")
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
    fn orders_http_exchanges_chronologically() {
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
            vec!["/early", "/late"]
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
            vec!["/new", "/long"]
        );
        assert_eq!(exchanges[1].sequence, 10);
        assert_eq!(exchanges[1].order_sequence(), 40);
    }

    fn assert_section_order(details: &[String], sections: &[&str]) {
        let positions = sections
            .iter()
            .map(|section| {
                details
                    .iter()
                    .position(|line| line == section)
                    .unwrap_or_else(|| panic!("missing section {section} in {details:?}"))
            })
            .collect::<Vec<_>>();
        assert!(
            positions.windows(2).all(|window| window[0] < window[1]),
            "sections should appear in request/response order: {positions:?}"
        );
    }

    struct BodyPreviewCase {
        rows: Vec<TrafficRow>,
        expected_preview: &'static str,
        expected_payload: &'static str,
    }

    impl BodyPreviewCase {
        fn loaded(expected_preview: &'static str, expected_payload: &'static str) -> Self {
            Self {
                rows: request_rows(vec![body_row(2, 0, b"hello", true)]),
                expected_preview,
                expected_payload,
            }
        }

        fn none(expected_preview: &'static str, expected_payload: &'static str) -> Self {
            Self {
                rows: request_rows(Vec::new()),
                expected_preview,
                expected_payload,
            }
        }

        fn not_loaded(expected_preview: &'static str, expected_payload: &'static str) -> Self {
            Self {
                rows: request_rows(vec![tail_body_row(2, 0, b"hello", true)]),
                expected_preview,
                expected_payload,
            }
        }

        fn partial(expected_preview: &'static str, expected_payload: &'static str) -> Self {
            Self {
                rows: request_rows(vec![
                    body_row(2, 0, b"hello", false),
                    tail_body_row(3, 5, b"world", true),
                ]),
                expected_preview,
                expected_payload,
            }
        }

        fn incomplete(expected_preview: &'static str, expected_payload: &'static str) -> Self {
            Self {
                rows: request_rows(vec![body_row(2, 5, b"world", true)]),
                expected_preview,
                expected_payload,
            }
        }

        fn rows(self) -> Vec<TrafficRow> {
            self.rows
        }
    }

    fn single_exchange(rows: Vec<TrafficRow>) -> HttpExchangeRow {
        let exchanges = build_http_exchange_rows(&rows);
        let [exchange] = exchanges.as_slice() else {
            panic!("expected one exchange: {exchanges:?}");
        };
        exchange.clone()
    }

    fn request_rows(mut body_rows: Vec<TrafficRow>) -> Vec<TrafficRow> {
        let mut rows = vec![TrafficRow::from_event(
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
        )];
        rows.append(&mut body_rows);
        rows
    }

    fn body_row(sequence: u64, offset: u64, data: &'static [u8], end_stream: bool) -> TrafficRow {
        TrafficRow::from_event(sequence, body_event(offset, data, end_stream))
    }

    fn tail_body_row(
        sequence: u64,
        offset: u64,
        data: &'static [u8],
        end_stream: bool,
    ) -> TrafficRow {
        let event = body_event(offset, data, end_stream);
        TrafficRow::from_record(EventTailRecord {
            sequence,
            stored_at_unix_ns: sequence,
            event: EventTailEvent::from_envelope(&event),
        })
    }

    fn body_event(offset: u64, data: &'static [u8], end_stream: bool) -> EventEnvelope {
        event(EventKind::HttpBodyChunk(BodyChunk {
            direction: Direction::Outbound,
            stream_sequence: 1,
            offset,
            data: data.to_vec().into(),
            end_stream,
        }))
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

    fn libpcap_unknown_process_event(kind: EventKind) -> EventEnvelope {
        let mut flow = test_flow();
        flow.id = FlowIdentity("flow-libpcap".to_string());
        flow.process.identity.pid = 0;
        flow.process.identity.tgid = 0;
        flow.process.identity.exe_path = UNKNOWN_PROCESS_LABEL.to_string();
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

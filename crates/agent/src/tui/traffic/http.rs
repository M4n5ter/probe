use std::collections::{BTreeMap, HashMap, VecDeque};

use probe_core::{Direction, Gap, HttpHeaders};

use super::{
    attribution::TrafficAttribution,
    event_ref::{TrafficEventKindRef, TrafficEventRef, TrafficHttpBodyChunk},
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

    pub(crate) fn matches_selection_fallback(&self, identity: &HttpExchangeIdentity) -> bool {
        self.identity.matches_selection_fallback(identity)
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

    pub(crate) fn preview_lines_with_loaded_sequences(
        &self,
        loaded_sequences: &[u64],
        max_lines: usize,
    ) -> Vec<String> {
        let lines = vec![
            format!("Sequence: {}", self.sequence),
            "View: HTTP exchange".to_string(),
            format!("Process: {}", self.process),
            format!("Remote: {}", self.endpoint),
            format!("Request: {} {}", self.method, self.target),
            format!("Response: {}", self.status),
            format!(
                "Request body: {}",
                self.request
                    .body_preview_with_loaded_sequences(loaded_sequences)
            ),
            format!(
                "Response body: {}",
                self.response
                    .body_preview_with_loaded_sequences(loaded_sequences)
            ),
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
        if !self.raw_sequences.contains(&row.sequence) {
            return;
        }
        let Some(chunk) = event.http_body_chunk() else {
            return;
        };
        if let Some(existing) = self
            .request
            .body
            .iter_mut()
            .find(|existing| existing.sequence == row.sequence)
        {
            apply_loaded_body_chunk(existing, chunk);
            return;
        }
        if let Some(existing) = self
            .response
            .body
            .iter_mut()
            .find(|existing| existing.sequence == row.sequence)
        {
            apply_loaded_body_chunk(existing, chunk);
        }
    }
}

fn apply_loaded_body_chunk(existing: &mut BodyChunk, chunk: TrafficHttpBodyChunk<'_>) {
    existing.offset = chunk.offset;
    existing.data_len = chunk.data_len;
    existing.data = chunk.data.map(<[u8]>::to_vec);
    existing.end_stream = chunk.end_stream;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HttpMessage {
    headers: Option<HttpHeaders>,
    body: Vec<BodyChunk>,
    gaps: Vec<CaptureGapEvidence>,
}

impl HttpMessage {
    fn body_len(&self) -> usize {
        self.body.iter().map(|chunk| chunk.data_len).sum()
    }

    fn has_body_evidence(&self) -> bool {
        !self.body.is_empty() || !self.gaps.is_empty()
    }

    fn body_preview_with_loaded_sequences(&self, loaded_sequences: &[u64]) -> String {
        let bytes = self.body_len();
        let status = self.body_payload_status_with_loaded_sequences(loaded_sequences);
        format!("{} bytes ({})", bytes, status.preview_label())
    }

    fn body_table_label(&self) -> String {
        let bytes = self.body_len();
        let status = self.body_payload_status();
        format!("{bytes}B {}", status.preview_label())
    }

    fn body_summary_label(&self) -> String {
        let bytes = self.body_len();
        match self.body_payload_status() {
            BodyPayloadStatus::Incomplete => format!("{bytes} B incomplete"),
            BodyPayloadStatus::None
            | BodyPayloadStatus::NotLoaded { .. }
            | BodyPayloadStatus::Partial { .. }
            | BodyPayloadStatus::Loaded => format!("{bytes} B"),
        }
    }

    fn body_payload_status(&self) -> BodyPayloadStatus {
        self.body_payload_status_with_loaded_sequences(&[])
    }

    fn body_payload_status_with_loaded_sequences(
        &self,
        loaded_sequences: &[u64],
    ) -> BodyPayloadStatus {
        if !self.gaps.is_empty() {
            return BodyPayloadStatus::Incomplete;
        }
        if self.body.is_empty() {
            return BodyPayloadStatus::None;
        }
        let missing_chunks = self
            .body
            .iter()
            .filter(|chunk| !chunk.is_payload_loaded(loaded_sequences))
            .count();
        if missing_chunks == self.body.len() {
            return BodyPayloadStatus::NotLoaded { missing_chunks };
        }
        if missing_chunks > 0 {
            return BodyPayloadStatus::Partial { missing_chunks };
        }
        match BodyPayloadCoverage::from_chunk_metadata(&self.body)
            .expect("non-empty body chunks must classify")
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
            BodyPayloadStatus::Loaded => {
                match BodyPayloadDetail::from_chunks(&self.body)
                    .expect("non-empty loaded body chunks must classify")
                {
                    BodyPayloadDetail::Complete { bytes } => BodyPayloadState::Loaded { bytes },
                    BodyPayloadDetail::Incomplete {
                        start_offset,
                        observed_bytes,
                        reason,
                        gaps,
                    } => BodyPayloadState::Incomplete {
                        start_offset,
                        observed_bytes,
                        reason,
                        gaps,
                    },
                }
            }
            BodyPayloadStatus::Incomplete => {
                let detail = BodyPayloadIncompleteDetail::from_parts(&self.body, &self.gaps);
                BodyPayloadState::Incomplete {
                    start_offset: detail.start_offset,
                    observed_bytes: detail.observed_bytes,
                    reason: detail.reason,
                    gaps: detail.gaps,
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
        if self.has_body_evidence() {
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
            if !self.gaps.is_empty() {
                lines.push(format!("  Body capture gaps: {}", self.gaps.len()));
                for gap in sorted_body_gaps(&self.gaps) {
                    lines.push(format!(
                        "  Capture gap sequence={} stream_expected_offset={} stream_next_offset={}: {}",
                        gap.sequence,
                        gap.expected_stream_offset,
                        gap.next_stream_offset
                            .map(|offset| offset.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        escape_text(&gap.reason)
                    ));
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
        gaps: Vec<CaptureGapEvidence>,
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
                gaps,
            } => {
                let label = if *start_offset == 0 {
                    "  Body payload".to_string()
                } else {
                    format!("  Body payload from offset {start_offset}")
                };
                let mut lines = vec![
                    format!("{label}: incomplete"),
                    format!("  Observed body bytes: {}", bytes_detail(observed_bytes)),
                    format!("  Incomplete reason: {reason}"),
                    "  Body payload is incomplete; chunk offsets below show the observed ranges"
                        .to_string(),
                ];
                if !gaps.is_empty() {
                    lines.push("  Capture gaps explain missing body ranges".to_string());
                }
                lines
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

impl BodyChunk {
    fn is_payload_loaded(&self, loaded_sequences: &[u64]) -> bool {
        self.data.is_some() || loaded_sequences.contains(&self.sequence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaptureGapEvidence {
    sequence: u64,
    expected_stream_offset: u64,
    next_stream_offset: Option<u64>,
    reason: String,
}

impl CaptureGapEvidence {
    fn from_gap(sequence: u64, gap: &Gap) -> Self {
        Self {
            sequence,
            expected_stream_offset: gap.expected_offset,
            next_stream_offset: gap.next_offset,
            reason: gap.reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BodyPayloadScan {
    coverage: BodyPayloadCoverage,
    start_offset: u64,
    observed_bytes: Vec<u8>,
}

impl BodyPayloadScan {
    fn scan(chunks: &[BodyChunk], collect_bytes: bool) -> Option<Self> {
        scan_body_payload(chunks, BodyPayloadScanMode::RequireBytes { collect_bytes })
    }

    fn scan_available(chunks: &[BodyChunk]) -> Option<Self> {
        scan_body_payload(chunks, BodyPayloadScanMode::CollectAvailableBytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyPayloadScanMode {
    RequireBytes { collect_bytes: bool },
    CollectAvailableBytes,
    MetadataOnly,
}

fn scan_body_payload(chunks: &[BodyChunk], mode: BodyPayloadScanMode) -> Option<BodyPayloadScan> {
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
        let payload_len = match mode {
            BodyPayloadScanMode::RequireBytes { .. } => chunk.data.as_ref()?.len(),
            BodyPayloadScanMode::CollectAvailableBytes | BodyPayloadScanMode::MetadataOnly => {
                chunk.data_len
            }
        };
        let overlap = next_offset.saturating_sub(chunk.offset) as usize;
        if overlap >= payload_len {
            continue;
        }
        let new_len = payload_len - overlap;
        match mode {
            BodyPayloadScanMode::RequireBytes {
                collect_bytes: true,
            } => {
                let data = chunk.data.as_ref()?;
                observed_bytes.extend_from_slice(&data[overlap..]);
            }
            BodyPayloadScanMode::CollectAvailableBytes => {
                if let Some(data) = &chunk.data {
                    let data_overlap = overlap.min(data.len());
                    if data_overlap < data.len() {
                        observed_bytes.extend_from_slice(&data[data_overlap..]);
                    }
                }
            }
            BodyPayloadScanMode::RequireBytes {
                collect_bytes: false,
            }
            | BodyPayloadScanMode::MetadataOnly => {}
        }
        next_offset = next_offset.saturating_add(new_len as u64);
    }
    let coverage = if start_offset == 0 && !has_gap && has_end_stream {
        BodyPayloadCoverage::Complete
    } else {
        BodyPayloadCoverage::Incomplete {
            start_offset,
            reason: incomplete_body_reason(start_offset, has_gap),
        }
    };
    Some(BodyPayloadScan {
        coverage,
        start_offset,
        observed_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyPayloadCoverage {
    Complete,
    Incomplete {
        start_offset: u64,
        reason: &'static str,
    },
}

impl BodyPayloadCoverage {
    fn from_chunk_metadata(chunks: &[BodyChunk]) -> Option<Self> {
        scan_body_payload(chunks, BodyPayloadScanMode::MetadataOnly).map(|scan| scan.coverage)
    }
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
        gaps: Vec<CaptureGapEvidence>,
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
                gaps: Vec::new(),
            }),
        }
    }
}

struct BodyPayloadIncompleteDetail {
    start_offset: u64,
    observed_bytes: Vec<u8>,
    reason: &'static str,
    gaps: Vec<CaptureGapEvidence>,
}

impl BodyPayloadIncompleteDetail {
    fn from_parts(chunks: &[BodyChunk], gaps: &[CaptureGapEvidence]) -> Self {
        let Some(scan) = BodyPayloadScan::scan_available(chunks) else {
            return Self::from_gaps(gaps);
        };
        let (start_offset, chunk_reason) = match scan.coverage {
            BodyPayloadCoverage::Complete => {
                (scan.start_offset, "capture gap interrupted body payload")
            }
            BodyPayloadCoverage::Incomplete {
                start_offset,
                reason,
            } => (start_offset, reason),
        };
        Self {
            start_offset,
            observed_bytes: scan.observed_bytes,
            reason: if gaps.is_empty() {
                chunk_reason
            } else {
                "capture gap interrupted body payload"
            },
            gaps: gaps.to_vec(),
        }
    }

    fn from_gaps(gaps: &[CaptureGapEvidence]) -> Self {
        Self {
            start_offset: 0,
            observed_bytes: Vec::new(),
            reason: "capture gap interrupted body payload",
            gaps: gaps.to_vec(),
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
    discriminator: HttpExchangeDiscriminator,
}

impl HttpExchangeIdentity {
    fn request_stream(flow_id: String, stream_sequence: u64) -> Self {
        Self {
            flow_id,
            stream_sequence,
            discriminator: HttpExchangeDiscriminator::RequestStream,
        }
    }

    fn orphan_response(flow_id: String, stream_sequence: u64, sequence: u64) -> Self {
        Self {
            flow_id,
            stream_sequence,
            discriminator: HttpExchangeDiscriminator::OrphanResponse { sequence },
        }
    }

    fn matches_selection_fallback(&self, other: &Self) -> bool {
        self == other
            || (self.flow_id == other.flow_id && self.stream_sequence == other.stream_sequence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum HttpExchangeDiscriminator {
    RequestStream,
    OrphanResponse { sequence: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowDirectionKey {
    flow_id: String,
    direction: Direction,
}

impl FlowDirectionKey {
    fn from_event(event: TrafficEventRef<'_>, direction: Direction) -> Option<Self> {
        Some(Self {
            flow_id: event.flow()?.id.0.clone(),
            direction,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyRole {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveBodyTarget {
    exchange: HttpExchangeIdentity,
    role: BodyRole,
    accepts_gap: bool,
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

    fn request_method(&self) -> Option<&str> {
        self.request.headers.as_ref()?.method.as_deref()
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
            let role = self.role_for_body_direction(chunk.direction);
            self.observe_body_chunk(row, chunk, role);
        } else if let Some(gap) = event.gap() {
            let role = self.role_for_body_direction(gap.direction);
            self.observe_gap(row, gap, role);
        }
    }

    fn observe_body_chunk(
        &mut self,
        row: &TrafficRow,
        chunk: TrafficHttpBodyChunk<'_>,
        role: BodyRole,
    ) {
        self.first_sequence = self.first_sequence.min(row.sequence);
        self.latest_sequence = self.latest_sequence.max(row.sequence);
        self.raw_sequences.push(row.sequence);
        let body = BodyChunk {
            sequence: row.sequence,
            offset: chunk.offset,
            data_len: chunk.data_len,
            data: chunk.data.map(<[u8]>::to_vec),
            end_stream: chunk.end_stream,
        };
        match role {
            BodyRole::Request => self.request.body.push(body),
            BodyRole::Response => self.response.body.push(body),
        }
    }

    fn observe_gap(&mut self, row: &TrafficRow, gap: &Gap, role: BodyRole) {
        self.first_sequence = self.first_sequence.min(row.sequence);
        self.latest_sequence = self.latest_sequence.max(row.sequence);
        self.raw_sequences.push(row.sequence);
        let body_gap = CaptureGapEvidence::from_gap(row.sequence, gap);
        match role {
            BodyRole::Request => self.request.gaps.push(body_gap),
            BodyRole::Response => self.response.gaps.push(body_gap),
        }
    }

    fn role_for_body_direction(&self, direction: Direction) -> BodyRole {
        if body_direction_is_response(&self.request, &self.response, direction) {
            BodyRole::Response
        } else {
            BodyRole::Request
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
            "{} {} -> {} (req {}, resp {})",
            method,
            target,
            status,
            self.request.body_summary_label(),
            self.response.body_summary_label()
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
    let mut active_body_targets = HashMap::<FlowDirectionKey, ActiveBodyTarget>::new();
    let mut pending_requests = HashMap::<String, VecDeque<HttpExchangeIdentity>>::new();
    let mut ordered_rows = rows.iter().collect::<Vec<_>>();
    ordered_rows.sort_by_key(|row| row.sequence);
    for row in ordered_rows {
        let Some(event) = row.event_ref() else {
            continue;
        };
        if let Some(headers) = event.http_request_headers() {
            let Some(key) = http_exchange_key(event) else {
                continue;
            };
            let builder = exchanges
                .entry(key.clone())
                .or_insert_with(|| HttpExchangeBuilder::new(key.clone(), row));
            builder.observe(row, event);
            if let Some(flow) = event.flow() {
                pending_requests
                    .entry(flow.id.0.clone())
                    .or_default()
                    .push_back(key.clone());
            }
            update_active_header_body_target(
                &mut active_body_targets,
                event,
                headers,
                &key,
                BodyRole::Request,
                None,
            );
            continue;
        }
        if let Some(headers) = event.http_response_headers() {
            let Some(key) = response_exchange_key(row, event, headers, &mut pending_requests)
            else {
                continue;
            };
            let builder = exchanges
                .entry(key.clone())
                .or_insert_with(|| HttpExchangeBuilder::new(key.clone(), row));
            builder.observe(row, event);
            let request_method = builder.request_method().map(str::to_string);
            update_active_header_body_target(
                &mut active_body_targets,
                event,
                headers,
                &key,
                BodyRole::Response,
                request_method.as_deref(),
            );
            continue;
        }
        if let Some(chunk) = event.http_body_chunk() {
            if let Some(flow_direction) = FlowDirectionKey::from_event(event, chunk.direction)
                && let Some(target) = active_body_targets.get(&flow_direction).cloned()
            {
                if let Some(exchange) = exchanges.get_mut(&target.exchange) {
                    exchange.observe_body_chunk(row, chunk, target.role);
                }
                if chunk.end_stream {
                    active_body_targets.remove(&flow_direction);
                } else if !target.accepts_gap {
                    active_body_targets.insert(
                        flow_direction,
                        ActiveBodyTarget {
                            accepts_gap: true,
                            ..target
                        },
                    );
                }
                continue;
            }
            let Some(key) = http_exchange_key(event) else {
                continue;
            };
            let builder = exchanges
                .entry(key.clone())
                .or_insert_with(|| HttpExchangeBuilder::new(key.clone(), row));
            let role = builder.role_for_body_direction(chunk.direction);
            builder.observe_body_chunk(row, chunk, role);
            if let Some(flow_direction) = FlowDirectionKey::from_event(event, chunk.direction) {
                if chunk.end_stream {
                    active_body_targets.remove(&flow_direction);
                } else {
                    active_body_targets.insert(
                        flow_direction,
                        ActiveBodyTarget {
                            exchange: key,
                            role,
                            accepts_gap: true,
                        },
                    );
                }
            }
            continue;
        }
        let Some(gap) = event.gap() else {
            clear_http_assembly_for_boundary(
                &mut active_body_targets,
                &mut pending_requests,
                event,
            );
            continue;
        };
        let Some(flow_direction) = FlowDirectionKey::from_event(event, gap.direction) else {
            continue;
        };
        if gap.next_offset.is_none() {
            clear_pending_requests_for_event(&mut pending_requests, event);
        }
        let Some(target) = active_body_targets.get(&flow_direction).cloned() else {
            continue;
        };
        if !target.accepts_gap {
            if gap.next_offset.is_none() {
                active_body_targets.remove(&flow_direction);
            }
            continue;
        }
        if let Some(exchange) = exchanges.get_mut(&target.exchange) {
            exchange.observe_gap(row, gap, target.role);
            active_body_targets.remove(&flow_direction);
        }
    }
    let mut rows = exchanges
        .into_values()
        .map(HttpExchangeBuilder::into_row)
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .order_sequence()
            .cmp(&left.order_sequence())
            .then_with(|| right.sequence.cmp(&left.sequence))
    });
    rows
}

fn http_exchange_key(event: TrafficEventRef<'_>) -> Option<HttpExchangeIdentity> {
    let flow_id = event.flow()?.id.0.clone();
    let stream_sequence = event
        .http_request_headers()
        .map(|headers| headers.stream_sequence)
        .or_else(|| event.http_body_chunk().map(|chunk| chunk.stream_sequence))?;
    Some(HttpExchangeIdentity::request_stream(
        flow_id,
        stream_sequence,
    ))
}

fn response_exchange_key(
    row: &TrafficRow,
    event: TrafficEventRef<'_>,
    headers: &HttpHeaders,
    pending_requests: &mut HashMap<String, VecDeque<HttpExchangeIdentity>>,
) -> Option<HttpExchangeIdentity> {
    let flow_id = event.flow()?.id.0.clone();
    let matched = pending_requests.get_mut(&flow_id).and_then(|queue| {
        let key = queue.front().cloned()?;
        if !response_status_is_interim(headers.status) {
            queue.pop_front();
        }
        Some((key, queue.is_empty()))
    });
    if let Some((key, empty)) = matched {
        if empty {
            pending_requests.remove(&flow_id);
        }
        return Some(key);
    }
    Some(HttpExchangeIdentity::orphan_response(
        flow_id,
        headers.stream_sequence,
        row.sequence,
    ))
}

fn update_active_header_body_target(
    active_body_targets: &mut HashMap<FlowDirectionKey, ActiveBodyTarget>,
    event: TrafficEventRef<'_>,
    headers: &HttpHeaders,
    exchange: &HttpExchangeIdentity,
    role: BodyRole,
    request_method: Option<&str>,
) {
    let Some(flow_direction) = FlowDirectionKey::from_event(event, headers.direction) else {
        return;
    };
    if let Some(accepts_gap) = active_body_target_gap_policy(headers, request_method) {
        active_body_targets.insert(
            flow_direction,
            ActiveBodyTarget {
                exchange: exchange.clone(),
                role,
                accepts_gap,
            },
        );
    } else {
        active_body_targets.remove(&flow_direction);
    }
}

fn clear_http_assembly_for_boundary(
    active_body_targets: &mut HashMap<FlowDirectionKey, ActiveBodyTarget>,
    pending_requests: &mut HashMap<String, VecDeque<HttpExchangeIdentity>>,
    event: TrafficEventRef<'_>,
) {
    match event.kind() {
        TrafficEventKindRef::ConnectionClosed => {
            let Some(flow) = event.flow() else {
                return;
            };
            active_body_targets.retain(|flow_direction, _| flow_direction.flow_id != flow.id.0);
            pending_requests.remove(&flow.id.0);
        }
        TrafficEventKindRef::WebSocketHandoff(handoff) => {
            remove_active_body_target(active_body_targets, event, handoff.direction);
            clear_pending_requests_for_event(pending_requests, event);
        }
        TrafficEventKindRef::WebSocketFrame(frame) => {
            remove_active_body_target(active_body_targets, event, frame.direction);
        }
        TrafficEventKindRef::WebSocketMessage(message) => {
            remove_active_body_target(active_body_targets, event, message.direction);
        }
        TrafficEventKindRef::OpaqueStream(stream) => {
            remove_active_body_target(active_body_targets, event, stream.direction);
        }
        TrafficEventKindRef::ProtocolError(error) => {
            remove_active_body_target(active_body_targets, event, error.direction);
        }
        TrafficEventKindRef::ConnectionOpened
        | TrafficEventKindRef::SseEvent(_)
        | TrafficEventKindRef::CaptureLoss(_)
        | TrafficEventKindRef::PolicyAlert(_)
        | TrafficEventKindRef::PolicyVerdict(_)
        | TrafficEventKindRef::PolicyRuntimeError(_)
        | TrafficEventKindRef::EnforcementDecision(_)
        | TrafficEventKindRef::L7MitmAudit(_)
        | TrafficEventKindRef::HttpRequestHeaders(_)
        | TrafficEventKindRef::HttpResponseHeaders(_)
        | TrafficEventKindRef::HttpBodyChunk(_)
        | TrafficEventKindRef::Gap(_) => {}
    }
}

fn clear_pending_requests_for_event(
    pending_requests: &mut HashMap<String, VecDeque<HttpExchangeIdentity>>,
    event: TrafficEventRef<'_>,
) {
    if let Some(flow) = event.flow() {
        pending_requests.remove(&flow.id.0);
    }
}

fn remove_active_body_target(
    active_body_targets: &mut HashMap<FlowDirectionKey, ActiveBodyTarget>,
    event: TrafficEventRef<'_>,
    direction: Direction,
) {
    if let Some(flow_direction) = FlowDirectionKey::from_event(event, direction) {
        active_body_targets.remove(&flow_direction);
    }
}

fn response_status_is_interim(status: Option<u16>) -> bool {
    status.is_some_and(|status| (100..200).contains(&status) && status != 101)
}

fn active_body_target_gap_policy(
    headers: &HttpHeaders,
    request_method: Option<&str>,
) -> Option<bool> {
    if http_message_may_have_body(headers, request_method) {
        return Some(true);
    }
    if response_body_chunk_may_arrive_without_request_context(headers, request_method) {
        return Some(false);
    }
    None
}

fn response_body_chunk_may_arrive_without_request_context(
    headers: &HttpHeaders,
    request_method: Option<&str>,
) -> bool {
    if headers.status.is_none() || request_method.is_some() {
        return false;
    }
    if headers.status.is_some_and(response_status_has_no_body) {
        return false;
    }
    !matches!(
        header_value(headers, "content-length").and_then(|value| value.trim().parse::<u64>().ok()),
        Some(0)
    )
}

fn http_message_may_have_body(headers: &HttpHeaders, request_method: Option<&str>) -> bool {
    if headers.status.is_some() && request_method.is_none() {
        return false;
    }
    if headers.status.is_some()
        && request_method.is_some_and(|method| method.eq_ignore_ascii_case("HEAD"))
    {
        return false;
    }
    if headers
        .status
        .is_some_and(|status| (200..300).contains(&status))
        && request_method.is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
    {
        return false;
    }
    if headers.status.is_some_and(response_status_has_no_body) {
        return false;
    }
    if header_value(headers, "transfer-encoding").is_some() {
        return true;
    }
    match header_value(headers, "content-length").and_then(|value| value.trim().parse::<u64>().ok())
    {
        Some(0) => false,
        Some(_) => true,
        None => headers.status.is_some(),
    }
}

fn response_status_has_no_body(status: u16) -> bool {
    (100..200).contains(&status) || status == 204 || status == 304
}

fn header_value<'a>(headers: &'a HttpHeaders, name: &str) -> Option<&'a str> {
    headers
        .headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn sorted_body_chunks(chunks: &[BodyChunk]) -> Vec<&BodyChunk> {
    let mut chunks = chunks.iter().collect::<Vec<_>>();
    chunks.sort_by_key(|chunk| chunk.offset);
    chunks
}

fn sorted_body_gaps(gaps: &[CaptureGapEvidence]) -> Vec<&CaptureGapEvidence> {
    let mut gaps = gaps.iter().collect::<Vec<_>>();
    gaps.sort_by_key(|gap| (gap.expected_stream_offset, gap.sequence));
    gaps
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
        ProcessIdentity, Timestamp, TransportProtocol, UNKNOWN_PROCESS_LABEL, WebSocketHandoff,
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
            let preview = exchange.preview_lines_with_loaded_sequences(&[], 16);

            assert!(
                preview.iter().any(|line| line == expected_preview),
                "missing {expected_preview} in {preview:?}"
            );
            assert_eq!(exchange.request_body, expected_payload);
            assert_eq!(exchange.response_body, "0B none");
        }
    }

    #[test]
    fn response_capture_gap_marks_exchange_body_incomplete() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: Some("GET".to_string()),
                    target: Some("/large".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "110048".to_string())],
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 480,
                    next_offset: Some(110_048),
                    reason:
                        "eBPF outbound syscall sample truncated payload after 480 of 110048 byte(s)"
                            .to_string(),
                })),
            ),
            TrafficRow::from_event(
                4,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 110_048,
                    next_offset: Some(120_000),
                    reason: "later unrelated gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "0B incomplete");
        assert_eq!(
            exchange.summary,
            "GET /large -> 200 OK (req 0 B, resp 0 B incomplete)"
        );
        let details = exchange.detail_lines();
        assert!(
            details
                .iter()
                .any(|line| line == "  Body payload: incomplete")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Incomplete reason: capture gap interrupted body payload")
        );
        assert!(details.iter().any(|line| {
            line == "  Capture gap sequence=3 stream_expected_offset=480 stream_next_offset=110048: eBPF outbound syscall sample truncated payload after 480 of 110048 byte(s)"
        }));
        assert!(details.iter().any(|line| line == "  Sequences: 1, 2, 3"));
        assert!(
            !details
                .iter()
                .any(|line| line.contains("later unrelated gap"))
        );
    }

    #[test]
    fn response_gap_without_request_context_does_not_infer_body() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "128".to_string())],
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 128,
                    next_offset: Some(256),
                    reason: "ambiguous response gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "0B none");
        assert_eq!(exchange.raw_sequences.to_vec(), vec![1]);
        assert!(
            !exchange
                .detail_lines()
                .iter()
                .any(|line| line.contains("ambiguous response gap"))
        );
    }

    #[test]
    fn final_response_after_interim_response_uses_pending_request_context_for_gap() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: Some("GET".to_string()),
                    target: Some("/continue".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(100),
                    reason: Some("Continue".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 2,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "110048".to_string())],
                })),
            ),
            TrafficRow::from_event(
                4,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 480,
                    next_offset: Some(110_048),
                    reason: "truncated final response".to_string(),
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let final_response = exchanges
            .iter()
            .find(|exchange| exchange.status == "200 OK")
            .unwrap_or_else(|| panic!("expected final response exchange: {exchanges:?}"));

        assert_eq!(final_response.method, "GET");
        assert_eq!(final_response.target, "/continue");
        assert_eq!(final_response.response_body, "0B incomplete");
        assert_eq!(final_response.raw_sequences.to_vec(), vec![1, 2, 3, 4]);
        assert!(
            final_response
                .detail_lines()
                .iter()
                .any(|line| line.contains("truncated final response"))
        );
    }

    #[test]
    fn final_response_after_interim_response_does_not_attach_to_next_request() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: Some("GET".to_string()),
                    target: Some("/first".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(100),
                    reason: Some("Continue".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 2,
                    method: Some("HEAD".to_string()),
                    target: Some("/second".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                4,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 2,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "4096".to_string())],
                })),
            ),
            TrafficRow::from_event(
                5,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 512,
                    next_offset: Some(4096),
                    reason: "first response truncated".to_string(),
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let first = exchanges
            .iter()
            .find(|exchange| exchange.target == "/first")
            .unwrap_or_else(|| panic!("expected first exchange: {exchanges:?}"));
        let second = exchanges
            .iter()
            .find(|exchange| exchange.target == "/second")
            .unwrap_or_else(|| panic!("expected second exchange: {exchanges:?}"));

        assert_eq!(first.status, "200 OK");
        assert_eq!(first.response_body, "0B incomplete");
        assert_eq!(first.raw_sequences.to_vec(), vec![1, 2, 4, 5]);
        assert_eq!(second.status, "pending");
        assert_eq!(second.response_body, "0B none");
        assert_eq!(second.raw_sequences.to_vec(), vec![3]);
    }

    #[test]
    fn final_response_after_interim_response_hydrates_tail_body_chunk() {
        let loaded_body = event(EventKind::HttpBodyChunk(BodyChunk {
            direction: Direction::Outbound,
            stream_sequence: 2,
            offset: 0,
            data: b"payload".to_vec().into(),
            end_stream: true,
        }));
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: Some("GET".to_string()),
                    target: Some("/tail-hydrate".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(100),
                    reason: Some("Continue".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 2,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "7".to_string())],
                })),
            ),
            TrafficRow::from_record(EventTailRecord {
                sequence: 4,
                stored_at_unix_ns: 4,
                event: EventTailEvent::from_envelope(&loaded_body),
            }),
        ];
        let loaded_rows = [TrafficRow::from_event(4, loaded_body)];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "7B not loaded");
        let details = exchange.detail_lines_with_loaded_rows(loaded_rows.iter());
        assert!(details.iter().any(|line| line == "  Body payload: payload"));
        assert!(
            details
                .iter()
                .any(|line| line == "  Body chunk offset=0 end_stream=true: payload")
        );
    }

    #[test]
    fn unknown_gap_breaks_pending_request_response_context() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: Some("GET".to_string()),
                    target: Some("/stale".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 0,
                    next_offset: None,
                    reason: "lost stream context".to_string(),
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "128".to_string())],
                })),
            ),
            TrafficRow::from_event(
                4,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 0,
                    next_offset: Some(128),
                    reason: "response gap must stay orphaned".to_string(),
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let stale = exchanges
            .iter()
            .find(|exchange| exchange.target == "/stale")
            .unwrap_or_else(|| panic!("expected stale request exchange: {exchanges:?}"));
        let orphan_response = exchanges
            .iter()
            .find(|exchange| exchange.status == "200 OK")
            .unwrap_or_else(|| panic!("expected orphan response exchange: {exchanges:?}"));

        assert_eq!(stale.status, "pending");
        assert_eq!(stale.raw_sequences.to_vec(), vec![1]);
        assert_eq!(orphan_response.target, "-");
        assert_eq!(orphan_response.response_body, "0B none");
        assert_eq!(orphan_response.raw_sequences.to_vec(), vec![3]);
        assert!(
            !orphan_response
                .detail_lines()
                .iter()
                .any(|line| line.contains("response gap must stay orphaned"))
        );
    }

    #[test]
    fn active_unknown_gap_breaks_pending_request_response_context() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: Some("POST".to_string()),
                    target: Some("/upload".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "4096".to_string())],
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::Gap(Gap {
                    direction: Direction::Inbound,
                    expected_offset: 512,
                    next_offset: None,
                    reason: "request body stream context lost".to_string(),
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "128".to_string())],
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let request = exchanges
            .iter()
            .find(|exchange| exchange.target == "/upload")
            .unwrap_or_else(|| panic!("expected request exchange: {exchanges:?}"));
        let orphan_response = exchanges
            .iter()
            .find(|exchange| exchange.status == "200 OK")
            .unwrap_or_else(|| panic!("expected orphan response exchange: {exchanges:?}"));

        assert_eq!(request.status, "pending");
        assert_eq!(request.request_body, "0B incomplete");
        assert_eq!(request.raw_sequences.to_vec(), vec![1, 2]);
        assert_eq!(orphan_response.target, "-");
        assert_eq!(orphan_response.raw_sequences.to_vec(), vec![3]);
    }

    #[test]
    fn switching_protocols_response_closes_pending_request_context() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: Some("GET".to_string()),
                    target: Some("/socket".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(101),
                    reason: Some("Switching Protocols".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("upgrade".to_string(), "websocket".to_string())],
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 2,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "32".to_string())],
                })),
            ),
        ];

        let exchanges = build_http_exchange_rows(&rows);
        let upgrade = exchanges
            .iter()
            .find(|exchange| exchange.target == "/socket")
            .unwrap_or_else(|| panic!("expected upgrade exchange: {exchanges:?}"));
        let orphan_response = exchanges
            .iter()
            .find(|exchange| exchange.status == "200 OK")
            .unwrap_or_else(|| panic!("expected orphan response exchange: {exchanges:?}"));

        assert_eq!(upgrade.status, "101 Switching Protocols");
        assert_eq!(upgrade.raw_sequences.to_vec(), vec![1, 2]);
        assert_eq!(orphan_response.target, "-");
        assert_eq!(orphan_response.raw_sequences.to_vec(), vec![3]);
    }

    #[test]
    fn capture_gap_keeps_loaded_body_prefix_visible() {
        let rows = vec![
            TrafficRow::from_event(
                1,
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
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: b"hello".to_vec().into(),
                    end_stream: false,
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::Gap(Gap {
                    direction: Direction::Inbound,
                    expected_offset: 5,
                    next_offset: Some(12),
                    reason: "capture gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "5B incomplete");
        let details = exchange.detail_lines();
        assert!(
            details
                .iter()
                .any(|line| line == "  Observed body bytes: hello")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Incomplete reason: capture gap interrupted body payload")
        );
        assert!(details.iter().any(|line| {
            line == "  Capture gap sequence=3 stream_expected_offset=5 stream_next_offset=12: capture gap"
        }));
    }

    #[test]
    fn capture_gap_with_unloaded_body_chunk_marks_exchange_incomplete() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            tail_body_row(2, 0, b"hello", false),
            TrafficRow::from_event(
                3,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 5,
                    next_offset: Some(12),
                    reason: "capture gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "5B incomplete");
        assert!(
            exchange
                .detail_lines()
                .iter()
                .any(|line| line == "  Body payload: incomplete")
        );
    }

    #[test]
    fn capture_gap_preserves_loaded_prefix_when_tail_chunk_is_unloaded() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
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
                    end_stream: false,
                })),
            ),
            tail_body_row(3, 5, b"world", false),
            TrafficRow::from_event(
                4,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 10,
                    next_offset: Some(64),
                    reason: "capture gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "10B incomplete");
        let details = exchange.detail_lines();
        assert!(
            details
                .iter()
                .any(|line| line == "  Observed body bytes: hello")
        );
        assert!(
            details
                .iter()
                .any(|line| line == "  Body chunk offset=5 len=5 end_stream=false not_loaded=true")
        );
        assert!(details.iter().any(|line| {
            line == "  Capture gap sequence=4 stream_expected_offset=10 stream_next_offset=64: capture gap"
        }));
    }

    #[test]
    fn capture_gap_after_complete_body_does_not_reopen_exchange() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "5".to_string())],
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: b"hello".to_vec().into(),
                    end_stream: true,
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::Gap(Gap {
                    direction: Direction::Inbound,
                    expected_offset: 5,
                    next_offset: Some(12),
                    reason: "post-body gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "5B loaded");
        assert_eq!(exchange.raw_sequences.to_vec(), vec![1, 2]);
        assert!(
            !exchange
                .detail_lines()
                .iter()
                .any(|line| line.contains("post-body gap"))
        );
    }

    #[test]
    fn websocket_gap_after_handoff_does_not_mark_http_upgrade_incomplete() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(101),
                    reason: Some("Switching Protocols".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("upgrade".to_string(), "websocket".to_string())],
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::WebSocketHandoff(WebSocketHandoff {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    target: Some("/socket".to_string()),
                    subprotocol: None,
                    extensions: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 12,
                    next_offset: Some(24),
                    reason: "websocket gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "0B none");
        assert_eq!(exchange.raw_sequences.to_vec(), vec![1]);
        assert!(
            !exchange
                .detail_lines()
                .iter()
                .any(|line| line.contains("websocket gap"))
        );
    }

    #[test]
    fn head_response_gap_does_not_mark_body_incomplete() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: Some("HEAD".to_string()),
                    target: Some("/metadata".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("OK".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("content-length".to_string(), "128".to_string())],
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::Gap(Gap {
                    direction: Direction::Outbound,
                    expected_offset: 128,
                    next_offset: Some(256),
                    reason: "later stream gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "0B none");
        assert_eq!(exchange.raw_sequences.to_vec(), vec![1, 2]);
        assert!(
            !exchange
                .detail_lines()
                .iter()
                .any(|line| line.contains("later stream gap"))
        );
    }

    #[test]
    fn connect_tunnel_gap_does_not_mark_response_body_incomplete() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::HttpRequestHeaders(HttpHeaders {
                    direction: Direction::Outbound,
                    stream_sequence: 1,
                    method: Some("CONNECT".to_string()),
                    target: Some("example.test:443".to_string()),
                    status: None,
                    reason: None,
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::HttpResponseHeaders(HttpHeaders {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    method: None,
                    target: None,
                    status: Some(200),
                    reason: Some("Connection Established".to_string()),
                    version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::Gap(Gap {
                    direction: Direction::Inbound,
                    expected_offset: 64,
                    next_offset: Some(128),
                    reason: "tunnel gap".to_string(),
                })),
            ),
        ];

        let exchange = single_exchange(rows);

        assert_eq!(exchange.response_body, "0B none");
        assert_eq!(exchange.raw_sequences.to_vec(), vec![1, 2]);
        assert!(
            !exchange
                .detail_lines()
                .iter()
                .any(|line| line.contains("tunnel gap"))
        );
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
    fn orders_http_exchanges_by_latest_activity_descending_without_changing_identity_sequence() {
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

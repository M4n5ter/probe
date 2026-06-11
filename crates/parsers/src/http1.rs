use std::collections::VecDeque;

use bytes::{Buf, Bytes, BytesMut};
use probe_core::{
    BodyChunk, Direction, EventKind, HttpHeaders, OpaqueStream, ProtocolError, SseEvent,
};
use thiserror::Error;

use crate::{ParserInput, ParserOutput, ProtocolParser, gap_event};

const MAX_SSE_PENDING_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error("invalid HTTP request: {0}")]
    InvalidRequest(String),
    #[error("invalid HTTP response: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, Default)]
pub struct Http1Parser {
    inbound: DirectionState,
    outbound: DirectionState,
    pending_response_contexts: VecDeque<ResponseContext>,
    opaque_handoff: bool,
}

impl Http1Parser {
    pub fn ingest(&mut self, direction: Direction, bytes: &[u8]) -> Vec<EventKind> {
        ProtocolParser::ingest(self, ParserInput::Data { direction, bytes }).into_events()
    }
}

impl ProtocolParser for Http1Parser {
    fn ingest(&mut self, input: ParserInput<'_>) -> ParserOutput {
        match input {
            ParserInput::Data { direction, bytes } => {
                if self.opaque_handoff {
                    return ParserOutput::from_events(opaque_data_events(direction, bytes));
                }
                let mut events = match direction {
                    Direction::Inbound => self.inbound.ingest_data(
                        direction,
                        bytes,
                        &mut self.pending_response_contexts,
                    ),
                    Direction::Outbound => self.outbound.ingest_data(
                        direction,
                        bytes,
                        &mut self.pending_response_contexts,
                    ),
                };
                self.pending_response_contexts
                    .extend(events.iter().filter_map(|event| match event {
                        EventKind::HttpRequestHeaders(headers) => {
                            Some(ResponseContext::from_request(headers))
                        }
                        _ => None,
                    }));
                if events.iter().any(is_handoff_opaque_event) {
                    self.opaque_handoff = true;
                    self.pending_response_contexts.clear();
                    self.inbound.enter_opaque();
                    self.outbound.enter_opaque();
                }
                ParserOutput::from_events(std::mem::take(&mut events))
            }
            ParserInput::Gap {
                direction,
                expected_offset,
                next_offset,
                reason,
            } => {
                if !self.opaque_handoff {
                    self.state_mut(direction).reset();
                }
                ParserOutput::from_events(vec![gap_event(
                    direction,
                    expected_offset,
                    next_offset,
                    reason,
                )])
            }
            ParserInput::ConnectionClosed => ParserOutput::from_events(self.finish_flow()),
        }
    }
}

impl Http1Parser {
    fn finish_flow(&mut self) -> Vec<EventKind> {
        let mut events = Vec::new();
        if !self.opaque_handoff {
            self.inbound.finish(Direction::Inbound, &mut events);
            self.outbound.finish(Direction::Outbound, &mut events);
        }
        events
    }

    fn state_mut(&mut self, direction: Direction) -> &mut DirectionState {
        match direction {
            Direction::Inbound => &mut self.inbound,
            Direction::Outbound => &mut self.outbound,
        }
    }
}

#[derive(Debug, Default)]
struct DirectionState {
    buffer: BytesMut,
    state: HttpState,
    stream_sequence: u64,
    body_offset: u64,
    sse: SseDecoder,
}

impl DirectionState {
    fn ingest_data(
        &mut self,
        direction: Direction,
        bytes: &[u8],
        response_contexts: &mut VecDeque<ResponseContext>,
    ) -> Vec<EventKind> {
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();

        loop {
            let before = Progress::new(self.buffer.len(), &self.state);
            match self.state {
                HttpState::ReadingHeaders => {
                    self.read_headers(direction, response_contexts, &mut events)
                }
                HttpState::ReadingFixedBody { remaining } => {
                    self.read_fixed_body(direction, remaining, &mut events)
                }
                HttpState::StreamingUntilClose => {
                    self.read_available_body(direction, false, &mut events);
                }
                HttpState::ReadingChunkSize => self.read_chunk_size(direction, &mut events),
                HttpState::ReadingChunkData { remaining } => {
                    self.read_chunk_data(direction, remaining, &mut events)
                }
                HttpState::ReadingChunkTerminator => {
                    self.read_chunk_terminator(direction, &mut events)
                }
                HttpState::ReadingChunkTrailers => self.read_chunk_trailers(direction, &mut events),
                HttpState::Opaque => self.read_opaque(direction, &mut events),
            };

            if before == Progress::new(self.buffer.len(), &self.state) {
                break;
            }

            if self.buffer.is_empty() && !self.state.can_progress_without_buffer() {
                break;
            }
        }

        events
    }

    fn read_headers(
        &mut self,
        direction: Direction,
        response_contexts: &mut VecDeque<ResponseContext>,
        events: &mut Vec<EventKind>,
    ) {
        match parse_headers(direction, &self.buffer) {
            HeaderParse::Complete {
                consumed,
                role,
                headers,
            } => {
                self.stream_sequence = self.stream_sequence.saturating_add(1);
                self.body_offset = 0;
                self.buffer.advance(consumed);

                let response_context = (role == HeaderRole::Response)
                    .then(|| {
                        if is_interim_non_switching(headers.status) {
                            response_contexts.front().copied()
                        } else {
                            response_contexts.pop_front()
                        }
                    })
                    .flatten();
                let body_plan = BodyPlan::from_headers(role, &headers, response_context);
                self.sse = SseDecoder::new(body_plan.is_sse);

                let mut headers = headers;
                headers.stream_sequence = self.stream_sequence;
                events.push(match role {
                    HeaderRole::Request => EventKind::HttpRequestHeaders(headers),
                    HeaderRole::Response => EventKind::HttpResponseHeaders(headers),
                });

                if let Some(reason) = body_plan.opaque_reason {
                    events.push(EventKind::OpaqueStream(OpaqueStream {
                        direction,
                        fingerprint: opaque_fingerprint(&self.buffer),
                        reason,
                    }));
                    self.buffer.clear();
                }
                self.state = body_plan.state;
            }
            HeaderParse::Partial => {}
            HeaderParse::Invalid(reason) => self.fail(direction, reason, events),
        }
    }

    fn read_fixed_body(
        &mut self,
        direction: Direction,
        remaining: usize,
        events: &mut Vec<EventKind>,
    ) {
        if remaining == 0 {
            self.state = HttpState::ReadingHeaders;
            return;
        }
        if self.buffer.is_empty() {
            return;
        }

        let len = remaining.min(self.buffer.len());
        let data = self.buffer.split_to(len).freeze();
        let next_remaining = remaining - len;
        self.emit_body(direction, data, next_remaining == 0, events);
        self.state = if next_remaining == 0 {
            HttpState::ReadingHeaders
        } else {
            HttpState::ReadingFixedBody {
                remaining: next_remaining,
            }
        };
    }

    fn read_available_body(
        &mut self,
        direction: Direction,
        end_stream: bool,
        events: &mut Vec<EventKind>,
    ) {
        if self.buffer.is_empty() {
            return;
        }
        let len = self.buffer.len();
        let data = self.buffer.split_to(len).freeze();
        self.emit_body(direction, data, end_stream, events);
    }

    fn read_chunk_size(&mut self, direction: Direction, events: &mut Vec<EventKind>) {
        let Some(line_end) = find_line_end(&self.buffer) else {
            return;
        };
        let line = self.buffer.split_to(line_end).freeze();
        consume_line_ending(&mut self.buffer);

        match parse_chunk_size(&line) {
            Ok(0) => self.state = HttpState::ReadingChunkTrailers,
            Ok(size) => {
                self.state = HttpState::ReadingChunkData { remaining: size };
            }
            Err(reason) => self.fail(direction, reason, events),
        }
    }

    fn read_chunk_data(
        &mut self,
        direction: Direction,
        remaining: usize,
        events: &mut Vec<EventKind>,
    ) {
        if self.buffer.is_empty() {
            return;
        }

        let len = remaining.min(self.buffer.len());
        let data = self.buffer.split_to(len).freeze();
        let next_remaining = remaining - len;
        self.emit_body(direction, data, false, events);
        self.state = if next_remaining == 0 {
            HttpState::ReadingChunkTerminator
        } else {
            HttpState::ReadingChunkData {
                remaining: next_remaining,
            }
        };
    }

    fn read_chunk_terminator(&mut self, direction: Direction, events: &mut Vec<EventKind>) {
        if self.buffer.is_empty() {
            return;
        }
        match consume_line_ending(&mut self.buffer) {
            LineEnding::Complete => self.state = HttpState::ReadingChunkSize,
            LineEnding::Partial => {}
            LineEnding::Invalid => {
                self.fail(direction, "invalid chunk terminator".to_string(), events);
            }
        }
    }

    fn read_chunk_trailers(&mut self, direction: Direction, events: &mut Vec<EventKind>) {
        match consume_line_ending(&mut self.buffer) {
            LineEnding::Complete => {
                self.emit_body(direction, Bytes::new(), true, events);
                self.state = HttpState::ReadingHeaders;
                return;
            }
            LineEnding::Partial => return,
            LineEnding::Invalid => {}
        }
        let Some(consumed) = find_header_terminator(&self.buffer) else {
            return;
        };
        self.buffer.advance(consumed);
        self.emit_body(direction, Bytes::new(), true, events);
        self.state = HttpState::ReadingHeaders;
    }

    fn emit_body(
        &mut self,
        direction: Direction,
        data: Bytes,
        end_stream: bool,
        events: &mut Vec<EventKind>,
    ) {
        let chunk = BodyChunk {
            direction,
            stream_sequence: self.stream_sequence,
            offset: self.body_offset,
            data: data.clone(),
            end_stream,
        };
        self.body_offset = self
            .body_offset
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        events.push(EventKind::HttpBodyChunk(chunk));
        let sse = self.sse.ingest(direction, self.stream_sequence, &data);
        if sse.overflowed {
            events.push(EventKind::ProtocolError(ProtocolError {
                direction,
                reason: "sse event exceeded pending byte limit".to_string(),
            }));
        }
        events.extend(sse.events.into_iter().map(EventKind::SseEvent));
    }

    fn read_opaque(&mut self, direction: Direction, events: &mut Vec<EventKind>) {
        if self.buffer.is_empty() {
            return;
        }
        events.push(EventKind::OpaqueStream(OpaqueStream {
            direction,
            fingerprint: opaque_fingerprint(&self.buffer),
            reason: "opaque stream bytes after HTTP handoff".to_string(),
        }));
        self.buffer.clear();
    }

    fn fail(&mut self, direction: Direction, reason: String, events: &mut Vec<EventKind>) {
        self.reset();
        events.push(EventKind::ProtocolError(ProtocolError {
            direction,
            reason,
        }));
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.state = HttpState::ReadingHeaders;
        self.body_offset = 0;
        self.sse = SseDecoder::default();
    }

    fn enter_opaque(&mut self) {
        self.buffer.clear();
        self.state = HttpState::Opaque;
        self.body_offset = 0;
        self.sse = SseDecoder::default();
    }

    fn finish(&mut self, direction: Direction, events: &mut Vec<EventKind>) {
        match self.state {
            HttpState::StreamingUntilClose => {
                if self.buffer.is_empty() {
                    self.emit_body(direction, Bytes::new(), true, events);
                } else {
                    self.read_available_body(direction, true, events);
                }
            }
            HttpState::ReadingHeaders if !self.buffer.is_empty() => {
                self.fail(
                    direction,
                    "connection closed with partial HTTP headers".to_string(),
                    events,
                );
            }
            HttpState::ReadingFixedBody { remaining } => {
                if remaining > 0 {
                    self.read_available_body(direction, false, events);
                    self.fail(
                        direction,
                        "connection closed before fixed HTTP body completed".to_string(),
                        events,
                    );
                }
            }
            HttpState::ReadingChunkSize
            | HttpState::ReadingChunkData { .. }
            | HttpState::ReadingChunkTerminator
            | HttpState::ReadingChunkTrailers => {
                self.fail(
                    direction,
                    "connection closed before chunked HTTP body completed".to_string(),
                    events,
                );
            }
            HttpState::ReadingHeaders | HttpState::Opaque => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum HttpState {
    #[default]
    ReadingHeaders,
    ReadingFixedBody {
        remaining: usize,
    },
    StreamingUntilClose,
    ReadingChunkSize,
    ReadingChunkData {
        remaining: usize,
    },
    ReadingChunkTerminator,
    ReadingChunkTrailers,
    Opaque,
}

impl HttpState {
    fn can_progress_without_buffer(self) -> bool {
        matches!(self, Self::ReadingFixedBody { remaining: 0 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Progress {
    buffer_len: usize,
    state: HttpState,
}

impl Progress {
    fn new(buffer_len: usize, state: &HttpState) -> Self {
        Self {
            buffer_len,
            state: *state,
        }
    }
}

#[derive(Debug, Clone)]
struct BodyPlan {
    state: HttpState,
    is_sse: bool,
    opaque_reason: Option<String>,
}

impl BodyPlan {
    fn from_headers(
        role: HeaderRole,
        headers: &HttpHeaders,
        response_context: Option<ResponseContext>,
    ) -> Self {
        let is_sse = is_sse(&headers.headers);
        let opaque_reason = opaque_handoff_reason(role, headers, response_context);
        let has_no_body = response_context.is_some_and(ResponseContext::has_no_response_body)
            || response_status_has_no_body(role, headers.status);
        let state = if opaque_reason.is_some() {
            HttpState::Opaque
        } else if has_no_body {
            HttpState::ReadingHeaders
        } else if is_chunked(&headers.headers) {
            HttpState::ReadingChunkSize
        } else if let Some(content_length) = content_length(&headers.headers) {
            if content_length == 0 {
                HttpState::ReadingHeaders
            } else {
                HttpState::ReadingFixedBody {
                    remaining: content_length,
                }
            }
        } else if is_sse || role == HeaderRole::Response {
            HttpState::StreamingUntilClose
        } else {
            HttpState::ReadingHeaders
        };
        Self {
            state,
            is_sse,
            opaque_reason,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ResponseContext {
    request_method: RequestMethod,
}

impl ResponseContext {
    fn from_request(headers: &HttpHeaders) -> Self {
        let request_method = headers
            .method
            .as_deref()
            .map(RequestMethod::from_method)
            .unwrap_or(RequestMethod::Other);
        Self { request_method }
    }

    fn has_no_response_body(self) -> bool {
        self.request_method == RequestMethod::Head
    }

    fn is_connect(self) -> bool {
        self.request_method == RequestMethod::Connect
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestMethod {
    Head,
    Connect,
    Other,
}

impl RequestMethod {
    fn from_method(method: &str) -> Self {
        if method.eq_ignore_ascii_case("HEAD") {
            Self::Head
        } else if method.eq_ignore_ascii_case("CONNECT") {
            Self::Connect
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderRole {
    Request,
    Response,
}

fn response_status_has_no_body(role: HeaderRole, status: Option<u16>) -> bool {
    role == HeaderRole::Response && matches!(status, Some(100..=199) | Some(204) | Some(304))
}

fn is_interim_non_switching(status: Option<u16>) -> bool {
    matches!(status, Some(100..=199)) && status != Some(101)
}

fn opaque_handoff_reason(
    role: HeaderRole,
    headers: &HttpHeaders,
    response_context: Option<ResponseContext>,
) -> Option<String> {
    if role != HeaderRole::Response {
        return None;
    }
    if response_context.is_some_and(ResponseContext::is_connect)
        && headers
            .status
            .is_some_and(|status| (200..=299).contains(&status))
    {
        return Some("CONNECT tunnel established".to_string());
    }
    if headers.status == Some(101) || has_upgrade_header(&headers.headers) {
        return Some("HTTP upgrade handoff".to_string());
    }
    None
}

fn is_handoff_opaque_event(event: &EventKind) -> bool {
    matches!(
        event,
        EventKind::OpaqueStream(opaque)
            if opaque.reason == "CONNECT tunnel established"
                || opaque.reason == "HTTP upgrade handoff"
    )
}

fn opaque_data_events(direction: Direction, bytes: &[u8]) -> Vec<EventKind> {
    if bytes.is_empty() {
        return Vec::new();
    }
    vec![EventKind::OpaqueStream(OpaqueStream {
        direction,
        fingerprint: opaque_fingerprint(bytes),
        reason: "opaque stream bytes after HTTP handoff".to_string(),
    })]
}

fn has_upgrade_header(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name == "connection"
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
    }) || headers.iter().any(|(name, _)| name == "upgrade")
}

enum HeaderParse {
    Complete {
        consumed: usize,
        role: HeaderRole,
        headers: HttpHeaders,
    },
    Partial,
    Invalid(String),
}

fn parse_headers(direction: Direction, bytes: &[u8]) -> HeaderParse {
    if looks_like_response_prefix(bytes) {
        parse_response_headers(direction, bytes)
    } else {
        parse_request_headers(direction, bytes)
    }
}

fn parse_request_headers(direction: Direction, bytes: &[u8]) -> HeaderParse {
    let mut raw_headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut raw_headers);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(consumed)) => HeaderParse::Complete {
            consumed,
            role: HeaderRole::Request,
            headers: HttpHeaders {
                direction,
                stream_sequence: 0,
                method: request.method.map(str::to_string),
                target: request.path.map(str::to_string),
                status: None,
                reason: None,
                version: request.version.map_or_else(
                    || "HTTP/1.x".to_string(),
                    |version| format!("HTTP/1.{version}"),
                ),
                headers: normalize_headers(request.headers),
            },
        },
        Ok(httparse::Status::Partial) => HeaderParse::Partial,
        Err(error) => HeaderParse::Invalid(error.to_string()),
    }
}

fn parse_response_headers(direction: Direction, bytes: &[u8]) -> HeaderParse {
    let mut raw_headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut raw_headers);
    match response.parse(bytes) {
        Ok(httparse::Status::Complete(consumed)) => HeaderParse::Complete {
            consumed,
            role: HeaderRole::Response,
            headers: HttpHeaders {
                direction,
                stream_sequence: 0,
                method: None,
                target: None,
                status: response.code,
                reason: response.reason.map(str::to_string),
                version: response.version.map_or_else(
                    || "HTTP/1.x".to_string(),
                    |version| format!("HTTP/1.{version}"),
                ),
                headers: normalize_headers(response.headers),
            },
        },
        Ok(httparse::Status::Partial) => HeaderParse::Partial,
        Err(error) => HeaderParse::Invalid(error.to_string()),
    }
}

fn looks_like_response_prefix(bytes: &[u8]) -> bool {
    const RESPONSE_PREFIX: &[u8] = b"HTTP/";
    bytes.starts_with(RESPONSE_PREFIX) || RESPONSE_PREFIX.starts_with(bytes)
}

fn normalize_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|header| {
            (
                header.name.to_ascii_lowercase(),
                String::from_utf8_lossy(header.value).into_owned(),
            )
        })
        .collect()
}

fn content_length(headers: &[(String, String)]) -> Option<usize> {
    headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name == "transfer-encoding"
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    })
}

fn is_sse(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name == "content-type"
            && value
                .split(';')
                .any(|part| part.trim().eq_ignore_ascii_case("text/event-stream"))
    })
}

fn find_header_terminator(input: &[u8]) -> Option<usize> {
    input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            input
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        })
}

fn find_line_end(input: &[u8]) -> Option<usize> {
    input
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|position| {
            if position > 0 && input[position - 1] == b'\r' {
                position - 1
            } else {
                position
            }
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineEnding {
    Complete,
    Partial,
    Invalid,
}

fn consume_line_ending(buffer: &mut BytesMut) -> LineEnding {
    if buffer.starts_with(b"\r\n") {
        buffer.advance(2);
        LineEnding::Complete
    } else if buffer.starts_with(b"\n") {
        buffer.advance(1);
        LineEnding::Complete
    } else if buffer.as_ref() == b"\r" {
        LineEnding::Partial
    } else {
        LineEnding::Invalid
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, String> {
    let text = std::str::from_utf8(line).map_err(|error| error.to_string())?;
    let size = text.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(size, 16).map_err(|error| format!("invalid chunk size: {error}"))
}

fn opaque_fingerprint(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len().min(16)].to_vec()
}

#[derive(Debug, Default)]
struct SseDecoder {
    enabled: bool,
    pending: Vec<u8>,
}

impl SseDecoder {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            pending: Vec::new(),
        }
    }

    fn ingest(
        &mut self,
        direction: Direction,
        stream_sequence: u64,
        bytes: &[u8],
    ) -> SseDecodeOutput {
        if !self.enabled || bytes.is_empty() {
            return SseDecodeOutput::default();
        }
        self.pending.extend_from_slice(bytes);
        if self.pending.len() > MAX_SSE_PENDING_BYTES {
            self.pending.clear();
            return SseDecodeOutput {
                events: Vec::new(),
                overflowed: true,
            };
        }

        let mut events = Vec::new();
        while let Some(split_at) = find_sse_boundary(&self.pending) {
            let raw = bytes_to_sse_text(self.pending[..split_at].to_vec());
            let drain_to = split_at + boundary_len(&self.pending[split_at..]);
            self.pending.drain(..drain_to);
            if let Some(event) = parse_sse_event(direction, stream_sequence, &raw) {
                events.push(event);
            }
        }
        SseDecodeOutput {
            events,
            overflowed: false,
        }
    }
}

#[derive(Debug, Default)]
struct SseDecodeOutput {
    events: Vec<SseEvent>,
    overflowed: bool,
}

fn find_sse_boundary(input: &[u8]) -> Option<usize> {
    input
        .windows(2)
        .position(|window| window == b"\n\n")
        .or_else(|| input.windows(4).position(|window| window == b"\r\n\r\n"))
}

fn boundary_len(input: &[u8]) -> usize {
    if input.starts_with(b"\r\n\r\n") { 4 } else { 2 }
}

fn bytes_to_sse_text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|error| {
        let bytes = error.into_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

fn parse_sse_event(direction: Direction, stream_sequence: u64, raw: &str) -> Option<SseEvent> {
    let mut event = None;
    let mut id = None;
    let mut retry_ms = None;
    let mut data = Vec::new();

    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = line
            .split_once(':')
            .map(|(field, value)| (field, value.trim_start()))
            .unwrap_or((line, ""));
        match field {
            "event" => event = Some(value.to_string()),
            "id" => id = Some(value.to_string()),
            "retry" => retry_ms = value.parse::<u64>().ok(),
            "data" => data.push(value.to_string()),
            _ => {}
        }
    }

    if event.is_none() && id.is_none() && retry_ms.is_none() && data.is_empty() {
        return None;
    }

    Some(SseEvent {
        direction,
        stream_sequence,
        event,
        id,
        retry_ms,
        data: data.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use probe_core::{Direction, EventKind};

    use crate::{Http1Parser, ParserInput, ProtocolParser};

    #[test]
    fn parses_http_request_headers_and_body_chunk() {
        let mut parser = Http1Parser::default();
        let events = parser.ingest(
            Direction::Outbound,
            b"POST /v1/chat HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello",
        );

        assert!(matches!(
            events.first(),
            Some(EventKind::HttpRequestHeaders(headers)) if headers.stream_sequence == 1
        ));
        assert!(matches!(
            events.get(1),
            Some(EventKind::HttpBodyChunk(chunk)) if chunk.end_stream && chunk.data.as_ref() == b"hello"
        ));
    }

    #[test]
    fn parses_process_inbound_http_request_as_request() {
        let mut parser = Http1Parser::default();
        let events = parser.ingest(
            Direction::Inbound,
            b"GET /server HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );

        assert!(matches!(
            events.first(),
            Some(EventKind::HttpRequestHeaders(headers))
                if headers.direction == Direction::Inbound
                    && headers.target.as_deref() == Some("/server")
        ));
    }

    #[test]
    fn matches_process_outbound_response_to_inbound_head_request() {
        let mut parser = Http1Parser::default();
        let request_events = parser.ingest(
            Direction::Inbound,
            b"HEAD /server HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );
        let response_events = parser.ingest(
            Direction::Outbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n",
        );

        assert!(matches!(
            request_events.first(),
            Some(EventKind::HttpRequestHeaders(headers))
                if headers.direction == Direction::Inbound
                    && headers.method.as_deref() == Some("HEAD")
        ));
        assert!(matches!(
            response_events.first(),
            Some(EventKind::HttpResponseHeaders(headers))
                if headers.direction == Direction::Outbound
                    && headers.status == Some(200)
        ));
        assert_eq!(
            response_events
                .iter()
                .filter(|event| matches!(event, EventKind::HttpBodyChunk(_)))
                .count(),
            0
        );
    }

    #[test]
    fn parses_pipelined_requests_as_distinct_messages() {
        let mut parser = Http1Parser::default();
        let events = parser.ingest(
            Direction::Outbound,
            b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );

        let targets = events
            .into_iter()
            .filter_map(|event| match event {
                EventKind::HttpRequestHeaders(headers) => headers.target,
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(targets, vec!["/one", "/two"]);
    }

    #[test]
    fn parses_chunked_body_and_returns_to_headers() {
        let mut parser = Http1Parser::default();
        let events = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nHTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
        );

        assert!(events.iter().any(
            |event| matches!(event, EventKind::HttpBodyChunk(chunk) if chunk.data.as_ref() == b"hello")
        ));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, EventKind::HttpResponseHeaders(_)))
                .count(),
            2
        );
    }

    #[test]
    fn waits_for_split_chunk_terminator() {
        let mut parser = Http1Parser::default();
        let first = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r",
        );
        assert!(
            first
                .iter()
                .all(|event| !matches!(event, EventKind::ProtocolError(_)))
        );

        let second = parser.ingest(Direction::Inbound, b"\n0\r\n\r\n");
        assert!(
            second
                .iter()
                .any(|event| matches!(event, EventKind::HttpBodyChunk(chunk) if chunk.end_stream))
        );
    }

    #[test]
    fn no_body_response_status_returns_to_headers() {
        let mut parser = Http1Parser::default();
        let events = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 304 Not Modified\r\n\r\n",
        );

        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, EventKind::HttpResponseHeaders(_)))
                .count(),
            2
        );
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EventKind::HttpBodyChunk(_)))
        );
    }

    #[test]
    fn head_response_does_not_swallow_next_response() {
        let mut parser = Http1Parser::default();
        parser.ingest(
            Direction::Outbound,
            b"HEAD / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );
        let events = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        );

        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, EventKind::HttpResponseHeaders(_)))
                .count(),
            2
        );
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EventKind::HttpBodyChunk(_)))
        );
    }

    #[test]
    fn connect_success_hands_off_to_opaque_stream() {
        let mut parser = Http1Parser::default();
        parser.ingest(
            Direction::Outbound,
            b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );
        let events = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 Connection Established\r\n\r\nTLSBYTES",
        );

        assert!(
            events
                .iter()
                .any(|event| matches!(event, EventKind::OpaqueStream(opaque) if opaque.reason == "CONNECT tunnel established"))
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, EventKind::OpaqueStream(_)))
                .count(),
            1
        );
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EventKind::HttpBodyChunk(_)))
        );
    }

    #[test]
    fn connect_handoff_makes_both_directions_opaque() {
        let mut parser = Http1Parser::default();
        parser.ingest(
            Direction::Outbound,
            b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );
        parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        );
        let events = parser.ingest(Direction::Outbound, b"TLSBYTES");

        assert!(
            events
                .iter()
                .any(|event| matches!(event, EventKind::OpaqueStream(opaque) if opaque.direction == Direction::Outbound))
        );
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EventKind::ProtocolError(_)))
        );
    }

    #[test]
    fn interim_response_does_not_consume_head_context() {
        let mut parser = Http1Parser::default();
        parser.ingest(
            Direction::Outbound,
            b"HEAD / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );
        let events = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        );

        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, EventKind::HttpResponseHeaders(_)))
                .count(),
            3
        );
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EventKind::HttpBodyChunk(_)))
        );
    }

    #[test]
    fn interim_response_does_not_consume_connect_context() {
        let mut parser = Http1Parser::default();
        parser.ingest(
            Direction::Outbound,
            b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );
        let events = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\n",
        );

        assert!(
            events
                .iter()
                .any(|event| matches!(event, EventKind::OpaqueStream(opaque) if opaque.reason == "CONNECT tunnel established"))
        );
    }

    #[test]
    fn parses_sse_events_from_streaming_response() {
        let mut parser = Http1Parser::default();
        let events = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: message\ndata: hello\n\n",
        );

        assert!(
            events
                .iter()
                .any(|event| matches!(event, EventKind::SseEvent(sse) if sse.data == "hello"))
        );
    }

    #[test]
    fn parses_sse_utf8_split_across_chunks() {
        let mut parser = Http1Parser::default();
        let first = parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: caf\xc3",
        );
        assert!(
            first
                .iter()
                .all(|event| !matches!(event, EventKind::SseEvent(_)))
        );

        let second = parser.ingest(Direction::Inbound, b"\xa9\n\n");
        assert!(
            second.iter().any(
                |event| matches!(event, EventKind::SseEvent(sse) if sse.data == "caf\u{00e9}")
            )
        );
    }

    #[test]
    fn emits_gap_and_resets_parser_state() {
        let mut parser = Http1Parser::default();
        let output = ProtocolParser::ingest(
            &mut parser,
            ParserInput::Gap {
                direction: Direction::Outbound,
                expected_offset: 10,
                next_offset: Some(20),
                reason: "lost bytes",
            },
        );

        assert!(
            matches!(output.events().first(), Some(EventKind::Gap(gap)) if gap.reason == "lost bytes")
        );
    }

    #[test]
    fn waits_for_partial_headers() {
        let mut parser = Http1Parser::default();
        let events = parser.ingest(Direction::Outbound, b"GET / HTTP/1.1\r\nHost:");
        assert!(events.is_empty());
    }

    #[test]
    fn connection_close_reports_partial_headers() {
        let mut parser = Http1Parser::default();
        assert!(
            parser
                .ingest(Direction::Outbound, b"GET / HTTP/1.1\r\nHost:")
                .is_empty()
        );

        let events = close_events(&mut parser);

        assert!(events.iter().any(|event| matches!(
            event,
            EventKind::ProtocolError(error)
                if error.direction == Direction::Outbound
                    && error.reason == "connection closed with partial HTTP headers"
        )));
    }

    #[test]
    fn connection_close_reports_incomplete_fixed_body() {
        let mut parser = Http1Parser::default();
        parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe",
        );

        let events = close_events(&mut parser);

        assert!(events.iter().any(|event| matches!(
            event,
            EventKind::ProtocolError(error)
                if error.direction == Direction::Inbound
                    && error.reason
                        == "connection closed before fixed HTTP body completed"
        )));
    }

    #[test]
    fn connection_close_reports_incomplete_chunked_body() {
        let mut parser = Http1Parser::default();
        parser.ingest(
            Direction::Inbound,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhe",
        );

        let events = close_events(&mut parser);

        assert!(events.iter().any(|event| matches!(
            event,
            EventKind::ProtocolError(error)
                if error.direction == Direction::Inbound
                    && error.reason
                        == "connection closed before chunked HTTP body completed"
        )));
    }

    fn close_events(parser: &mut Http1Parser) -> Vec<EventKind> {
        ProtocolParser::ingest(parser, ParserInput::ConnectionClosed).into_events()
    }
}

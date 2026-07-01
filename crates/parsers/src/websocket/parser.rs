use bytes::{Bytes, BytesMut};
use probe_core::{
    Direction, EventKind, ProtocolError, WebSocketFrame, WebSocketMessage, WebSocketMessageOpcode,
    WebSocketOpcode,
};

use crate::{ParserInput, ParserOutput, ProtocolParser, gap_event};

const MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WEBSOCKET_MESSAGE_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WEBSOCKET_FRAME_HEADER_BYTES: usize = 14;
const MASK_HASH_SCRATCH_BYTES: usize = 4096;

#[derive(Debug)]
pub struct WebSocketFrameParser {
    stream_sequence: u64,
    inbound: WebSocketDirectionState,
    outbound: WebSocketDirectionState,
}

impl WebSocketFrameParser {
    pub fn new(stream_sequence: u64) -> Self {
        Self {
            stream_sequence,
            inbound: WebSocketDirectionState::default(),
            outbound: WebSocketDirectionState::default(),
        }
    }

    fn state_mut(&mut self, direction: Direction) -> &mut WebSocketDirectionState {
        match direction {
            Direction::Inbound => &mut self.inbound,
            Direction::Outbound => &mut self.outbound,
        }
    }
}

impl Default for WebSocketFrameParser {
    fn default() -> Self {
        Self::new(0)
    }
}

impl ProtocolParser for WebSocketFrameParser {
    fn ingest(&mut self, input: ParserInput<'_>) -> ParserOutput {
        match input {
            ParserInput::Data { direction, bytes } => {
                let stream_sequence = self.stream_sequence;
                ParserOutput::from_events(self.state_mut(direction).ingest_data(
                    direction,
                    stream_sequence,
                    bytes,
                ))
            }
            ParserInput::Gap {
                direction,
                expected_offset,
                next_offset,
                reason,
            } => {
                self.state_mut(direction).reset();
                ParserOutput::from_events(vec![gap_event(
                    direction,
                    expected_offset,
                    next_offset,
                    reason,
                )])
            }
            ParserInput::ConnectionClosed => {
                let mut events = Vec::new();
                self.inbound.finish(Direction::Inbound, &mut events);
                self.outbound.finish(Direction::Outbound, &mut events);
                ParserOutput::from_events(events)
            }
        }
    }

    fn is_checkpoint_safe(&self) -> bool {
        self.inbound.is_checkpoint_safe() && self.outbound.is_checkpoint_safe()
    }
}

#[derive(Debug, Default)]
struct WebSocketDirectionState {
    header_buffer: BytesMut,
    pending: Option<PendingWebSocketFrame>,
    frame_sequence: u64,
    messages: WebSocketMessageAggregator,
}

impl WebSocketDirectionState {
    fn ingest_data(
        &mut self,
        direction: Direction,
        stream_sequence: u64,
        bytes: &[u8],
    ) -> Vec<EventKind> {
        let mut cursor = 0;
        let mut events = Vec::new();

        while cursor < bytes.len() {
            if self.pending.is_some() {
                cursor += self.consume_pending_payload(&bytes[cursor..]);
                self.emit_completed_pending(direction, stream_sequence, &mut events);
                continue;
            }

            if self.header_buffer.is_empty() {
                match parse_frame_header(&bytes[cursor..]) {
                    FrameHeaderParse::Complete { consumed, header } => {
                        cursor += consumed;
                        if !self.accept_frame_header(direction, header, &mut events) {
                            break;
                        }
                        self.emit_completed_pending(direction, stream_sequence, &mut events);
                    }
                    FrameHeaderParse::Partial => {
                        self.header_buffer.extend_from_slice(&bytes[cursor..]);
                        break;
                    }
                    FrameHeaderParse::Invalid(reason) => {
                        self.fail(direction, reason, &mut events);
                        break;
                    }
                }
            } else {
                let remaining_header_budget =
                    MAX_WEBSOCKET_FRAME_HEADER_BYTES.saturating_sub(self.header_buffer.len());
                let copied = remaining_header_budget.min(bytes.len() - cursor);
                self.header_buffer
                    .extend_from_slice(&bytes[cursor..cursor + copied]);
                cursor += copied;

                match parse_frame_header(&self.header_buffer) {
                    FrameHeaderParse::Complete { consumed, header } => {
                        let payload_prefix = self.header_buffer.split_off(consumed);
                        self.header_buffer.clear();
                        if !self.accept_frame_header(direction, header, &mut events) {
                            break;
                        }
                        if !payload_prefix.is_empty() {
                            self.consume_pending_payload(&payload_prefix);
                        }
                        self.emit_completed_pending(direction, stream_sequence, &mut events);
                    }
                    FrameHeaderParse::Partial => {
                        if copied == 0 {
                            self.fail(
                                direction,
                                "websocket frame header exceeds maximum length".to_string(),
                                &mut events,
                            );
                            break;
                        }
                    }
                    FrameHeaderParse::Invalid(reason) => {
                        self.fail(direction, reason, &mut events);
                        break;
                    }
                }
            }
        }
        events
    }

    fn finish(&mut self, direction: Direction, events: &mut Vec<EventKind>) {
        if !self.header_buffer.is_empty() || self.pending.is_some() {
            events.push(EventKind::ProtocolError(ProtocolError {
                direction,
                reason: "incomplete websocket frame at connection close".to_string(),
            }));
            self.reset();
        } else if !self.messages.is_checkpoint_safe() {
            events.push(EventKind::ProtocolError(ProtocolError {
                direction,
                reason: "incomplete websocket message at connection close".to_string(),
            }));
            self.reset();
        }
    }

    fn reset(&mut self) {
        self.header_buffer.clear();
        self.pending = None;
        self.messages.reset();
    }

    fn is_checkpoint_safe(&self) -> bool {
        self.header_buffer.is_empty()
            && self.pending.is_none()
            && self.messages.is_checkpoint_safe()
    }

    fn accept_frame_header(
        &mut self,
        direction: Direction,
        header: ParsedWebSocketHeader,
        events: &mut Vec<EventKind>,
    ) -> bool {
        let frame_sequence = self.frame_sequence.saturating_add(1);
        if let Err(reason) = self.prepare_message_state(&header) {
            self.fail(direction, reason, events);
            return false;
        }
        self.messages.on_frame_start(&header, frame_sequence);
        self.pending = Some(PendingWebSocketFrame::new(header, frame_sequence));
        true
    }

    fn prepare_message_state(&mut self, header: &ParsedWebSocketHeader) -> Result<(), String> {
        match header.opcode {
            WebSocketOpcode::Text | WebSocketOpcode::Binary => {
                if !self.messages.is_checkpoint_safe() {
                    return Err(
                        "websocket data frame started before fragmented message completed"
                            .to_string(),
                    );
                }
                Ok(())
            }
            WebSocketOpcode::Continuation => {
                if self.messages.is_checkpoint_safe() {
                    return Err("websocket continuation frame without open message".to_string());
                }
                Ok(())
            }
            WebSocketOpcode::Close | WebSocketOpcode::Ping | WebSocketOpcode::Pong => {
                validate_control_frame(header)
            }
            WebSocketOpcode::Other { .. } if is_control_wire_opcode(header.wire_opcode) => {
                validate_control_frame(header)
            }
            WebSocketOpcode::Other { .. } if !self.messages.is_checkpoint_safe() => {
                Err("websocket data frame started before fragmented message completed".to_string())
            }
            WebSocketOpcode::Other { .. } => Ok(()),
        }
    }

    fn consume_pending_payload(&mut self, bytes: &[u8]) -> usize {
        let Some(pending) = &mut self.pending else {
            return 0;
        };
        let payload_offset = pending.consumed_payload_len;
        let consumed = pending.consume_payload(bytes);
        let mask_key = pending.mask_key;
        self.messages
            .on_payload_chunk(pending, &bytes[..consumed], mask_key, payload_offset);
        consumed
    }

    fn emit_completed_pending(
        &mut self,
        direction: Direction,
        stream_sequence: u64,
        events: &mut Vec<EventKind>,
    ) {
        let Some(pending) = &self.pending else {
            return;
        };
        if !pending.is_complete() {
            return;
        }
        let pending = self.pending.take().expect("pending frame must exist");
        let frame_sequence = pending.frame_sequence;
        let message = self
            .messages
            .on_frame_complete(&pending, direction, stream_sequence);
        self.frame_sequence = frame_sequence;
        events.push(EventKind::WebSocketFrame(WebSocketFrame {
            direction,
            stream_sequence,
            frame_sequence,
            fin: pending.fin,
            rsv1: pending.rsv1,
            rsv2: pending.rsv2,
            rsv3: pending.rsv3,
            opcode: pending.opcode,
            payload_len: pending.payload_len,
            masked: pending.mask_key.is_some(),
            payload_fingerprint: pending.payload_fingerprint(),
        }));
        if let Some(message) = message {
            events.push(EventKind::WebSocketMessage(message));
        }
    }

    fn fail(&mut self, direction: Direction, reason: String, events: &mut Vec<EventKind>) {
        self.reset();
        events.push(EventKind::ProtocolError(ProtocolError {
            direction,
            reason,
        }));
    }
}

enum FrameHeaderParse {
    Complete {
        consumed: usize,
        header: ParsedWebSocketHeader,
    },
    Partial,
    Invalid(String),
}

struct ParsedWebSocketHeader {
    wire_opcode: u8,
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: WebSocketOpcode,
    payload_len: u64,
    mask_key: Option<[u8; 4]>,
}

#[derive(Debug)]
struct PendingWebSocketFrame {
    frame_sequence: u64,
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: WebSocketOpcode,
    payload_len: u64,
    consumed_payload_len: u64,
    mask_key: Option<[u8; 4]>,
    hasher: blake3::Hasher,
}

impl PendingWebSocketFrame {
    fn new(header: ParsedWebSocketHeader, frame_sequence: u64) -> Self {
        Self {
            frame_sequence,
            fin: header.fin,
            rsv1: header.rsv1,
            rsv2: header.rsv2,
            rsv3: header.rsv3,
            opcode: header.opcode,
            payload_len: header.payload_len,
            consumed_payload_len: 0,
            mask_key: header.mask_key,
            hasher: blake3::Hasher::new(),
        }
    }

    fn consume_payload(&mut self, bytes: &[u8]) -> usize {
        let remaining = self.payload_len.saturating_sub(self.consumed_payload_len);
        let consumed = bytes.len().min(
            usize::try_from(remaining)
                .expect("payload length is bounded below usize::MAX by parser limit"),
        );
        let payload = &bytes[..consumed];
        update_payload_hash(
            &mut self.hasher,
            payload,
            self.mask_key,
            self.consumed_payload_len,
        );
        self.consumed_payload_len = self.consumed_payload_len.saturating_add(consumed as u64);
        consumed
    }

    fn is_complete(&self) -> bool {
        self.consumed_payload_len >= self.payload_len
    }

    fn is_message_payload_frame(&self) -> bool {
        matches!(
            self.opcode,
            WebSocketOpcode::Text | WebSocketOpcode::Binary | WebSocketOpcode::Continuation
        )
    }

    fn completes_message(&self) -> bool {
        self.fin && self.is_message_payload_frame()
    }

    fn payload_fingerprint(self) -> Vec<u8> {
        self.hasher.finalize().as_bytes()[..16].to_vec()
    }
}

#[derive(Debug, Default)]
struct WebSocketMessageAggregator {
    pending: Option<PendingWebSocketMessage>,
    sequence: u64,
}

impl WebSocketMessageAggregator {
    fn reset(&mut self) {
        self.pending = None;
    }

    fn is_checkpoint_safe(&self) -> bool {
        self.pending.is_none()
    }

    fn on_frame_start(&mut self, header: &ParsedWebSocketHeader, frame_sequence: u64) {
        match header.opcode {
            WebSocketOpcode::Text | WebSocketOpcode::Binary => {
                if header.rsv1 || header.rsv2 || header.rsv3 {
                    if !header.fin {
                        self.pending = Some(PendingWebSocketMessage::skipping());
                    }
                    return;
                }
                self.pending = Some(PendingWebSocketMessage::aggregating(
                    message_opcode_from_frame(header.opcode)
                        .expect("data frame opcode should convert to a message opcode"),
                    frame_sequence,
                ));
            }
            WebSocketOpcode::Continuation => {
                if header.rsv1 || header.rsv2 || header.rsv3 {
                    self.skip();
                }
            }
            WebSocketOpcode::Other { .. } if !is_control_wire_opcode(header.wire_opcode) => {
                if !header.fin {
                    self.skip();
                }
            }
            WebSocketOpcode::Close
            | WebSocketOpcode::Ping
            | WebSocketOpcode::Pong
            | WebSocketOpcode::Other { .. } => {}
        }
    }

    fn on_payload_chunk(
        &mut self,
        frame: &PendingWebSocketFrame,
        payload: &[u8],
        mask_key: Option<[u8; 4]>,
        payload_offset: u64,
    ) {
        if !frame.is_message_payload_frame() {
            return;
        }
        let Some(PendingWebSocketMessage::Aggregating(message)) = self.pending.as_mut() else {
            return;
        };
        if !message.append_payload(payload, mask_key, payload_offset) {
            self.skip();
        }
    }

    fn on_frame_complete(
        &mut self,
        frame: &PendingWebSocketFrame,
        direction: Direction,
        stream_sequence: u64,
    ) -> Option<WebSocketMessage> {
        if !frame.completes_message() {
            return None;
        }
        let message = self.pending.take()?;
        let PendingWebSocketMessage::Aggregating(message) = message else {
            return None;
        };
        let payload_fingerprint = message.payload_fingerprint();
        let payload = Bytes::from(message.payload);
        self.sequence = self.sequence.saturating_add(1);
        Some(WebSocketMessage {
            direction,
            stream_sequence,
            message_sequence: self.sequence,
            first_frame_sequence: message.first_frame_sequence,
            final_frame_sequence: frame.frame_sequence,
            opcode: message.opcode,
            payload_len: message.payload_len,
            payload,
            payload_fingerprint,
        })
    }

    fn skip(&mut self) {
        self.pending = Some(PendingWebSocketMessage::skipping());
    }
}

#[derive(Debug)]
enum PendingWebSocketMessage {
    Aggregating(Box<AggregatingWebSocketMessage>),
    Skipping,
}

impl PendingWebSocketMessage {
    fn aggregating(opcode: WebSocketMessageOpcode, first_frame_sequence: u64) -> Self {
        Self::Aggregating(Box::new(AggregatingWebSocketMessage {
            opcode,
            first_frame_sequence,
            payload_len: 0,
            payload: Vec::new(),
            hasher: blake3::Hasher::new(),
        }))
    }

    fn skipping() -> Self {
        Self::Skipping
    }
}

#[derive(Debug)]
struct AggregatingWebSocketMessage {
    opcode: WebSocketMessageOpcode,
    first_frame_sequence: u64,
    payload_len: u64,
    payload: Vec<u8>,
    hasher: blake3::Hasher,
}

impl AggregatingWebSocketMessage {
    fn append_payload(
        &mut self,
        payload: &[u8],
        mask_key: Option<[u8; 4]>,
        payload_offset: u64,
    ) -> bool {
        let payload_len =
            u64::try_from(payload.len()).expect("payload slice length should fit into u64");
        let Some(next_payload_len) = self.payload_len.checked_add(payload_len) else {
            return false;
        };
        if next_payload_len > MAX_WEBSOCKET_MESSAGE_PAYLOAD_BYTES {
            return false;
        }
        update_payload_hash_and_collect(
            &mut self.hasher,
            payload,
            mask_key,
            payload_offset,
            &mut self.payload,
        );
        self.payload_len = next_payload_len;
        true
    }

    fn payload_fingerprint(&self) -> Vec<u8> {
        self.hasher.finalize().as_bytes()[..16].to_vec()
    }
}

fn parse_frame_header(buffer: &[u8]) -> FrameHeaderParse {
    if buffer.len() < 2 {
        return FrameHeaderParse::Partial;
    }
    let first = buffer[0];
    let second = buffer[1];
    let mut header_len: usize = 2;
    let payload_len = match second & 0x7f {
        len @ 0..=125 => u64::from(len),
        126 => {
            if buffer.len() < 4 {
                return FrameHeaderParse::Partial;
            }
            header_len = 4;
            u64::from(u16::from_be_bytes([buffer[2], buffer[3]]))
        }
        127 => {
            if buffer.len() < 10 {
                return FrameHeaderParse::Partial;
            }
            header_len = 10;
            let len = u64::from_be_bytes([
                buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8],
                buffer[9],
            ]);
            if len & (1 << 63) != 0 {
                return FrameHeaderParse::Invalid(
                    "websocket 64-bit payload length uses reserved high bit".to_string(),
                );
            }
            len
        }
        _ => unreachable!("7-bit payload length is exhaustive"),
    };
    if payload_len > MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES {
        return FrameHeaderParse::Invalid(format!(
            "websocket frame payload length {payload_len} exceeds limit {MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES}"
        ));
    }
    let masked = second & 0x80 != 0;
    let mask_len = if masked { 4 } else { 0 };
    let Some(payload_start) = header_len.checked_add(mask_len) else {
        return FrameHeaderParse::Invalid("websocket frame header length overflowed".to_string());
    };
    if buffer.len() < payload_start {
        return FrameHeaderParse::Partial;
    }
    let mask_key = masked.then(|| {
        [
            buffer[header_len],
            buffer[header_len + 1],
            buffer[header_len + 2],
            buffer[header_len + 3],
        ]
    });
    FrameHeaderParse::Complete {
        consumed: payload_start,
        header: ParsedWebSocketHeader {
            wire_opcode: first & 0x0f,
            fin: first & 0x80 != 0,
            rsv1: first & 0x40 != 0,
            rsv2: first & 0x20 != 0,
            rsv3: first & 0x10 != 0,
            opcode: opcode_from_wire(first & 0x0f),
            payload_len,
            mask_key,
        },
    }
}

fn validate_control_frame(header: &ParsedWebSocketHeader) -> Result<(), String> {
    if !header.fin {
        return Err("websocket control frame must not be fragmented".to_string());
    }
    if header.payload_len > 125 {
        return Err("websocket control frame payload exceeds 125 bytes".to_string());
    }
    Ok(())
}

fn is_control_wire_opcode(wire_opcode: u8) -> bool {
    wire_opcode >= 0x8
}

fn message_opcode_from_frame(opcode: WebSocketOpcode) -> Option<WebSocketMessageOpcode> {
    match opcode {
        WebSocketOpcode::Text => Some(WebSocketMessageOpcode::Text),
        WebSocketOpcode::Binary => Some(WebSocketMessageOpcode::Binary),
        WebSocketOpcode::Continuation
        | WebSocketOpcode::Close
        | WebSocketOpcode::Ping
        | WebSocketOpcode::Pong
        | WebSocketOpcode::Other { .. } => None,
    }
}

fn opcode_from_wire(code: u8) -> WebSocketOpcode {
    match code {
        0x0 => WebSocketOpcode::Continuation,
        0x1 => WebSocketOpcode::Text,
        0x2 => WebSocketOpcode::Binary,
        0x8 => WebSocketOpcode::Close,
        0x9 => WebSocketOpcode::Ping,
        0xa => WebSocketOpcode::Pong,
        code => WebSocketOpcode::Other { code },
    }
}

#[cfg(test)]
fn payload_fingerprint(payload: &[u8], mask_key: Option<[u8; 4]>) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    update_payload_hash(&mut hasher, payload, mask_key, 0);
    hasher.finalize().as_bytes()[..16].to_vec()
}

fn update_payload_hash(
    hasher: &mut blake3::Hasher,
    payload: &[u8],
    mask_key: Option<[u8; 4]>,
    payload_offset: u64,
) {
    visit_unmasked_payload_chunks(payload, mask_key, payload_offset, |chunk| {
        hasher.update(chunk);
    });
}

fn update_payload_hash_and_collect(
    hasher: &mut blake3::Hasher,
    payload: &[u8],
    mask_key: Option<[u8; 4]>,
    payload_offset: u64,
    output: &mut Vec<u8>,
) {
    visit_unmasked_payload_chunks(payload, mask_key, payload_offset, |chunk| {
        hasher.update(chunk);
        output.extend_from_slice(chunk);
    });
}

fn visit_unmasked_payload_chunks(
    payload: &[u8],
    mask_key: Option<[u8; 4]>,
    payload_offset: u64,
    mut visit: impl FnMut(&[u8]),
) {
    match mask_key {
        Some(mask_key) => {
            let mut scratch = [0u8; MASK_HASH_SCRATCH_BYTES];
            let mut offset = payload_offset as usize;
            for chunk in payload.chunks(MASK_HASH_SCRATCH_BYTES) {
                for (index, byte) in chunk.iter().enumerate() {
                    scratch[index] = *byte ^ mask_key[(offset + index) % mask_key.len()];
                }
                visit(&scratch[..chunk.len()]);
                offset = offset.saturating_add(chunk.len());
            }
        }
        None => {
            visit(payload);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_parser_emits_frame_metadata_for_unmasked_frame() {
        let mut parser = WebSocketFrameParser::new(9);

        let events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x81\x05hello",
            })
            .into_events();

        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[0],
            EventKind::WebSocketFrame(frame)
                if frame.direction == Direction::Inbound
                    && frame.stream_sequence == 9
                    && frame.frame_sequence == 1
                    && frame.fin
                    && !frame.rsv1
                    && frame.opcode == WebSocketOpcode::Text
                    && frame.payload_len == 5
                    && !frame.masked
                    && frame.payload_fingerprint == payload_fingerprint(b"hello", None)
        ));
        assert!(matches!(
            &events[1],
            EventKind::WebSocketMessage(message)
                if message.direction == Direction::Inbound
                    && message.stream_sequence == 9
                    && message.message_sequence == 1
                    && message.first_frame_sequence == 1
                    && message.final_frame_sequence == 1
                    && message.opcode == WebSocketMessageOpcode::Text
                    && message.payload_len == 5
                    && message.payload == Bytes::from_static(b"hello")
                    && message.payload_fingerprint == payload_fingerprint(b"hello", None)
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_unmasks_payload_before_fingerprinting() {
        let mut parser = WebSocketFrameParser::new(1);
        let masked_hello = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x5f, 0x9f, 0x4d, 0x51, 0x58,
        ];

        let events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Outbound,
                bytes: &masked_hello,
            })
            .into_events();

        assert!(matches!(
            &events[0],
            EventKind::WebSocketFrame(frame)
                if frame.masked
                    && frame.payload_fingerprint == payload_fingerprint(b"hello", None)
        ));
        assert!(matches!(
            &events[1],
            EventKind::WebSocketMessage(message)
                if message.payload == Bytes::from_static(b"hello")
                    && message.payload_fingerprint == payload_fingerprint(b"hello", None)
        ));
    }

    #[test]
    fn websocket_parser_unmasks_split_payload_with_global_mask_offset() {
        let mut parser = WebSocketFrameParser::new(1);
        let first = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x5f, 0x9f, 0x4d];
        let second = [0x51, 0x58];

        let first_events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Outbound,
                bytes: &first,
            })
            .into_events();
        let second_events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Outbound,
                bytes: &second,
            })
            .into_events();

        assert!(first_events.is_empty());
        assert!(matches!(
            &second_events[0],
            EventKind::WebSocketFrame(frame)
                if frame.masked
                    && frame.payload_fingerprint == payload_fingerprint(b"hello", None)
        ));
    }

    #[test]
    fn websocket_parser_waits_for_partial_frame() {
        let mut parser = WebSocketFrameParser::new(1);

        let first = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x82\x7e\x00\x05he",
            })
            .into_events();
        let second = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"llo",
            })
            .into_events();

        assert!(first.is_empty());
        assert_eq!(second.len(), 2);
    }

    #[test]
    fn websocket_parser_aggregates_fragmented_message_metadata() {
        let mut parser = WebSocketFrameParser::new(4);

        let first = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x01\x02he",
            })
            .into_events();
        assert_eq!(first.len(), 1);
        assert!(!parser.is_checkpoint_safe());

        let second = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x80\x03llo",
            })
            .into_events();

        assert_eq!(second.len(), 2);
        assert!(matches!(
            &second[1],
            EventKind::WebSocketMessage(message)
                if message.stream_sequence == 4
                    && message.message_sequence == 1
                    && message.first_frame_sequence == 1
                    && message.final_frame_sequence == 2
                    && message.opcode == WebSocketMessageOpcode::Text
                    && message.payload_len == 5
                    && message.payload == Bytes::from_static(b"hello")
                    && message.payload_fingerprint == payload_fingerprint(b"hello", None)
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_does_not_hash_interleaved_control_frame_into_message() {
        let mut parser = WebSocketFrameParser::new(4);

        parser.ingest(ParserInput::Data {
            direction: Direction::Inbound,
            bytes: b"\x01\x02he",
        });
        let ping = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x89\x01x",
            })
            .into_events();
        let final_fragment = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x80\x03llo",
            })
            .into_events();

        assert_eq!(ping.len(), 1);
        assert!(matches!(
            &ping[0],
            EventKind::WebSocketFrame(frame)
                if frame.opcode == WebSocketOpcode::Ping
                    && frame.payload_fingerprint == payload_fingerprint(b"x", None)
        ));
        assert!(matches!(
            &final_fragment[1],
            EventKind::WebSocketMessage(message)
                if message.payload_fingerprint == payload_fingerprint(b"hello", None)
        ));
    }

    #[test]
    fn websocket_parser_skips_extension_payload_message_aggregation() {
        let mut parser = WebSocketFrameParser::new(1);

        let events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\xc1\x05hello",
            })
            .into_events();

        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            EventKind::WebSocketFrame(frame)
                if frame.rsv1
                    && frame.opcode == WebSocketOpcode::Text
                    && frame.payload_len == 5
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_skips_fragmented_extension_message_aggregation() {
        let mut parser = WebSocketFrameParser::new(1);

        let first = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x41\x02he",
            })
            .into_events();
        let second = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x80\x03llo",
            })
            .into_events();

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert!(matches!(
            &first[0],
            EventKind::WebSocketFrame(frame)
                if frame.rsv1
                    && !frame.fin
                    && frame.opcode == WebSocketOpcode::Text
        ));
        assert!(matches!(
            &second[0],
            EventKind::WebSocketFrame(frame)
                if frame.fin
                    && frame.opcode == WebSocketOpcode::Continuation
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_reports_incomplete_message_on_close() {
        let mut parser = WebSocketFrameParser::new(1);

        let events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x01\x02he",
            })
            .into_events();
        assert_eq!(events.len(), 1);

        let events = parser.ingest(ParserInput::ConnectionClosed).into_events();

        assert!(matches!(
            &events[0],
            EventKind::ProtocolError(error)
                if error.reason == "incomplete websocket message at connection close"
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_rejects_fragmented_control_frame() {
        let mut parser = WebSocketFrameParser::new(1);

        let events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x09\x00",
            })
            .into_events();

        assert!(matches!(
            &events[0],
            EventKind::ProtocolError(error)
                if error.reason == "websocket control frame must not be fragmented"
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_rejects_fragmented_reserved_control_frame() {
        let mut parser = WebSocketFrameParser::new(1);

        let events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x0b\x00",
            })
            .into_events();

        assert!(matches!(
            &events[0],
            EventKind::ProtocolError(error)
                if error.reason == "websocket control frame must not be fragmented"
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_omits_oversized_message_metadata_without_dropping_frame_metadata() {
        let mut parser = WebSocketFrameParser::new(1);
        let payload = vec![b'a'; MAX_WEBSOCKET_MESSAGE_PAYLOAD_BYTES as usize];
        let mut first_frame = vec![0x01, 0x7f];
        first_frame.extend_from_slice(&MAX_WEBSOCKET_MESSAGE_PAYLOAD_BYTES.to_be_bytes());
        first_frame.extend_from_slice(&payload);

        let first = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: &first_frame,
            })
            .into_events();
        let second = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x80\x01x",
            })
            .into_events();

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert!(matches!(
            &first[0],
            EventKind::WebSocketFrame(frame)
                if !frame.fin
                    && frame.frame_sequence == 1
                    && frame.payload_len == MAX_WEBSOCKET_MESSAGE_PAYLOAD_BYTES
        ));
        assert!(matches!(
            &second[0],
            EventKind::WebSocketFrame(frame)
                if frame.fin
                    && frame.frame_sequence == 2
                    && frame.payload_len == 1
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_rejects_orphan_continuation_frame() {
        let mut parser = WebSocketFrameParser::new(1);

        let events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: b"\x80\x00",
            })
            .into_events();

        assert!(matches!(
            &events[0],
            EventKind::ProtocolError(error)
                if error.reason == "websocket continuation frame without open message"
        ));
        assert!(parser.is_checkpoint_safe());
    }

    #[test]
    fn websocket_parser_reports_oversized_frame() {
        let mut parser = WebSocketFrameParser::new(1);
        let too_large = (MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES + 1).to_be_bytes();
        let mut bytes = vec![0x82, 0x7f];
        bytes.extend_from_slice(&too_large);

        let events = parser
            .ingest(ParserInput::Data {
                direction: Direction::Inbound,
                bytes: &bytes,
            })
            .into_events();

        assert!(matches!(
            &events[0],
            EventKind::ProtocolError(error)
                if error.reason.contains("exceeds limit")
        ));
    }

    #[test]
    fn websocket_parser_reports_partial_frame_on_close() {
        let mut parser = WebSocketFrameParser::new(1);
        assert!(
            parser
                .ingest(ParserInput::Data {
                    direction: Direction::Inbound,
                    bytes: b"\x81\x05he",
                })
                .into_events()
                .is_empty()
        );

        let events = parser.ingest(ParserInput::ConnectionClosed).into_events();

        assert!(matches!(
            &events[0],
            EventKind::ProtocolError(error)
                if error.reason == "incomplete websocket frame at connection close"
        ));
    }
}

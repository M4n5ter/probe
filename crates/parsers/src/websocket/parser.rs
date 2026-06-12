use bytes::BytesMut;
use probe_core::{Direction, EventKind, ProtocolError, WebSocketFrame, WebSocketOpcode};

use crate::{ParserInput, ParserOutput, ProtocolParser, gap_event};

const MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;
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
                        self.pending = Some(PendingWebSocketFrame::new(header));
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
                        self.pending = Some(PendingWebSocketFrame::new(header));
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
        }
    }

    fn reset(&mut self) {
        self.header_buffer.clear();
        self.pending = None;
    }

    fn is_checkpoint_safe(&self) -> bool {
        self.header_buffer.is_empty() && self.pending.is_none()
    }

    fn consume_pending_payload(&mut self, bytes: &[u8]) -> usize {
        let Some(pending) = &mut self.pending else {
            return 0;
        };
        pending.consume_payload(bytes)
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
        self.frame_sequence = self.frame_sequence.saturating_add(1);
        events.push(EventKind::WebSocketFrame(WebSocketFrame {
            direction,
            stream_sequence,
            frame_sequence: self.frame_sequence,
            fin: pending.fin,
            rsv1: pending.rsv1,
            rsv2: pending.rsv2,
            rsv3: pending.rsv3,
            opcode: pending.opcode,
            payload_len: pending.payload_len,
            masked: pending.mask_key.is_some(),
            payload_fingerprint: pending.payload_fingerprint(),
        }));
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
    fn new(header: ParsedWebSocketHeader) -> Self {
        Self {
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

    fn payload_fingerprint(self) -> Vec<u8> {
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
    match mask_key {
        Some(mask_key) => {
            let mut scratch = [0u8; MASK_HASH_SCRATCH_BYTES];
            let mut offset = payload_offset as usize;
            for chunk in payload.chunks(MASK_HASH_SCRATCH_BYTES) {
                for (index, byte) in chunk.iter().enumerate() {
                    scratch[index] = *byte ^ mask_key[(offset + index) % mask_key.len()];
                }
                hasher.update(&scratch[..chunk.len()]);
                offset = offset.saturating_add(chunk.len());
            }
        }
        None => {
            hasher.update(payload);
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

        assert_eq!(events.len(), 1);
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
        assert_eq!(second.len(), 1);
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

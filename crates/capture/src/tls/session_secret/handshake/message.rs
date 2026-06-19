use bytes::BytesMut;

use super::{
    TLS_CLIENT_HELLO, TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_RECORD_PAYLOAD_BYTES, TLS_SERVER_HELLO,
    u24,
};

pub(super) const TLS_MAX_CAPTURED_HELLO_BODY_BYTES: usize = 64 * 1024;
const TLS_HANDSHAKE_HEADER_BYTES: usize = 4;

#[derive(Debug, Default)]
pub(super) struct Tls13SessionSecretHandshakeMessageStream {
    state: Tls13SessionSecretHandshakeMessageState,
}

impl Tls13SessionSecretHandshakeMessageStream {
    pub(super) fn push_record(
        &mut self,
        payload_offset: u64,
        payload: &[u8],
    ) -> Tls13SessionSecretHandshakeMessageRead {
        let mut cursor = 0;
        let mut completed = Vec::new();
        while cursor < payload.len() {
            match std::mem::take(&mut self.state) {
                Tls13SessionSecretHandshakeMessageState::Empty => {
                    let Some(message_offset) = payload_offset.checked_add(cursor as u64) else {
                        return Tls13SessionSecretHandshakeMessageRead::terminal(completed);
                    };
                    if payload.len() - cursor < TLS_HANDSHAKE_HEADER_BYTES {
                        let mut header = BytesMut::new();
                        header.extend_from_slice(&payload[cursor..]);
                        self.state = Tls13SessionSecretHandshakeMessageState::Header {
                            message_offset,
                            header,
                        };
                        break;
                    }
                    let Some(state) = handshake_message_body_state(
                        message_offset,
                        &payload[cursor..cursor + TLS_HANDSHAKE_HEADER_BYTES],
                    ) else {
                        return Tls13SessionSecretHandshakeMessageRead::terminal(completed);
                    };
                    cursor += TLS_HANDSHAKE_HEADER_BYTES;
                    if let Some(state) =
                        consume_handshake_message_body(state, &mut cursor, payload, &mut completed)
                    {
                        self.state = state;
                        break;
                    }
                }
                Tls13SessionSecretHandshakeMessageState::Header {
                    message_offset,
                    mut header,
                } => {
                    let needed = TLS_HANDSHAKE_HEADER_BYTES - header.len();
                    let take = needed.min(payload.len() - cursor);
                    header.extend_from_slice(&payload[cursor..cursor + take]);
                    cursor += take;
                    if header.len() < TLS_HANDSHAKE_HEADER_BYTES {
                        self.state = Tls13SessionSecretHandshakeMessageState::Header {
                            message_offset,
                            header,
                        };
                        break;
                    }
                    let Some(state) = handshake_message_body_state(message_offset, header.as_ref())
                    else {
                        return Tls13SessionSecretHandshakeMessageRead::terminal(completed);
                    };
                    if let Some(state) =
                        consume_handshake_message_body(state, &mut cursor, payload, &mut completed)
                    {
                        self.state = state;
                        break;
                    }
                }
                state @ (Tls13SessionSecretHandshakeMessageState::CaptureBody(_)
                | Tls13SessionSecretHandshakeMessageState::SkipBody { .. }) => {
                    if let Some(state) =
                        consume_handshake_message_body(state, &mut cursor, payload, &mut completed)
                    {
                        self.state = state;
                        break;
                    }
                }
            }
        }
        Tls13SessionSecretHandshakeMessageRead::alive(completed)
    }

    pub(super) fn has_pending_message(&self) -> bool {
        !matches!(self.state, Tls13SessionSecretHandshakeMessageState::Empty)
    }

    pub(super) fn clear(&mut self) {
        self.state = Tls13SessionSecretHandshakeMessageState::Empty;
    }
}

#[derive(Debug, Clone, Default)]
enum Tls13SessionSecretHandshakeMessageState {
    #[default]
    Empty,
    Header {
        message_offset: u64,
        header: BytesMut,
    },
    CaptureBody(Tls13SessionSecretPendingHandshakeMessage),
    SkipBody {
        remaining: usize,
    },
}

#[derive(Debug, Clone)]
struct Tls13SessionSecretPendingHandshakeMessage {
    handshake_type: u8,
    body_len: usize,
    body: BytesMut,
    message_offset: u64,
}

impl Tls13SessionSecretPendingHandshakeMessage {
    fn extend_body(&mut self, payload: &[u8]) -> usize {
        let take = self.remaining_body_bytes().min(payload.len());
        self.body.extend_from_slice(&payload[..take]);
        take
    }

    fn is_complete(&self) -> bool {
        self.body.len() == self.body_len
    }

    fn remaining_body_bytes(&self) -> usize {
        self.body_len - self.body.len()
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct Tls13SessionSecretHandshakeMessageRead {
    pub(super) completed: Vec<Tls13SessionSecretCompletedHandshakeMessage>,
    pub(super) terminal: bool,
}

impl Tls13SessionSecretHandshakeMessageRead {
    fn alive(completed: Vec<Tls13SessionSecretCompletedHandshakeMessage>) -> Self {
        Self {
            completed,
            terminal: false,
        }
    }

    fn terminal(completed: Vec<Tls13SessionSecretCompletedHandshakeMessage>) -> Self {
        Self {
            completed,
            terminal: true,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Tls13SessionSecretCompletedHandshakeMessage {
    pub(super) handshake_type: u8,
    pub(super) message_offset: u64,
    pub(super) body: BytesMut,
}

fn handshake_message_body_state(
    message_offset: u64,
    header: &[u8],
) -> Option<Tls13SessionSecretHandshakeMessageState> {
    let body_len = u24(header.get(1..4)?);
    if captures_handshake_body(header[0]) {
        if body_len > TLS_MAX_CAPTURED_HELLO_BODY_BYTES {
            return None;
        }
        Some(Tls13SessionSecretHandshakeMessageState::CaptureBody(
            Tls13SessionSecretPendingHandshakeMessage {
                handshake_type: header[0],
                body_len,
                body: BytesMut::with_capacity(
                    body_len.min(TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_RECORD_PAYLOAD_BYTES),
                ),
                message_offset,
            },
        ))
    } else {
        Some(Tls13SessionSecretHandshakeMessageState::SkipBody {
            remaining: body_len,
        })
    }
}

fn consume_handshake_message_body(
    state: Tls13SessionSecretHandshakeMessageState,
    cursor: &mut usize,
    payload: &[u8],
    completed: &mut Vec<Tls13SessionSecretCompletedHandshakeMessage>,
) -> Option<Tls13SessionSecretHandshakeMessageState> {
    match state {
        Tls13SessionSecretHandshakeMessageState::CaptureBody(mut pending) => {
            *cursor += pending.extend_body(&payload[*cursor..]);
            if pending.is_complete() {
                completed.push(Tls13SessionSecretCompletedHandshakeMessage {
                    handshake_type: pending.handshake_type,
                    message_offset: pending.message_offset,
                    body: pending.body,
                });
                None
            } else {
                Some(Tls13SessionSecretHandshakeMessageState::CaptureBody(
                    pending,
                ))
            }
        }
        Tls13SessionSecretHandshakeMessageState::SkipBody { remaining } => {
            let consumed = remaining.min(payload.len() - *cursor);
            *cursor += consumed;
            let remaining = remaining - consumed;
            (remaining > 0)
                .then_some(Tls13SessionSecretHandshakeMessageState::SkipBody { remaining })
        }
        Tls13SessionSecretHandshakeMessageState::Empty
        | Tls13SessionSecretHandshakeMessageState::Header { .. } => None,
    }
}

fn captures_handshake_body(handshake_type: u8) -> bool {
    matches!(handshake_type, TLS_CLIENT_HELLO | TLS_SERVER_HELLO)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLS_CERTIFICATE: u8 = 11;

    #[test]
    fn stream_reassembles_split_handshake_header() {
        let mut stream = Tls13SessionSecretHandshakeMessageStream::default();
        let message = handshake_message(TLS_CLIENT_HELLO, b"hello");

        let read = stream.push_record(100, &message[..2]);
        assert!(read.completed.is_empty());
        assert!(!read.terminal);
        assert!(stream.has_pending_message());

        let read = stream.push_record(102, &message[2..]);

        let [completed] = read.completed.as_slice() else {
            panic!("expected one completed message: {read:?}");
        };
        assert!(!read.terminal);
        assert_eq!(completed.handshake_type, TLS_CLIENT_HELLO);
        assert_eq!(completed.message_offset, 100);
        assert_eq!(completed.body.as_ref(), b"hello");
    }

    #[test]
    fn stream_skips_split_non_target_body_before_target_message() {
        let mut stream = Tls13SessionSecretHandshakeMessageStream::default();
        let skipped = handshake_message(TLS_CERTIFICATE, b"certificate");
        let target = handshake_message(TLS_SERVER_HELLO, b"server");

        let read = stream.push_record(200, &skipped[..7]);
        assert!(read.completed.is_empty());
        assert!(!read.terminal);
        assert!(stream.has_pending_message());

        let mut continuation = skipped[7..].to_vec();
        continuation.extend_from_slice(&target);
        let read = stream.push_record(207, &continuation);

        let [completed] = read.completed.as_slice() else {
            panic!("expected one completed target message: {read:?}");
        };
        assert!(!read.terminal);
        assert_eq!(completed.handshake_type, TLS_SERVER_HELLO);
        assert_eq!(completed.message_offset, 200 + skipped.len() as u64);
        assert_eq!(completed.body.as_ref(), b"server");
    }

    #[test]
    fn stream_terminates_oversized_captured_hello() {
        let mut stream = Tls13SessionSecretHandshakeMessageStream::default();
        let read = stream.push_record(
            300,
            &handshake_header(TLS_CLIENT_HELLO, TLS_MAX_CAPTURED_HELLO_BODY_BYTES + 1),
        );

        assert!(read.completed.is_empty());
        assert!(read.terminal);
        assert!(!stream.has_pending_message());
    }

    fn handshake_message(handshake_type: u8, body: &[u8]) -> Vec<u8> {
        let mut message = handshake_header(handshake_type, body.len());
        message.extend_from_slice(body);
        message
    }

    fn handshake_header(handshake_type: u8, body_len: usize) -> Vec<u8> {
        vec![
            handshake_type,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ]
    }
}

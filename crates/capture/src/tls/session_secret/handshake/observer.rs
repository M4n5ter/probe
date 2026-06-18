use std::collections::HashMap;

use bytes::BytesMut;
use probe_core::{Direction, FlowContext, FlowIdentity, Timestamp};

use crate::tls::TlsRandom;
use crate::{CaptureEvent, CapturedBytes};

use super::super::{TlsCipherSuite, frame::TLS_RECORD_HEADER_BYTES};
use super::{
    TLS_CLIENT_HELLO, TLS_HANDSHAKE_OBSERVER_MAX_ACTIVE_STREAMS,
    TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_RECORD_PAYLOAD_BYTES, TLS_SERVER_HELLO,
    hello::{parse_tls13_client_hello, parse_tls13_server_hello},
    message::{
        Tls13SessionSecretCompletedHandshakeMessage, Tls13SessionSecretHandshakeMessageStream,
    },
    record::{BufferedHandshakeRecord, buffered_record, could_start_tls_handshake_stream},
};
#[cfg(test)]
use crate::tls::TLS_RANDOM_BYTES;

const TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_STREAM_BYTES: usize =
    TLS_RECORD_HEADER_BYTES + TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_RECORD_PAYLOAD_BYTES;

pub struct Tls13SessionSecretHandshakeObserver {
    streams: HashMap<Tls13SessionSecretHandshakeStreamKey, Tls13SessionSecretHandshakeStream>,
    max_active_streams: usize,
}

impl Default for Tls13SessionSecretHandshakeObserver {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
            max_active_streams: TLS_HANDSHAKE_OBSERVER_MAX_ACTIVE_STREAMS,
        }
    }
}

impl Tls13SessionSecretHandshakeObserver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_capture_event(
        &mut self,
        event: &CaptureEvent,
    ) -> Vec<Tls13SessionSecretHandshakeObservation> {
        match event {
            CaptureEvent::Bytes(bytes) => self.push_captured_bytes(bytes),
            CaptureEvent::Gap(gap) => {
                self.remove_stream(&gap.flow.id, gap.gap.direction);
                Vec::new()
            }
            CaptureEvent::ConnectionClosed { flow, .. } => {
                self.remove_flow(&flow.id);
                Vec::new()
            }
            CaptureEvent::ConnectionOpened { .. } | CaptureEvent::Loss(_) => Vec::new(),
        }
    }

    fn push_captured_bytes(
        &mut self,
        bytes: &CapturedBytes,
    ) -> Vec<Tls13SessionSecretHandshakeObservation> {
        let payload = bytes.bytes.as_ref();
        if payload.is_empty() {
            return Vec::new();
        }
        let key = Tls13SessionSecretHandshakeStreamKey::new(bytes.flow.id.clone(), bytes.direction);
        if let Some(stream) = self.streams.get_mut(&key) {
            let outcome = stream.push(bytes);
            if outcome.terminal {
                self.streams.remove(&key);
            }
            return outcome.observations;
        }
        if !could_start_tls_handshake_stream(payload) {
            return Vec::new();
        }
        let mut stream = Tls13SessionSecretHandshakeStream::new(bytes);
        let outcome = stream.push(bytes);
        if !outcome.terminal {
            self.insert_active_stream(key, stream);
        }
        outcome.observations
    }

    fn remove_stream(&mut self, flow: &FlowIdentity, direction: Direction) {
        self.streams
            .remove(&Tls13SessionSecretHandshakeStreamKey::new(
                flow.clone(),
                direction,
            ));
    }

    fn remove_flow(&mut self, flow: &FlowIdentity) {
        self.streams.retain(|key, _| key.flow != *flow);
    }

    fn evict_oldest_stream(&mut self) {
        let Some(key) = self
            .streams
            .iter()
            .min_by_key(|(_, stream)| {
                (
                    stream.last_timestamp.monotonic_ns,
                    stream.last_timestamp.wall_time_unix_ns,
                )
            })
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        self.streams.remove(&key);
    }

    fn insert_active_stream(
        &mut self,
        key: Tls13SessionSecretHandshakeStreamKey,
        stream: Tls13SessionSecretHandshakeStream,
    ) {
        if self.max_active_streams == 0 {
            return;
        }
        if self.streams.len() >= self.max_active_streams {
            self.evict_oldest_stream();
        }
        self.streams.insert(key, stream);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13SessionSecretHandshakeObservation {
    timestamp: Timestamp,
    flow: FlowContext,
    direction: Direction,
    message_offset: u64,
    next_record_offset: u64,
    kind: Tls13SessionSecretHandshakeObservationKind,
}

impl Tls13SessionSecretHandshakeObservation {
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn flow(&self) -> &FlowContext {
        &self.flow
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub fn message_offset(&self) -> u64 {
        self.message_offset
    }

    pub fn next_record_offset(&self) -> u64 {
        self.next_record_offset
    }

    pub fn kind(&self) -> &Tls13SessionSecretHandshakeObservationKind {
        &self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tls13SessionSecretHandshakeObservationKind {
    ClientHello {
        client_random: TlsRandom,
    },
    ServerHello {
        server_random: TlsRandom,
        cipher_suite: TlsCipherSuite,
    },
}

#[derive(Debug)]
struct Tls13SessionSecretHandshakeStream {
    buffer: BytesMut,
    buffer_offset: u64,
    next_stream_offset: u64,
    last_timestamp: Timestamp,
    messages: Tls13SessionSecretHandshakeMessageStream,
}

impl Tls13SessionSecretHandshakeStream {
    fn new(bytes: &CapturedBytes) -> Self {
        Self {
            buffer: BytesMut::new(),
            buffer_offset: bytes.stream_offset,
            next_stream_offset: bytes.stream_offset,
            last_timestamp: bytes.timestamp,
            messages: Tls13SessionSecretHandshakeMessageStream::default(),
        }
    }

    fn push(&mut self, bytes: &CapturedBytes) -> Tls13SessionSecretHandshakeStreamOutcome {
        let payload = bytes.bytes.as_ref();
        if payload.is_empty() {
            return Tls13SessionSecretHandshakeStreamOutcome::default();
        }
        self.last_timestamp = bytes.timestamp;
        if self.next_stream_offset != bytes.stream_offset {
            self.clear_protocol_state(bytes.stream_offset);
            if !could_start_tls_handshake_stream(payload) {
                return Tls13SessionSecretHandshakeStreamOutcome::terminal(Vec::new());
            }
        }
        if self.buffer.is_empty() {
            self.buffer_offset = bytes.stream_offset;
        }
        let Some(next_stream_offset) = bytes.stream_offset.checked_add(payload.len() as u64) else {
            self.clear_protocol_state(bytes.stream_offset);
            return Tls13SessionSecretHandshakeStreamOutcome::terminal(Vec::new());
        };
        let Some(buffered_len) = self.buffer.len().checked_add(payload.len()) else {
            self.clear_protocol_state(bytes.stream_offset);
            return Tls13SessionSecretHandshakeStreamOutcome::terminal(Vec::new());
        };
        if buffered_len > TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_STREAM_BYTES {
            self.clear_protocol_state(bytes.stream_offset);
            return Tls13SessionSecretHandshakeStreamOutcome::terminal(Vec::new());
        }
        self.next_stream_offset = next_stream_offset;
        self.buffer.extend_from_slice(payload);
        self.drain(bytes)
    }

    fn drain(&mut self, bytes: &CapturedBytes) -> Tls13SessionSecretHandshakeStreamOutcome {
        let mut observations = Vec::new();
        while let Some(record) = buffered_record(self.buffer.as_ref()) {
            let record_offset = self.buffer_offset;
            match record {
                BufferedHandshakeRecord::Incomplete => break,
                BufferedHandshakeRecord::Invalid => {
                    self.clear_protocol_state(bytes.stream_offset);
                    return Tls13SessionSecretHandshakeStreamOutcome::terminal(observations);
                }
                BufferedHandshakeRecord::Ignored { len, terminal } => {
                    self.discard_record(len);
                    if terminal || self.messages.has_pending_message() {
                        self.clear_protocol_state(bytes.stream_offset);
                        return Tls13SessionSecretHandshakeStreamOutcome::terminal(observations);
                    }
                }
                BufferedHandshakeRecord::Handshake { len, payload } => {
                    let Some(next_record_offset) = record_offset.checked_add(len as u64) else {
                        self.clear_protocol_state(bytes.stream_offset);
                        return Tls13SessionSecretHandshakeStreamOutcome::terminal(observations);
                    };
                    let Some(payload_offset) =
                        record_offset.checked_add(TLS_RECORD_HEADER_BYTES as u64)
                    else {
                        self.clear_protocol_state(bytes.stream_offset);
                        return Tls13SessionSecretHandshakeStreamOutcome::terminal(observations);
                    };
                    let read = self.messages.push_record(payload_offset, payload);
                    let completed_messages = read.completed.len();
                    observations.extend(read.completed.iter().filter_map(|message| {
                        handshake_observation(bytes, message, next_record_offset)
                    }));
                    self.discard_record(len);
                    if read.terminal
                        || completed_messages > 0
                        || !self.messages.has_pending_message()
                    {
                        self.clear_protocol_state(bytes.stream_offset);
                        return Tls13SessionSecretHandshakeStreamOutcome::terminal(observations);
                    }
                }
            }
        }
        Tls13SessionSecretHandshakeStreamOutcome::alive(observations)
    }

    fn discard_record(&mut self, len: usize) {
        let _ = self.buffer.split_to(len);
        self.buffer_offset = self
            .buffer_offset
            .checked_add(len as u64)
            .expect("buffered TLS record offset was checked when bytes were accepted");
        if self.buffer.is_empty() {
            self.buffer_offset = self.next_stream_offset;
        }
    }

    fn clear_protocol_state(&mut self, stream_offset: u64) {
        self.buffer.clear();
        self.buffer_offset = stream_offset;
        self.messages.clear();
    }
}

#[derive(Debug, Default)]
struct Tls13SessionSecretHandshakeStreamOutcome {
    observations: Vec<Tls13SessionSecretHandshakeObservation>,
    terminal: bool,
}

impl Tls13SessionSecretHandshakeStreamOutcome {
    fn alive(observations: Vec<Tls13SessionSecretHandshakeObservation>) -> Self {
        Self {
            observations,
            terminal: false,
        }
    }

    fn terminal(observations: Vec<Tls13SessionSecretHandshakeObservation>) -> Self {
        Self {
            observations,
            terminal: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Tls13SessionSecretHandshakeStreamKey {
    flow: FlowIdentity,
    direction: Direction,
}

impl Tls13SessionSecretHandshakeStreamKey {
    fn new(flow: FlowIdentity, direction: Direction) -> Self {
        Self { flow, direction }
    }
}

fn handshake_observation(
    bytes: &CapturedBytes,
    message: &Tls13SessionSecretCompletedHandshakeMessage,
    next_record_offset: u64,
) -> Option<Tls13SessionSecretHandshakeObservation> {
    match message.handshake_type {
        TLS_CLIENT_HELLO => {
            let client_random = parse_tls13_client_hello(message.body.as_ref())?;
            Some(Tls13SessionSecretHandshakeObservation {
                timestamp: bytes.timestamp,
                flow: bytes.flow.clone(),
                direction: bytes.direction,
                message_offset: message.message_offset,
                next_record_offset,
                kind: Tls13SessionSecretHandshakeObservationKind::ClientHello { client_random },
            })
        }
        TLS_SERVER_HELLO => {
            let server_hello = parse_tls13_server_hello(message.body.as_ref())?;
            Some(Tls13SessionSecretHandshakeObservation {
                timestamp: bytes.timestamp,
                flow: bytes.flow.clone(),
                direction: bytes.direction,
                message_offset: message.message_offset,
                next_record_offset,
                kind: Tls13SessionSecretHandshakeObservationKind::ServerHello {
                    server_random: server_hello.server_random,
                    cipher_suite: server_hello.cipher_suite,
                },
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, EnforcementEvidence, ProcessContext,
        ProcessIdentity, TransportProtocol,
    };

    use super::super::hello::TLS13_HELLO_RETRY_REQUEST_RANDOM;
    use super::super::message::TLS_MAX_CAPTURED_HELLO_BODY_BYTES;
    use super::super::{
        TLS_CHANGE_CIPHER_SPEC_CONTENT_TYPE, TLS_HANDSHAKE_CONTENT_TYPE, TLS_LEGACY_RECORD_VERSION,
        TLS10_LEGACY_RECORD_VERSION, TLS13_VERSION,
    };
    use super::*;
    use crate::EnforcementEvidencePropagation;

    const CLIENT_RANDOM: [u8; TLS_RANDOM_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const SERVER_RANDOM: [u8; TLS_RANDOM_BYTES] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];

    #[test]
    fn observer_emits_tls13_client_and_server_hello() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            tls_record(TLS_CLIENT_HELLO, client_hello_body(true)),
        )));
        let [client] = observations.as_slice() else {
            panic!("expected one TLS 1.3 client hello observation: {observations:?}");
        };
        let Tls13SessionSecretHandshakeObservationKind::ClientHello { client_random } =
            client.kind()
        else {
            panic!("expected TLS 1.3 client hello kind: {client:?}");
        };
        assert_eq!(client.direction(), Direction::Outbound);
        assert_eq!(client.message_offset(), TLS_RECORD_HEADER_BYTES as u64);
        assert_eq!(client.next_record_offset(), 59);
        assert_eq!(client_random.as_bytes(), &CLIENT_RANDOM);

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Inbound,
            0,
            tls_record(TLS_SERVER_HELLO, server_hello_body(SERVER_RANDOM)),
        )));
        let [server] = observations.as_slice() else {
            panic!("expected one TLS 1.3 server hello observation: {observations:?}");
        };
        let Tls13SessionSecretHandshakeObservationKind::ServerHello {
            server_random,
            cipher_suite,
        } = server.kind()
        else {
            panic!("expected TLS 1.3 server hello kind: {server:?}");
        };
        assert_eq!(server.direction(), Direction::Inbound);
        assert_eq!(server.message_offset(), TLS_RECORD_HEADER_BYTES as u64);
        assert_eq!(server.next_record_offset(), 55);
        assert_eq!(server_random.as_bytes(), &SERVER_RANDOM);
        assert_eq!(cipher_suite.code(), 0x1301);
    }

    #[test]
    fn observer_buffers_split_handshake_record() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();
        let record = tls_record(TLS_CLIENT_HELLO, client_hello_body(true));
        let split_at = 7;

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            record[..split_at].to_vec(),
        )));
        assert!(observations.is_empty());
        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            split_at as u64,
            record[split_at..].to_vec(),
        )));

        let [client] = observations.as_slice() else {
            panic!("expected buffered TLS 1.3 client hello observation: {observations:?}");
        };
        let Tls13SessionSecretHandshakeObservationKind::ClientHello { client_random } =
            client.kind()
        else {
            panic!("expected TLS 1.3 client hello kind: {client:?}");
        };
        assert_eq!(client_random.as_bytes(), &CLIENT_RANDOM);
        assert_eq!(client.next_record_offset(), record.len() as u64);
    }

    #[test]
    fn observer_reassembles_handshake_message_across_tls_records() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();
        let message = tls_handshake_message(TLS_CLIENT_HELLO, client_hello_body(true));
        let split_at = 11;
        let first_record = tls_record_payload(message[..split_at].to_vec());
        let second_record = tls_record_payload(message[split_at..].to_vec());

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            first_record.clone(),
        )));
        assert!(observations.is_empty());
        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            first_record.len() as u64,
            second_record.clone(),
        )));

        let [client] = observations.as_slice() else {
            panic!("expected fragmented TLS 1.3 client hello observation: {observations:?}");
        };
        let Tls13SessionSecretHandshakeObservationKind::ClientHello { client_random } =
            client.kind()
        else {
            panic!("expected TLS 1.3 client hello kind: {client:?}");
        };
        assert_eq!(client.message_offset(), TLS_RECORD_HEADER_BYTES as u64);
        assert_eq!(
            client.next_record_offset(),
            (first_record.len() + second_record.len()) as u64
        );
        assert_eq!(client_random.as_bytes(), &CLIENT_RANDOM);
    }

    #[test]
    fn observer_rechecks_start_gate_after_offset_mismatch() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            vec![TLS_HANDSHAKE_CONTENT_TYPE],
        )));
        assert!(observations.is_empty());

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            10,
            b"G".to_vec(),
        )));
        assert!(observations.is_empty());

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            11,
            tls_record(TLS_CLIENT_HELLO, client_hello_body(true)),
        )));
        assert!(
            matches!(
                observations
                    .first()
                    .map(Tls13SessionSecretHandshakeObservation::kind),
                Some(Tls13SessionSecretHandshakeObservationKind::ClientHello { .. })
            ),
            "offset resync must not retain a non-TLS prefix that can poison the next real hello"
        );
    }

    #[test]
    fn observer_rejects_oversized_chunk_before_buffering() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();
        let mut payload = tls_record(TLS_CLIENT_HELLO, client_hello_body(true));
        payload.resize(TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_STREAM_BYTES + 1, 0);

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            payload,
        )));
        assert!(observations.is_empty());

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            tls_record(TLS_CLIENT_HELLO, client_hello_body(true)),
        )));
        assert!(
            matches!(
                observations
                    .first()
                    .map(Tls13SessionSecretHandshakeObservation::kind),
                Some(Tls13SessionSecretHandshakeObservationKind::ClientHello { .. })
            ),
            "oversized chunk must fail closed before retaining observer state"
        );
    }

    #[test]
    fn observer_ignores_non_tls_prefix_without_poisoning_flow() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        )));
        assert!(observations.is_empty());

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            tls_record(TLS_CLIENT_HELLO, client_hello_body(true)),
        )));
        assert!(
            matches!(
                observations
                    .first()
                    .map(Tls13SessionSecretHandshakeObservation::kind),
                Some(Tls13SessionSecretHandshakeObservationKind::ClientHello { .. })
            ),
            "rejected non-TLS prefix must not leave blocking stream state"
        );
    }

    #[test]
    fn observer_removes_active_stream_after_application_data_record() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();
        let change_cipher_spec = tls_record_with_content_type(
            TLS_CHANGE_CIPHER_SPEC_CONTENT_TYPE,
            TLS_LEGACY_RECORD_VERSION,
            vec![1],
        );
        let application_data = tls_record_with_content_type(23, TLS_LEGACY_RECORD_VERSION, vec![0]);

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            change_cipher_spec.clone(),
        )));
        assert!(observations.is_empty());

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            change_cipher_spec.len() as u64,
            application_data,
        )));
        assert!(observations.is_empty());

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            tls_record(TLS_CLIENT_HELLO, client_hello_body(true)),
        )));
        assert!(
            matches!(
                observations
                    .first()
                    .map(Tls13SessionSecretHandshakeObservation::kind),
                Some(Tls13SessionSecretHandshakeObservationKind::ClientHello { .. })
            ),
            "application data must terminate active observer state"
        );
    }

    #[test]
    fn observer_does_not_evict_partial_stream_for_terminal_new_candidate() {
        let mut observer = Tls13SessionSecretHandshakeObserver {
            streams: HashMap::new(),
            max_active_streams: 2,
        };
        for pid in [1, 2] {
            let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
                demo_flow_with_pid(pid),
                Direction::Outbound,
                0,
                vec![TLS_HANDSHAKE_CONTENT_TYPE],
            )));
            assert!(observations.is_empty());
        }

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            demo_flow_with_pid(3),
            Direction::Outbound,
            0,
            tls_record(TLS_CLIENT_HELLO, client_hello_body(true)),
        )));

        assert!(
            matches!(
                observations
                    .first()
                    .map(Tls13SessionSecretHandshakeObservation::kind),
                Some(Tls13SessionSecretHandshakeObservationKind::ClientHello { .. })
            ),
            "complete new hello must still be observed under active stream budget pressure"
        );

        let record = tls_record(TLS_CLIENT_HELLO, client_hello_body(true));
        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            demo_flow_with_pid(1),
            Direction::Outbound,
            1,
            record[1..].to_vec(),
        )));
        assert!(
            matches!(
                observations
                    .first()
                    .map(Tls13SessionSecretHandshakeObservation::kind),
                Some(Tls13SessionSecretHandshakeObservationKind::ClientHello { .. })
            ),
            "terminal new candidate must not evict an older stream that still needs its continuation"
        );
    }

    #[test]
    fn observer_removes_stream_after_oversized_hello_body() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            tls_record_payload(tls_handshake_header(
                TLS_CLIENT_HELLO,
                TLS_MAX_CAPTURED_HELLO_BODY_BYTES + 1,
            )),
        )));
        assert!(observations.is_empty());

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            tls_record(TLS_CLIENT_HELLO, client_hello_body(true)),
        )));
        assert!(
            matches!(
                observations
                    .first()
                    .map(Tls13SessionSecretHandshakeObservation::kind),
                Some(Tls13SessionSecretHandshakeObservationKind::ClientHello { .. })
            ),
            "oversized hello must terminate observer state rather than poison the flow"
        );
    }

    #[test]
    fn observer_ignores_client_hello_without_tls13_supported_versions() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            tls_record(TLS_CLIENT_HELLO, client_hello_body(false)),
        )));

        assert!(observations.is_empty());
    }

    #[test]
    fn observer_accepts_initial_client_hello_with_tls10_record_version() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            tls_record_with_version(
                TLS10_LEGACY_RECORD_VERSION,
                TLS_CLIENT_HELLO,
                client_hello_body(true),
            ),
        )));

        let [client] = observations.as_slice() else {
            panic!("expected TLS 1.3 client hello observation: {observations:?}");
        };
        let Tls13SessionSecretHandshakeObservationKind::ClientHello { client_random } =
            client.kind()
        else {
            panic!("expected TLS 1.3 client hello kind: {client:?}");
        };
        assert_eq!(client_random.as_bytes(), &CLIENT_RANDOM);
    }

    #[test]
    fn observer_ignores_tls13_hello_retry_request() {
        let flow = demo_flow();
        let mut observer = Tls13SessionSecretHandshakeObserver::new();

        let observations = observer.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Inbound,
            0,
            tls_record(
                TLS_SERVER_HELLO,
                server_hello_body(TLS13_HELLO_RETRY_REQUEST_RANDOM),
            ),
        )));

        assert!(observations.is_empty());
    }

    fn tls_record(handshake_type: u8, body: Vec<u8>) -> Vec<u8> {
        tls_record_payload(tls_handshake_message(handshake_type, body))
    }

    fn tls_record_with_version(version: [u8; 2], handshake_type: u8, body: Vec<u8>) -> Vec<u8> {
        tls_record_payload_with_version(version, tls_handshake_message(handshake_type, body))
    }

    fn tls_handshake_message(handshake_type: u8, body: Vec<u8>) -> Vec<u8> {
        let mut handshake = tls_handshake_header(handshake_type, body.len());
        handshake.extend_from_slice(&body);
        handshake
    }

    fn tls_handshake_header(handshake_type: u8, body_len: usize) -> Vec<u8> {
        vec![
            handshake_type,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ]
    }

    fn tls_record_payload(payload: Vec<u8>) -> Vec<u8> {
        tls_record_payload_with_version(TLS_LEGACY_RECORD_VERSION, payload)
    }

    fn tls_record_payload_with_version(version: [u8; 2], payload: Vec<u8>) -> Vec<u8> {
        tls_record_with_content_type(TLS_HANDSHAKE_CONTENT_TYPE, version, payload)
    }

    fn tls_record_with_content_type(
        content_type: u8,
        version: [u8; 2],
        payload: Vec<u8>,
    ) -> Vec<u8> {
        let mut record = vec![
            content_type,
            version[0],
            version[1],
            ((payload.len() >> 8) & 0xff) as u8,
            (payload.len() & 0xff) as u8,
        ];
        record.extend_from_slice(&payload);
        record
    }

    fn client_hello_body(tls13: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&CLIENT_RANDOM);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        let extensions = if tls13 {
            supported_versions_client_extension()
        } else {
            Vec::new()
        };
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        body
    }

    fn server_hello_body(server_random: [u8; TLS_RANDOM_BYTES]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&server_random);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0);
        let extensions = supported_versions_server_extension();
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        body
    }

    fn supported_versions_client_extension() -> Vec<u8> {
        vec![
            0x00,
            0x2b,
            0x00,
            0x03,
            0x02,
            TLS13_VERSION[0],
            TLS13_VERSION[1],
        ]
    }

    fn supported_versions_server_extension() -> Vec<u8> {
        vec![0x00, 0x2b, 0x00, 0x02, TLS13_VERSION[0], TLS13_VERSION[1]]
    }

    fn captured_bytes(
        flow: FlowContext,
        direction: Direction,
        stream_offset: u64,
        bytes: Vec<u8>,
    ) -> CapturedBytes {
        CapturedBytes {
            timestamp: Timestamp {
                monotonic_ns: 17,
                wall_time_unix_ns: 23,
            },
            flow,
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            direction,
            stream_offset,
            bytes: Bytes::from(bytes),
            attribution_confidence: 100,
            degraded: false,
            degradation_reason: None,
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }
    }

    fn demo_flow() -> FlowContext {
        demo_flow_with_pid(1)
    }

    fn demo_flow_with_pid(pid: u32) -> FlowContext {
        let process = ProcessIdentity {
            pid,
            tgid: pid,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 12345,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 443,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process,
                &local,
                &remote,
                TransportProtocol::Tcp,
                1,
                Some(7),
            ),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(7),
            attribution_confidence: 100,
        }
    }
}

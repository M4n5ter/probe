use super::super::common::{
    EBPF_EVENT_HEADER_BYTES, EBPF_PAYLOAD_SAMPLE_BYTES, EbpfEventDecodeError, EbpfEventHeader,
    EbpfEventKind, decode_record_header, encode_event_header, read_i32, read_u16, read_u32,
    read_u64, validate_event_header, validate_expected_event_kind, validate_record_len, write_i32,
    write_u16, write_u32, write_u64,
};

pub const EBPF_TLS_PLAINTEXT_SAMPLE_BYTES: usize = EBPF_PAYLOAD_SAMPLE_BYTES;
pub const EBPF_TLS_PLAINTEXT_EVENT_BYTES: usize = core::mem::size_of::<EbpfTlsPlaintextEvent>();
pub const EBPF_TLS_PLAINTEXT_FD_VALID: u16 = 1 << 0;
pub const EBPF_TLS_PLAINTEXT_TRUNCATED: u16 = 1 << 1;
pub const EBPF_TLS_PLAINTEXT_READ_FAILED: u16 = 1 << 2;
pub const EBPF_TLS_DIRECTION_INBOUND: u8 = 1;
pub const EBPF_TLS_DIRECTION_OUTBOUND: u8 = 2;
const EVENT_COMMAND_BYTES: usize = 16;
const OBSERVATION_BYTES: usize = core::mem::size_of::<EbpfTlsPlaintextObservation>();
const OBSERVATION_OFFSET: usize = EBPF_EVENT_HEADER_BYTES + EVENT_COMMAND_BYTES;
const OBSERVATION_END: usize = OBSERVATION_OFFSET + OBSERVATION_BYTES;
const OBSERVATION_PAYLOAD_OFFSET: usize = 32;
const OBSERVATION_PAYLOAD_END: usize = OBSERVATION_PAYLOAD_OFFSET + EBPF_TLS_PLAINTEXT_SAMPLE_BYTES;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsPlaintextObservation {
    pub ssl_pointer: u64,
    pub stream_offset: u64,
    pub original_len: u32,
    pub fd: i32,
    pub captured_len: u16,
    pub direction: u8,
    pub reserved0: u8,
    pub reserved1: u32,
    pub payload: [u8; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES],
}

impl EbpfTlsPlaintextObservation {
    pub const fn new(
        ssl_pointer: u64,
        fd: i32,
        direction: u8,
        stream_offset: u64,
        original_len: u32,
        captured_len: u16,
        payload: [u8; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES],
    ) -> Self {
        Self {
            ssl_pointer,
            stream_offset,
            original_len,
            fd,
            captured_len,
            direction,
            reserved0: 0,
            reserved1: 0,
            payload,
        }
    }

    pub fn captured_payload(&self) -> Option<&[u8]> {
        self.payload.get(..usize::from(self.captured_len))
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsPlaintextEvent {
    header: EbpfEventHeader,
    command: [u8; 16],
    observation: EbpfTlsPlaintextObservation,
}

impl EbpfTlsPlaintextEvent {
    pub fn libssl_plaintext_sampled(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        observation: EbpfTlsPlaintextObservation,
        flags: u16,
    ) -> Self {
        Self {
            header: EbpfEventHeader::new_with_flags(
                EbpfEventKind::LibsslPlaintextSampled,
                core::mem::size_of::<Self>() as u16,
                flags,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
            observation,
        }
    }

    pub const fn header(&self) -> &EbpfEventHeader {
        &self.header
    }

    pub const fn kind(&self) -> Option<EbpfEventKind> {
        self.header.kind()
    }

    pub const fn kind_wire(&self) -> u16 {
        self.header.kind
    }

    pub const fn flags(&self) -> u16 {
        self.header.flags
    }

    pub const fn command(&self) -> [u8; 16] {
        self.command
    }

    pub const fn observation(&self) -> &EbpfTlsPlaintextObservation {
        &self.observation
    }

    pub fn overwrite_libssl_plaintext_sampled_metadata(
        &mut self,
        metadata: EbpfTlsPlaintextEventMetadata,
    ) {
        self.header = EbpfEventHeader::new_with_flags(
            EbpfEventKind::LibsslPlaintextSampled,
            core::mem::size_of::<Self>() as u16,
            metadata.flags,
            metadata.pid,
            metadata.tgid,
            metadata.uid,
            metadata.gid,
        );
        self.command = metadata.command;
        self.observation.ssl_pointer = metadata.observation.ssl_pointer;
        self.observation.stream_offset = metadata.observation.stream_offset;
        self.observation.original_len = metadata.observation.original_len;
        self.observation.fd = metadata.observation.fd;
        self.observation.captured_len = metadata.observation.captured_len;
        self.observation.direction = metadata.observation.direction;
        self.observation.reserved0 = 0;
        self.observation.reserved1 = 0;
    }

    pub fn clear_payload(&mut self) {
        self.observation.payload.fill(0);
    }

    pub fn payload_mut(&mut self) -> &mut [u8; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES] {
        &mut self.observation.payload
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsPlaintextEventMetadata {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub command: [u8; 16],
    pub flags: u16,
    pub observation: EbpfTlsPlaintextMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTlsPlaintextMetadata {
    pub ssl_pointer: u64,
    pub fd: i32,
    pub direction: u8,
    pub stream_offset: u64,
    pub original_len: u32,
    pub captured_len: u16,
}

pub fn decode_tls_plaintext_event(
    bytes: &[u8],
) -> Result<EbpfTlsPlaintextEvent, EbpfEventDecodeError> {
    let mut command = [0; 16];
    let header = decode_record_header(
        bytes,
        EBPF_TLS_PLAINTEXT_EVENT_BYTES,
        "libssl plaintext event",
        is_tls_plaintext_kind,
    )?;
    command.copy_from_slice(&bytes[EBPF_EVENT_HEADER_BYTES..OBSERVATION_OFFSET]);
    let event = EbpfTlsPlaintextEvent {
        header,
        command,
        observation: decode_tls_plaintext_observation(&bytes[OBSERVATION_OFFSET..OBSERVATION_END]),
    };
    validate_tls_plaintext_event(event)
}

pub fn encode_tls_plaintext_event(
    event: &EbpfTlsPlaintextEvent,
) -> [u8; EBPF_TLS_PLAINTEXT_EVENT_BYTES] {
    let mut bytes = [0; EBPF_TLS_PLAINTEXT_EVENT_BYTES];
    encode_event_header(&mut bytes, event.header);
    bytes[EBPF_EVENT_HEADER_BYTES..OBSERVATION_OFFSET].copy_from_slice(&event.command);
    encode_tls_plaintext_observation(
        &mut bytes[OBSERVATION_OFFSET..OBSERVATION_END],
        event.observation,
    );
    bytes
}

fn validate_tls_plaintext_event(
    event: EbpfTlsPlaintextEvent,
) -> Result<EbpfTlsPlaintextEvent, EbpfEventDecodeError> {
    validate_event_header(event.header)?;
    validate_expected_event_kind(
        event.header,
        "libssl plaintext event",
        is_tls_plaintext_kind,
    )?;
    validate_record_len(event.header, EBPF_TLS_PLAINTEXT_EVENT_BYTES)?;
    if usize::from(event.observation.captured_len) > EBPF_TLS_PLAINTEXT_SAMPLE_BYTES {
        return Err(EbpfEventDecodeError::InvalidTlsPlaintextCapturedLength {
            captured: event.observation.captured_len,
            capacity: EBPF_TLS_PLAINTEXT_SAMPLE_BYTES,
        });
    }
    if u32::from(event.observation.captured_len) > event.observation.original_len {
        return Err(EbpfEventDecodeError::InvalidTlsPlaintextOriginalLength {
            captured: event.observation.captured_len,
            original: event.observation.original_len,
        });
    }
    if event.header.flags & EBPF_TLS_PLAINTEXT_READ_FAILED != 0
        && event.observation.captured_len > 0
    {
        return Err(EbpfEventDecodeError::InvalidTlsPlaintextReadFailure {
            captured: event.observation.captured_len,
        });
    }
    match event.observation.direction {
        EBPF_TLS_DIRECTION_INBOUND | EBPF_TLS_DIRECTION_OUTBOUND => Ok(event),
        value => Err(EbpfEventDecodeError::InvalidTlsPlaintextDirection { value }),
    }
}

fn is_tls_plaintext_kind(kind: EbpfEventKind) -> bool {
    matches!(kind, EbpfEventKind::LibsslPlaintextSampled)
}

fn decode_tls_plaintext_observation(bytes: &[u8]) -> EbpfTlsPlaintextObservation {
    let mut payload = [0; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES];
    payload.copy_from_slice(&bytes[OBSERVATION_PAYLOAD_OFFSET..OBSERVATION_PAYLOAD_END]);
    EbpfTlsPlaintextObservation {
        ssl_pointer: read_u64(bytes, 0),
        stream_offset: read_u64(bytes, 8),
        original_len: read_u32(bytes, 16),
        fd: read_i32(bytes, 20),
        captured_len: read_u16(bytes, 24),
        direction: bytes[26],
        reserved0: bytes[27],
        reserved1: read_u32(bytes, 28),
        payload,
    }
}

fn encode_tls_plaintext_observation(bytes: &mut [u8], observation: EbpfTlsPlaintextObservation) {
    write_u64(bytes, 0, observation.ssl_pointer);
    write_u64(bytes, 8, observation.stream_offset);
    write_u32(bytes, 16, observation.original_len);
    write_i32(bytes, 20, observation.fd);
    write_u16(bytes, 24, observation.captured_len);
    bytes[26] = observation.direction;
    bytes[27] = observation.reserved0;
    write_u32(bytes, 28, observation.reserved1);
    bytes[OBSERVATION_PAYLOAD_OFFSET..OBSERVATION_PAYLOAD_END]
        .copy_from_slice(&observation.payload);
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use crate::event::{EBPF_ABI_REVISION, EBPF_MAGIC, EBPF_SOCKET_WRITE_SAMPLE_BYTES};

    use super::*;

    #[test]
    fn tls_plaintext_event_layout_fits_ringbuf_alignment() {
        assert_eq!(
            size_of::<EbpfTlsPlaintextObservation>(),
            OBSERVATION_PAYLOAD_OFFSET + EBPF_TLS_PLAINTEXT_SAMPLE_BYTES
        );
        assert_eq!(align_of::<EbpfTlsPlaintextObservation>(), 8);
        assert_eq!(
            size_of::<EbpfTlsPlaintextEvent>(),
            OBSERVATION_OFFSET + size_of::<EbpfTlsPlaintextObservation>()
        );
        assert_eq!(align_of::<EbpfTlsPlaintextEvent>(), 8);
        assert_eq!(8 % align_of::<EbpfTlsPlaintextEvent>(), 0);
    }

    #[test]
    fn tls_plaintext_sample_uses_process_payload_window() {
        assert_eq!(
            EBPF_TLS_PLAINTEXT_SAMPLE_BYTES,
            EBPF_SOCKET_WRITE_SAMPLE_BYTES
        );
    }

    #[test]
    fn tls_plaintext_event_field_offsets_match_decoder() {
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, ssl_pointer), 0);
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, stream_offset), 8);
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, original_len), 16);
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, fd), 20);
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, captured_len), 24);
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, direction), 26);
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, reserved0), 27);
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, reserved1), 28);
        assert_eq!(offset_of!(EbpfTlsPlaintextObservation, payload), 32);
        assert_eq!(offset_of!(EbpfTlsPlaintextEvent, header), 0);
        assert_eq!(offset_of!(EbpfTlsPlaintextEvent, command), 32);
        assert_eq!(offset_of!(EbpfTlsPlaintextEvent, observation), 48);
    }

    #[test]
    fn libssl_plaintext_sampled_populates_header_fields() {
        let event = sample_event();

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(
            event.header.kind(),
            Some(EbpfEventKind::LibsslPlaintextSampled)
        );
        assert_eq!(
            usize::from(event.header.record_len),
            size_of::<EbpfTlsPlaintextEvent>()
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, EBPF_TLS_PLAINTEXT_FD_VALID);
        assert_eq!(event.observation.ssl_pointer, 0xfeed);
        assert_eq!(event.observation.fd, 7);
        assert_eq!(
            event.observation.captured_payload(),
            Some(b"GET /".as_slice())
        );
    }

    #[test]
    fn tls_plaintext_event_decodes_from_wire_bytes() {
        let event = sample_event();

        let decoded = match decode_tls_plaintext_event(&encode_tls_plaintext_event(&event)) {
            Ok(decoded) => decoded,
            Err(error) => panic!("event must decode: {error:?}"),
        };

        assert_eq!(decoded, event);
    }

    #[test]
    fn tls_plaintext_event_rejects_invalid_direction() {
        let mut event = sample_event();
        event.observation.direction = 9;

        let error = match decode_tls_plaintext_event(&encode_tls_plaintext_event(&event)) {
            Ok(_) => panic!("invalid direction must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidTlsPlaintextDirection { value: 9 }
        );
    }

    #[test]
    fn tls_plaintext_event_rejects_read_failed_payload() {
        let mut event = sample_event();
        event.header.flags |= EBPF_TLS_PLAINTEXT_READ_FAILED;

        let error = match decode_tls_plaintext_event(&encode_tls_plaintext_event(&event)) {
            Ok(_) => panic!("read-failed event must not carry plaintext bytes"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidTlsPlaintextReadFailure { captured: 5 }
        );
    }

    fn sample_event() -> EbpfTlsPlaintextEvent {
        let mut payload = [0; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES];
        payload[..5].copy_from_slice(b"GET /");
        EbpfTlsPlaintextEvent::libssl_plaintext_sampled(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            EbpfTlsPlaintextObservation::new(
                0xfeed,
                7,
                EBPF_TLS_DIRECTION_OUTBOUND,
                100,
                5,
                5,
                payload,
            ),
            EBPF_TLS_PLAINTEXT_FD_VALID,
        )
    }
}

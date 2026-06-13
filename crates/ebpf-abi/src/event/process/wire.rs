use super::super::common::{
    EbpfEventDecodeError, EbpfEventHeader, EbpfEventKind, decode_record_header,
    encode_event_header, read_i32, read_u16, read_u32, validate_event_header,
    validate_expected_event_kind, validate_record_len, write_i32, write_u16, write_u32,
};

pub const EBPF_PROCESS_PROBE_EVENT_BYTES: usize = core::mem::size_of::<EbpfProcessProbeEvent>();
const EBPF_PROCESS_PROBE_PAYLOAD_BYTES: usize = core::mem::size_of::<EbpfConnectObservation>();
pub const EBPF_CONNECT_REMOTE_ENDPOINT_VALID: u16 = 1 << 0;
pub const EBPF_CONNECT_SOCKADDR_READ_FAILED: u16 = 1 << 1;
pub const EBPF_CONNECT_UNSUPPORTED_ADDRESS_FAMILY: u16 = 1 << 2;
pub const EBPF_ADDRESS_FAMILY_UNSPEC: u16 = 0;
pub const EBPF_ADDRESS_FAMILY_INET: u16 = 2;
pub const EBPF_ADDRESS_FAMILY_INET6: u16 = 10;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfConnectObservation {
    pub fd: i32,
    pub addrlen: u32,
    pub address_family: u16,
    pub remote_port: u16,
    pub remote_address: [u8; 16],
    pub reserved: u32,
}

impl EbpfConnectObservation {
    pub const fn unavailable(fd: i32, addrlen: u32) -> Self {
        Self {
            fd,
            addrlen,
            address_family: EBPF_ADDRESS_FAMILY_UNSPEC,
            remote_port: 0,
            remote_address: [0; 16],
            reserved: 0,
        }
    }

    pub const fn remote_endpoint(
        fd: i32,
        addrlen: u32,
        address_family: u16,
        remote_port: u16,
        remote_address: [u8; 16],
    ) -> Self {
        Self {
            fd,
            addrlen,
            address_family,
            remote_port,
            remote_address,
            reserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfCloseObservation {
    pub fd: i32,
    pub reserved: u32,
}

impl EbpfCloseObservation {
    pub const fn observed(fd: i32) -> Self {
        Self { fd, reserved: 0 }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessProbeEvent {
    header: EbpfEventHeader,
    command: [u8; 16],
    payload: [u8; EBPF_PROCESS_PROBE_PAYLOAD_BYTES],
}

impl EbpfProcessProbeEvent {
    pub fn connect_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        connect: EbpfConnectObservation,
        flags: u16,
    ) -> Self {
        let mut payload = [0; EBPF_PROCESS_PROBE_PAYLOAD_BYTES];
        encode_connect_observation(&mut payload, connect);
        Self {
            header: EbpfEventHeader::new_with_flags(
                EbpfEventKind::ConnectTracepointObserved,
                core::mem::size_of::<Self>() as u16,
                flags,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
            payload,
        }
    }

    pub fn close_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        close: EbpfCloseObservation,
    ) -> Self {
        let mut payload = [0; EBPF_PROCESS_PROBE_PAYLOAD_BYTES];
        encode_close_observation(&mut payload, close);
        Self {
            header: EbpfEventHeader::new(
                EbpfEventKind::CloseTracepointObserved,
                core::mem::size_of::<Self>() as u16,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
            payload,
        }
    }

    pub fn connect_observation(&self) -> Option<EbpfConnectObservation> {
        match self.header.kind() {
            Some(EbpfEventKind::ConnectTracepointObserved) => {
                Some(decode_connect_observation(&self.payload))
            }
            _ => None,
        }
    }

    pub fn close_observation(&self) -> Option<EbpfCloseObservation> {
        match self.header.kind() {
            Some(EbpfEventKind::CloseTracepointObserved) => {
                Some(decode_close_observation(&self.payload))
            }
            _ => None,
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
}

pub fn decode_process_probe_event(
    bytes: &[u8],
) -> Result<EbpfProcessProbeEvent, EbpfEventDecodeError> {
    let header = decode_record_header(
        bytes,
        EBPF_PROCESS_PROBE_EVENT_BYTES,
        "process probe event",
        is_process_probe_kind,
    )?;

    let mut command = [0; 16];
    command.copy_from_slice(&bytes[32..48]);
    let mut payload = [0; EBPF_PROCESS_PROBE_PAYLOAD_BYTES];
    payload.copy_from_slice(&bytes[48..80]);
    let event = EbpfProcessProbeEvent {
        header,
        command,
        payload,
    };
    validate_process_probe_event(event)
}

pub fn encode_process_probe_event(
    event: &EbpfProcessProbeEvent,
) -> [u8; EBPF_PROCESS_PROBE_EVENT_BYTES] {
    let mut bytes = [0; EBPF_PROCESS_PROBE_EVENT_BYTES];
    encode_event_header(&mut bytes, event.header);
    bytes[32..48].copy_from_slice(&event.command);
    bytes[48..80].copy_from_slice(&event.payload);
    bytes
}

fn validate_process_probe_event(
    event: EbpfProcessProbeEvent,
) -> Result<EbpfProcessProbeEvent, EbpfEventDecodeError> {
    validate_event_header(event.header)?;
    validate_expected_event_kind(event.header, "process probe event", is_process_probe_kind)?;
    validate_record_len(event.header, EBPF_PROCESS_PROBE_EVENT_BYTES)?;
    Ok(event)
}

fn is_process_probe_kind(kind: EbpfEventKind) -> bool {
    matches!(
        kind,
        EbpfEventKind::ConnectTracepointObserved | EbpfEventKind::CloseTracepointObserved
    )
}

fn decode_connect_observation(
    bytes: &[u8; EBPF_PROCESS_PROBE_PAYLOAD_BYTES],
) -> EbpfConnectObservation {
    let mut remote_address = [0; 16];
    remote_address.copy_from_slice(&bytes[12..28]);
    EbpfConnectObservation {
        fd: read_i32(bytes, 0),
        addrlen: read_u32(bytes, 4),
        address_family: read_u16(bytes, 8),
        remote_port: read_u16(bytes, 10),
        remote_address,
        reserved: read_u32(bytes, 28),
    }
}

fn encode_connect_observation(
    bytes: &mut [u8; EBPF_PROCESS_PROBE_PAYLOAD_BYTES],
    connect: EbpfConnectObservation,
) {
    write_i32(bytes, 0, connect.fd);
    write_u32(bytes, 4, connect.addrlen);
    write_u16(bytes, 8, connect.address_family);
    write_u16(bytes, 10, connect.remote_port);
    bytes[12..28].copy_from_slice(&connect.remote_address);
    write_u32(bytes, 28, connect.reserved);
}

fn decode_close_observation(
    bytes: &[u8; EBPF_PROCESS_PROBE_PAYLOAD_BYTES],
) -> EbpfCloseObservation {
    EbpfCloseObservation {
        fd: read_i32(bytes, 0),
        reserved: read_u32(bytes, 4),
    }
}

fn encode_close_observation(
    bytes: &mut [u8; EBPF_PROCESS_PROBE_PAYLOAD_BYTES],
    close: EbpfCloseObservation,
) {
    write_i32(bytes, 0, close.fd);
    write_u32(bytes, 4, close.reserved);
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use crate::event::{EBPF_ABI_REVISION, EBPF_MAGIC};

    use super::*;

    #[test]
    fn process_event_layout_fits_ringbuf_alignment() {
        assert_eq!(size_of::<EbpfConnectObservation>(), 32);
        assert_eq!(align_of::<EbpfConnectObservation>(), 4);
        assert_eq!(size_of::<EbpfCloseObservation>(), 8);
        assert_eq!(align_of::<EbpfCloseObservation>(), 4);
        assert_eq!(size_of::<EbpfProcessProbeEvent>(), 80);
        assert_eq!(align_of::<EbpfProcessProbeEvent>(), 4);
        assert_eq!(8 % align_of::<EbpfProcessProbeEvent>(), 0);
    }

    #[test]
    fn process_event_field_offsets_match_decoder() {
        assert_eq!(offset_of!(EbpfEventHeader, magic), 0);
        assert_eq!(offset_of!(EbpfEventHeader, abi_revision), 4);
        assert_eq!(offset_of!(EbpfEventHeader, kind), 6);
        assert_eq!(offset_of!(EbpfEventHeader, record_len), 8);
        assert_eq!(offset_of!(EbpfEventHeader, flags), 10);
        assert_eq!(offset_of!(EbpfEventHeader, reserved), 12);
        assert_eq!(offset_of!(EbpfEventHeader, pid), 16);
        assert_eq!(offset_of!(EbpfEventHeader, tgid), 20);
        assert_eq!(offset_of!(EbpfEventHeader, uid), 24);
        assert_eq!(offset_of!(EbpfEventHeader, gid), 28);
        assert_eq!(offset_of!(EbpfConnectObservation, fd), 0);
        assert_eq!(offset_of!(EbpfConnectObservation, addrlen), 4);
        assert_eq!(offset_of!(EbpfConnectObservation, address_family), 8);
        assert_eq!(offset_of!(EbpfConnectObservation, remote_port), 10);
        assert_eq!(offset_of!(EbpfConnectObservation, remote_address), 12);
        assert_eq!(offset_of!(EbpfConnectObservation, reserved), 28);
        assert_eq!(offset_of!(EbpfCloseObservation, fd), 0);
        assert_eq!(offset_of!(EbpfCloseObservation, reserved), 4);
        assert_eq!(offset_of!(EbpfProcessProbeEvent, header), 0);
        assert_eq!(offset_of!(EbpfProcessProbeEvent, command), 32);
        assert_eq!(offset_of!(EbpfProcessProbeEvent, payload), 48);
    }

    #[test]
    fn connect_tracepoint_observed_populates_header_fields() {
        let event = EbpfProcessProbeEvent::connect_tracepoint_observed(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            EbpfConnectObservation::remote_endpoint(
                7,
                16,
                EBPF_ADDRESS_FAMILY_INET,
                443,
                [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
        );

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(
            event.header.kind(),
            Some(EbpfEventKind::ConnectTracepointObserved)
        );
        assert_eq!(
            usize::from(event.header.record_len),
            size_of::<EbpfProcessProbeEvent>()
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, EBPF_CONNECT_REMOTE_ENDPOINT_VALID);
        let connect = event
            .connect_observation()
            .expect("connect event should expose connect payload");
        assert_eq!(connect.fd, 7);
        assert_eq!(connect.addrlen, 16);
        assert_eq!(connect.address_family, EBPF_ADDRESS_FAMILY_INET);
        assert_eq!(connect.remote_port, 443);
        assert_eq!(connect.remote_address[0..4], [127, 0, 0, 1]);
        assert!(event.close_observation().is_none());
    }

    #[test]
    fn close_tracepoint_observed_populates_header_fields() {
        let event = EbpfProcessProbeEvent::close_tracepoint_observed(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            EbpfCloseObservation::observed(7),
        );

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(
            event.header.kind(),
            Some(EbpfEventKind::CloseTracepointObserved)
        );
        assert_eq!(
            usize::from(event.header.record_len),
            size_of::<EbpfProcessProbeEvent>()
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, 0);
        let close = event
            .close_observation()
            .expect("close event should expose close payload");
        assert_eq!(close.fd, 7);
        assert!(event.connect_observation().is_none());
    }

    #[test]
    fn process_event_decodes_from_wire_bytes() {
        let event = EbpfProcessProbeEvent::connect_tracepoint_observed(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            EbpfConnectObservation::remote_endpoint(
                7,
                16,
                EBPF_ADDRESS_FAMILY_INET,
                443,
                [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
        );

        let decoded = match decode_process_probe_event(&encode_process_probe_event(&event)) {
            Ok(decoded) => decoded,
            Err(error) => panic!("event must decode: {error:?}"),
        };

        assert_eq!(decoded, event);
    }

    #[test]
    fn process_event_decoder_rejects_tls_plaintext_record_kind() {
        let event = tls_plaintext_sample_event();
        let bytes = crate::event::encode_tls_plaintext_event(&event);

        let error = match decode_process_probe_event(&bytes) {
            Ok(_) => panic!("TLS plaintext record must not decode as process observation"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::UnexpectedEventKind {
                actual: EbpfEventKind::LibsslPlaintextSampled.wire(),
                expected: "process probe event"
            }
        );
    }

    #[test]
    fn process_event_rejects_invalid_wire_bytes() {
        let mut event = EbpfProcessProbeEvent::connect_tracepoint_observed(
            11,
            22,
            33,
            44,
            [0; 16],
            EbpfConnectObservation::unavailable(7, 0),
            EBPF_CONNECT_SOCKADDR_READ_FAILED,
        );
        event.header.magic = 0;

        let error = match decode_process_probe_event(&encode_process_probe_event(&event)) {
            Ok(_) => panic!("invalid event must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidMagic {
                actual: 0,
                expected: EBPF_MAGIC
            }
        );
    }

    fn tls_plaintext_sample_event() -> crate::event::EbpfTlsPlaintextEvent {
        let mut payload = [0; crate::event::EBPF_TLS_PLAINTEXT_SAMPLE_BYTES];
        payload[..5].copy_from_slice(b"GET /");
        crate::event::EbpfTlsPlaintextEvent::libssl_plaintext_sampled(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            crate::event::EbpfTlsPlaintextObservation::new(
                0xfeed,
                7,
                crate::event::EBPF_TLS_DIRECTION_OUTBOUND,
                100,
                5,
                5,
                payload,
            ),
            crate::event::EBPF_TLS_PLAINTEXT_FD_VALID,
        )
    }
}

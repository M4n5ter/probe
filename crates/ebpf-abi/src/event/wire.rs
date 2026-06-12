pub const EBPF_MAGIC: u32 = 0x4153_5353;
pub const EBPF_ABI_REVISION: u16 = 3;
pub const EBPF_RING_BUFFER_BYTES: u32 = 256 * 1024;
pub const EBPF_PROCESS_PROBE_EVENT_BYTES: usize = core::mem::size_of::<EbpfProcessProbeEvent>();
const EBPF_PROCESS_PROBE_PAYLOAD_BYTES: usize = core::mem::size_of::<EbpfConnectObservation>();
pub const EBPF_CONNECT_REMOTE_ENDPOINT_VALID: u16 = 1 << 0;
pub const EBPF_CONNECT_SOCKADDR_READ_FAILED: u16 = 1 << 1;
pub const EBPF_CONNECT_UNSUPPORTED_ADDRESS_FAMILY: u16 = 1 << 2;
pub const EBPF_ADDRESS_FAMILY_UNSPEC: u16 = 0;
pub const EBPF_ADDRESS_FAMILY_INET: u16 = 2;
pub const EBPF_ADDRESS_FAMILY_INET6: u16 = 10;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventKind {
    ConnectTracepointObserved = 1,
    CloseTracepointObserved = 2,
}

impl EbpfEventKind {
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::ConnectTracepointObserved),
            2 => Some(Self::CloseTracepointObserved),
            _ => None,
        }
    }

    pub const fn wire(self) -> u16 {
        self as u16
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfEventHeader {
    pub magic: u32,
    pub abi_revision: u16,
    pub kind: u16,
    pub record_len: u16,
    pub flags: u16,
    pub reserved: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl EbpfEventHeader {
    pub const fn new(
        kind: EbpfEventKind,
        record_len: u16,
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
    ) -> Self {
        Self::new_with_flags(kind, record_len, 0, pid, tgid, uid, gid)
    }

    pub const fn new_with_flags(
        kind: EbpfEventKind,
        record_len: u16,
        flags: u16,
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
    ) -> Self {
        Self {
            magic: EBPF_MAGIC,
            abi_revision: EBPF_ABI_REVISION,
            kind: kind.wire(),
            record_len,
            flags,
            reserved: 0,
            pid,
            tgid,
            uid,
            gid,
        }
    }

    pub const fn kind(&self) -> Option<EbpfEventKind> {
        EbpfEventKind::from_wire(self.kind)
    }
}

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
            Some(EbpfEventKind::CloseTracepointObserved) | None => None,
        }
    }

    pub fn close_observation(&self) -> Option<EbpfCloseObservation> {
        match self.header.kind() {
            Some(EbpfEventKind::CloseTracepointObserved) => {
                Some(decode_close_observation(&self.payload))
            }
            Some(EbpfEventKind::ConnectTracepointObserved) | None => None,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventDecodeError {
    UnexpectedRecordSize { actual: usize, expected: usize },
    InvalidMagic { actual: u32, expected: u32 },
    UnsupportedAbiRevision { actual: u16, expected: u16 },
    UnknownEventKind { value: u16 },
    RecordLengthMismatch { actual: u16, expected: usize },
}

pub fn decode_process_probe_event(
    bytes: &[u8],
) -> Result<EbpfProcessProbeEvent, EbpfEventDecodeError> {
    if bytes.len() != EBPF_PROCESS_PROBE_EVENT_BYTES {
        return Err(EbpfEventDecodeError::UnexpectedRecordSize {
            actual: bytes.len(),
            expected: EBPF_PROCESS_PROBE_EVENT_BYTES,
        });
    }

    let mut command = [0; 16];
    command.copy_from_slice(&bytes[32..48]);
    let mut payload = [0; EBPF_PROCESS_PROBE_PAYLOAD_BYTES];
    payload.copy_from_slice(&bytes[48..80]);
    let event = EbpfProcessProbeEvent {
        header: EbpfEventHeader {
            magic: read_u32(bytes, 0),
            abi_revision: read_u16(bytes, 4),
            kind: read_u16(bytes, 6),
            record_len: read_u16(bytes, 8),
            flags: read_u16(bytes, 10),
            reserved: read_u32(bytes, 12),
            pid: read_u32(bytes, 16),
            tgid: read_u32(bytes, 20),
            uid: read_u32(bytes, 24),
            gid: read_u32(bytes, 28),
        },
        command,
        payload,
    };
    validate_process_probe_event(event)
}

pub fn encode_process_probe_event(
    event: &EbpfProcessProbeEvent,
) -> [u8; EBPF_PROCESS_PROBE_EVENT_BYTES] {
    let mut bytes = [0; EBPF_PROCESS_PROBE_EVENT_BYTES];
    write_u32(&mut bytes, 0, event.header.magic);
    write_u16(&mut bytes, 4, event.header.abi_revision);
    write_u16(&mut bytes, 6, event.header.kind);
    write_u16(&mut bytes, 8, event.header.record_len);
    write_u16(&mut bytes, 10, event.header.flags);
    write_u32(&mut bytes, 12, event.header.reserved);
    write_u32(&mut bytes, 16, event.header.pid);
    write_u32(&mut bytes, 20, event.header.tgid);
    write_u32(&mut bytes, 24, event.header.uid);
    write_u32(&mut bytes, 28, event.header.gid);
    bytes[32..48].copy_from_slice(&event.command);
    bytes[48..80].copy_from_slice(&event.payload);
    bytes
}

fn validate_process_probe_event(
    event: EbpfProcessProbeEvent,
) -> Result<EbpfProcessProbeEvent, EbpfEventDecodeError> {
    if event.header.magic != EBPF_MAGIC {
        return Err(EbpfEventDecodeError::InvalidMagic {
            actual: event.header.magic,
            expected: EBPF_MAGIC,
        });
    }
    if event.header.abi_revision != EBPF_ABI_REVISION {
        return Err(EbpfEventDecodeError::UnsupportedAbiRevision {
            actual: event.header.abi_revision,
            expected: EBPF_ABI_REVISION,
        });
    }
    if event.header.kind().is_none() {
        return Err(EbpfEventDecodeError::UnknownEventKind {
            value: event.header.kind,
        });
    }
    if usize::from(event.header.record_len) != EBPF_PROCESS_PROBE_EVENT_BYTES {
        return Err(EbpfEventDecodeError::RecordLengthMismatch {
            actual: event.header.record_len,
            expected: EBPF_PROCESS_PROBE_EVENT_BYTES,
        });
    }
    Ok(event)
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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use super::*;

    #[test]
    fn event_kind_wire_values_are_stable() {
        assert_eq!(
            EbpfEventKind::from_wire(1),
            Some(EbpfEventKind::ConnectTracepointObserved)
        );
        assert_eq!(
            EbpfEventKind::from_wire(2),
            Some(EbpfEventKind::CloseTracepointObserved)
        );
        assert_eq!(EbpfEventKind::from_wire(3), None);
    }

    #[test]
    fn header_layout_is_fixed_for_ringbuf_wire_reads() {
        assert_eq!(size_of::<EbpfEventHeader>(), 32);
        assert_eq!(align_of::<EbpfEventHeader>(), 4);
    }

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
}

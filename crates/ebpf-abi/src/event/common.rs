pub const EBPF_MAGIC: u32 = 0x4153_5353;
pub const EBPF_ABI_REVISION: u16 = 11;
pub const EBPF_RING_BUFFER_BYTES: u32 = 256 * 1024;
pub const EBPF_EVENT_HEADER_BYTES: usize = core::mem::size_of::<EbpfEventHeader>();

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventKind {
    ConnectTracepointObserved = 1,
    CloseTracepointObserved = 2,
    LibsslPlaintextSampled = 3,
    SocketWriteSampled = 4,
    SocketReadSampled = 5,
    AcceptTracepointObserved = 6,
}

impl EbpfEventKind {
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::ConnectTracepointObserved),
            2 => Some(Self::CloseTracepointObserved),
            3 => Some(Self::LibsslPlaintextSampled),
            4 => Some(Self::SocketWriteSampled),
            5 => Some(Self::SocketReadSampled),
            6 => Some(Self::AcceptTracepointObserved),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfEventDecodeError {
    UnexpectedRecordSize { actual: usize, expected: usize },
    InvalidMagic { actual: u32, expected: u32 },
    UnsupportedAbiRevision { actual: u16, expected: u16 },
    UnknownEventKind { value: u16 },
    UnexpectedEventKind { actual: u16, expected: &'static str },
    RecordLengthMismatch { actual: u16, expected: usize },
    InvalidTlsPlaintextDirection { value: u8 },
    InvalidTlsPlaintextCapturedLength { captured: u16, capacity: usize },
    InvalidTlsPlaintextOriginalLength { captured: u16, original: u32 },
    InvalidTlsPlaintextReadFailure { captured: u16 },
    InvalidSocketWriteCapturedLength { captured: u16, capacity: usize },
    InvalidSocketWriteOriginalLength { captured: u16, original: u32 },
    InvalidSocketWriteIncompleteSample { captured: u16, original: u32 },
    InvalidSocketWriteReadFailure { captured: u16 },
    InvalidSocketReadCapturedLength { captured: u16, capacity: usize },
    InvalidSocketReadOriginalLength { captured: u16, original: u32 },
    InvalidSocketReadIncompleteSample { captured: u16, original: u32 },
    InvalidSocketReadReadFailure { captured: u16 },
}

pub fn decode_event_header(bytes: &[u8]) -> Result<EbpfEventHeader, EbpfEventDecodeError> {
    if bytes.len() < EBPF_EVENT_HEADER_BYTES {
        return Err(EbpfEventDecodeError::UnexpectedRecordSize {
            actual: bytes.len(),
            expected: EBPF_EVENT_HEADER_BYTES,
        });
    }
    let header = EbpfEventHeader {
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
    };
    validate_event_header(header)?;
    Ok(header)
}

pub(super) fn encode_event_header(bytes: &mut [u8], header: EbpfEventHeader) {
    write_u32(bytes, 0, header.magic);
    write_u16(bytes, 4, header.abi_revision);
    write_u16(bytes, 6, header.kind);
    write_u16(bytes, 8, header.record_len);
    write_u16(bytes, 10, header.flags);
    write_u32(bytes, 12, header.reserved);
    write_u32(bytes, 16, header.pid);
    write_u32(bytes, 20, header.tgid);
    write_u32(bytes, 24, header.uid);
    write_u32(bytes, 28, header.gid);
}

pub(super) fn validate_event_header(header: EbpfEventHeader) -> Result<(), EbpfEventDecodeError> {
    if header.magic != EBPF_MAGIC {
        return Err(EbpfEventDecodeError::InvalidMagic {
            actual: header.magic,
            expected: EBPF_MAGIC,
        });
    }
    if header.abi_revision != EBPF_ABI_REVISION {
        return Err(EbpfEventDecodeError::UnsupportedAbiRevision {
            actual: header.abi_revision,
            expected: EBPF_ABI_REVISION,
        });
    }
    if header.kind().is_none() {
        return Err(EbpfEventDecodeError::UnknownEventKind { value: header.kind });
    }
    Ok(())
}

pub(super) fn validate_expected_event_kind(
    header: EbpfEventHeader,
    expected: &'static str,
    accepts: fn(EbpfEventKind) -> bool,
) -> Result<(), EbpfEventDecodeError> {
    let Some(kind) = header.kind() else {
        return Err(EbpfEventDecodeError::UnknownEventKind { value: header.kind });
    };
    if accepts(kind) {
        Ok(())
    } else {
        Err(EbpfEventDecodeError::UnexpectedEventKind {
            actual: kind.wire(),
            expected,
        })
    }
}

pub(super) fn decode_record_header(
    bytes: &[u8],
    expected_len: usize,
    expected_kind: &'static str,
    accepts: fn(EbpfEventKind) -> bool,
) -> Result<EbpfEventHeader, EbpfEventDecodeError> {
    let header = decode_event_header(bytes)?;
    validate_expected_event_kind(header, expected_kind, accepts)?;
    if bytes.len() != expected_len {
        return Err(EbpfEventDecodeError::UnexpectedRecordSize {
            actual: bytes.len(),
            expected: expected_len,
        });
    }
    validate_record_len(header, expected_len)?;
    Ok(header)
}

pub(super) fn validate_record_len(
    header: EbpfEventHeader,
    expected: usize,
) -> Result<(), EbpfEventDecodeError> {
    if usize::from(header.record_len) != expected {
        return Err(EbpfEventDecodeError::RecordLengthMismatch {
            actual: header.record_len,
            expected,
        });
    }
    Ok(())
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(super) fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

pub(super) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

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
        assert_eq!(
            EbpfEventKind::from_wire(3),
            Some(EbpfEventKind::LibsslPlaintextSampled)
        );
        assert_eq!(
            EbpfEventKind::from_wire(4),
            Some(EbpfEventKind::SocketWriteSampled)
        );
        assert_eq!(
            EbpfEventKind::from_wire(5),
            Some(EbpfEventKind::SocketReadSampled)
        );
        assert_eq!(
            EbpfEventKind::from_wire(6),
            Some(EbpfEventKind::AcceptTracepointObserved)
        );
        assert_eq!(EbpfEventKind::from_wire(7), None);
    }

    #[test]
    fn header_layout_is_fixed_for_ringbuf_wire_reads() {
        assert_eq!(EBPF_EVENT_HEADER_BYTES, 32);
        assert_eq!(size_of::<EbpfEventHeader>(), 32);
        assert_eq!(align_of::<EbpfEventHeader>(), 4);
    }

    #[test]
    fn event_header_decodes_from_prefix_without_full_record() {
        let event = tls_plaintext_sample_event();
        let bytes = crate::event::encode_tls_plaintext_event(&event);

        let header = match decode_event_header(&bytes[..EBPF_EVENT_HEADER_BYTES]) {
            Ok(header) => header,
            Err(error) => panic!("header prefix must decode: {error:?}"),
        };

        assert_eq!(header.kind(), Some(EbpfEventKind::LibsslPlaintextSampled));
        assert_eq!(
            usize::from(header.record_len),
            crate::event::EBPF_TLS_PLAINTEXT_EVENT_BYTES
        );
    }

    #[test]
    fn event_header_decodes_tls_plaintext_record_for_dispatch() {
        let event = tls_plaintext_sample_event();
        let bytes = crate::event::encode_tls_plaintext_event(&event);

        let header = match decode_event_header(&bytes) {
            Ok(header) => header,
            Err(error) => panic!("header must decode: {error:?}"),
        };

        assert_eq!(header.kind(), Some(EbpfEventKind::LibsslPlaintextSampled));
        assert_eq!(
            usize::from(header.record_len),
            crate::event::EBPF_TLS_PLAINTEXT_EVENT_BYTES
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

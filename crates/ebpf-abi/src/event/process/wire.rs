use super::super::common::{
    EBPF_EVENT_HEADER_BYTES, EbpfEventDecodeError, EbpfEventHeader, EbpfEventKind,
    decode_event_header, encode_event_header, read_i32, read_u16, read_u32, read_u64,
    validate_event_header, validate_expected_event_kind, validate_record_len, write_i32, write_u16,
    write_u32, write_u64,
};

pub const EBPF_PROCESS_PROBE_MAX_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfSocketWriteSampleRecord>();
pub const EBPF_CONNECT_TRACEPOINT_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfConnectTracepointRecord>();
pub const EBPF_CLOSE_TRACEPOINT_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfCloseTracepointRecord>();
pub const EBPF_SOCKET_WRITE_SAMPLE_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfSocketWriteSampleRecord>();
pub const EBPF_SOCKET_WRITE_SAMPLE_BYTES: usize = 256;
const EBPF_PROCESS_COMMAND_OFFSET: usize = EBPF_EVENT_HEADER_BYTES;
const EBPF_PROCESS_COMMAND_BYTES: usize = 16;
const EBPF_PROCESS_PROBE_PAYLOAD_OFFSET: usize =
    EBPF_PROCESS_COMMAND_OFFSET + EBPF_PROCESS_COMMAND_BYTES;
pub const EBPF_CONNECT_REMOTE_ENDPOINT_VALID: u16 = 1 << 0;
pub const EBPF_CONNECT_SOCKADDR_READ_FAILED: u16 = 1 << 1;
pub const EBPF_CONNECT_UNSUPPORTED_ADDRESS_FAMILY: u16 = 1 << 2;
pub const EBPF_SOCKET_WRITE_TRUNCATED: u16 = 1 << 0;
pub const EBPF_SOCKET_WRITE_READ_FAILED: u16 = 1 << 1;
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
    pub fd_table_epoch: u64,
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
            fd_table_epoch: 0,
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
            fd_table_epoch: 0,
        }
    }

    pub const fn with_fd_table_epoch(self, fd_table_epoch: u64) -> Self {
        Self {
            fd_table_epoch,
            ..self
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
pub struct EbpfSocketWriteSample {
    pub fd: i32,
    pub original_len: u32,
    pub captured_len: u16,
    pub reserved: u16,
    pub buffer: [u8; EBPF_SOCKET_WRITE_SAMPLE_BYTES],
}

impl EbpfSocketWriteSample {
    pub const fn new(
        fd: i32,
        original_len: u32,
        captured_len: u16,
        buffer: [u8; EBPF_SOCKET_WRITE_SAMPLE_BYTES],
    ) -> Self {
        Self {
            fd,
            original_len,
            captured_len,
            reserved: 0,
            buffer,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfConnectTracepointRecord {
    header: EbpfEventHeader,
    command: [u8; 16],
    connect: EbpfConnectObservation,
}

impl EbpfConnectTracepointRecord {
    pub fn connect_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        connect: EbpfConnectObservation,
        flags: u16,
    ) -> Self {
        Self {
            header: EbpfEventHeader::new_with_flags(
                EbpfEventKind::ConnectTracepointObserved,
                EBPF_CONNECT_TRACEPOINT_RECORD_BYTES as u16,
                flags,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
            connect,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfCloseTracepointRecord {
    header: EbpfEventHeader,
    command: [u8; 16],
    close: EbpfCloseObservation,
}

impl EbpfCloseTracepointRecord {
    pub fn close_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        close: EbpfCloseObservation,
    ) -> Self {
        Self {
            header: EbpfEventHeader::new(
                EbpfEventKind::CloseTracepointObserved,
                EBPF_CLOSE_TRACEPOINT_RECORD_BYTES as u16,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
            close,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfSocketWriteSampleRecord {
    header: EbpfEventHeader,
    command: [u8; 16],
    sample: EbpfSocketWriteSample,
}

impl EbpfSocketWriteSampleRecord {
    pub fn socket_write_sampled(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        sample: EbpfSocketWriteSample,
        flags: u16,
    ) -> Self {
        Self {
            header: EbpfEventHeader::new_with_flags(
                EbpfEventKind::SocketWriteSampled,
                EBPF_SOCKET_WRITE_SAMPLE_RECORD_BYTES as u16,
                flags,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
            sample,
        }
    }

    pub fn clear_sample(&mut self) {
        self.sample = EbpfSocketWriteSample::new(0, 0, 0, [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES]);
    }

    pub fn socket_write_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.sample.buffer
    }

    pub fn overwrite_socket_write_sampled_metadata(
        &mut self,
        metadata: EbpfProcessProbeMetadata,
        sample: EbpfSocketWriteMetadata,
        flags: u16,
    ) {
        self.header = EbpfEventHeader::new_with_flags(
            EbpfEventKind::SocketWriteSampled,
            EBPF_SOCKET_WRITE_SAMPLE_RECORD_BYTES as u16,
            flags,
            metadata.pid,
            metadata.tgid,
            metadata.uid,
            metadata.gid,
        );
        self.command = metadata.command;
        self.sample.fd = sample.fd;
        self.sample.original_len = sample.original_len;
        self.sample.captured_len = sample.captured_len;
        self.sample.reserved = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessProbeEvent {
    header: EbpfEventHeader,
    command: [u8; 16],
    connect: EbpfConnectObservation,
    close: EbpfCloseObservation,
    socket_write: EbpfSocketWriteSample,
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
        EbpfConnectTracepointRecord::connect_tracepoint_observed(
            pid, tgid, uid, gid, command, connect, flags,
        )
        .into()
    }

    pub fn close_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        close: EbpfCloseObservation,
    ) -> Self {
        EbpfCloseTracepointRecord::close_tracepoint_observed(pid, tgid, uid, gid, command, close)
            .into()
    }

    pub fn socket_write_sampled(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        sample: EbpfSocketWriteSample,
        flags: u16,
    ) -> Self {
        EbpfSocketWriteSampleRecord::socket_write_sampled(
            pid, tgid, uid, gid, command, sample, flags,
        )
        .into()
    }

    pub fn connect_observation(&self) -> Option<EbpfConnectObservation> {
        match self.kind() {
            Some(EbpfEventKind::ConnectTracepointObserved) => Some(self.connect),
            _ => None,
        }
    }

    pub fn socket_write_sample(&self) -> Option<EbpfSocketWriteSample> {
        match self.kind() {
            Some(EbpfEventKind::SocketWriteSampled) => Some(self.socket_write),
            _ => None,
        }
    }

    pub fn close_observation(&self) -> Option<EbpfCloseObservation> {
        match self.kind() {
            Some(EbpfEventKind::CloseTracepointObserved) => Some(self.close),
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

impl From<EbpfConnectTracepointRecord> for EbpfProcessProbeEvent {
    fn from(record: EbpfConnectTracepointRecord) -> Self {
        let mut event = empty_process_probe_event(record.header, record.command);
        event.connect = record.connect;
        event
    }
}

impl From<EbpfCloseTracepointRecord> for EbpfProcessProbeEvent {
    fn from(record: EbpfCloseTracepointRecord) -> Self {
        let mut event = empty_process_probe_event(record.header, record.command);
        event.close = record.close;
        event
    }
}

impl From<EbpfSocketWriteSampleRecord> for EbpfProcessProbeEvent {
    fn from(record: EbpfSocketWriteSampleRecord) -> Self {
        let mut event = empty_process_probe_event(record.header, record.command);
        event.socket_write = record.sample;
        event
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessProbeMetadata {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub command: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfSocketWriteMetadata {
    pub fd: i32,
    pub original_len: u32,
    pub captured_len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedProcessProbeEvent {
    bytes: [u8; EBPF_PROCESS_PROBE_MAX_RECORD_BYTES],
    len: usize,
}

impl EncodedProcessProbeEvent {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl core::ops::Deref for EncodedProcessProbeEvent {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

pub fn decode_process_probe_event(
    bytes: &[u8],
) -> Result<EbpfProcessProbeEvent, EbpfEventDecodeError> {
    let header = decode_event_header(bytes)?;
    validate_expected_event_kind(header, "process probe event", is_process_probe_kind)?;
    let kind = header
        .kind()
        .ok_or(EbpfEventDecodeError::UnknownEventKind { value: header.kind })?;
    let expected_len = process_record_len(kind);
    if bytes.len() != expected_len {
        return Err(EbpfEventDecodeError::UnexpectedRecordSize {
            actual: bytes.len(),
            expected: expected_len,
        });
    }
    validate_record_len(header, expected_len)?;

    let mut command = [0; 16];
    command.copy_from_slice(&bytes[EBPF_PROCESS_COMMAND_OFFSET..EBPF_PROCESS_PROBE_PAYLOAD_OFFSET]);
    let event = decode_process_probe_payload(kind, header, command, bytes);
    validate_process_probe_event(event)
}

pub fn encode_process_probe_event(event: &EbpfProcessProbeEvent) -> EncodedProcessProbeEvent {
    let len = process_record_len(
        event
            .kind()
            .expect("process probe event constructor should set a known kind"),
    );
    let mut bytes = [0; EBPF_PROCESS_PROBE_MAX_RECORD_BYTES];
    encode_event_header(&mut bytes, event.header);
    bytes[EBPF_PROCESS_COMMAND_OFFSET..EBPF_PROCESS_PROBE_PAYLOAD_OFFSET]
        .copy_from_slice(&event.command);
    match event.kind() {
        Some(EbpfEventKind::ConnectTracepointObserved) => {
            encode_connect_observation(
                &mut bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..],
                event.connect,
            );
        }
        Some(EbpfEventKind::CloseTracepointObserved) => {
            encode_close_observation(&mut bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..], event.close);
        }
        Some(EbpfEventKind::SocketWriteSampled) => {
            encode_socket_write_sample(
                &mut bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..],
                event.socket_write,
            );
        }
        Some(EbpfEventKind::LibsslPlaintextSampled) | None => {
            unreachable!("process probe event constructor should set a known process kind")
        }
    }
    EncodedProcessProbeEvent { bytes, len }
}

fn validate_process_probe_event(
    event: EbpfProcessProbeEvent,
) -> Result<EbpfProcessProbeEvent, EbpfEventDecodeError> {
    validate_event_header(event.header)?;
    validate_expected_event_kind(event.header, "process probe event", is_process_probe_kind)?;
    validate_record_len(
        event.header,
        process_record_len(
            event
                .kind()
                .expect("process probe event kind should already be validated"),
        ),
    )?;
    if event.kind() == Some(EbpfEventKind::SocketWriteSampled) {
        validate_socket_write_sample(event)?;
    }
    Ok(event)
}

fn is_process_probe_kind(kind: EbpfEventKind) -> bool {
    matches!(
        kind,
        EbpfEventKind::ConnectTracepointObserved
            | EbpfEventKind::CloseTracepointObserved
            | EbpfEventKind::SocketWriteSampled
    )
}

fn process_record_len(kind: EbpfEventKind) -> usize {
    match kind {
        EbpfEventKind::ConnectTracepointObserved => EBPF_CONNECT_TRACEPOINT_RECORD_BYTES,
        EbpfEventKind::CloseTracepointObserved => EBPF_CLOSE_TRACEPOINT_RECORD_BYTES,
        EbpfEventKind::SocketWriteSampled => EBPF_SOCKET_WRITE_SAMPLE_RECORD_BYTES,
        EbpfEventKind::LibsslPlaintextSampled => unreachable!("not a process probe kind"),
    }
}

fn decode_process_probe_payload(
    kind: EbpfEventKind,
    header: EbpfEventHeader,
    command: [u8; 16],
    bytes: &[u8],
) -> EbpfProcessProbeEvent {
    let payload = &bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..];
    let mut event = empty_process_probe_event(header, command);
    match kind {
        EbpfEventKind::ConnectTracepointObserved => {
            event.connect = decode_connect_observation(payload);
        }
        EbpfEventKind::CloseTracepointObserved => {
            event.close = decode_close_observation(payload);
        }
        EbpfEventKind::SocketWriteSampled => {
            event.socket_write = decode_socket_write_sample(payload);
        }
        EbpfEventKind::LibsslPlaintextSampled => unreachable!("not a process probe kind"),
    }
    event
}

fn empty_process_probe_event(header: EbpfEventHeader, command: [u8; 16]) -> EbpfProcessProbeEvent {
    EbpfProcessProbeEvent {
        header,
        command,
        connect: EbpfConnectObservation::unavailable(0, 0),
        close: EbpfCloseObservation::observed(0),
        socket_write: EbpfSocketWriteSample::new(0, 0, 0, [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES]),
    }
}

fn decode_connect_observation(bytes: &[u8]) -> EbpfConnectObservation {
    let mut remote_address = [0; 16];
    remote_address.copy_from_slice(&bytes[12..28]);
    EbpfConnectObservation {
        fd: read_i32(bytes, 0),
        addrlen: read_u32(bytes, 4),
        address_family: read_u16(bytes, 8),
        remote_port: read_u16(bytes, 10),
        remote_address,
        reserved: read_u32(bytes, 28),
        fd_table_epoch: read_u64(bytes, 32),
    }
}

fn encode_connect_observation(bytes: &mut [u8], connect: EbpfConnectObservation) {
    write_i32(bytes, 0, connect.fd);
    write_u32(bytes, 4, connect.addrlen);
    write_u16(bytes, 8, connect.address_family);
    write_u16(bytes, 10, connect.remote_port);
    bytes[12..28].copy_from_slice(&connect.remote_address);
    write_u32(bytes, 28, connect.reserved);
    write_u64(bytes, 32, connect.fd_table_epoch);
}

fn decode_close_observation(bytes: &[u8]) -> EbpfCloseObservation {
    EbpfCloseObservation {
        fd: read_i32(bytes, 0),
        reserved: read_u32(bytes, 4),
    }
}

fn encode_close_observation(bytes: &mut [u8], close: EbpfCloseObservation) {
    write_i32(bytes, 0, close.fd);
    write_u32(bytes, 4, close.reserved);
}

fn decode_socket_write_sample(bytes: &[u8]) -> EbpfSocketWriteSample {
    let mut buffer = [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES];
    buffer.copy_from_slice(&bytes[12..12 + EBPF_SOCKET_WRITE_SAMPLE_BYTES]);
    EbpfSocketWriteSample {
        fd: read_i32(bytes, 0),
        original_len: read_u32(bytes, 4),
        captured_len: read_u16(bytes, 8),
        reserved: read_u16(bytes, 10),
        buffer,
    }
}

fn encode_socket_write_sample(bytes: &mut [u8], sample: EbpfSocketWriteSample) {
    write_i32(bytes, 0, sample.fd);
    write_u32(bytes, 4, sample.original_len);
    write_u16(bytes, 8, sample.captured_len);
    write_u16(bytes, 10, sample.reserved);
    bytes[12..12 + EBPF_SOCKET_WRITE_SAMPLE_BYTES].copy_from_slice(&sample.buffer);
}

fn validate_socket_write_sample(event: EbpfProcessProbeEvent) -> Result<(), EbpfEventDecodeError> {
    let Some(sample) = event.socket_write_sample() else {
        return Ok(());
    };
    let captured = usize::from(sample.captured_len);
    if captured > EBPF_SOCKET_WRITE_SAMPLE_BYTES {
        return Err(EbpfEventDecodeError::InvalidSocketWriteCapturedLength {
            captured: sample.captured_len,
            capacity: EBPF_SOCKET_WRITE_SAMPLE_BYTES,
        });
    }
    if u32::from(sample.captured_len) > sample.original_len {
        return Err(EbpfEventDecodeError::InvalidSocketWriteOriginalLength {
            captured: sample.captured_len,
            original: sample.original_len,
        });
    }
    if u32::from(sample.captured_len) < sample.original_len
        && event.header.flags & (EBPF_SOCKET_WRITE_TRUNCATED | EBPF_SOCKET_WRITE_READ_FAILED) == 0
    {
        return Err(EbpfEventDecodeError::InvalidSocketWriteIncompleteSample {
            captured: sample.captured_len,
            original: sample.original_len,
        });
    }
    if event.header.flags & EBPF_SOCKET_WRITE_READ_FAILED != 0 && sample.captured_len > 0 {
        return Err(EbpfEventDecodeError::InvalidSocketWriteReadFailure {
            captured: sample.captured_len,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use crate::event::{EBPF_ABI_REVISION, EBPF_MAGIC};

    use super::*;

    #[test]
    fn process_event_layout_fits_ringbuf_alignment() {
        assert_eq!(size_of::<EbpfConnectObservation>(), 40);
        assert_eq!(align_of::<EbpfConnectObservation>(), 8);
        assert_eq!(size_of::<EbpfCloseObservation>(), 8);
        assert_eq!(align_of::<EbpfCloseObservation>(), 4);
        assert_eq!(size_of::<EbpfSocketWriteSample>(), 268);
        assert_eq!(align_of::<EbpfSocketWriteSample>(), 4);
        assert_eq!(size_of::<EbpfConnectTracepointRecord>(), 88);
        assert_eq!(align_of::<EbpfConnectTracepointRecord>(), 8);
        assert_eq!(size_of::<EbpfCloseTracepointRecord>(), 56);
        assert_eq!(align_of::<EbpfCloseTracepointRecord>(), 4);
        assert_eq!(size_of::<EbpfSocketWriteSampleRecord>(), 316);
        assert_eq!(align_of::<EbpfSocketWriteSampleRecord>(), 4);
        assert_eq!(8 % align_of::<EbpfSocketWriteSampleRecord>(), 0);
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
        assert_eq!(offset_of!(EbpfConnectObservation, fd_table_epoch), 32);
        assert_eq!(offset_of!(EbpfCloseObservation, fd), 0);
        assert_eq!(offset_of!(EbpfCloseObservation, reserved), 4);
        assert_eq!(offset_of!(EbpfSocketWriteSample, fd), 0);
        assert_eq!(offset_of!(EbpfSocketWriteSample, original_len), 4);
        assert_eq!(offset_of!(EbpfSocketWriteSample, captured_len), 8);
        assert_eq!(offset_of!(EbpfSocketWriteSample, reserved), 10);
        assert_eq!(offset_of!(EbpfSocketWriteSample, buffer), 12);
        assert_eq!(offset_of!(EbpfConnectTracepointRecord, header), 0);
        assert_eq!(offset_of!(EbpfConnectTracepointRecord, command), 32);
        assert_eq!(offset_of!(EbpfConnectTracepointRecord, connect), 48);
        assert_eq!(offset_of!(EbpfCloseTracepointRecord, header), 0);
        assert_eq!(offset_of!(EbpfCloseTracepointRecord, command), 32);
        assert_eq!(offset_of!(EbpfCloseTracepointRecord, close), 48);
        assert_eq!(offset_of!(EbpfSocketWriteSampleRecord, header), 0);
        assert_eq!(offset_of!(EbpfSocketWriteSampleRecord, command), 32);
        assert_eq!(offset_of!(EbpfSocketWriteSampleRecord, sample), 48);
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
            )
            .with_fd_table_epoch(9),
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
            EBPF_CONNECT_TRACEPOINT_RECORD_BYTES
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
        assert_eq!(connect.fd_table_epoch, 9);
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
            EBPF_CLOSE_TRACEPOINT_RECORD_BYTES
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
    fn socket_write_sampled_populates_header_fields() {
        let event = sample_write_event(5, 5, 0);

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(event.header.kind(), Some(EbpfEventKind::SocketWriteSampled));
        assert_eq!(
            usize::from(event.header.record_len),
            EBPF_SOCKET_WRITE_SAMPLE_RECORD_BYTES
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, 0);
        let sample = event
            .socket_write_sample()
            .expect("write event should expose write sample");
        assert_eq!(sample.fd, 7);
        assert_eq!(sample.original_len, 5);
        assert_eq!(sample.captured_len, 5);
        assert_eq!(&sample.buffer[..5], b"GET /");
        assert!(event.connect_observation().is_none());
        assert!(event.close_observation().is_none());
    }

    #[test]
    fn socket_write_sampled_metadata_can_be_overwritten_in_place() {
        let expected = sample_write_record(5, 5, 0);
        let mut event = EbpfSocketWriteSampleRecord::socket_write_sampled(
            0,
            0,
            0,
            0,
            [0; 16],
            EbpfSocketWriteSample::new(-1, 0, 0, [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES]),
            0,
        );
        event.clear_sample();
        event.socket_write_buffer_mut()[..5].copy_from_slice(b"GET /");
        event.overwrite_socket_write_sampled_metadata(
            EbpfProcessProbeMetadata {
                pid: 11,
                tgid: 22,
                uid: 33,
                gid: 44,
                command: *b"0123456789abcdef",
            },
            EbpfSocketWriteMetadata {
                fd: 7,
                original_len: 5,
                captured_len: 5,
            },
            0,
        );

        assert_eq!(event, expected);
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
    fn process_event_rejects_invalid_write_sample_lengths() {
        let error = match decode_process_probe_event(&encode_process_probe_event(
            &sample_write_event(5, 6, 0),
        )) {
            Ok(_) => panic!("captured bytes beyond original write must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidSocketWriteOriginalLength {
                captured: 6,
                original: 5
            }
        );

        let error = match decode_process_probe_event(&encode_process_probe_event(
            &sample_write_event(10, 5, 0),
        )) {
            Ok(_) => panic!("incomplete sample without a gap flag must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidSocketWriteIncompleteSample {
                captured: 5,
                original: 10
            }
        );

        let error = match decode_process_probe_event(&encode_process_probe_event(
            &sample_write_event(5, 1, EBPF_SOCKET_WRITE_READ_FAILED),
        )) {
            Ok(_) => panic!("read failure with captured bytes must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidSocketWriteReadFailure { captured: 1 }
        );
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

    fn sample_write_event(
        original_len: u32,
        captured_len: u16,
        flags: u16,
    ) -> EbpfProcessProbeEvent {
        sample_write_record(original_len, captured_len, flags).into()
    }

    fn sample_write_record(
        original_len: u32,
        captured_len: u16,
        flags: u16,
    ) -> EbpfSocketWriteSampleRecord {
        let mut buffer = [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES];
        buffer[..5].copy_from_slice(b"GET /");
        EbpfSocketWriteSampleRecord::socket_write_sampled(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            EbpfSocketWriteSample::new(7, original_len, captured_len, buffer),
            flags,
        )
    }
}

use super::super::common::{
    EBPF_EVENT_HEADER_BYTES, EBPF_PAYLOAD_SAMPLE_BYTES, EbpfEventDecodeError, EbpfEventHeader,
    EbpfEventKind, decode_event_header, encode_event_header, read_i32, read_u16, read_u32,
    read_u64, validate_event_header, validate_expected_event_kind, validate_record_len, write_i32,
    write_u16, write_u32, write_u64,
};

pub const EBPF_PROCESS_PROBE_MAX_RECORD_BYTES: usize = max_record_bytes([
    core::mem::size_of::<EbpfConnectTracepointRecord>(),
    core::mem::size_of::<EbpfAcceptTracepointRecord>(),
    core::mem::size_of::<EbpfCloseTracepointRecord>(),
    core::mem::size_of::<EbpfCloseRangeTracepointRecord>(),
    core::mem::size_of::<EbpfProcessLifecycleRecord>(),
    core::mem::size_of::<EbpfSocketWriteSampleRecord>(),
    core::mem::size_of::<EbpfSocketReadSampleRecord>(),
]);
pub const EBPF_CONNECT_TRACEPOINT_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfConnectTracepointRecord>();
pub const EBPF_ACCEPT_TRACEPOINT_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfAcceptTracepointRecord>();
pub const EBPF_CLOSE_TRACEPOINT_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfCloseTracepointRecord>();
pub const EBPF_CLOSE_RANGE_TRACEPOINT_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfCloseRangeTracepointRecord>();
pub const EBPF_PROCESS_LIFECYCLE_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfProcessLifecycleRecord>();
pub const EBPF_SOCKET_WRITE_SAMPLE_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfSocketWriteSampleRecord>();
pub const EBPF_SOCKET_WRITE_SAMPLE_BYTES: usize = EBPF_PAYLOAD_SAMPLE_BYTES;
pub const EBPF_SOCKET_READ_SAMPLE_RECORD_BYTES: usize =
    core::mem::size_of::<EbpfSocketReadSampleRecord>();
pub const EBPF_SOCKET_READ_SAMPLE_BYTES: usize = EBPF_SOCKET_WRITE_SAMPLE_BYTES;
const EBPF_PROCESS_COMMAND_OFFSET: usize = EBPF_EVENT_HEADER_BYTES;
const EBPF_PROCESS_COMMAND_BYTES: usize = 16;
const EBPF_PROCESS_PROBE_PAYLOAD_OFFSET: usize =
    EBPF_PROCESS_COMMAND_OFFSET + EBPF_PROCESS_COMMAND_BYTES;
pub const EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID: u16 = 1 << 0;
pub const EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED: u16 = 1 << 1;
pub const EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY: u16 = 1 << 2;
pub const EBPF_CONNECT_REMOTE_ENDPOINT_VALID: u16 = EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID;
pub const EBPF_CONNECT_SOCKADDR_READ_FAILED: u16 = EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED;
pub const EBPF_CONNECT_UNSUPPORTED_ADDRESS_FAMILY: u16 =
    EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY;
pub const EBPF_ACCEPT_REMOTE_ENDPOINT_VALID: u16 = EBPF_SOCKET_FLOW_REMOTE_ENDPOINT_VALID;
pub const EBPF_ACCEPT_SOCKADDR_READ_FAILED: u16 = EBPF_SOCKET_FLOW_SOCKADDR_READ_FAILED;
pub const EBPF_ACCEPT_UNSUPPORTED_ADDRESS_FAMILY: u16 = EBPF_SOCKET_FLOW_UNSUPPORTED_ADDRESS_FAMILY;
pub const EBPF_SOCKET_WRITE_TRUNCATED: u16 = 1 << 0;
pub const EBPF_SOCKET_WRITE_READ_FAILED: u16 = 1 << 1;
pub const EBPF_SOCKET_WRITE_KERNEL_TRANSFER: u16 = 1 << 2;
pub const EBPF_SOCKET_READ_TRUNCATED: u16 = 1 << 0;
pub const EBPF_SOCKET_READ_READ_FAILED: u16 = 1 << 1;
pub const EBPF_ADDRESS_FAMILY_UNSPEC: u16 = 0;
pub const EBPF_ADDRESS_FAMILY_INET: u16 = 2;
pub const EBPF_ADDRESS_FAMILY_INET6: u16 = 10;

const fn max_record_bytes(record_bytes: [usize; 7]) -> usize {
    let mut max = 0;
    let mut index = 0;
    while index < record_bytes.len() {
        if record_bytes[index] > max {
            max = record_bytes[index];
        }
        index += 1;
    }
    max
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfAcceptObservation {
    pub fd: i32,
    pub listen_fd: i32,
    pub addrlen: u32,
    pub address_family: u16,
    pub remote_port: u16,
    pub remote_address: [u8; 16],
    pub fd_table_epoch: u64,
    pub fd_generation: u64,
}

impl EbpfAcceptObservation {
    pub const fn unavailable(fd: i32, listen_fd: i32, addrlen: u32) -> Self {
        Self {
            fd,
            listen_fd,
            addrlen,
            address_family: EBPF_ADDRESS_FAMILY_UNSPEC,
            remote_port: 0,
            remote_address: [0; 16],
            fd_table_epoch: 0,
            fd_generation: 0,
        }
    }

    pub const fn remote_endpoint(
        fd: i32,
        listen_fd: i32,
        addrlen: u32,
        address_family: u16,
        remote_port: u16,
        remote_address: [u8; 16],
    ) -> Self {
        Self {
            fd,
            listen_fd,
            addrlen,
            address_family,
            remote_port,
            remote_address,
            fd_table_epoch: 0,
            fd_generation: 0,
        }
    }

    pub const fn with_descriptor_lease(self, fd_table_epoch: u64, fd_generation: u64) -> Self {
        Self {
            fd_table_epoch,
            fd_generation,
            ..self
        }
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
    pub fd_table_epoch: u64,
    pub fd_generation: u64,
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
            fd_generation: 0,
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
            fd_generation: 0,
        }
    }

    pub const fn with_descriptor_lease(self, fd_table_epoch: u64, fd_generation: u64) -> Self {
        Self {
            fd_table_epoch,
            fd_generation,
            ..self
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfCloseObservation {
    pub fd: i32,
    pub reserved: u32,
    pub fd_generation: u64,
}

impl EbpfCloseObservation {
    pub const fn observed(fd: i32, fd_generation: u64) -> Self {
        Self {
            fd,
            reserved: 0,
            fd_generation,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfCloseRangeObservation {
    pub first_fd: u32,
    pub last_fd: u32,
    pub reserved: u32,
}

impl EbpfCloseRangeObservation {
    pub const fn observed(first_fd: u32, last_fd: u32) -> Self {
        Self {
            first_fd,
            last_fd,
            reserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfSocketWriteSample {
    pub fd: i32,
    pub original_len: u32,
    pub fd_generation: u64,
    pub captured_len: u16,
    pub reserved: [u8; 6],
    pub buffer: [u8; EBPF_SOCKET_WRITE_SAMPLE_BYTES],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfSocketReadSample {
    pub fd: i32,
    pub original_len: u32,
    pub fd_generation: u64,
    pub captured_len: u16,
    pub reserved: [u8; 6],
    pub buffer: [u8; EBPF_SOCKET_READ_SAMPLE_BYTES],
}

impl EbpfSocketReadSample {
    pub const fn new(
        fd: i32,
        fd_generation: u64,
        original_len: u32,
        captured_len: u16,
        buffer: [u8; EBPF_SOCKET_READ_SAMPLE_BYTES],
    ) -> Self {
        Self {
            fd,
            original_len,
            fd_generation,
            captured_len,
            reserved: [0; 6],
            buffer,
        }
    }
}

impl EbpfSocketWriteSample {
    pub const fn new(
        fd: i32,
        fd_generation: u64,
        original_len: u32,
        captured_len: u16,
        buffer: [u8; EBPF_SOCKET_WRITE_SAMPLE_BYTES],
    ) -> Self {
        Self {
            fd,
            original_len,
            fd_generation,
            captured_len,
            reserved: [0; 6],
            buffer,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessLifecycleRecord {
    header: EbpfEventHeader,
    command: [u8; 16],
}

impl EbpfProcessLifecycleRecord {
    pub fn process_exit_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
    ) -> Self {
        Self::observed(
            EbpfEventKind::ProcessExitObserved,
            pid,
            tgid,
            uid,
            gid,
            command,
        )
    }

    pub fn process_exec_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
    ) -> Self {
        Self::observed(
            EbpfEventKind::ProcessExecObserved,
            pid,
            tgid,
            uid,
            gid,
            command,
        )
    }

    fn observed(
        kind: EbpfEventKind,
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
    ) -> Self {
        Self {
            header: EbpfEventHeader::new(
                kind,
                EBPF_PROCESS_LIFECYCLE_RECORD_BYTES as u16,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
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
pub struct EbpfAcceptTracepointRecord {
    header: EbpfEventHeader,
    command: [u8; 16],
    accept: EbpfAcceptObservation,
}

impl EbpfAcceptTracepointRecord {
    pub fn accept_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        accept: EbpfAcceptObservation,
        flags: u16,
    ) -> Self {
        Self {
            header: EbpfEventHeader::new_with_flags(
                EbpfEventKind::AcceptTracepointObserved,
                EBPF_ACCEPT_TRACEPOINT_RECORD_BYTES as u16,
                flags,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
            accept,
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
pub struct EbpfCloseRangeTracepointRecord {
    header: EbpfEventHeader,
    command: [u8; 16],
    close_range: EbpfCloseRangeObservation,
}

impl EbpfCloseRangeTracepointRecord {
    pub fn close_range_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        close_range: EbpfCloseRangeObservation,
    ) -> Self {
        Self {
            header: EbpfEventHeader::new(
                EbpfEventKind::CloseRangeTracepointObserved,
                EBPF_CLOSE_RANGE_TRACEPOINT_RECORD_BYTES as u16,
                pid,
                tgid,
                uid,
                gid,
            ),
            command,
            close_range,
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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfSocketReadSampleRecord {
    header: EbpfEventHeader,
    command: [u8; 16],
    sample: EbpfSocketReadSample,
}

impl EbpfSocketReadSampleRecord {
    pub fn socket_read_sampled(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        sample: EbpfSocketReadSample,
        flags: u16,
    ) -> Self {
        Self {
            header: EbpfEventHeader::new_with_flags(
                EbpfEventKind::SocketReadSampled,
                EBPF_SOCKET_READ_SAMPLE_RECORD_BYTES as u16,
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
        self.sample = EbpfSocketReadSample::new(0, 0, 0, 0, [0; EBPF_SOCKET_READ_SAMPLE_BYTES]);
    }

    pub fn socket_read_buffer_mut(&mut self) -> &mut [u8; EBPF_SOCKET_READ_SAMPLE_BYTES] {
        &mut self.sample.buffer
    }

    pub fn overwrite_socket_read_sampled_metadata(
        &mut self,
        metadata: EbpfProcessProbeMetadata,
        sample: EbpfSocketReadMetadata,
        flags: u16,
    ) {
        self.header = EbpfEventHeader::new_with_flags(
            EbpfEventKind::SocketReadSampled,
            EBPF_SOCKET_READ_SAMPLE_RECORD_BYTES as u16,
            flags,
            metadata.pid,
            metadata.tgid,
            metadata.uid,
            metadata.gid,
        );
        self.command = metadata.command;
        self.sample.fd = sample.fd;
        self.sample.original_len = sample.original_len;
        self.sample.fd_generation = sample.fd_generation;
        self.sample.captured_len = sample.captured_len;
        self.sample.reserved = [0; 6];
    }
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
        self.sample = EbpfSocketWriteSample::new(0, 0, 0, 0, [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES]);
    }

    pub fn socket_write_buffer_mut(&mut self) -> &mut [u8; EBPF_SOCKET_WRITE_SAMPLE_BYTES] {
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
        self.sample.fd_generation = sample.fd_generation;
        self.sample.captured_len = sample.captured_len;
        self.sample.reserved = [0; 6];
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessProbeEvent {
    header: EbpfEventHeader,
    command: [u8; 16],
    accept: EbpfAcceptObservation,
    connect: EbpfConnectObservation,
    close: EbpfCloseObservation,
    close_range: EbpfCloseRangeObservation,
    socket_write: EbpfSocketWriteSample,
    socket_read: EbpfSocketReadSample,
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

    pub fn accept_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        accept: EbpfAcceptObservation,
        flags: u16,
    ) -> Self {
        EbpfAcceptTracepointRecord::accept_tracepoint_observed(
            pid, tgid, uid, gid, command, accept, flags,
        )
        .into()
    }

    pub fn socket_read_sampled(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        sample: EbpfSocketReadSample,
        flags: u16,
    ) -> Self {
        EbpfSocketReadSampleRecord::socket_read_sampled(pid, tgid, uid, gid, command, sample, flags)
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

    pub fn close_range_tracepoint_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
        close_range: EbpfCloseRangeObservation,
    ) -> Self {
        EbpfCloseRangeTracepointRecord::close_range_tracepoint_observed(
            pid,
            tgid,
            uid,
            gid,
            command,
            close_range,
        )
        .into()
    }

    pub fn process_exit_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
    ) -> Self {
        EbpfProcessLifecycleRecord::process_exit_observed(pid, tgid, uid, gid, command).into()
    }

    pub fn process_exec_observed(
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        command: [u8; 16],
    ) -> Self {
        EbpfProcessLifecycleRecord::process_exec_observed(pid, tgid, uid, gid, command).into()
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

    pub fn accept_observation(&self) -> Option<EbpfAcceptObservation> {
        match self.kind() {
            Some(EbpfEventKind::AcceptTracepointObserved) => Some(self.accept),
            _ => None,
        }
    }

    pub fn socket_write_sample(&self) -> Option<EbpfSocketWriteSample> {
        match self.kind() {
            Some(EbpfEventKind::SocketWriteSampled) => Some(self.socket_write),
            _ => None,
        }
    }

    pub fn socket_read_sample(&self) -> Option<EbpfSocketReadSample> {
        match self.kind() {
            Some(EbpfEventKind::SocketReadSampled) => Some(self.socket_read),
            _ => None,
        }
    }

    pub fn close_observation(&self) -> Option<EbpfCloseObservation> {
        match self.kind() {
            Some(EbpfEventKind::CloseTracepointObserved) => Some(self.close),
            _ => None,
        }
    }

    pub fn close_range_observation(&self) -> Option<EbpfCloseRangeObservation> {
        match self.kind() {
            Some(EbpfEventKind::CloseRangeTracepointObserved) => Some(self.close_range),
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

impl From<EbpfAcceptTracepointRecord> for EbpfProcessProbeEvent {
    fn from(record: EbpfAcceptTracepointRecord) -> Self {
        let mut event = empty_process_probe_event(record.header, record.command);
        event.accept = record.accept;
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

impl From<EbpfCloseRangeTracepointRecord> for EbpfProcessProbeEvent {
    fn from(record: EbpfCloseRangeTracepointRecord) -> Self {
        let mut event = empty_process_probe_event(record.header, record.command);
        event.close_range = record.close_range;
        event
    }
}

impl From<EbpfProcessLifecycleRecord> for EbpfProcessProbeEvent {
    fn from(record: EbpfProcessLifecycleRecord) -> Self {
        empty_process_probe_event(record.header, record.command)
    }
}

impl From<EbpfSocketWriteSampleRecord> for EbpfProcessProbeEvent {
    fn from(record: EbpfSocketWriteSampleRecord) -> Self {
        let mut event = empty_process_probe_event(record.header, record.command);
        event.socket_write = record.sample;
        event
    }
}

impl From<EbpfSocketReadSampleRecord> for EbpfProcessProbeEvent {
    fn from(record: EbpfSocketReadSampleRecord) -> Self {
        let mut event = empty_process_probe_event(record.header, record.command);
        event.socket_read = record.sample;
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
    pub fd_generation: u64,
    pub captured_len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfSocketReadMetadata {
    pub fd: i32,
    pub original_len: u32,
    pub fd_generation: u64,
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
        Some(EbpfEventKind::AcceptTracepointObserved) => {
            encode_accept_observation(
                &mut bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..],
                event.accept,
            );
        }
        Some(EbpfEventKind::CloseTracepointObserved) => {
            encode_close_observation(&mut bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..], event.close);
        }
        Some(EbpfEventKind::CloseRangeTracepointObserved) => {
            encode_close_range_observation(
                &mut bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..],
                event.close_range,
            );
        }
        Some(EbpfEventKind::ProcessExitObserved | EbpfEventKind::ProcessExecObserved) => {}
        Some(EbpfEventKind::SocketWriteSampled) => {
            encode_socket_write_sample(
                &mut bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..],
                event.socket_write,
            );
        }
        Some(EbpfEventKind::SocketReadSampled) => {
            encode_socket_read_sample(
                &mut bytes[EBPF_PROCESS_PROBE_PAYLOAD_OFFSET..],
                event.socket_read,
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
    if event.kind() == Some(EbpfEventKind::SocketReadSampled) {
        validate_socket_read_sample(event)?;
    }
    Ok(event)
}

fn is_process_probe_kind(kind: EbpfEventKind) -> bool {
    matches!(
        kind,
        EbpfEventKind::ConnectTracepointObserved
            | EbpfEventKind::AcceptTracepointObserved
            | EbpfEventKind::CloseTracepointObserved
            | EbpfEventKind::CloseRangeTracepointObserved
            | EbpfEventKind::ProcessExitObserved
            | EbpfEventKind::ProcessExecObserved
            | EbpfEventKind::SocketWriteSampled
            | EbpfEventKind::SocketReadSampled
    )
}

fn process_record_len(kind: EbpfEventKind) -> usize {
    match kind {
        EbpfEventKind::ConnectTracepointObserved => EBPF_CONNECT_TRACEPOINT_RECORD_BYTES,
        EbpfEventKind::AcceptTracepointObserved => EBPF_ACCEPT_TRACEPOINT_RECORD_BYTES,
        EbpfEventKind::CloseTracepointObserved => EBPF_CLOSE_TRACEPOINT_RECORD_BYTES,
        EbpfEventKind::CloseRangeTracepointObserved => EBPF_CLOSE_RANGE_TRACEPOINT_RECORD_BYTES,
        EbpfEventKind::ProcessExitObserved | EbpfEventKind::ProcessExecObserved => {
            EBPF_PROCESS_LIFECYCLE_RECORD_BYTES
        }
        EbpfEventKind::SocketWriteSampled => EBPF_SOCKET_WRITE_SAMPLE_RECORD_BYTES,
        EbpfEventKind::SocketReadSampled => EBPF_SOCKET_READ_SAMPLE_RECORD_BYTES,
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
        EbpfEventKind::AcceptTracepointObserved => {
            event.accept = decode_accept_observation(payload);
        }
        EbpfEventKind::CloseTracepointObserved => {
            event.close = decode_close_observation(payload);
        }
        EbpfEventKind::CloseRangeTracepointObserved => {
            event.close_range = decode_close_range_observation(payload);
        }
        EbpfEventKind::ProcessExitObserved | EbpfEventKind::ProcessExecObserved => {}
        EbpfEventKind::SocketWriteSampled => {
            event.socket_write = decode_socket_write_sample(payload);
        }
        EbpfEventKind::SocketReadSampled => {
            event.socket_read = decode_socket_read_sample(payload);
        }
        EbpfEventKind::LibsslPlaintextSampled => unreachable!("not a process probe kind"),
    }
    event
}

fn empty_process_probe_event(header: EbpfEventHeader, command: [u8; 16]) -> EbpfProcessProbeEvent {
    EbpfProcessProbeEvent {
        header,
        command,
        accept: EbpfAcceptObservation::unavailable(0, 0, 0),
        connect: EbpfConnectObservation::unavailable(0, 0),
        close: EbpfCloseObservation::observed(0, 0),
        close_range: EbpfCloseRangeObservation::observed(0, 0),
        socket_write: EbpfSocketWriteSample::new(0, 0, 0, 0, [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES]),
        socket_read: EbpfSocketReadSample::new(0, 0, 0, 0, [0; EBPF_SOCKET_READ_SAMPLE_BYTES]),
    }
}

fn decode_accept_observation(bytes: &[u8]) -> EbpfAcceptObservation {
    let mut remote_address = [0; 16];
    remote_address.copy_from_slice(&bytes[16..32]);
    EbpfAcceptObservation {
        fd: read_i32(bytes, 0),
        listen_fd: read_i32(bytes, 4),
        addrlen: read_u32(bytes, 8),
        address_family: read_u16(bytes, 12),
        remote_port: read_u16(bytes, 14),
        remote_address,
        fd_table_epoch: read_u64(bytes, 32),
        fd_generation: read_u64(bytes, 40),
    }
}

fn encode_accept_observation(bytes: &mut [u8], accept: EbpfAcceptObservation) {
    write_i32(bytes, 0, accept.fd);
    write_i32(bytes, 4, accept.listen_fd);
    write_u32(bytes, 8, accept.addrlen);
    write_u16(bytes, 12, accept.address_family);
    write_u16(bytes, 14, accept.remote_port);
    bytes[16..32].copy_from_slice(&accept.remote_address);
    write_u64(bytes, 32, accept.fd_table_epoch);
    write_u64(bytes, 40, accept.fd_generation);
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
        fd_generation: read_u64(bytes, 40),
    }
}

fn encode_connect_observation(bytes: &mut [u8], connect: EbpfConnectObservation) {
    write_i32(bytes, 0, connect.fd);
    write_u32(bytes, 4, connect.addrlen);
    write_u16(bytes, 8, connect.address_family);
    write_u16(bytes, 10, connect.remote_port);
    bytes[12..28].copy_from_slice(&connect.remote_address);
    write_u32(bytes, 28, 0);
    write_u64(bytes, 32, connect.fd_table_epoch);
    write_u64(bytes, 40, connect.fd_generation);
}

fn decode_close_observation(bytes: &[u8]) -> EbpfCloseObservation {
    EbpfCloseObservation {
        fd: read_i32(bytes, 0),
        reserved: read_u32(bytes, 4),
        fd_generation: read_u64(bytes, 8),
    }
}

fn encode_close_observation(bytes: &mut [u8], close: EbpfCloseObservation) {
    write_i32(bytes, 0, close.fd);
    write_u32(bytes, 4, close.reserved);
    write_u64(bytes, 8, close.fd_generation);
}

fn decode_close_range_observation(bytes: &[u8]) -> EbpfCloseRangeObservation {
    EbpfCloseRangeObservation {
        first_fd: read_u32(bytes, 0),
        last_fd: read_u32(bytes, 4),
        reserved: read_u32(bytes, 8),
    }
}

fn encode_close_range_observation(bytes: &mut [u8], close_range: EbpfCloseRangeObservation) {
    write_u32(bytes, 0, close_range.first_fd);
    write_u32(bytes, 4, close_range.last_fd);
    write_u32(bytes, 8, close_range.reserved);
}

fn decode_socket_write_sample(bytes: &[u8]) -> EbpfSocketWriteSample {
    let mut buffer = [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES];
    buffer.copy_from_slice(&bytes[24..24 + EBPF_SOCKET_WRITE_SAMPLE_BYTES]);
    EbpfSocketWriteSample {
        fd: read_i32(bytes, 0),
        original_len: read_u32(bytes, 4),
        fd_generation: read_u64(bytes, 8),
        captured_len: read_u16(bytes, 16),
        reserved: [
            bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ],
        buffer,
    }
}

fn encode_socket_write_sample(bytes: &mut [u8], sample: EbpfSocketWriteSample) {
    write_i32(bytes, 0, sample.fd);
    write_u32(bytes, 4, sample.original_len);
    write_u64(bytes, 8, sample.fd_generation);
    write_u16(bytes, 16, sample.captured_len);
    bytes[18..24].copy_from_slice(&sample.reserved);
    bytes[24..24 + EBPF_SOCKET_WRITE_SAMPLE_BYTES].copy_from_slice(&sample.buffer);
}

fn decode_socket_read_sample(bytes: &[u8]) -> EbpfSocketReadSample {
    let mut buffer = [0; EBPF_SOCKET_READ_SAMPLE_BYTES];
    buffer.copy_from_slice(&bytes[24..24 + EBPF_SOCKET_READ_SAMPLE_BYTES]);
    EbpfSocketReadSample {
        fd: read_i32(bytes, 0),
        original_len: read_u32(bytes, 4),
        fd_generation: read_u64(bytes, 8),
        captured_len: read_u16(bytes, 16),
        reserved: [
            bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ],
        buffer,
    }
}

fn encode_socket_read_sample(bytes: &mut [u8], sample: EbpfSocketReadSample) {
    write_i32(bytes, 0, sample.fd);
    write_u32(bytes, 4, sample.original_len);
    write_u64(bytes, 8, sample.fd_generation);
    write_u16(bytes, 16, sample.captured_len);
    bytes[18..24].copy_from_slice(&sample.reserved);
    bytes[24..24 + EBPF_SOCKET_READ_SAMPLE_BYTES].copy_from_slice(&sample.buffer);
}

fn validate_socket_write_sample(event: EbpfProcessProbeEvent) -> Result<(), EbpfEventDecodeError> {
    let Some(sample) = event.socket_write_sample() else {
        return Ok(());
    };
    let flags = event.header.flags;
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
        && event.header.flags
            & (EBPF_SOCKET_WRITE_TRUNCATED
                | EBPF_SOCKET_WRITE_READ_FAILED
                | EBPF_SOCKET_WRITE_KERNEL_TRANSFER)
            == 0
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
    if flags & EBPF_SOCKET_WRITE_KERNEL_TRANSFER != 0
        && flags & (EBPF_SOCKET_WRITE_TRUNCATED | EBPF_SOCKET_WRITE_READ_FAILED) != 0
    {
        return Err(EbpfEventDecodeError::InvalidSocketWriteKernelTransferFlags { flags });
    }
    if flags & EBPF_SOCKET_WRITE_KERNEL_TRANSFER != 0 && sample.captured_len > 0 {
        return Err(
            EbpfEventDecodeError::InvalidSocketWriteKernelTransferPayload {
                captured: sample.captured_len,
            },
        );
    }
    Ok(())
}

fn validate_socket_read_sample(event: EbpfProcessProbeEvent) -> Result<(), EbpfEventDecodeError> {
    let Some(sample) = event.socket_read_sample() else {
        return Ok(());
    };
    let captured = usize::from(sample.captured_len);
    if captured > EBPF_SOCKET_READ_SAMPLE_BYTES {
        return Err(EbpfEventDecodeError::InvalidSocketReadCapturedLength {
            captured: sample.captured_len,
            capacity: EBPF_SOCKET_READ_SAMPLE_BYTES,
        });
    }
    if u32::from(sample.captured_len) > sample.original_len {
        return Err(EbpfEventDecodeError::InvalidSocketReadOriginalLength {
            captured: sample.captured_len,
            original: sample.original_len,
        });
    }
    if u32::from(sample.captured_len) < sample.original_len
        && event.header.flags & (EBPF_SOCKET_READ_TRUNCATED | EBPF_SOCKET_READ_READ_FAILED) == 0
    {
        return Err(EbpfEventDecodeError::InvalidSocketReadIncompleteSample {
            captured: sample.captured_len,
            original: sample.original_len,
        });
    }
    if event.header.flags & EBPF_SOCKET_READ_READ_FAILED != 0 && sample.captured_len > 0 {
        return Err(EbpfEventDecodeError::InvalidSocketReadReadFailure {
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
        assert_eq!(size_of::<EbpfAcceptObservation>(), 48);
        assert_eq!(align_of::<EbpfAcceptObservation>(), 8);
        assert_eq!(size_of::<EbpfConnectObservation>(), 48);
        assert_eq!(align_of::<EbpfConnectObservation>(), 8);
        assert_eq!(size_of::<EbpfCloseObservation>(), 16);
        assert_eq!(align_of::<EbpfCloseObservation>(), 8);
        assert_eq!(size_of::<EbpfCloseRangeObservation>(), 12);
        assert_eq!(align_of::<EbpfCloseRangeObservation>(), 4);
        assert_eq!(size_of::<EbpfProcessLifecycleRecord>(), 48);
        assert_eq!(align_of::<EbpfProcessLifecycleRecord>(), 4);
        assert_eq!(
            size_of::<EbpfSocketWriteSample>(),
            24 + EBPF_SOCKET_WRITE_SAMPLE_BYTES
        );
        assert_eq!(align_of::<EbpfSocketWriteSample>(), 8);
        assert_eq!(
            size_of::<EbpfSocketReadSample>(),
            24 + EBPF_SOCKET_READ_SAMPLE_BYTES
        );
        assert_eq!(align_of::<EbpfSocketReadSample>(), 8);
        assert_eq!(size_of::<EbpfAcceptTracepointRecord>(), 96);
        assert_eq!(align_of::<EbpfAcceptTracepointRecord>(), 8);
        assert_eq!(size_of::<EbpfConnectTracepointRecord>(), 96);
        assert_eq!(align_of::<EbpfConnectTracepointRecord>(), 8);
        assert_eq!(size_of::<EbpfCloseTracepointRecord>(), 64);
        assert_eq!(align_of::<EbpfCloseTracepointRecord>(), 8);
        assert_eq!(size_of::<EbpfCloseRangeTracepointRecord>(), 60);
        assert_eq!(align_of::<EbpfCloseRangeTracepointRecord>(), 4);
        assert_eq!(
            size_of::<EbpfSocketWriteSampleRecord>(),
            48 + size_of::<EbpfSocketWriteSample>()
        );
        assert_eq!(align_of::<EbpfSocketWriteSampleRecord>(), 8);
        assert_eq!(
            size_of::<EbpfSocketReadSampleRecord>(),
            48 + size_of::<EbpfSocketReadSample>()
        );
        assert_eq!(align_of::<EbpfSocketReadSampleRecord>(), 8);
        assert_eq!(8 % align_of::<EbpfProcessLifecycleRecord>(), 0);
        assert_eq!(8 % align_of::<EbpfSocketWriteSampleRecord>(), 0);
        assert_eq!(8 % align_of::<EbpfSocketReadSampleRecord>(), 0);
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
        assert_eq!(offset_of!(EbpfAcceptObservation, fd), 0);
        assert_eq!(offset_of!(EbpfAcceptObservation, listen_fd), 4);
        assert_eq!(offset_of!(EbpfAcceptObservation, addrlen), 8);
        assert_eq!(offset_of!(EbpfAcceptObservation, address_family), 12);
        assert_eq!(offset_of!(EbpfAcceptObservation, remote_port), 14);
        assert_eq!(offset_of!(EbpfAcceptObservation, remote_address), 16);
        assert_eq!(offset_of!(EbpfAcceptObservation, fd_table_epoch), 32);
        assert_eq!(offset_of!(EbpfAcceptObservation, fd_generation), 40);
        assert_eq!(offset_of!(EbpfConnectObservation, fd), 0);
        assert_eq!(offset_of!(EbpfConnectObservation, addrlen), 4);
        assert_eq!(offset_of!(EbpfConnectObservation, address_family), 8);
        assert_eq!(offset_of!(EbpfConnectObservation, remote_port), 10);
        assert_eq!(offset_of!(EbpfConnectObservation, remote_address), 12);
        assert_eq!(offset_of!(EbpfConnectObservation, reserved), 28);
        assert_eq!(offset_of!(EbpfConnectObservation, fd_table_epoch), 32);
        assert_eq!(offset_of!(EbpfConnectObservation, fd_generation), 40);
        assert_eq!(offset_of!(EbpfCloseObservation, fd), 0);
        assert_eq!(offset_of!(EbpfCloseObservation, reserved), 4);
        assert_eq!(offset_of!(EbpfCloseObservation, fd_generation), 8);
        assert_eq!(offset_of!(EbpfCloseRangeObservation, first_fd), 0);
        assert_eq!(offset_of!(EbpfCloseRangeObservation, last_fd), 4);
        assert_eq!(offset_of!(EbpfCloseRangeObservation, reserved), 8);
        assert_eq!(offset_of!(EbpfSocketWriteSample, fd), 0);
        assert_eq!(offset_of!(EbpfSocketWriteSample, original_len), 4);
        assert_eq!(offset_of!(EbpfSocketWriteSample, fd_generation), 8);
        assert_eq!(offset_of!(EbpfSocketWriteSample, captured_len), 16);
        assert_eq!(offset_of!(EbpfSocketWriteSample, reserved), 18);
        assert_eq!(offset_of!(EbpfSocketWriteSample, buffer), 24);
        assert_eq!(offset_of!(EbpfSocketReadSample, fd), 0);
        assert_eq!(offset_of!(EbpfSocketReadSample, original_len), 4);
        assert_eq!(offset_of!(EbpfSocketReadSample, fd_generation), 8);
        assert_eq!(offset_of!(EbpfSocketReadSample, captured_len), 16);
        assert_eq!(offset_of!(EbpfSocketReadSample, reserved), 18);
        assert_eq!(offset_of!(EbpfSocketReadSample, buffer), 24);
        assert_eq!(offset_of!(EbpfAcceptTracepointRecord, header), 0);
        assert_eq!(offset_of!(EbpfAcceptTracepointRecord, command), 32);
        assert_eq!(offset_of!(EbpfAcceptTracepointRecord, accept), 48);
        assert_eq!(offset_of!(EbpfConnectTracepointRecord, header), 0);
        assert_eq!(offset_of!(EbpfConnectTracepointRecord, command), 32);
        assert_eq!(offset_of!(EbpfConnectTracepointRecord, connect), 48);
        assert_eq!(offset_of!(EbpfCloseTracepointRecord, header), 0);
        assert_eq!(offset_of!(EbpfCloseTracepointRecord, command), 32);
        assert_eq!(offset_of!(EbpfCloseTracepointRecord, close), 48);
        assert_eq!(offset_of!(EbpfCloseRangeTracepointRecord, header), 0);
        assert_eq!(offset_of!(EbpfCloseRangeTracepointRecord, command), 32);
        assert_eq!(offset_of!(EbpfCloseRangeTracepointRecord, close_range), 48);
        assert_eq!(offset_of!(EbpfProcessLifecycleRecord, header), 0);
        assert_eq!(offset_of!(EbpfProcessLifecycleRecord, command), 32);
        assert_eq!(offset_of!(EbpfSocketWriteSampleRecord, header), 0);
        assert_eq!(offset_of!(EbpfSocketWriteSampleRecord, command), 32);
        assert_eq!(offset_of!(EbpfSocketWriteSampleRecord, sample), 48);
        assert_eq!(offset_of!(EbpfSocketReadSampleRecord, header), 0);
        assert_eq!(offset_of!(EbpfSocketReadSampleRecord, command), 32);
        assert_eq!(offset_of!(EbpfSocketReadSampleRecord, sample), 48);
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
            .with_descriptor_lease(9, 10),
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
        assert_eq!(connect.fd_generation, 10);
        assert!(event.close_observation().is_none());
    }

    #[test]
    fn accept_tracepoint_observed_populates_header_fields() {
        let event = EbpfProcessProbeEvent::accept_tracepoint_observed(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            EbpfAcceptObservation::remote_endpoint(
                9,
                3,
                16,
                EBPF_ADDRESS_FAMILY_INET,
                50_000,
                [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            )
            .with_descriptor_lease(12, 13),
            EBPF_ACCEPT_REMOTE_ENDPOINT_VALID,
        );

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(
            event.header.kind(),
            Some(EbpfEventKind::AcceptTracepointObserved)
        );
        assert_eq!(
            usize::from(event.header.record_len),
            EBPF_ACCEPT_TRACEPOINT_RECORD_BYTES
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, EBPF_ACCEPT_REMOTE_ENDPOINT_VALID);
        let accept = event
            .accept_observation()
            .expect("accept event should expose accept payload");
        assert_eq!(accept.fd, 9);
        assert_eq!(accept.listen_fd, 3);
        assert_eq!(accept.addrlen, 16);
        assert_eq!(accept.address_family, EBPF_ADDRESS_FAMILY_INET);
        assert_eq!(accept.remote_port, 50_000);
        assert_eq!(accept.remote_address[0..4], [127, 0, 0, 1]);
        assert_eq!(accept.fd_table_epoch, 12);
        assert_eq!(accept.fd_generation, 13);
        assert!(event.connect_observation().is_none());
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
            EbpfCloseObservation::observed(7, 10),
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
        assert_eq!(close.fd_generation, 10);
        assert!(event.connect_observation().is_none());
    }

    #[test]
    fn close_range_tracepoint_observed_populates_header_fields() {
        let event = EbpfProcessProbeEvent::close_range_tracepoint_observed(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            EbpfCloseRangeObservation::observed(7, 11),
        );

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(
            event.header.kind(),
            Some(EbpfEventKind::CloseRangeTracepointObserved)
        );
        assert_eq!(
            usize::from(event.header.record_len),
            EBPF_CLOSE_RANGE_TRACEPOINT_RECORD_BYTES
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, 0);
        let close_range = event
            .close_range_observation()
            .expect("close_range event should expose close_range payload");
        assert_eq!(close_range.first_fd, 7);
        assert_eq!(close_range.last_fd, 11);
        assert_eq!(close_range.reserved, 0);
        assert!(event.connect_observation().is_none());
        assert!(event.accept_observation().is_none());
        assert!(event.close_observation().is_none());
    }

    #[test]
    fn process_exit_observed_populates_header_fields() {
        let event =
            EbpfProcessProbeEvent::process_exit_observed(11, 22, 33, 44, *b"0123456789abcdef");

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(
            event.header.kind(),
            Some(EbpfEventKind::ProcessExitObserved)
        );
        assert_eq!(
            usize::from(event.header.record_len),
            EBPF_PROCESS_LIFECYCLE_RECORD_BYTES
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, 0);
        assert!(event.connect_observation().is_none());
        assert!(event.accept_observation().is_none());
        assert!(event.close_observation().is_none());
        assert!(event.close_range_observation().is_none());
    }

    #[test]
    fn process_exec_observed_populates_header_fields() {
        let event =
            EbpfProcessProbeEvent::process_exec_observed(11, 22, 33, 44, *b"0123456789abcdef");

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(
            event.header.kind(),
            Some(EbpfEventKind::ProcessExecObserved)
        );
        assert_eq!(
            usize::from(event.header.record_len),
            EBPF_PROCESS_LIFECYCLE_RECORD_BYTES
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, 0);
        assert!(event.connect_observation().is_none());
        assert!(event.accept_observation().is_none());
        assert!(event.close_observation().is_none());
        assert!(event.close_range_observation().is_none());
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
        assert_eq!(sample.fd_generation, 10);
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
            EbpfSocketWriteSample::new(-1, 0, 0, 0, [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES]),
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
                fd_generation: 10,
                captured_len: 5,
            },
            0,
        );

        assert_eq!(event, expected);
    }

    #[test]
    fn socket_read_sampled_populates_header_fields() {
        let event = sample_read_event(5, 5, 0);

        assert_eq!(event.header.magic, EBPF_MAGIC);
        assert_eq!(event.header.abi_revision, EBPF_ABI_REVISION);
        assert_eq!(event.header.kind(), Some(EbpfEventKind::SocketReadSampled));
        assert_eq!(
            usize::from(event.header.record_len),
            EBPF_SOCKET_READ_SAMPLE_RECORD_BYTES
        );
        assert_eq!(event.header.pid, 11);
        assert_eq!(event.header.tgid, 22);
        assert_eq!(event.header.uid, 33);
        assert_eq!(event.header.gid, 44);
        assert_eq!(&event.command, b"0123456789abcdef");
        assert_eq!(event.header.flags, 0);
        let sample = event
            .socket_read_sample()
            .expect("read event should expose read sample");
        assert_eq!(sample.fd, 7);
        assert_eq!(sample.fd_generation, 10);
        assert_eq!(sample.original_len, 5);
        assert_eq!(sample.captured_len, 5);
        assert_eq!(&sample.buffer[..5], b"HTTP/");
        assert!(event.connect_observation().is_none());
        assert!(event.close_observation().is_none());
    }

    #[test]
    fn socket_read_sampled_metadata_can_be_overwritten_in_place() {
        let expected = sample_read_record(5, 5, 0);
        let mut event = EbpfSocketReadSampleRecord::socket_read_sampled(
            0,
            0,
            0,
            0,
            [0; 16],
            EbpfSocketReadSample::new(-1, 0, 0, 0, [0; EBPF_SOCKET_READ_SAMPLE_BYTES]),
            0,
        );
        event.clear_sample();
        event.socket_read_buffer_mut()[..5].copy_from_slice(b"HTTP/");
        event.overwrite_socket_read_sampled_metadata(
            EbpfProcessProbeMetadata {
                pid: 11,
                tgid: 22,
                uid: 33,
                gid: 44,
                command: *b"0123456789abcdef",
            },
            EbpfSocketReadMetadata {
                fd: 7,
                original_len: 5,
                fd_generation: 10,
                captured_len: 5,
            },
            0,
        );

        assert_eq!(event, expected);
    }

    #[test]
    fn process_event_decodes_from_wire_bytes() {
        for event in sample_process_events() {
            let decoded = match decode_process_probe_event(&encode_process_probe_event(&event)) {
                Ok(decoded) => decoded,
                Err(error) => panic!("event must decode: {error:?}"),
            };

            assert_eq!(decoded, event);
        }
    }

    fn sample_process_events() -> [EbpfProcessProbeEvent; 8] {
        [
            EbpfProcessProbeEvent::connect_tracepoint_observed(
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
                .with_descriptor_lease(1, 10),
                EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
            ),
            EbpfProcessProbeEvent::accept_tracepoint_observed(
                11,
                22,
                33,
                44,
                *b"0123456789abcdef",
                EbpfAcceptObservation::remote_endpoint(
                    9,
                    3,
                    16,
                    EBPF_ADDRESS_FAMILY_INET,
                    50_000,
                    [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                )
                .with_descriptor_lease(2, 11),
                EBPF_ACCEPT_REMOTE_ENDPOINT_VALID,
            ),
            EbpfProcessProbeEvent::close_tracepoint_observed(
                11,
                22,
                33,
                44,
                *b"0123456789abcdef",
                EbpfCloseObservation::observed(7, 10),
            ),
            EbpfProcessProbeEvent::close_range_tracepoint_observed(
                11,
                22,
                33,
                44,
                *b"0123456789abcdef",
                EbpfCloseRangeObservation::observed(7, 11),
            ),
            EbpfProcessProbeEvent::process_exit_observed(11, 22, 33, 44, *b"0123456789abcdef"),
            EbpfProcessProbeEvent::process_exec_observed(11, 22, 33, 44, *b"0123456789abcdef"),
            EbpfProcessProbeEvent::socket_write_sampled(
                11,
                22,
                33,
                44,
                *b"0123456789abcdef",
                EbpfSocketWriteSample::new(7, 10, 5, 5, write_sample_bytes(b"HTTP/")),
                EBPF_SOCKET_WRITE_TRUNCATED,
            ),
            EbpfProcessProbeEvent::socket_read_sampled(
                11,
                22,
                33,
                44,
                *b"0123456789abcdef",
                EbpfSocketReadSample::new(7, 10, 5, 5, read_sample_bytes(b"HTTP/")),
                EBPF_SOCKET_READ_TRUNCATED,
            ),
        ]
    }

    fn write_sample_bytes(prefix: &[u8]) -> [u8; EBPF_SOCKET_WRITE_SAMPLE_BYTES] {
        let mut bytes = [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes
    }

    fn read_sample_bytes(prefix: &[u8]) -> [u8; EBPF_SOCKET_READ_SAMPLE_BYTES] {
        let mut bytes = [0; EBPF_SOCKET_READ_SAMPLE_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes
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

        let error = match decode_process_probe_event(&encode_process_probe_event(
            &sample_write_event(5, 1, EBPF_SOCKET_WRITE_KERNEL_TRANSFER),
        )) {
            Ok(_) => panic!("kernel-transfer gap must not carry captured userspace bytes"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidSocketWriteKernelTransferPayload { captured: 1 }
        );

        let flags = EBPF_SOCKET_WRITE_KERNEL_TRANSFER | EBPF_SOCKET_WRITE_TRUNCATED;
        let error = match decode_process_probe_event(&encode_process_probe_event(
            &sample_write_event(5, 0, flags),
        )) {
            Ok(_) => panic!("kernel-transfer gap must not also be a truncated userspace sample"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidSocketWriteKernelTransferFlags { flags }
        );
    }

    #[test]
    fn process_event_rejects_invalid_read_sample_lengths() {
        let error = match decode_process_probe_event(&encode_process_probe_event(
            &sample_read_event(5, 6, 0),
        )) {
            Ok(_) => panic!("captured bytes beyond original read must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidSocketReadOriginalLength {
                captured: 6,
                original: 5
            }
        );

        let error = match decode_process_probe_event(&encode_process_probe_event(
            &sample_read_event(10, 5, 0),
        )) {
            Ok(_) => panic!("incomplete read sample without a gap flag must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidSocketReadIncompleteSample {
                captured: 5,
                original: 10
            }
        );

        let error = match decode_process_probe_event(&encode_process_probe_event(
            &sample_read_event(5, 1, EBPF_SOCKET_READ_READ_FAILED),
        )) {
            Ok(_) => panic!("read failure with captured bytes must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            EbpfEventDecodeError::InvalidSocketReadReadFailure { captured: 1 }
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
            EbpfSocketWriteSample::new(7, 10, original_len, captured_len, buffer),
            flags,
        )
    }

    fn sample_read_event(
        original_len: u32,
        captured_len: u16,
        flags: u16,
    ) -> EbpfProcessProbeEvent {
        sample_read_record(original_len, captured_len, flags).into()
    }

    fn sample_read_record(
        original_len: u32,
        captured_len: u16,
        flags: u16,
    ) -> EbpfSocketReadSampleRecord {
        let mut buffer = [0; EBPF_SOCKET_READ_SAMPLE_BYTES];
        buffer[..5].copy_from_slice(b"HTTP/");
        EbpfSocketReadSampleRecord::socket_read_sampled(
            11,
            22,
            33,
            44,
            *b"0123456789abcdef",
            EbpfSocketReadSample::new(7, 10, original_len, captured_len, buffer),
            flags,
        )
    }
}

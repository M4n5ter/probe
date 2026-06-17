use core::fmt;

use super::common::{EBPF_EVENTS_MAP_NAME, EbpfMapKind, EbpfMapSpec};
use crate::event::{
    EBPF_RING_BUFFER_BYTES, EBPF_SOCKET_WRITE_SAMPLE_BYTES, EbpfSocketReadSampleRecord,
    EbpfSocketWriteSampleRecord,
};

pub const EBPF_CONNECT_PROGRAM_NAME: &str = "sssa_sys_enter_connect";
pub const EBPF_CONNECT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_CONNECT_TRACEPOINT_NAME: &str = "sys_enter_connect";
pub const EBPF_CLOSE_PROGRAM_NAME: &str = "sssa_sys_enter_close";
pub const EBPF_CLOSE_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_CLOSE_TRACEPOINT_NAME: &str = "sys_enter_close";
pub const EBPF_DUP_PROGRAM_NAME: &str = "sssa_sys_enter_dup";
pub const EBPF_DUP_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_DUP_TRACEPOINT_NAME: &str = "sys_enter_dup";
pub const EBPF_DUP2_PROGRAM_NAME: &str = "sssa_sys_enter_dup2";
pub const EBPF_DUP2_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_DUP2_TRACEPOINT_NAME: &str = "sys_enter_dup2";
pub const EBPF_DUP3_PROGRAM_NAME: &str = "sssa_sys_enter_dup3";
pub const EBPF_DUP3_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_DUP3_TRACEPOINT_NAME: &str = "sys_enter_dup3";
pub const EBPF_FCNTL_PROGRAM_NAME: &str = "sssa_sys_enter_fcntl";
pub const EBPF_FCNTL_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_FCNTL_TRACEPOINT_NAME: &str = "sys_enter_fcntl";
pub const EBPF_CLOSE_RANGE_PROGRAM_NAME: &str = "sssa_sys_enter_close_range";
pub const EBPF_CLOSE_RANGE_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_CLOSE_RANGE_TRACEPOINT_NAME: &str = "sys_enter_close_range";
pub const EBPF_PROCESS_EXIT_PROGRAM_NAME: &str = "sssa_sched_process_exit";
pub const EBPF_PROCESS_EXIT_TRACEPOINT_CATEGORY: &str = "sched";
pub const EBPF_PROCESS_EXIT_TRACEPOINT_NAME: &str = "sched_process_exit";
pub const EBPF_PROCESS_EXEC_PROGRAM_NAME: &str = "sssa_sched_process_exec";
pub const EBPF_PROCESS_EXEC_TRACEPOINT_CATEGORY: &str = "sched";
pub const EBPF_PROCESS_EXEC_TRACEPOINT_NAME: &str = "sched_process_exec";
pub const EBPF_WRITE_ENTER_PROGRAM_NAME: &str = "sssa_sys_enter_write";
pub const EBPF_WRITE_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_WRITE_ENTER_TRACEPOINT_NAME: &str = "sys_enter_write";
pub const EBPF_WRITE_EXIT_PROGRAM_NAME: &str = "sssa_sys_exit_write";
pub const EBPF_WRITE_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_WRITE_EXIT_TRACEPOINT_NAME: &str = "sys_exit_write";
pub const EBPF_SENDTO_ENTER_PROGRAM_NAME: &str = "sssa_sys_enter_sendto";
pub const EBPF_SENDTO_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDTO_ENTER_TRACEPOINT_NAME: &str = "sys_enter_sendto";
pub const EBPF_SENDTO_EXIT_PROGRAM_NAME: &str = "sssa_sys_exit_sendto";
pub const EBPF_SENDTO_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDTO_EXIT_TRACEPOINT_NAME: &str = "sys_exit_sendto";
pub const EBPF_READ_ENTER_PROGRAM_NAME: &str = "sssa_sys_enter_read";
pub const EBPF_READ_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_READ_ENTER_TRACEPOINT_NAME: &str = "sys_enter_read";
pub const EBPF_READ_EXIT_PROGRAM_NAME: &str = "sssa_sys_exit_read";
pub const EBPF_READ_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_READ_EXIT_TRACEPOINT_NAME: &str = "sys_exit_read";
pub const EBPF_RECVFROM_ENTER_PROGRAM_NAME: &str = "sssa_sys_enter_recvfrom";
pub const EBPF_RECVFROM_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_RECVFROM_ENTER_TRACEPOINT_NAME: &str = "sys_enter_recvfrom";
pub const EBPF_RECVFROM_EXIT_PROGRAM_NAME: &str = "sssa_sys_exit_recvfrom";
pub const EBPF_RECVFROM_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_RECVFROM_EXIT_TRACEPOINT_NAME: &str = "sys_exit_recvfrom";
pub const EBPF_ALLOWED_SOCKET_FDS_MAP_NAME: &str = "SSSA_ALLOWED_SOCKET_FDS";
pub const EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_ALLOWED_SOCKET_FD_KEY_BYTES: u32 = core::mem::size_of::<EbpfSocketFdKey>() as u32;
pub const EBPF_ALLOWED_SOCKET_FD_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfSocketPayloadAllowance>() as u32;
pub const EBPF_SOCKET_PAYLOAD_ALLOW_WRITE: u8 = 1 << 0;
pub const EBPF_SOCKET_PAYLOAD_ALLOW_READ: u8 = 1 << 1;
pub const EBPF_FD_TABLE_EPOCHS_MAP_NAME: &str = "SSSA_FD_TABLE_EPOCHS";
pub const EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_FD_TABLE_EPOCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_FD_TABLE_EPOCH_VALUE_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_WRITES_MAP_NAME: &str = "SSSA_PENDING_WRITES";
pub const EBPF_PENDING_WRITES_MAX_ENTRIES: u32 = 8192;
pub const EBPF_PENDING_WRITE_KEY_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_WRITE_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfPendingSocketWriteSample>() as u32;
pub const EBPF_PENDING_WRITE_SCRATCH_MAP_NAME: &str = "SSSA_PENDING_WRITE_SCRATCH";
pub const EBPF_PENDING_WRITE_SCRATCH_MAX_ENTRIES: u32 = 1;
pub const EBPF_PENDING_WRITE_SCRATCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PENDING_WRITE_SCRATCH_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfPendingSocketWriteSample>() as u32;
pub const EBPF_PENDING_READS_MAP_NAME: &str = "SSSA_PENDING_READS";
pub const EBPF_PENDING_READS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_PENDING_READ_KEY_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_READ_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfPendingSocketReadAttempt>() as u32;
pub const EBPF_PROCESS_EVENT_SCRATCH_MAP_NAME: &str = "SSSA_PROCESS_EVENT_SCRATCH";
pub const EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES: u32 = 1;
pub const EBPF_PROCESS_EVENT_SCRATCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PROCESS_EVENT_SCRATCH_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfSocketWriteSampleRecord>() as u32;
pub const EBPF_PROCESS_READ_EVENT_SCRATCH_MAP_NAME: &str = "SSSA_PROCESS_READ_EVENT_SCRATCH";
pub const EBPF_PROCESS_READ_EVENT_SCRATCH_MAX_ENTRIES: u32 = 1;
pub const EBPF_PROCESS_READ_EVENT_SCRATCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PROCESS_READ_EVENT_SCRATCH_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfSocketReadSampleRecord>() as u32;

pub const EBPF_PROCESS_TRACEPOINT_SPECS: [EbpfProcessTracepointSpec; 17] = [
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::ConnectEnter,
        program_name: EBPF_CONNECT_PROGRAM_NAME,
        category: EBPF_CONNECT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_CONNECT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::CloseEnter,
        program_name: EBPF_CLOSE_PROGRAM_NAME,
        category: EBPF_CLOSE_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_CLOSE_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::DupEnter,
        program_name: EBPF_DUP_PROGRAM_NAME,
        category: EBPF_DUP_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_DUP_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::Dup2Enter,
        program_name: EBPF_DUP2_PROGRAM_NAME,
        category: EBPF_DUP2_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_DUP2_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::Dup3Enter,
        program_name: EBPF_DUP3_PROGRAM_NAME,
        category: EBPF_DUP3_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_DUP3_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::FcntlEnter,
        program_name: EBPF_FCNTL_PROGRAM_NAME,
        category: EBPF_FCNTL_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_FCNTL_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::CloseRangeEnter,
        program_name: EBPF_CLOSE_RANGE_PROGRAM_NAME,
        category: EBPF_CLOSE_RANGE_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_CLOSE_RANGE_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::ProcessExit,
        program_name: EBPF_PROCESS_EXIT_PROGRAM_NAME,
        category: EBPF_PROCESS_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_PROCESS_EXIT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::ProcessExec,
        program_name: EBPF_PROCESS_EXEC_PROGRAM_NAME,
        category: EBPF_PROCESS_EXEC_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_PROCESS_EXEC_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::WriteEnter,
        program_name: EBPF_WRITE_ENTER_PROGRAM_NAME,
        category: EBPF_WRITE_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_WRITE_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::WriteExit,
        program_name: EBPF_WRITE_EXIT_PROGRAM_NAME,
        category: EBPF_WRITE_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_WRITE_EXIT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::SendtoEnter,
        program_name: EBPF_SENDTO_ENTER_PROGRAM_NAME,
        category: EBPF_SENDTO_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_SENDTO_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::SendtoExit,
        program_name: EBPF_SENDTO_EXIT_PROGRAM_NAME,
        category: EBPF_SENDTO_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_SENDTO_EXIT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::ReadEnter,
        program_name: EBPF_READ_ENTER_PROGRAM_NAME,
        category: EBPF_READ_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_READ_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::ReadExit,
        program_name: EBPF_READ_EXIT_PROGRAM_NAME,
        category: EBPF_READ_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_READ_EXIT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::RecvfromEnter,
        program_name: EBPF_RECVFROM_ENTER_PROGRAM_NAME,
        category: EBPF_RECVFROM_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_RECVFROM_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::RecvfromExit,
        program_name: EBPF_RECVFROM_EXIT_PROGRAM_NAME,
        category: EBPF_RECVFROM_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_RECVFROM_EXIT_TRACEPOINT_NAME,
    },
];

pub const EBPF_PROCESS_MAP_SPECS: [EbpfMapSpec; 8] = [
    EbpfMapSpec {
        name: EBPF_EVENTS_MAP_NAME,
        kind: EbpfMapKind::Ringbuf,
        key_size: 0,
        value_size: 0,
        max_entries: EBPF_RING_BUFFER_BYTES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_ALLOWED_SOCKET_FDS_MAP_NAME,
        kind: EbpfMapKind::LruHash,
        key_size: EBPF_ALLOWED_SOCKET_FD_KEY_BYTES,
        value_size: EBPF_ALLOWED_SOCKET_FD_VALUE_BYTES,
        max_entries: EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_FD_TABLE_EPOCHS_MAP_NAME,
        kind: EbpfMapKind::Hash,
        key_size: EBPF_FD_TABLE_EPOCH_KEY_BYTES,
        value_size: EBPF_FD_TABLE_EPOCH_VALUE_BYTES,
        max_entries: EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PENDING_WRITES_MAP_NAME,
        kind: EbpfMapKind::Hash,
        key_size: EBPF_PENDING_WRITE_KEY_BYTES,
        value_size: EBPF_PENDING_WRITE_VALUE_BYTES,
        max_entries: EBPF_PENDING_WRITES_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PENDING_WRITE_SCRATCH_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: EBPF_PENDING_WRITE_SCRATCH_KEY_BYTES,
        value_size: EBPF_PENDING_WRITE_SCRATCH_VALUE_BYTES,
        max_entries: EBPF_PENDING_WRITE_SCRATCH_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PENDING_READS_MAP_NAME,
        kind: EbpfMapKind::Hash,
        key_size: EBPF_PENDING_READ_KEY_BYTES,
        value_size: EBPF_PENDING_READ_VALUE_BYTES,
        max_entries: EBPF_PENDING_READS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PROCESS_EVENT_SCRATCH_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: EBPF_PROCESS_EVENT_SCRATCH_KEY_BYTES,
        value_size: EBPF_PROCESS_EVENT_SCRATCH_VALUE_BYTES,
        max_entries: EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PROCESS_READ_EVENT_SCRATCH_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: EBPF_PROCESS_READ_EVENT_SCRATCH_KEY_BYTES,
        value_size: EBPF_PROCESS_READ_EVENT_SCRATCH_VALUE_BYTES,
        max_entries: EBPF_PROCESS_READ_EVENT_SCRATCH_MAX_ENTRIES,
        map_flags: 0,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessTracepointSpec {
    pub role: EbpfProcessTracepointRole,
    pub program_name: &'static str,
    pub category: &'static str,
    pub tracepoint_name: &'static str,
}

impl EbpfProcessTracepointSpec {
    pub const fn section_name(self) -> EbpfTracepointSectionName {
        EbpfTracepointSectionName {
            category: self.category,
            tracepoint_name: self.tracepoint_name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfTracepointSectionName {
    category: &'static str,
    tracepoint_name: &'static str,
}

impl fmt::Display for EbpfTracepointSectionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tracepoint/{}/{}",
            self.category, self.tracepoint_name
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EbpfProcessTracepointRole {
    ConnectEnter,
    CloseEnter,
    DupEnter,
    Dup2Enter,
    Dup3Enter,
    FcntlEnter,
    CloseRangeEnter,
    ProcessExit,
    ProcessExec,
    WriteEnter,
    WriteExit,
    SendtoEnter,
    SendtoExit,
    ReadEnter,
    ReadExit,
    RecvfromEnter,
    RecvfromExit,
}

impl EbpfProcessTracepointRole {
    pub fn spec(self) -> &'static EbpfProcessTracepointSpec {
        EBPF_PROCESS_TRACEPOINT_SPECS
            .iter()
            .find(|spec| spec.role == self)
            .expect("process tracepoint role should be listed in the canonical spec table")
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfSocketFdKey {
    pub tgid: u32,
    pub fd: i32,
}

impl EbpfSocketFdKey {
    pub const fn new(tgid: u32, fd: i32) -> Self {
        Self { tgid, fd }
    }

    pub fn to_bpfel_bytes(self) -> [u8; core::mem::size_of::<Self>()] {
        let tgid = self.tgid.to_le_bytes();
        let fd = self.fd.to_le_bytes();
        [
            tgid[0], tgid[1], tgid[2], tgid[3], fd[0], fd[1], fd[2], fd[3],
        ]
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfSocketPayloadAllowance {
    pub fd_table_epoch: u64,
    pub direction_mask: u8,
    pub _reserved: [u8; 7],
}

impl EbpfSocketPayloadAllowance {
    pub const fn new(fd_table_epoch: u64, direction_mask: u8) -> Self {
        Self {
            fd_table_epoch,
            direction_mask,
            _reserved: [0; 7],
        }
    }

    pub fn to_bpfel_bytes(self) -> [u8; core::mem::size_of::<Self>()] {
        let epoch = self.fd_table_epoch.to_le_bytes();
        [
            epoch[0],
            epoch[1],
            epoch[2],
            epoch[3],
            epoch[4],
            epoch[5],
            epoch[6],
            epoch[7],
            self.direction_mask,
            self._reserved[0],
            self._reserved[1],
            self._reserved[2],
            self._reserved[3],
            self._reserved[4],
            self._reserved[5],
            self._reserved[6],
        ]
    }

    pub fn allows(self, direction: u8) -> bool {
        self.direction_mask & direction != 0
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfPendingSocketWriteSample {
    pub fd: i32,
    pub original_len: u32,
    pub captured_len: u16,
    pub flags: u16,
    pub buffer: [u8; EBPF_SOCKET_WRITE_SAMPLE_BYTES],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfPendingSocketReadAttempt {
    pub fd: i32,
    pub requested_len: u32,
    pub user_buffer: u64,
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};
    use std::{collections::BTreeSet, string::ToString};

    use super::*;

    #[test]
    fn process_map_specs_are_unique_and_layout_complete() {
        assert_eq!(EBPF_PROCESS_MAP_SPECS.len(), 8);
        assert_unique(EBPF_PROCESS_MAP_SPECS.map(|spec| spec.name));

        let allow_map = process_map(EBPF_ALLOWED_SOCKET_FDS_MAP_NAME);
        assert_eq!(allow_map.kind, EbpfMapKind::LruHash);
        assert_eq!(allow_map.key_size, EBPF_ALLOWED_SOCKET_FD_KEY_BYTES);
        assert_eq!(allow_map.value_size, EBPF_ALLOWED_SOCKET_FD_VALUE_BYTES);

        let epoch_map = process_map(EBPF_FD_TABLE_EPOCHS_MAP_NAME);
        assert_eq!(epoch_map.kind, EbpfMapKind::Hash);
        assert_eq!(epoch_map.key_size, EBPF_FD_TABLE_EPOCH_KEY_BYTES);
        assert_eq!(epoch_map.value_size, EBPF_FD_TABLE_EPOCH_VALUE_BYTES);

        let pending_map = process_map(EBPF_PENDING_WRITES_MAP_NAME);
        assert_eq!(pending_map.kind, EbpfMapKind::Hash);
        assert_eq!(
            pending_map.value_size,
            size_of::<EbpfPendingSocketWriteSample>() as u32
        );

        let pending_scratch = process_map(EBPF_PENDING_WRITE_SCRATCH_MAP_NAME);
        assert_eq!(pending_scratch.kind, EbpfMapKind::PerCpuArray);
        assert_eq!(
            pending_scratch.value_size,
            size_of::<EbpfPendingSocketWriteSample>() as u32
        );

        let pending_reads = process_map(EBPF_PENDING_READS_MAP_NAME);
        assert_eq!(pending_reads.kind, EbpfMapKind::Hash);
        assert_eq!(
            pending_reads.value_size,
            size_of::<EbpfPendingSocketReadAttempt>() as u32
        );

        let read_scratch = process_map(EBPF_PROCESS_READ_EVENT_SCRATCH_MAP_NAME);
        assert_eq!(read_scratch.kind, EbpfMapKind::PerCpuArray);
        assert_eq!(
            read_scratch.value_size,
            size_of::<EbpfSocketReadSampleRecord>() as u32
        );

        assert_eq!(
            EbpfSocketFdKey::new(0x0102_0304, -2).to_bpfel_bytes(),
            [0x04, 0x03, 0x02, 0x01, 0xfe, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            EbpfSocketPayloadAllowance::new(0x0102_0304_0506_0708, EBPF_SOCKET_PAYLOAD_ALLOW_READ)
                .to_bpfel_bytes(),
            [
                0x08,
                0x07,
                0x06,
                0x05,
                0x04,
                0x03,
                0x02,
                0x01,
                EBPF_SOCKET_PAYLOAD_ALLOW_READ,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]
        );
    }

    #[test]
    fn process_tracepoint_specs_are_complete() {
        assert_eq!(EBPF_PROCESS_TRACEPOINT_SPECS.len(), 17);
        assert_unique(EBPF_PROCESS_TRACEPOINT_SPECS.map(|spec| spec.program_name));
        assert_unique(EBPF_PROCESS_TRACEPOINT_SPECS.map(|spec| spec.tracepoint_name));

        for spec in EBPF_PROCESS_TRACEPOINT_SPECS {
            assert_eq!(spec.role.spec(), &spec);
            assert_eq!(
                spec.section_name().to_string(),
                std::format!("tracepoint/{}/{}", spec.category, spec.tracepoint_name)
            );
        }
    }

    #[test]
    fn pending_socket_write_sample_layout_is_stable() {
        assert_eq!(size_of::<EbpfPendingSocketWriteSample>(), 268);
        assert_eq!(align_of::<EbpfPendingSocketWriteSample>(), 4);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, fd), 0);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, original_len), 4);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, captured_len), 8);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, flags), 10);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, buffer), 12);
    }

    #[test]
    fn socket_payload_allowance_layout_is_stable() {
        assert_eq!(size_of::<EbpfSocketPayloadAllowance>(), 16);
        assert_eq!(align_of::<EbpfSocketPayloadAllowance>(), 8);
        assert_eq!(offset_of!(EbpfSocketPayloadAllowance, fd_table_epoch), 0);
        assert_eq!(offset_of!(EbpfSocketPayloadAllowance, direction_mask), 8);
        assert_eq!(offset_of!(EbpfSocketPayloadAllowance, _reserved), 9);
        let allowance = EbpfSocketPayloadAllowance::new(
            9,
            EBPF_SOCKET_PAYLOAD_ALLOW_READ | EBPF_SOCKET_PAYLOAD_ALLOW_WRITE,
        );
        assert!(allowance.allows(EBPF_SOCKET_PAYLOAD_ALLOW_READ));
        assert!(allowance.allows(EBPF_SOCKET_PAYLOAD_ALLOW_WRITE));
        assert!(!allowance.allows(1 << 7));
    }

    #[test]
    fn pending_socket_read_attempt_layout_is_stable() {
        assert_eq!(size_of::<EbpfPendingSocketReadAttempt>(), 16);
        assert_eq!(align_of::<EbpfPendingSocketReadAttempt>(), 8);
        assert_eq!(offset_of!(EbpfPendingSocketReadAttempt, fd), 0);
        assert_eq!(offset_of!(EbpfPendingSocketReadAttempt, requested_len), 4);
        assert_eq!(offset_of!(EbpfPendingSocketReadAttempt, user_buffer), 8);
    }

    fn process_map(name: &'static str) -> EbpfMapSpec {
        *EBPF_PROCESS_MAP_SPECS
            .iter()
            .find(|spec| spec.name == name)
            .expect("process map should exist")
    }

    fn assert_unique(values: impl IntoIterator<Item = &'static str>) {
        let mut seen = BTreeSet::new();
        for value in values {
            assert!(seen.insert(value), "duplicate value: {value}");
        }
    }
}

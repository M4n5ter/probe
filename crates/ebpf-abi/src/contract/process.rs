use core::fmt;

use super::common::{EBPF_EVENTS_MAP_NAME, EbpfMapKind, EbpfMapSpec};
use crate::event::{EBPF_RING_BUFFER_BYTES, EbpfSocketWriteSampleRecord};

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
pub const EBPF_WRITE_ENTER_PROGRAM_NAME: &str = "sssa_sys_enter_write";
pub const EBPF_WRITE_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_WRITE_ENTER_TRACEPOINT_NAME: &str = "sys_enter_write";
pub const EBPF_WRITE_EXIT_PROGRAM_NAME: &str = "sssa_sys_exit_write";
pub const EBPF_WRITE_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_WRITE_EXIT_TRACEPOINT_NAME: &str = "sys_exit_write";
pub const EBPF_ALLOWED_SOCKET_FDS_MAP_NAME: &str = "SSSA_ALLOWED_SOCKET_FDS";
pub const EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_ALLOWED_SOCKET_FD_KEY_BYTES: u32 = core::mem::size_of::<EbpfSocketFdKey>() as u32;
pub const EBPF_ALLOWED_SOCKET_FD_VALUE_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_FD_TABLE_EPOCHS_MAP_NAME: &str = "SSSA_FD_TABLE_EPOCHS";
pub const EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_FD_TABLE_EPOCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_FD_TABLE_EPOCH_VALUE_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_WRITES_MAP_NAME: &str = "SSSA_PENDING_WRITES";
pub const EBPF_PENDING_WRITES_MAX_ENTRIES: u32 = 8192;
pub const EBPF_PENDING_WRITE_KEY_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_WRITE_VALUE_BYTES: u32 = core::mem::size_of::<EbpfPendingWrite>() as u32;
pub const EBPF_PROCESS_EVENT_SCRATCH_MAP_NAME: &str = "SSSA_PROCESS_EVENT_SCRATCH";
pub const EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES: u32 = 1;
pub const EBPF_PROCESS_EVENT_SCRATCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PROCESS_EVENT_SCRATCH_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfSocketWriteSampleRecord>() as u32;

pub const EBPF_PROCESS_TRACEPOINT_SPECS: [EbpfProcessTracepointSpec; 10] = [
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
];

pub const EBPF_PROCESS_MAP_SPECS: [EbpfMapSpec; 5] = [
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
        name: EBPF_PROCESS_EVENT_SCRATCH_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: EBPF_PROCESS_EVENT_SCRATCH_KEY_BYTES,
        value_size: EBPF_PROCESS_EVENT_SCRATCH_VALUE_BYTES,
        max_entries: EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES,
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
    WriteEnter,
    WriteExit,
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
    pub pid: u32,
    pub fd: i32,
}

impl EbpfSocketFdKey {
    pub const fn new(pid: u32, fd: i32) -> Self {
        Self { pid, fd }
    }

    pub fn to_bpfel_bytes(self) -> [u8; core::mem::size_of::<Self>()] {
        let pid = self.pid.to_le_bytes();
        let fd = self.fd.to_le_bytes();
        [pid[0], pid[1], pid[2], pid[3], fd[0], fd[1], fd[2], fd[3]]
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfPendingWrite {
    pub fd: i32,
    pub reserved: u32,
    pub user_buffer: u64,
    pub requested_len: u64,
}

impl EbpfPendingWrite {
    pub const fn new(fd: i32, user_buffer: u64, requested_len: u64) -> Self {
        Self {
            fd,
            reserved: 0,
            user_buffer,
            requested_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, string::ToString};

    use super::*;

    #[test]
    fn process_map_specs_are_unique_and_layout_complete() {
        assert_eq!(EBPF_PROCESS_MAP_SPECS.len(), 5);
        assert_unique(EBPF_PROCESS_MAP_SPECS.map(|spec| spec.name));

        let allow_map = process_map(EBPF_ALLOWED_SOCKET_FDS_MAP_NAME);
        assert_eq!(allow_map.kind, EbpfMapKind::LruHash);
        assert_eq!(allow_map.key_size, EBPF_ALLOWED_SOCKET_FD_KEY_BYTES);
        assert_eq!(allow_map.value_size, EBPF_ALLOWED_SOCKET_FD_VALUE_BYTES);

        let epoch_map = process_map(EBPF_FD_TABLE_EPOCHS_MAP_NAME);
        assert_eq!(epoch_map.kind, EbpfMapKind::Hash);
        assert_eq!(epoch_map.key_size, EBPF_FD_TABLE_EPOCH_KEY_BYTES);
        assert_eq!(epoch_map.value_size, EBPF_FD_TABLE_EPOCH_VALUE_BYTES);

        assert_eq!(
            EbpfSocketFdKey::new(0x0102_0304, -2).to_bpfel_bytes(),
            [0x04, 0x03, 0x02, 0x01, 0xfe, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn process_tracepoint_specs_are_complete() {
        assert_eq!(EBPF_PROCESS_TRACEPOINT_SPECS.len(), 10);
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

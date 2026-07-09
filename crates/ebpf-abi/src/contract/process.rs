use core::fmt;

use super::common::{EBPF_EVENTS_MAP_NAME, EbpfMapKind, EbpfMapSpec};
use crate::event::{
    EBPF_RING_BUFFER_BYTES, EBPF_SOCKET_WRITE_SAMPLE_BYTES, EbpfConnectObservation,
    EbpfSocketReadSampleRecord, EbpfSocketWriteSampleRecord,
};

pub const EBPF_CONNECT_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_connect";
pub const EBPF_CONNECT_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_CONNECT_ENTER_TRACEPOINT_NAME: &str = "sys_enter_connect";
pub const EBPF_CONNECT_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_connect";
pub const EBPF_CONNECT_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_CONNECT_EXIT_TRACEPOINT_NAME: &str = "sys_exit_connect";
pub const EBPF_ACCEPT_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_accept";
pub const EBPF_ACCEPT_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_ACCEPT_ENTER_TRACEPOINT_NAME: &str = "sys_enter_accept";
pub const EBPF_ACCEPT_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_accept";
pub const EBPF_ACCEPT_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_ACCEPT_EXIT_TRACEPOINT_NAME: &str = "sys_exit_accept";
pub const EBPF_ACCEPT4_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_accept4";
pub const EBPF_ACCEPT4_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_ACCEPT4_ENTER_TRACEPOINT_NAME: &str = "sys_enter_accept4";
pub const EBPF_ACCEPT4_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_accept4";
pub const EBPF_ACCEPT4_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_ACCEPT4_EXIT_TRACEPOINT_NAME: &str = "sys_exit_accept4";
pub const EBPF_CLOSE_PROGRAM_NAME: &str = "traffic_probe_sys_enter_close";
pub const EBPF_CLOSE_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_CLOSE_TRACEPOINT_NAME: &str = "sys_enter_close";
pub const EBPF_DUP_PROGRAM_NAME: &str = "traffic_probe_sys_enter_dup";
pub const EBPF_DUP_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_DUP_TRACEPOINT_NAME: &str = "sys_enter_dup";
pub const EBPF_DUP2_PROGRAM_NAME: &str = "traffic_probe_sys_enter_dup2";
pub const EBPF_DUP2_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_DUP2_TRACEPOINT_NAME: &str = "sys_enter_dup2";
pub const EBPF_DUP3_PROGRAM_NAME: &str = "traffic_probe_sys_enter_dup3";
pub const EBPF_DUP3_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_DUP3_TRACEPOINT_NAME: &str = "sys_enter_dup3";
pub const EBPF_FCNTL_PROGRAM_NAME: &str = "traffic_probe_sys_enter_fcntl";
pub const EBPF_FCNTL_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_FCNTL_TRACEPOINT_NAME: &str = "sys_enter_fcntl";
pub const EBPF_CLOSE_RANGE_PROGRAM_NAME: &str = "traffic_probe_sys_enter_close_range";
pub const EBPF_CLOSE_RANGE_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_CLOSE_RANGE_TRACEPOINT_NAME: &str = "sys_enter_close_range";
pub const EBPF_PROCESS_EXIT_PROGRAM_NAME: &str = "traffic_probe_sched_process_exit";
pub const EBPF_PROCESS_EXIT_TRACEPOINT_CATEGORY: &str = "sched";
pub const EBPF_PROCESS_EXIT_TRACEPOINT_NAME: &str = "sched_process_exit";
pub const EBPF_PROCESS_EXEC_PROGRAM_NAME: &str = "traffic_probe_sched_process_exec";
pub const EBPF_PROCESS_EXEC_TRACEPOINT_CATEGORY: &str = "sched";
pub const EBPF_PROCESS_EXEC_TRACEPOINT_NAME: &str = "sched_process_exec";
pub const EBPF_WRITE_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_write";
pub const EBPF_WRITE_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_WRITE_ENTER_TRACEPOINT_NAME: &str = "sys_enter_write";
pub const EBPF_WRITE_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_write";
pub const EBPF_WRITE_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_WRITE_EXIT_TRACEPOINT_NAME: &str = "sys_exit_write";
pub const EBPF_WRITEV_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_writev";
pub const EBPF_WRITEV_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_WRITEV_ENTER_TRACEPOINT_NAME: &str = "sys_enter_writev";
pub const EBPF_WRITEV_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_writev";
pub const EBPF_WRITEV_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_WRITEV_EXIT_TRACEPOINT_NAME: &str = "sys_exit_writev";
pub const EBPF_SENDTO_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_sendto";
pub const EBPF_SENDTO_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDTO_ENTER_TRACEPOINT_NAME: &str = "sys_enter_sendto";
pub const EBPF_SENDTO_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_sendto";
pub const EBPF_SENDTO_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDTO_EXIT_TRACEPOINT_NAME: &str = "sys_exit_sendto";
pub const EBPF_SENDMSG_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_sendmsg";
pub const EBPF_SENDMSG_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDMSG_ENTER_TRACEPOINT_NAME: &str = "sys_enter_sendmsg";
pub const EBPF_SENDMSG_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_sendmsg";
pub const EBPF_SENDMSG_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDMSG_EXIT_TRACEPOINT_NAME: &str = "sys_exit_sendmsg";
pub const EBPF_SENDFILE_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_sendfile";
pub const EBPF_SENDFILE_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDFILE_ENTER_TRACEPOINT_NAME: &str = "sys_enter_sendfile";
pub const EBPF_SENDFILE_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_sendfile";
pub const EBPF_SENDFILE_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDFILE_EXIT_TRACEPOINT_NAME: &str = "sys_exit_sendfile";
pub const EBPF_SENDFILE64_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_sendfile64";
pub const EBPF_SENDFILE64_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDFILE64_ENTER_TRACEPOINT_NAME: &str = "sys_enter_sendfile64";
pub const EBPF_SENDFILE64_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_sendfile64";
pub const EBPF_SENDFILE64_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_SENDFILE64_EXIT_TRACEPOINT_NAME: &str = "sys_exit_sendfile64";
pub const EBPF_READ_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_read";
pub const EBPF_READ_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_READ_ENTER_TRACEPOINT_NAME: &str = "sys_enter_read";
pub const EBPF_READ_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_read";
pub const EBPF_READ_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_READ_EXIT_TRACEPOINT_NAME: &str = "sys_exit_read";
pub const EBPF_READV_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_readv";
pub const EBPF_READV_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_READV_ENTER_TRACEPOINT_NAME: &str = "sys_enter_readv";
pub const EBPF_READV_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_readv";
pub const EBPF_READV_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_READV_EXIT_TRACEPOINT_NAME: &str = "sys_exit_readv";
pub const EBPF_RECVFROM_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_recvfrom";
pub const EBPF_RECVFROM_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_RECVFROM_ENTER_TRACEPOINT_NAME: &str = "sys_enter_recvfrom";
pub const EBPF_RECVFROM_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_recvfrom";
pub const EBPF_RECVFROM_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_RECVFROM_EXIT_TRACEPOINT_NAME: &str = "sys_exit_recvfrom";
pub const EBPF_RECVMSG_ENTER_PROGRAM_NAME: &str = "traffic_probe_sys_enter_recvmsg";
pub const EBPF_RECVMSG_ENTER_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_RECVMSG_ENTER_TRACEPOINT_NAME: &str = "sys_enter_recvmsg";
pub const EBPF_RECVMSG_EXIT_PROGRAM_NAME: &str = "traffic_probe_sys_exit_recvmsg";
pub const EBPF_RECVMSG_EXIT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const EBPF_RECVMSG_EXIT_TRACEPOINT_NAME: &str = "sys_exit_recvmsg";
pub const EBPF_ALLOWED_SOCKET_FDS_MAP_NAME: &str = "TRAFFIC_PROBE_ALLOWED_SOCKET_FDS";
pub const EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_ALLOWED_SOCKET_FD_KEY_BYTES: u32 = core::mem::size_of::<EbpfSocketFdKey>() as u32;
pub const EBPF_ALLOWED_SOCKET_FD_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfSocketPayloadAllowance>() as u32;
pub const EBPF_ALLOWED_PROCESS_TGIDS_MAP_NAME: &str = "TRAFFIC_PROBE_ALLOWED_PROCESS_TGIDS";
pub const EBPF_ALLOWED_PROCESS_TGIDS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_ALLOWED_PROCESS_TGID_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_ALLOWED_PROCESS_TGID_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfProcessPayloadAllowance>() as u32;
pub const EBPF_SOCKET_PAYLOAD_ALLOW_WRITE: u8 = 1 << 0;
pub const EBPF_SOCKET_PAYLOAD_ALLOW_READ: u8 = 1 << 1;
pub const EBPF_FD_TABLE_EPOCHS_MAP_NAME: &str = "TRAFFIC_PROBE_FD_TABLE_EPOCHS";
pub const EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_FD_TABLE_EPOCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_FD_TABLE_EPOCH_VALUE_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_SOCKET_FD_GENERATIONS_MAP_NAME: &str = "TRAFFIC_PROBE_SOCKET_FD_GENERATIONS";
pub const EBPF_SOCKET_FD_GENERATIONS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_SOCKET_FD_GENERATION_KEY_BYTES: u32 = core::mem::size_of::<EbpfSocketFdKey>() as u32;
pub const EBPF_SOCKET_FD_GENERATION_VALUE_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_CONNECTS_MAP_NAME: &str = "TRAFFIC_PROBE_PENDING_CONNECTS";
pub const EBPF_PENDING_CONNECTS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_PENDING_CONNECT_KEY_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_CONNECT_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfPendingSocketConnectAttempt>() as u32;
pub const EBPF_PENDING_ACCEPTS_MAP_NAME: &str = "TRAFFIC_PROBE_PENDING_ACCEPTS";
pub const EBPF_PENDING_ACCEPTS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_PENDING_ACCEPT_KEY_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_ACCEPT_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfPendingSocketAcceptAttempt>() as u32;
pub const EBPF_PENDING_WRITES_MAP_NAME: &str = "TRAFFIC_PROBE_PENDING_WRITES";
pub const EBPF_PENDING_WRITES_MAX_ENTRIES: u32 = 8192;
pub const EBPF_PENDING_WRITE_KEY_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_WRITE_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfPendingSocketWriteSample>() as u32;
pub const EBPF_PENDING_WRITE_SCRATCH_MAP_NAME: &str = "TRAFFIC_PROBE_PENDING_WRITE_SCRATCH";
pub const EBPF_PENDING_WRITE_SCRATCH_MAX_ENTRIES: u32 = 1;
pub const EBPF_PENDING_WRITE_SCRATCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PENDING_WRITE_SCRATCH_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfPendingSocketWriteSample>() as u32;
pub const EBPF_PENDING_READS_MAP_NAME: &str = "TRAFFIC_PROBE_PENDING_READS";
pub const EBPF_PENDING_READS_MAX_ENTRIES: u32 = 8192;
pub const EBPF_PENDING_READ_KEY_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_READ_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfPendingSocketReadAttempt>() as u32;
pub const EBPF_PROCESS_EVENT_SCRATCH_MAP_NAME: &str = "TRAFFIC_PROBE_PROCESS_EVENT_SCRATCH";
pub const EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES: u32 = 1;
pub const EBPF_PROCESS_EVENT_SCRATCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PROCESS_EVENT_SCRATCH_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfSocketWriteSampleRecord>() as u32;
pub const EBPF_PROCESS_READ_EVENT_SCRATCH_MAP_NAME: &str =
    "TRAFFIC_PROBE_PROCESS_READ_EVENT_SCRATCH";
pub const EBPF_PROCESS_READ_EVENT_SCRATCH_MAX_ENTRIES: u32 = 1;
pub const EBPF_PROCESS_READ_EVENT_SCRATCH_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PROCESS_READ_EVENT_SCRATCH_VALUE_BYTES: u32 =
    core::mem::size_of::<EbpfSocketReadSampleRecord>() as u32;
pub const EBPF_PROCESS_OUTPUT_LOSSES_MAP_NAME: &str = "TRAFFIC_PROBE_PROCESS_OUTPUT_LOSSES";
pub const EBPF_PROCESS_OUTPUT_LOSSES_MAX_ENTRIES: u32 = 1;
pub const EBPF_PROCESS_OUTPUT_LOSS_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PROCESS_OUTPUT_LOSS_VALUE_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PROCESS_PAYLOAD_GATE_STATS_MAP_NAME: &str =
    "TRAFFIC_PROBE_PROCESS_PAYLOAD_GATE_STATS";
pub const EBPF_PROCESS_PAYLOAD_GATE_STATS_MAX_ENTRIES: u32 =
    EBPF_PROCESS_PAYLOAD_GATE_KINDS.len() as u32;
pub const EBPF_PROCESS_PAYLOAD_GATE_STAT_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PROCESS_PAYLOAD_GATE_STAT_VALUE_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PROCESS_TRACEPOINT_FIRINGS_MAP_NAME: &str =
    "TRAFFIC_PROBE_PROCESS_TRACEPOINT_FIRINGS";
pub const EBPF_PROCESS_TRACEPOINT_FIRINGS_MAX_ENTRIES: u32 =
    EBPF_PROCESS_TRACEPOINT_SPECS.len() as u32;
pub const EBPF_PROCESS_TRACEPOINT_FIRING_KEY_BYTES: u32 = core::mem::size_of::<u32>() as u32;
pub const EBPF_PROCESS_TRACEPOINT_FIRING_VALUE_BYTES: u32 = core::mem::size_of::<u64>() as u32;
pub const EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN: u32 = 1 << 0;
pub const EBPF_PENDING_SOCKET_READ_SOURCE_IOVEC: u32 = 1 << 1;

pub const EBPF_PROCESS_PAYLOAD_GATE_KINDS: [EbpfProcessPayloadGateKind; 38] = [
    EbpfProcessPayloadGateKind::WriteAttempt,
    EbpfProcessPayloadGateKind::WriteSocketAllowance,
    EbpfProcessPayloadGateKind::WriteProcessAllowance,
    EbpfProcessPayloadGateKind::WriteNoAllowance,
    EbpfProcessPayloadGateKind::WriteScratchUnavailable,
    EbpfProcessPayloadGateKind::WritePlanSkipped,
    EbpfProcessPayloadGateKind::WritePendingInserted,
    EbpfProcessPayloadGateKind::WritePendingInsertFailed,
    EbpfProcessPayloadGateKind::WriteExit,
    EbpfProcessPayloadGateKind::WriteMissingPending,
    EbpfProcessPayloadGateKind::WriteLeaseInvalid,
    EbpfProcessPayloadGateKind::WriteLeaseZeroGeneration,
    EbpfProcessPayloadGateKind::WriteLeaseNoProcessAllowance,
    EbpfProcessPayloadGateKind::WriteLeaseDirectionDenied,
    EbpfProcessPayloadGateKind::WriteLeaseGenerationMismatch,
    EbpfProcessPayloadGateKind::WriteLeaseValidated,
    EbpfProcessPayloadGateKind::WriteResultSkipped,
    EbpfProcessPayloadGateKind::WriteEventScratchUnavailable,
    EbpfProcessPayloadGateKind::WriteCopyFailed,
    EbpfProcessPayloadGateKind::WriteSubmitted,
    EbpfProcessPayloadGateKind::ReadAttempt,
    EbpfProcessPayloadGateKind::ReadSocketAllowance,
    EbpfProcessPayloadGateKind::ReadProcessAllowance,
    EbpfProcessPayloadGateKind::ReadNoAllowance,
    EbpfProcessPayloadGateKind::ReadPlanSkipped,
    EbpfProcessPayloadGateKind::ReadPendingInserted,
    EbpfProcessPayloadGateKind::ReadPendingInsertFailed,
    EbpfProcessPayloadGateKind::ReadExit,
    EbpfProcessPayloadGateKind::ReadMissingPending,
    EbpfProcessPayloadGateKind::ReadLeaseInvalid,
    EbpfProcessPayloadGateKind::ReadLeaseZeroGeneration,
    EbpfProcessPayloadGateKind::ReadLeaseNoProcessAllowance,
    EbpfProcessPayloadGateKind::ReadLeaseDirectionDenied,
    EbpfProcessPayloadGateKind::ReadLeaseGenerationMismatch,
    EbpfProcessPayloadGateKind::ReadLeaseValidated,
    EbpfProcessPayloadGateKind::ReadEventScratchUnavailable,
    EbpfProcessPayloadGateKind::ReadResultSkipped,
    EbpfProcessPayloadGateKind::ReadSubmitted,
];

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfProcessPayloadGateKind {
    WriteAttempt = 0,
    WriteSocketAllowance = 1,
    WriteProcessAllowance = 2,
    WriteNoAllowance = 3,
    WriteScratchUnavailable = 4,
    WritePlanSkipped = 5,
    WritePendingInserted = 6,
    WritePendingInsertFailed = 7,
    WriteExit = 8,
    WriteMissingPending = 9,
    WriteLeaseInvalid = 10,
    WriteLeaseZeroGeneration = 11,
    WriteLeaseNoProcessAllowance = 12,
    WriteLeaseDirectionDenied = 13,
    WriteLeaseGenerationMismatch = 14,
    WriteLeaseValidated = 15,
    WriteResultSkipped = 16,
    WriteEventScratchUnavailable = 17,
    WriteCopyFailed = 18,
    WriteSubmitted = 19,
    ReadAttempt = 20,
    ReadSocketAllowance = 21,
    ReadProcessAllowance = 22,
    ReadNoAllowance = 23,
    ReadPlanSkipped = 24,
    ReadPendingInserted = 25,
    ReadPendingInsertFailed = 26,
    ReadExit = 27,
    ReadMissingPending = 28,
    ReadLeaseInvalid = 29,
    ReadLeaseZeroGeneration = 30,
    ReadLeaseNoProcessAllowance = 31,
    ReadLeaseDirectionDenied = 32,
    ReadLeaseGenerationMismatch = 33,
    ReadLeaseValidated = 34,
    ReadEventScratchUnavailable = 35,
    ReadResultSkipped = 36,
    ReadSubmitted = 37,
}

impl EbpfProcessPayloadGateKind {
    pub const fn counter_index(self) -> u32 {
        self as u32
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::WriteAttempt => "write_attempt",
            Self::WriteSocketAllowance => "write_socket_allowance",
            Self::WriteProcessAllowance => "write_process_allowance",
            Self::WriteNoAllowance => "write_no_allowance",
            Self::WriteScratchUnavailable => "write_scratch_unavailable",
            Self::WritePlanSkipped => "write_plan_skipped",
            Self::WritePendingInserted => "write_pending_inserted",
            Self::WritePendingInsertFailed => "write_pending_insert_failed",
            Self::WriteExit => "write_exit",
            Self::WriteMissingPending => "write_missing_pending",
            Self::WriteLeaseInvalid => "write_lease_invalid",
            Self::WriteLeaseZeroGeneration => "write_lease_zero_generation",
            Self::WriteLeaseNoProcessAllowance => "write_lease_no_process_allowance",
            Self::WriteLeaseDirectionDenied => "write_lease_direction_denied",
            Self::WriteLeaseGenerationMismatch => "write_lease_generation_mismatch",
            Self::WriteLeaseValidated => "write_lease_validated",
            Self::WriteResultSkipped => "write_result_skipped",
            Self::WriteEventScratchUnavailable => "write_event_scratch_unavailable",
            Self::WriteCopyFailed => "write_copy_failed",
            Self::WriteSubmitted => "write_submitted",
            Self::ReadAttempt => "read_attempt",
            Self::ReadSocketAllowance => "read_socket_allowance",
            Self::ReadProcessAllowance => "read_process_allowance",
            Self::ReadNoAllowance => "read_no_allowance",
            Self::ReadPlanSkipped => "read_plan_skipped",
            Self::ReadPendingInserted => "read_pending_inserted",
            Self::ReadPendingInsertFailed => "read_pending_insert_failed",
            Self::ReadExit => "read_exit",
            Self::ReadMissingPending => "read_missing_pending",
            Self::ReadLeaseInvalid => "read_lease_invalid",
            Self::ReadLeaseZeroGeneration => "read_lease_zero_generation",
            Self::ReadLeaseNoProcessAllowance => "read_lease_no_process_allowance",
            Self::ReadLeaseDirectionDenied => "read_lease_direction_denied",
            Self::ReadLeaseGenerationMismatch => "read_lease_generation_mismatch",
            Self::ReadLeaseValidated => "read_lease_validated",
            Self::ReadEventScratchUnavailable => "read_event_scratch_unavailable",
            Self::ReadResultSkipped => "read_result_skipped",
            Self::ReadSubmitted => "read_submitted",
        }
    }
}

pub const EBPF_PROCESS_TRACEPOINT_SPECS: [EbpfProcessTracepointSpec; 34] = [
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::ConnectEnter,
        program_name: EBPF_CONNECT_ENTER_PROGRAM_NAME,
        category: EBPF_CONNECT_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_CONNECT_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::ConnectExit,
        program_name: EBPF_CONNECT_EXIT_PROGRAM_NAME,
        category: EBPF_CONNECT_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_CONNECT_EXIT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::AcceptEnter,
        program_name: EBPF_ACCEPT_ENTER_PROGRAM_NAME,
        category: EBPF_ACCEPT_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_ACCEPT_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::AcceptExit,
        program_name: EBPF_ACCEPT_EXIT_PROGRAM_NAME,
        category: EBPF_ACCEPT_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_ACCEPT_EXIT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::Accept4Enter,
        program_name: EBPF_ACCEPT4_ENTER_PROGRAM_NAME,
        category: EBPF_ACCEPT4_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_ACCEPT4_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::Accept4Exit,
        program_name: EBPF_ACCEPT4_EXIT_PROGRAM_NAME,
        category: EBPF_ACCEPT4_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_ACCEPT4_EXIT_TRACEPOINT_NAME,
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
        role: EbpfProcessTracepointRole::WritevEnter,
        program_name: EBPF_WRITEV_ENTER_PROGRAM_NAME,
        category: EBPF_WRITEV_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_WRITEV_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::WritevExit,
        program_name: EBPF_WRITEV_EXIT_PROGRAM_NAME,
        category: EBPF_WRITEV_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_WRITEV_EXIT_TRACEPOINT_NAME,
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
        role: EbpfProcessTracepointRole::SendmsgEnter,
        program_name: EBPF_SENDMSG_ENTER_PROGRAM_NAME,
        category: EBPF_SENDMSG_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_SENDMSG_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::SendmsgExit,
        program_name: EBPF_SENDMSG_EXIT_PROGRAM_NAME,
        category: EBPF_SENDMSG_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_SENDMSG_EXIT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::SendfileEnter,
        program_name: EBPF_SENDFILE_ENTER_PROGRAM_NAME,
        category: EBPF_SENDFILE_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_SENDFILE_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::SendfileExit,
        program_name: EBPF_SENDFILE_EXIT_PROGRAM_NAME,
        category: EBPF_SENDFILE_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_SENDFILE_EXIT_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::Sendfile64Enter,
        program_name: EBPF_SENDFILE64_ENTER_PROGRAM_NAME,
        category: EBPF_SENDFILE64_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_SENDFILE64_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::Sendfile64Exit,
        program_name: EBPF_SENDFILE64_EXIT_PROGRAM_NAME,
        category: EBPF_SENDFILE64_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_SENDFILE64_EXIT_TRACEPOINT_NAME,
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
        role: EbpfProcessTracepointRole::ReadvEnter,
        program_name: EBPF_READV_ENTER_PROGRAM_NAME,
        category: EBPF_READV_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_READV_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::ReadvExit,
        program_name: EBPF_READV_EXIT_PROGRAM_NAME,
        category: EBPF_READV_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_READV_EXIT_TRACEPOINT_NAME,
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
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::RecvmsgEnter,
        program_name: EBPF_RECVMSG_ENTER_PROGRAM_NAME,
        category: EBPF_RECVMSG_ENTER_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_RECVMSG_ENTER_TRACEPOINT_NAME,
    },
    EbpfProcessTracepointSpec {
        role: EbpfProcessTracepointRole::RecvmsgExit,
        program_name: EBPF_RECVMSG_EXIT_PROGRAM_NAME,
        category: EBPF_RECVMSG_EXIT_TRACEPOINT_CATEGORY,
        tracepoint_name: EBPF_RECVMSG_EXIT_TRACEPOINT_NAME,
    },
];

pub const EBPF_PROCESS_OPTIONAL_TRACEPOINT_PAIR_SPECS: [EbpfProcessOptionalTracepointPairSpec; 2] = [
    EbpfProcessOptionalTracepointPairSpec {
        family_name: "sendfile",
        enter: EbpfProcessTracepointRole::SendfileEnter,
        exit: EbpfProcessTracepointRole::SendfileExit,
    },
    EbpfProcessOptionalTracepointPairSpec {
        family_name: "sendfile64",
        enter: EbpfProcessTracepointRole::Sendfile64Enter,
        exit: EbpfProcessTracepointRole::Sendfile64Exit,
    },
];

pub const EBPF_PROCESS_OPTIONAL_TRACEPOINT_SPECS: [EbpfProcessOptionalTracepointSpec; 5] = [
    EbpfProcessOptionalTracepointSpec {
        family_name: "dup",
        role: EbpfProcessTracepointRole::DupEnter,
    },
    EbpfProcessOptionalTracepointSpec {
        family_name: "dup2",
        role: EbpfProcessTracepointRole::Dup2Enter,
    },
    EbpfProcessOptionalTracepointSpec {
        family_name: "dup3",
        role: EbpfProcessTracepointRole::Dup3Enter,
    },
    EbpfProcessOptionalTracepointSpec {
        family_name: "fcntl_fd_duplication",
        role: EbpfProcessTracepointRole::FcntlEnter,
    },
    EbpfProcessOptionalTracepointSpec {
        family_name: "close_range",
        role: EbpfProcessTracepointRole::CloseRangeEnter,
    },
];

pub const EBPF_PROCESS_MAP_SPECS: [EbpfMapSpec; 15] = [
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
        name: EBPF_ALLOWED_PROCESS_TGIDS_MAP_NAME,
        kind: EbpfMapKind::LruHash,
        key_size: EBPF_ALLOWED_PROCESS_TGID_KEY_BYTES,
        value_size: EBPF_ALLOWED_PROCESS_TGID_VALUE_BYTES,
        max_entries: EBPF_ALLOWED_PROCESS_TGIDS_MAX_ENTRIES,
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
        name: EBPF_SOCKET_FD_GENERATIONS_MAP_NAME,
        kind: EbpfMapKind::Hash,
        key_size: EBPF_SOCKET_FD_GENERATION_KEY_BYTES,
        value_size: EBPF_SOCKET_FD_GENERATION_VALUE_BYTES,
        max_entries: EBPF_SOCKET_FD_GENERATIONS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PENDING_CONNECTS_MAP_NAME,
        kind: EbpfMapKind::Hash,
        key_size: EBPF_PENDING_CONNECT_KEY_BYTES,
        value_size: EBPF_PENDING_CONNECT_VALUE_BYTES,
        max_entries: EBPF_PENDING_CONNECTS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PENDING_ACCEPTS_MAP_NAME,
        kind: EbpfMapKind::Hash,
        key_size: EBPF_PENDING_ACCEPT_KEY_BYTES,
        value_size: EBPF_PENDING_ACCEPT_VALUE_BYTES,
        max_entries: EBPF_PENDING_ACCEPTS_MAX_ENTRIES,
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
    EbpfMapSpec {
        name: EBPF_PROCESS_OUTPUT_LOSSES_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: EBPF_PROCESS_OUTPUT_LOSS_KEY_BYTES,
        value_size: EBPF_PROCESS_OUTPUT_LOSS_VALUE_BYTES,
        max_entries: EBPF_PROCESS_OUTPUT_LOSSES_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PROCESS_PAYLOAD_GATE_STATS_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: EBPF_PROCESS_PAYLOAD_GATE_STAT_KEY_BYTES,
        value_size: EBPF_PROCESS_PAYLOAD_GATE_STAT_VALUE_BYTES,
        max_entries: EBPF_PROCESS_PAYLOAD_GATE_STATS_MAX_ENTRIES,
        map_flags: 0,
    },
    EbpfMapSpec {
        name: EBPF_PROCESS_TRACEPOINT_FIRINGS_MAP_NAME,
        kind: EbpfMapKind::PerCpuArray,
        key_size: EBPF_PROCESS_TRACEPOINT_FIRING_KEY_BYTES,
        value_size: EBPF_PROCESS_TRACEPOINT_FIRING_VALUE_BYTES,
        max_entries: EBPF_PROCESS_TRACEPOINT_FIRINGS_MAX_ENTRIES,
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
pub struct EbpfProcessOptionalTracepointPairSpec {
    family_name: &'static str,
    enter: EbpfProcessTracepointRole,
    exit: EbpfProcessTracepointRole,
}

impl EbpfProcessOptionalTracepointPairSpec {
    pub fn family_name(self) -> &'static str {
        self.family_name
    }

    pub fn enter_role(self) -> EbpfProcessTracepointRole {
        self.enter
    }

    pub fn exit_role(self) -> EbpfProcessTracepointRole {
        self.exit
    }

    pub fn enter_spec(self) -> &'static EbpfProcessTracepointSpec {
        self.enter.spec()
    }

    pub fn exit_spec(self) -> &'static EbpfProcessTracepointSpec {
        self.exit.spec()
    }

    pub fn contains_role(self, role: EbpfProcessTracepointRole) -> bool {
        self.enter == role || self.exit == role
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessOptionalTracepointSpec {
    family_name: &'static str,
    role: EbpfProcessTracepointRole,
}

impl EbpfProcessOptionalTracepointSpec {
    pub fn family_name(self) -> &'static str {
        self.family_name
    }

    pub fn role(self) -> EbpfProcessTracepointRole {
        self.role
    }

    pub fn tracepoint_spec(self) -> &'static EbpfProcessTracepointSpec {
        self.role.spec()
    }

    pub fn contains_role(self, role: EbpfProcessTracepointRole) -> bool {
        self.role == role
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

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EbpfProcessTracepointRole {
    ConnectEnter,
    ConnectExit,
    AcceptEnter,
    AcceptExit,
    Accept4Enter,
    Accept4Exit,
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
    WritevEnter,
    WritevExit,
    SendtoEnter,
    SendtoExit,
    SendmsgEnter,
    SendmsgExit,
    SendfileEnter,
    SendfileExit,
    Sendfile64Enter,
    Sendfile64Exit,
    ReadEnter,
    ReadExit,
    ReadvEnter,
    ReadvExit,
    RecvfromEnter,
    RecvfromExit,
    RecvmsgEnter,
    RecvmsgExit,
}

impl EbpfProcessTracepointRole {
    pub const fn counter_index(self) -> u32 {
        self as u32
    }

    pub fn has_optional_attach(self) -> bool {
        self.optional_tracepoint_spec().is_some() || self.optional_pair_spec().is_some()
    }

    pub fn optional_tracepoint_spec(self) -> Option<EbpfProcessOptionalTracepointSpec> {
        EBPF_PROCESS_OPTIONAL_TRACEPOINT_SPECS
            .into_iter()
            .find(|spec| spec.contains_role(self))
    }

    pub fn optional_pair_spec(self) -> Option<EbpfProcessOptionalTracepointPairSpec> {
        EBPF_PROCESS_OPTIONAL_TRACEPOINT_PAIR_SPECS
            .into_iter()
            .find(|pair| pair.contains_role(self))
    }

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
    pub fd_generation: u64,
    pub direction_mask: u8,
    pub _reserved: [u8; 7],
}

impl EbpfSocketPayloadAllowance {
    pub const fn new(fd_table_epoch: u64, fd_generation: u64, direction_mask: u8) -> Self {
        Self {
            fd_table_epoch,
            fd_generation,
            direction_mask,
            _reserved: [0; 7],
        }
    }

    pub fn to_bpfel_bytes(self) -> [u8; core::mem::size_of::<Self>()] {
        let epoch = self.fd_table_epoch.to_le_bytes();
        let generation = self.fd_generation.to_le_bytes();
        [
            epoch[0],
            epoch[1],
            epoch[2],
            epoch[3],
            epoch[4],
            epoch[5],
            epoch[6],
            epoch[7],
            generation[0],
            generation[1],
            generation[2],
            generation[3],
            generation[4],
            generation[5],
            generation[6],
            generation[7],
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
pub struct EbpfProcessPayloadAllowance {
    pub direction_mask: u8,
    pub _reserved: [u8; 7],
}

impl EbpfProcessPayloadAllowance {
    pub const fn new(direction_mask: u8) -> Self {
        Self {
            direction_mask,
            _reserved: [0; 7],
        }
    }

    pub fn to_bpfel_bytes(self) -> [u8; core::mem::size_of::<Self>()] {
        [
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
pub struct EbpfPendingSocketConnectAttempt {
    pub observation: EbpfConnectObservation,
    pub flags: u16,
    pub _reserved: [u8; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfPendingSocketAcceptAttempt {
    pub listen_fd: i32,
    pub addrlen_capacity: u32,
    pub user_sockaddr: u64,
    pub user_addrlen: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfPendingSocketWriteSample {
    pub fd: i32,
    pub original_len: u32,
    pub fd_generation: u64,
    pub captured_len: u16,
    pub flags: u16,
    pub _reserved: [u8; 4],
    pub buffer: [u8; EBPF_SOCKET_WRITE_SAMPLE_BYTES],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfPendingSocketReadAttempt {
    pub fd: i32,
    pub requested_len: u32,
    pub fd_generation: u64,
    pub readable_len: u32,
    pub logical_len_flags: u32,
    pub user_buffer: u64,
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};
    use std::{collections::BTreeSet, string::ToString};

    use super::*;

    #[test]
    fn process_map_specs_are_unique_and_layout_complete() {
        assert_eq!(EBPF_PROCESS_MAP_SPECS.len(), 15);
        assert_unique(EBPF_PROCESS_MAP_SPECS.map(|spec| spec.name));

        assert_map_layout(
            process_map(EBPF_EVENTS_MAP_NAME),
            EbpfMapKind::Ringbuf,
            0,
            0,
            128 * 1024 * 1024,
        );
        assert_map_layout(
            process_map(EBPF_ALLOWED_SOCKET_FDS_MAP_NAME),
            EbpfMapKind::LruHash,
            8,
            24,
            8192,
        );
        assert_map_layout(
            process_map(EBPF_ALLOWED_PROCESS_TGIDS_MAP_NAME),
            EbpfMapKind::LruHash,
            4,
            8,
            8192,
        );
        assert_map_layout(
            process_map(EBPF_FD_TABLE_EPOCHS_MAP_NAME),
            EbpfMapKind::Hash,
            4,
            8,
            8192,
        );
        assert_map_layout(
            process_map(EBPF_SOCKET_FD_GENERATIONS_MAP_NAME),
            EbpfMapKind::Hash,
            8,
            8,
            8192,
        );
        assert_map_layout(
            process_map(EBPF_PENDING_CONNECTS_MAP_NAME),
            EbpfMapKind::Hash,
            8,
            56,
            8192,
        );
        assert_map_layout(
            process_map(EBPF_PENDING_ACCEPTS_MAP_NAME),
            EbpfMapKind::Hash,
            8,
            24,
            8192,
        );
        assert_map_layout(
            process_map(EBPF_PENDING_WRITES_MAP_NAME),
            EbpfMapKind::Hash,
            8,
            16408,
            8192,
        );
        assert_map_layout(
            process_map(EBPF_PENDING_WRITE_SCRATCH_MAP_NAME),
            EbpfMapKind::PerCpuArray,
            4,
            16408,
            1,
        );
        assert_map_layout(
            process_map(EBPF_PENDING_READS_MAP_NAME),
            EbpfMapKind::Hash,
            8,
            32,
            8192,
        );
        assert_map_layout(
            process_map(EBPF_PROCESS_EVENT_SCRATCH_MAP_NAME),
            EbpfMapKind::PerCpuArray,
            4,
            16456,
            1,
        );
        assert_map_layout(
            process_map(EBPF_PROCESS_READ_EVENT_SCRATCH_MAP_NAME),
            EbpfMapKind::PerCpuArray,
            4,
            16456,
            1,
        );
        assert_map_layout(
            process_map(EBPF_PROCESS_OUTPUT_LOSSES_MAP_NAME),
            EbpfMapKind::PerCpuArray,
            4,
            8,
            1,
        );
        assert_map_layout(
            process_map(EBPF_PROCESS_PAYLOAD_GATE_STATS_MAP_NAME),
            EbpfMapKind::PerCpuArray,
            4,
            8,
            EBPF_PROCESS_PAYLOAD_GATE_KINDS.len() as u32,
        );
        assert_map_layout(
            process_map(EBPF_PROCESS_TRACEPOINT_FIRINGS_MAP_NAME),
            EbpfMapKind::PerCpuArray,
            4,
            8,
            34,
        );

        assert_eq!(
            EbpfSocketFdKey::new(0x0102_0304, -2).to_bpfel_bytes(),
            [0x04, 0x03, 0x02, 0x01, 0xfe, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            EbpfSocketPayloadAllowance::new(
                0x0102_0304_0506_0708,
                0x1112_1314_1516_1718,
                EBPF_SOCKET_PAYLOAD_ALLOW_READ,
            )
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
                0x18,
                0x17,
                0x16,
                0x15,
                0x14,
                0x13,
                0x12,
                0x11,
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
        assert_eq!(EBPF_PROCESS_TRACEPOINT_SPECS.len(), 34);
        assert_unique(EBPF_PROCESS_TRACEPOINT_SPECS.map(|spec| spec.program_name));
        assert_unique(EBPF_PROCESS_TRACEPOINT_SPECS.map(|spec| spec.tracepoint_name));

        for spec in EBPF_PROCESS_TRACEPOINT_SPECS {
            assert_eq!(
                spec.role.counter_index(),
                EBPF_PROCESS_TRACEPOINT_SPECS
                    .iter()
                    .position(|candidate| candidate.role == spec.role)
                    .expect("role should be present") as u32
            );
            assert_eq!(spec.role.spec(), &spec);
            assert_eq!(
                spec.section_name().to_string(),
                std::format!("tracepoint/{}/{}", spec.category, spec.tracepoint_name)
            );
        }
    }

    #[test]
    fn sendfile_family_tracepoints_are_optional_kernel_variants() {
        assert_eq!(EBPF_PROCESS_OPTIONAL_TRACEPOINT_PAIR_SPECS.len(), 2);
        assert_unique(EBPF_PROCESS_OPTIONAL_TRACEPOINT_PAIR_SPECS.map(|pair| pair.family_name()));

        let mut optional_roles = BTreeSet::new();
        for pair in EBPF_PROCESS_OPTIONAL_TRACEPOINT_PAIR_SPECS {
            assert!(optional_roles.insert(pair.enter_role()));
            assert!(optional_roles.insert(pair.exit_role()));
            assert_eq!(pair.enter_role().spec(), pair.enter_spec());
            assert_eq!(pair.exit_role().spec(), pair.exit_spec());
            assert!(pair.enter_role().has_optional_attach());
            assert!(pair.exit_role().has_optional_attach());
        }

        assert_eq!(
            optional_roles,
            BTreeSet::from([
                EbpfProcessTracepointRole::SendfileEnter,
                EbpfProcessTracepointRole::SendfileExit,
                EbpfProcessTracepointRole::Sendfile64Enter,
                EbpfProcessTracepointRole::Sendfile64Exit,
            ])
        );
        assert!(!EbpfProcessTracepointRole::WriteEnter.has_optional_attach());
    }

    #[test]
    fn fd_table_maintenance_tracepoints_are_optional_kernel_features() {
        assert_eq!(EBPF_PROCESS_OPTIONAL_TRACEPOINT_SPECS.len(), 5);
        assert_unique(EBPF_PROCESS_OPTIONAL_TRACEPOINT_SPECS.map(|spec| spec.family_name()));

        let mut optional_roles = BTreeSet::new();
        for optional in EBPF_PROCESS_OPTIONAL_TRACEPOINT_SPECS {
            assert!(optional_roles.insert(optional.role()));
            assert_eq!(optional.role().spec(), optional.tracepoint_spec());
            assert!(optional.role().has_optional_attach());
            assert_eq!(optional.role().optional_tracepoint_spec(), Some(optional));
        }

        assert_eq!(
            optional_roles,
            BTreeSet::from([
                EbpfProcessTracepointRole::DupEnter,
                EbpfProcessTracepointRole::Dup2Enter,
                EbpfProcessTracepointRole::Dup3Enter,
                EbpfProcessTracepointRole::FcntlEnter,
                EbpfProcessTracepointRole::CloseRangeEnter,
            ])
        );
        assert!(!EbpfProcessTracepointRole::ConnectEnter.has_optional_attach());
    }

    #[test]
    fn process_payload_allowance_layout_is_stable() {
        assert_eq!(size_of::<EbpfProcessPayloadAllowance>(), 8);
        assert_eq!(align_of::<EbpfProcessPayloadAllowance>(), 1);
        assert_eq!(offset_of!(EbpfProcessPayloadAllowance, direction_mask), 0);
        assert_eq!(offset_of!(EbpfProcessPayloadAllowance, _reserved), 1);
        let allowance = EbpfProcessPayloadAllowance::new(
            EBPF_SOCKET_PAYLOAD_ALLOW_READ | EBPF_SOCKET_PAYLOAD_ALLOW_WRITE,
        );
        assert!(allowance.allows(EBPF_SOCKET_PAYLOAD_ALLOW_READ));
        assert!(allowance.allows(EBPF_SOCKET_PAYLOAD_ALLOW_WRITE));
        assert!(!allowance.allows(1 << 7));
    }

    #[test]
    fn pending_socket_connect_attempt_layout_is_stable() {
        assert_eq!(size_of::<EbpfPendingSocketConnectAttempt>(), 56);
        assert_eq!(align_of::<EbpfPendingSocketConnectAttempt>(), 8);
        assert_eq!(offset_of!(EbpfPendingSocketConnectAttempt, observation), 0);
        assert_eq!(offset_of!(EbpfPendingSocketConnectAttempt, flags), 48);
        assert_eq!(offset_of!(EbpfPendingSocketConnectAttempt, _reserved), 50);
    }

    #[test]
    fn pending_socket_write_sample_layout_is_stable() {
        assert_eq!(
            size_of::<EbpfPendingSocketWriteSample>(),
            24 + EBPF_SOCKET_WRITE_SAMPLE_BYTES
        );
        assert_eq!(align_of::<EbpfPendingSocketWriteSample>(), 8);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, fd), 0);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, original_len), 4);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, fd_generation), 8);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, captured_len), 16);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, flags), 18);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, _reserved), 20);
        assert_eq!(offset_of!(EbpfPendingSocketWriteSample, buffer), 24);
    }

    #[test]
    fn pending_socket_accept_attempt_layout_is_stable() {
        assert_eq!(size_of::<EbpfPendingSocketAcceptAttempt>(), 24);
        assert_eq!(align_of::<EbpfPendingSocketAcceptAttempt>(), 8);
        assert_eq!(offset_of!(EbpfPendingSocketAcceptAttempt, listen_fd), 0);
        assert_eq!(
            offset_of!(EbpfPendingSocketAcceptAttempt, addrlen_capacity),
            4
        );
        assert_eq!(offset_of!(EbpfPendingSocketAcceptAttempt, user_sockaddr), 8);
        assert_eq!(offset_of!(EbpfPendingSocketAcceptAttempt, user_addrlen), 16);
    }

    #[test]
    fn socket_payload_allowance_layout_is_stable() {
        assert_eq!(size_of::<EbpfSocketPayloadAllowance>(), 24);
        assert_eq!(align_of::<EbpfSocketPayloadAllowance>(), 8);
        assert_eq!(offset_of!(EbpfSocketPayloadAllowance, fd_table_epoch), 0);
        assert_eq!(offset_of!(EbpfSocketPayloadAllowance, fd_generation), 8);
        assert_eq!(offset_of!(EbpfSocketPayloadAllowance, direction_mask), 16);
        assert_eq!(offset_of!(EbpfSocketPayloadAllowance, _reserved), 17);
        let allowance = EbpfSocketPayloadAllowance::new(
            9,
            10,
            EBPF_SOCKET_PAYLOAD_ALLOW_READ | EBPF_SOCKET_PAYLOAD_ALLOW_WRITE,
        );
        assert!(allowance.allows(EBPF_SOCKET_PAYLOAD_ALLOW_READ));
        assert!(allowance.allows(EBPF_SOCKET_PAYLOAD_ALLOW_WRITE));
        assert!(!allowance.allows(1 << 7));
    }

    #[test]
    fn pending_socket_read_attempt_layout_is_stable() {
        assert_eq!(EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN, 1 << 0);
        assert_eq!(EBPF_PENDING_SOCKET_READ_SOURCE_IOVEC, 1 << 1);
        assert_eq!(size_of::<EbpfPendingSocketReadAttempt>(), 32);
        assert_eq!(align_of::<EbpfPendingSocketReadAttempt>(), 8);
        assert_eq!(offset_of!(EbpfPendingSocketReadAttempt, fd), 0);
        assert_eq!(offset_of!(EbpfPendingSocketReadAttempt, requested_len), 4);
        assert_eq!(offset_of!(EbpfPendingSocketReadAttempt, fd_generation), 8);
        assert_eq!(offset_of!(EbpfPendingSocketReadAttempt, readable_len), 16);
        assert_eq!(
            offset_of!(EbpfPendingSocketReadAttempt, logical_len_flags),
            20
        );
        assert_eq!(offset_of!(EbpfPendingSocketReadAttempt, user_buffer), 24);
    }

    fn process_map(name: &'static str) -> EbpfMapSpec {
        *EBPF_PROCESS_MAP_SPECS
            .iter()
            .find(|spec| spec.name == name)
            .expect("process map should exist")
    }

    fn assert_map_layout(
        spec: EbpfMapSpec,
        kind: EbpfMapKind,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) {
        assert_eq!(spec.kind, kind);
        assert_eq!(spec.key_size, key_size);
        assert_eq!(spec.value_size, value_size);
        assert_eq!(spec.max_entries, max_entries);
    }

    fn assert_unique(values: impl IntoIterator<Item = &'static str>) {
        let mut seen = BTreeSet::new();
        for value in values {
            assert!(seen.insert(value), "duplicate value: {value}");
        }
    }
}

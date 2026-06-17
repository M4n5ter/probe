#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

mod close;
mod connect;
mod read;
mod write;

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use ebpf_abi::{
    EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES, EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES,
    EBPF_PENDING_READS_MAX_ENTRIES, EBPF_PENDING_WRITE_SCRATCH_MAX_ENTRIES,
    EBPF_PENDING_WRITES_MAX_ENTRIES, EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES,
    EBPF_PROCESS_READ_EVENT_SCRATCH_MAX_ENTRIES, EBPF_RING_BUFFER_BYTES,
    EBPF_SOCKET_PAYLOAD_ALLOW_READ, EBPF_SOCKET_PAYLOAD_ALLOW_WRITE, EbpfCloseTracepointRecord,
    EbpfConnectTracepointRecord, EbpfPendingSocketReadAttempt, EbpfPendingSocketWriteSample,
    EbpfProcessProbeMetadata, EbpfSocketFdKey, EbpfSocketPayloadAllowance,
    EbpfSocketReadSampleRecord, EbpfSocketWriteSampleRecord,
};

use close::close_observation_from_tracepoint;
use connect::connect_observation_from_tracepoint;
use read::{capture_read_sample_from_result, read_attempt_from_tracepoint};
use write::{
    capture_write_sample_from_attempt, pending_write_metadata, trim_write_sample_to_result,
    write_attempt_from_tracepoint,
};

const FCNTL_CMD_OFFSET: usize = 24;
const F_DUPFD: u64 = 0;
const F_DUPFD_CLOEXEC: u64 = 1030;

#[map(name = "SSSA_EVENTS")]
static SSSA_EVENTS: RingBuf = RingBuf::with_byte_size(EBPF_RING_BUFFER_BYTES, 0);

#[map(name = "SSSA_ALLOWED_SOCKET_FDS")]
static SSSA_ALLOWED_SOCKET_FDS: LruHashMap<EbpfSocketFdKey, EbpfSocketPayloadAllowance> =
    LruHashMap::with_max_entries(EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES, 0);

#[map(name = "SSSA_FD_TABLE_EPOCHS")]
static SSSA_FD_TABLE_EPOCHS: HashMap<u32, u64> =
    HashMap::with_max_entries(EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES, 0);

#[map(name = "SSSA_PENDING_WRITES")]
static SSSA_PENDING_WRITES: HashMap<u64, EbpfPendingSocketWriteSample> =
    HashMap::with_max_entries(EBPF_PENDING_WRITES_MAX_ENTRIES, 0);

#[map(name = "SSSA_PENDING_WRITE_SCRATCH")]
static SSSA_PENDING_WRITE_SCRATCH: PerCpuArray<EbpfPendingSocketWriteSample> =
    PerCpuArray::with_max_entries(EBPF_PENDING_WRITE_SCRATCH_MAX_ENTRIES, 0);

#[map(name = "SSSA_PENDING_READS")]
static SSSA_PENDING_READS: HashMap<u64, EbpfPendingSocketReadAttempt> =
    HashMap::with_max_entries(EBPF_PENDING_READS_MAX_ENTRIES, 0);

#[map(name = "SSSA_PROCESS_EVENT_SCRATCH")]
static SSSA_PROCESS_EVENT_SCRATCH: PerCpuArray<EbpfSocketWriteSampleRecord> =
    PerCpuArray::with_max_entries(EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES, 0);

#[map(name = "SSSA_PROCESS_READ_EVENT_SCRATCH")]
static SSSA_PROCESS_READ_EVENT_SCRATCH: PerCpuArray<EbpfSocketReadSampleRecord> =
    PerCpuArray::with_max_entries(EBPF_PROCESS_READ_EVENT_SCRATCH_MAX_ENTRIES, 0);

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
pub fn sssa_sys_enter_connect(ctx: TracePointContext) -> u32 {
    emit_connect_attempt(ctx);
    0
}

#[tracepoint(name = "sys_enter_close", category = "syscalls")]
pub fn sssa_sys_enter_close(ctx: TracePointContext) -> u32 {
    emit_close_attempt(ctx);
    0
}

#[tracepoint(name = "sys_enter_dup", category = "syscalls")]
pub fn sssa_sys_enter_dup(_ctx: TracePointContext) -> u32 {
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sys_enter_dup2", category = "syscalls")]
pub fn sssa_sys_enter_dup2(_ctx: TracePointContext) -> u32 {
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sys_enter_dup3", category = "syscalls")]
pub fn sssa_sys_enter_dup3(_ctx: TracePointContext) -> u32 {
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sys_enter_fcntl", category = "syscalls")]
pub fn sssa_sys_enter_fcntl(ctx: TracePointContext) -> u32 {
    if fcntl_may_create_fd(&ctx) {
        invalidate_current_fd_table();
    }
    0
}

#[tracepoint(name = "sys_enter_close_range", category = "syscalls")]
pub fn sssa_sys_enter_close_range(_ctx: TracePointContext) -> u32 {
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sssa_sched_process_exit(_ctx: TracePointContext) -> u32 {
    if current_pid() == current_tgid() {
        invalidate_current_fd_table();
    }
    0
}

#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sssa_sched_process_exec(_ctx: TracePointContext) -> u32 {
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sys_enter_write", category = "syscalls")]
pub fn sssa_sys_enter_write(ctx: TracePointContext) -> u32 {
    record_write_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_write", category = "syscalls")]
pub fn sssa_sys_exit_write(ctx: TracePointContext) -> u32 {
    emit_write_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_read", category = "syscalls")]
pub fn sssa_sys_enter_read(ctx: TracePointContext) -> u32 {
    record_read_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_read", category = "syscalls")]
pub fn sssa_sys_exit_read(ctx: TracePointContext) -> u32 {
    emit_read_sample(ctx);
    0
}

fn emit_connect_attempt(ctx: TracePointContext) {
    let connect = connect_observation_from_tracepoint(&ctx);
    let metadata = process_metadata(&ctx);
    let observation = connect
        .observation
        .with_fd_table_epoch(ensure_fd_table_epoch(metadata.tgid));
    let event = EbpfConnectTracepointRecord::connect_tracepoint_observed(
        metadata.pid,
        metadata.tgid,
        metadata.uid,
        metadata.gid,
        metadata.command,
        observation,
        connect.flags,
    );
    let _ = SSSA_EVENTS.output(&event, 0);
}

fn emit_close_attempt(ctx: TracePointContext) {
    let Some(close) = close_observation_from_tracepoint(&ctx) else {
        return;
    };
    untrack_socket_fd(close.fd);
    let metadata = process_metadata(&ctx);
    let event = EbpfCloseTracepointRecord::close_tracepoint_observed(
        metadata.pid,
        metadata.tgid,
        metadata.uid,
        metadata.gid,
        metadata.command,
        close,
    );
    let _ = SSSA_EVENTS.output(&event, 0);
}

fn record_write_attempt(ctx: TracePointContext) {
    let Some(attempt) = write_attempt_from_tracepoint(&ctx) else {
        return;
    };
    if !is_allowed_socket_payload(attempt.fd, EBPF_SOCKET_PAYLOAD_ALLOW_WRITE) {
        return;
    }
    let Some(pending) = pending_write_scratch() else {
        return;
    };
    capture_write_sample_from_attempt(attempt, pending);
    let key = bpf_get_current_pid_tgid();
    let _ = SSSA_PENDING_WRITES.insert(&key, pending, 0);
}

fn emit_write_sample(ctx: TracePointContext) {
    let key = bpf_get_current_pid_tgid();
    let Some(pending_ptr) = SSSA_PENDING_WRITES.get_ptr_mut(&key) else {
        return;
    };
    let pending = unsafe { &mut *pending_ptr };
    if !is_allowed_socket_payload(pending.fd, EBPF_SOCKET_PAYLOAD_ALLOW_WRITE) {
        let _ = SSSA_PENDING_WRITES.remove(&key);
        return;
    }
    if trim_write_sample_to_result(&ctx, pending).is_none() {
        let _ = SSSA_PENDING_WRITES.remove(&key);
        return;
    };
    let Some(event) = scratch_event() else {
        let _ = SSSA_PENDING_WRITES.remove(&key);
        return;
    };
    event.clear_sample();
    if !copy_captured_write_prefix(event, pending) {
        let _ = SSSA_PENDING_WRITES.remove(&key);
        return;
    }
    event.overwrite_socket_write_sampled_metadata(
        process_metadata(&ctx),
        pending_write_metadata(pending),
        pending.flags,
    );
    let _ = SSSA_EVENTS.output(event, 0);
    let _ = SSSA_PENDING_WRITES.remove(&key);
}

fn record_read_attempt(ctx: TracePointContext) {
    let Some(attempt) = read_attempt_from_tracepoint(&ctx) else {
        return;
    };
    if !is_allowed_socket_payload(attempt.fd, EBPF_SOCKET_PAYLOAD_ALLOW_READ) {
        return;
    }
    let key = bpf_get_current_pid_tgid();
    let _ = SSSA_PENDING_READS.insert(&key, &attempt, 0);
}

fn emit_read_sample(ctx: TracePointContext) {
    let key = bpf_get_current_pid_tgid();
    let Some(attempt) = (unsafe { SSSA_PENDING_READS.get(&key).copied() }) else {
        return;
    };
    if !is_allowed_socket_payload(attempt.fd, EBPF_SOCKET_PAYLOAD_ALLOW_READ) {
        let _ = SSSA_PENDING_READS.remove(&key);
        return;
    }
    let Some(event) = read_scratch_event() else {
        let _ = SSSA_PENDING_READS.remove(&key);
        return;
    };
    if capture_read_sample_from_result(&ctx, attempt, event).is_none() {
        let _ = SSSA_PENDING_READS.remove(&key);
        return;
    }
    let _ = SSSA_EVENTS.output(event, 0);
    let _ = SSSA_PENDING_READS.remove(&key);
}

fn pending_write_scratch() -> Option<&'static mut EbpfPendingSocketWriteSample> {
    let ptr = SSSA_PENDING_WRITE_SCRATCH.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}

fn scratch_event() -> Option<&'static mut EbpfSocketWriteSampleRecord> {
    let ptr = SSSA_PROCESS_EVENT_SCRATCH.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}

fn read_scratch_event() -> Option<&'static mut EbpfSocketReadSampleRecord> {
    let ptr = SSSA_PROCESS_READ_EVENT_SCRATCH.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}

fn copy_captured_write_prefix(
    event: &mut EbpfSocketWriteSampleRecord,
    pending: &EbpfPendingSocketWriteSample,
) -> bool {
    let captured_len = usize::from(pending.captured_len);
    let Some(output) = event.socket_write_buffer_mut().get_mut(..captured_len) else {
        return false;
    };
    let Some(input) = pending.buffer.get(..captured_len) else {
        return false;
    };
    output.copy_from_slice(input);
    true
}

fn process_metadata(ctx: &impl EbpfContext) -> EbpfProcessProbeMetadata {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    EbpfProcessProbeMetadata {
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        command: ctx.command().unwrap_or_default(),
    }
}

fn is_allowed_socket_payload(fd: i32, direction: u8) -> bool {
    if fd < 0 {
        return false;
    }
    let tgid = current_tgid();
    let key = EbpfSocketFdKey::new(tgid, fd);
    let Some(allowance) = (unsafe { SSSA_ALLOWED_SOCKET_FDS.get(&key).copied() }) else {
        return false;
    };
    allowance.fd_table_epoch != 0
        && allowance.allows(direction)
        && current_fd_table_epoch(tgid).is_some_and(|epoch| epoch == allowance.fd_table_epoch)
}

fn untrack_socket_fd(fd: i32) {
    if fd < 0 {
        return;
    }
    let key = EbpfSocketFdKey::new(current_tgid(), fd);
    let _ = SSSA_ALLOWED_SOCKET_FDS.remove(&key);
}

fn invalidate_current_fd_table() {
    let tgid = current_tgid();
    let next_epoch = next_fd_table_epoch(tgid);
    let _ = SSSA_FD_TABLE_EPOCHS.insert(&tgid, &next_epoch, 0);
}

fn ensure_fd_table_epoch(tgid: u32) -> u64 {
    if let Some(epoch) = current_fd_table_epoch(tgid) {
        return epoch;
    }
    let epoch = next_fd_table_epoch(tgid);
    if SSSA_FD_TABLE_EPOCHS.insert(&tgid, &epoch, 0).is_ok() {
        epoch
    } else {
        0
    }
}

fn next_fd_table_epoch(tgid: u32) -> u64 {
    let mut next_epoch = current_fd_table_epoch(tgid).unwrap_or(0).wrapping_add(1);
    if next_epoch == 0 {
        next_epoch = 1;
    }
    next_epoch
}

fn current_fd_table_epoch(tgid: u32) -> Option<u64> {
    unsafe { SSSA_FD_TABLE_EPOCHS.get(&tgid).copied() }
}

fn fcntl_may_create_fd(ctx: &TracePointContext) -> bool {
    let Ok(cmd) = (unsafe { ctx.read_at::<u64>(FCNTL_CMD_OFFSET) }) else {
        return true;
    };
    fcntl_cmd_may_create_fd(cmd)
}

fn fcntl_cmd_may_create_fd(cmd: u64) -> bool {
    cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC
}

fn current_pid() -> u32 {
    bpf_get_current_pid_tgid() as u32
}

fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[cfg(test)]
mod tests {
    use ebpf_abi::{EBPF_SOCKET_WRITE_SAMPLE_BYTES, EbpfSocketWriteSample};

    use super::*;

    #[test]
    fn copy_captured_write_prefix_leaves_raw_record_tail_zeroed() {
        let mut event = EbpfSocketWriteSampleRecord::socket_write_sampled(
            1,
            1,
            0,
            0,
            [0; 16],
            EbpfSocketWriteSample::new(0, 0, 0, [0x7f; EBPF_SOCKET_WRITE_SAMPLE_BYTES]),
            0,
        );
        let mut pending = EbpfPendingSocketWriteSample {
            fd: 7,
            original_len: 3,
            captured_len: 3,
            flags: 0,
            buffer: [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES],
        };
        pending.buffer[..5].copy_from_slice(b"GET /");

        event.clear_sample();
        assert!(copy_captured_write_prefix(&mut event, &pending));

        let buffer = event.socket_write_buffer_mut();
        assert_eq!(&buffer[..3], b"GET");
        assert!(buffer[3..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn fcntl_epoch_invalidation_is_limited_to_fd_duplication() {
        assert!(fcntl_cmd_may_create_fd(F_DUPFD));
        assert!(fcntl_cmd_may_create_fd(F_DUPFD_CLOEXEC));
        assert!(!fcntl_cmd_may_create_fd(1));
        assert!(!fcntl_cmd_may_create_fd(2));
        assert!(!fcntl_cmd_may_create_fd(3));
        assert!(!fcntl_cmd_may_create_fd(4));
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

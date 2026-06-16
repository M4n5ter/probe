#![no_std]
#![no_main]

mod close;
mod connect;
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
    EBPF_PENDING_WRITES_MAX_ENTRIES, EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES,
    EBPF_RING_BUFFER_BYTES, EbpfCloseTracepointRecord, EbpfConnectTracepointRecord,
    EbpfPendingWrite, EbpfProcessProbeMetadata, EbpfSocketFdKey, EbpfSocketWriteSampleRecord,
};

use close::close_observation_from_tracepoint;
use connect::connect_observation_from_tracepoint;
use write::{pending_write_from_tracepoint, socket_write_sample_from_tracepoint};

#[map(name = "SSSA_EVENTS")]
static SSSA_EVENTS: RingBuf = RingBuf::with_byte_size(EBPF_RING_BUFFER_BYTES, 0);

#[map(name = "SSSA_ALLOWED_SOCKET_FDS")]
static SSSA_ALLOWED_SOCKET_FDS: LruHashMap<EbpfSocketFdKey, u64> =
    LruHashMap::with_max_entries(EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES, 0);

#[map(name = "SSSA_FD_TABLE_EPOCHS")]
static SSSA_FD_TABLE_EPOCHS: HashMap<u32, u64> =
    HashMap::with_max_entries(EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES, 0);

#[map(name = "SSSA_PENDING_WRITES")]
static SSSA_PENDING_WRITES: HashMap<u64, EbpfPendingWrite> =
    HashMap::with_max_entries(EBPF_PENDING_WRITES_MAX_ENTRIES, 0);

#[map(name = "SSSA_PROCESS_EVENT_SCRATCH")]
static SSSA_PROCESS_EVENT_SCRATCH: PerCpuArray<EbpfSocketWriteSampleRecord> =
    PerCpuArray::with_max_entries(EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES, 0);

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
pub fn sssa_sys_enter_fcntl(_ctx: TracePointContext) -> u32 {
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sys_enter_close_range", category = "syscalls")]
pub fn sssa_sys_enter_close_range(_ctx: TracePointContext) -> u32 {
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sssa_sched_process_exit(_ctx: TracePointContext) -> u32 {
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
    if close.fd >= 0 {
        invalidate_current_fd_table();
    }
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
    let Some(pending) = pending_write_from_tracepoint(&ctx) else {
        return;
    };
    if !is_allowed_socket_fd(pending.fd) {
        return;
    }
    let key = bpf_get_current_pid_tgid();
    let _ = SSSA_PENDING_WRITES.insert(&key, &pending, 0);
}

fn emit_write_sample(ctx: TracePointContext) {
    let key = bpf_get_current_pid_tgid();
    let Some(pending) = (unsafe { SSSA_PENDING_WRITES.get(&key).copied() }) else {
        return;
    };
    let _ = SSSA_PENDING_WRITES.remove(&key);
    if !is_allowed_socket_fd(pending.fd) {
        return;
    }
    let Some(event) = scratch_event() else {
        return;
    };
    event.clear_sample();
    let Some(sample) =
        socket_write_sample_from_tracepoint(&ctx, pending, event.socket_write_buffer_mut())
    else {
        return;
    };
    event.overwrite_socket_write_sampled_metadata(
        process_metadata(&ctx),
        sample.metadata,
        sample.flags,
    );
    let _ = SSSA_EVENTS.output(event, 0);
}

fn scratch_event() -> Option<&'static mut EbpfSocketWriteSampleRecord> {
    let ptr = SSSA_PROCESS_EVENT_SCRATCH.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
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

fn is_allowed_socket_fd(fd: i32) -> bool {
    if fd < 0 {
        return false;
    }
    let tgid = current_tgid();
    let key = EbpfSocketFdKey::new(current_pid(), fd);
    let Some(allowed_epoch) = (unsafe { SSSA_ALLOWED_SOCKET_FDS.get(&key).copied() }) else {
        return false;
    };
    allowed_epoch != 0 && current_fd_table_epoch(tgid).is_some_and(|epoch| epoch == allowed_epoch)
}

fn untrack_socket_fd(fd: i32) {
    if fd < 0 {
        return;
    }
    let key = EbpfSocketFdKey::new(current_pid(), fd);
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

fn current_pid() -> u32 {
    bpf_get_current_pid_tgid() as u32
}

fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

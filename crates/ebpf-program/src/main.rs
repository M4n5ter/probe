#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

mod accept;
mod close;
mod connect;
mod payload;
mod read;
mod sockaddr;
mod write;

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use ebpf_abi::{
    EBPF_ALLOWED_PROCESS_TGIDS_MAX_ENTRIES, EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES,
    EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES, EBPF_PENDING_ACCEPTS_MAX_ENTRIES,
    EBPF_PENDING_CONNECTS_MAX_ENTRIES, EBPF_PENDING_READS_MAX_ENTRIES,
    EBPF_PENDING_WRITE_SCRATCH_MAX_ENTRIES, EBPF_PENDING_WRITES_MAX_ENTRIES,
    EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES, EBPF_PROCESS_OUTPUT_LOSSES_MAX_ENTRIES,
    EBPF_PROCESS_READ_EVENT_SCRATCH_MAX_ENTRIES, EBPF_PROCESS_TRACEPOINT_FIRINGS_MAX_ENTRIES,
    EBPF_RING_BUFFER_BYTES, EBPF_SOCKET_FD_GENERATIONS_MAX_ENTRIES,
    EBPF_SOCKET_PAYLOAD_ALLOW_READ, EBPF_SOCKET_PAYLOAD_ALLOW_WRITE,
    EbpfAcceptTracepointRecord, EbpfCloseObservation, EbpfCloseRangeTracepointRecord,
    EbpfCloseTracepointRecord, EbpfConnectTracepointRecord, EbpfPendingSocketAcceptAttempt,
    EbpfPendingSocketConnectAttempt, EbpfPendingSocketReadAttempt, EbpfPendingSocketWriteSample,
    EbpfProcessLifecycleRecord, EbpfProcessPayloadAllowance, EbpfProcessProbeMetadata,
    EbpfProcessTracepointRole, EbpfSocketFdKey, EbpfSocketPayloadAllowance,
    EbpfSocketReadSampleRecord, EbpfSocketWriteSampleRecord,
};

use accept::{accept_attempt_from_tracepoint, accept_observation_from_result};
use close::{close_observation_from_tracepoint, close_range_observation_from_tracepoint};
use connect::{connect_attempt_from_tracepoint, connect_observation_from_result};
use read::{
    capture_read_sample_from_result, pending_read_attempt_from_source, read_source_from_tracepoint,
    readv_source_from_tracepoint, recvmsg_source_from_tracepoint,
};
use write::{
    capture_kernel_transfer_write_gap, capture_write_sample_from_source, pending_write_metadata,
    sendfile_out_fd_from_tracepoint, sendmsg_source_from_tracepoint, trim_write_sample_to_result,
    write_source_from_tracepoint, writev_source_from_tracepoint,
};

const FCNTL_CMD_OFFSET: usize = 24;
const F_DUPFD: u64 = 0;
const F_DUPFD_CLOEXEC: u64 = 1030;

#[map(name = "TRAFFIC_PROBE_EVENTS")]
static TRAFFIC_PROBE_EVENTS: RingBuf = RingBuf::with_byte_size(EBPF_RING_BUFFER_BYTES, 0);

#[map(name = "TRAFFIC_PROBE_ALLOWED_SOCKET_FDS")]
static TRAFFIC_PROBE_ALLOWED_SOCKET_FDS: LruHashMap<EbpfSocketFdKey, EbpfSocketPayloadAllowance> =
    LruHashMap::with_max_entries(EBPF_ALLOWED_SOCKET_FDS_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_ALLOWED_PROCESS_TGIDS")]
static TRAFFIC_PROBE_ALLOWED_PROCESS_TGIDS: LruHashMap<u32, EbpfProcessPayloadAllowance> =
    LruHashMap::with_max_entries(EBPF_ALLOWED_PROCESS_TGIDS_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_FD_TABLE_EPOCHS")]
static TRAFFIC_PROBE_FD_TABLE_EPOCHS: HashMap<u32, u64> =
    HashMap::with_max_entries(EBPF_FD_TABLE_EPOCHS_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_SOCKET_FD_GENERATIONS")]
static TRAFFIC_PROBE_SOCKET_FD_GENERATIONS: HashMap<EbpfSocketFdKey, u64> =
    HashMap::with_max_entries(EBPF_SOCKET_FD_GENERATIONS_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PENDING_CONNECTS")]
static TRAFFIC_PROBE_PENDING_CONNECTS: HashMap<u64, EbpfPendingSocketConnectAttempt> =
    HashMap::with_max_entries(EBPF_PENDING_CONNECTS_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PENDING_ACCEPTS")]
static TRAFFIC_PROBE_PENDING_ACCEPTS: HashMap<u64, EbpfPendingSocketAcceptAttempt> =
    HashMap::with_max_entries(EBPF_PENDING_ACCEPTS_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PENDING_WRITES")]
static TRAFFIC_PROBE_PENDING_WRITES: HashMap<u64, EbpfPendingSocketWriteSample> =
    HashMap::with_max_entries(EBPF_PENDING_WRITES_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PENDING_WRITE_SCRATCH")]
static TRAFFIC_PROBE_PENDING_WRITE_SCRATCH: PerCpuArray<EbpfPendingSocketWriteSample> =
    PerCpuArray::with_max_entries(EBPF_PENDING_WRITE_SCRATCH_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PENDING_READS")]
static TRAFFIC_PROBE_PENDING_READS: HashMap<u64, EbpfPendingSocketReadAttempt> =
    HashMap::with_max_entries(EBPF_PENDING_READS_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PROCESS_EVENT_SCRATCH")]
static TRAFFIC_PROBE_PROCESS_EVENT_SCRATCH: PerCpuArray<EbpfSocketWriteSampleRecord> =
    PerCpuArray::with_max_entries(EBPF_PROCESS_EVENT_SCRATCH_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PROCESS_READ_EVENT_SCRATCH")]
static TRAFFIC_PROBE_PROCESS_READ_EVENT_SCRATCH: PerCpuArray<EbpfSocketReadSampleRecord> =
    PerCpuArray::with_max_entries(EBPF_PROCESS_READ_EVENT_SCRATCH_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PROCESS_OUTPUT_LOSSES")]
static TRAFFIC_PROBE_PROCESS_OUTPUT_LOSSES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(EBPF_PROCESS_OUTPUT_LOSSES_MAX_ENTRIES, 0);

#[map(name = "TRAFFIC_PROBE_PROCESS_TRACEPOINT_FIRINGS")]
static TRAFFIC_PROBE_PROCESS_TRACEPOINT_FIRINGS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(EBPF_PROCESS_TRACEPOINT_FIRINGS_MAX_ENTRIES, 0);

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
pub fn traffic_probe_sys_enter_connect(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::ConnectEnter);
    record_connect_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_connect", category = "syscalls")]
pub fn traffic_probe_sys_exit_connect(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::ConnectExit);
    emit_connect_observation(ctx);
    0
}

#[tracepoint(name = "sys_enter_accept", category = "syscalls")]
pub fn traffic_probe_sys_enter_accept(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::AcceptEnter);
    record_accept_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_accept", category = "syscalls")]
pub fn traffic_probe_sys_exit_accept(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::AcceptExit);
    emit_accept_observation(ctx);
    0
}

#[tracepoint(name = "sys_enter_accept4", category = "syscalls")]
pub fn traffic_probe_sys_enter_accept4(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::Accept4Enter);
    record_accept_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_accept4", category = "syscalls")]
pub fn traffic_probe_sys_exit_accept4(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::Accept4Exit);
    emit_accept_observation(ctx);
    0
}

#[tracepoint(name = "sys_enter_close", category = "syscalls")]
pub fn traffic_probe_sys_enter_close(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::CloseEnter);
    emit_close_attempt(ctx);
    0
}

#[tracepoint(name = "sys_enter_dup", category = "syscalls")]
pub fn traffic_probe_sys_enter_dup(_ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::DupEnter);
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sys_enter_dup2", category = "syscalls")]
pub fn traffic_probe_sys_enter_dup2(_ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::Dup2Enter);
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sys_enter_dup3", category = "syscalls")]
pub fn traffic_probe_sys_enter_dup3(_ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::Dup3Enter);
    invalidate_current_fd_table();
    0
}

#[tracepoint(name = "sys_enter_fcntl", category = "syscalls")]
pub fn traffic_probe_sys_enter_fcntl(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::FcntlEnter);
    if fcntl_may_create_fd(&ctx) {
        invalidate_current_fd_table();
    }
    0
}

#[tracepoint(name = "sys_enter_close_range", category = "syscalls")]
pub fn traffic_probe_sys_enter_close_range(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::CloseRangeEnter);
    emit_close_range_attempt(ctx);
    0
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn traffic_probe_sched_process_exit(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::ProcessExit);
    if current_pid() == current_tgid() {
        revoke_current_process_payload_allowance();
        invalidate_current_fd_table();
        emit_process_exit(ctx);
    }
    0
}

#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn traffic_probe_sched_process_exec(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::ProcessExec);
    revoke_current_process_payload_allowance();
    invalidate_current_fd_table();
    emit_process_exec(ctx);
    0
}

#[tracepoint(name = "sys_enter_write", category = "syscalls")]
pub fn traffic_probe_sys_enter_write(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::WriteEnter);
    record_write_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_write", category = "syscalls")]
pub fn traffic_probe_sys_exit_write(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::WriteExit);
    emit_write_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_sendto", category = "syscalls")]
pub fn traffic_probe_sys_enter_sendto(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::SendtoEnter);
    record_write_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_sendto", category = "syscalls")]
pub fn traffic_probe_sys_exit_sendto(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::SendtoExit);
    emit_write_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_writev", category = "syscalls")]
pub fn traffic_probe_sys_enter_writev(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::WritevEnter);
    record_writev_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_writev", category = "syscalls")]
pub fn traffic_probe_sys_exit_writev(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::WritevExit);
    emit_write_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_sendmsg", category = "syscalls")]
pub fn traffic_probe_sys_enter_sendmsg(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::SendmsgEnter);
    record_sendmsg_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_sendmsg", category = "syscalls")]
pub fn traffic_probe_sys_exit_sendmsg(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::SendmsgExit);
    emit_write_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_sendfile", category = "syscalls")]
pub fn traffic_probe_sys_enter_sendfile(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::SendfileEnter);
    record_sendfile_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_sendfile", category = "syscalls")]
pub fn traffic_probe_sys_exit_sendfile(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::SendfileExit);
    emit_write_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_sendfile64", category = "syscalls")]
pub fn traffic_probe_sys_enter_sendfile64(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::Sendfile64Enter);
    record_sendfile_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_sendfile64", category = "syscalls")]
pub fn traffic_probe_sys_exit_sendfile64(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::Sendfile64Exit);
    emit_write_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_read", category = "syscalls")]
pub fn traffic_probe_sys_enter_read(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::ReadEnter);
    record_read_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_read", category = "syscalls")]
pub fn traffic_probe_sys_exit_read(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::ReadExit);
    emit_read_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_recvfrom", category = "syscalls")]
pub fn traffic_probe_sys_enter_recvfrom(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::RecvfromEnter);
    record_read_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_recvfrom", category = "syscalls")]
pub fn traffic_probe_sys_exit_recvfrom(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::RecvfromExit);
    emit_read_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_readv", category = "syscalls")]
pub fn traffic_probe_sys_enter_readv(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::ReadvEnter);
    record_readv_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_readv", category = "syscalls")]
pub fn traffic_probe_sys_exit_readv(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::ReadvExit);
    emit_read_sample(ctx);
    0
}

#[tracepoint(name = "sys_enter_recvmsg", category = "syscalls")]
pub fn traffic_probe_sys_enter_recvmsg(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::RecvmsgEnter);
    record_recvmsg_attempt(ctx);
    0
}

#[tracepoint(name = "sys_exit_recvmsg", category = "syscalls")]
pub fn traffic_probe_sys_exit_recvmsg(ctx: TracePointContext) -> u32 {
    record_tracepoint_firing(EbpfProcessTracepointRole::RecvmsgExit);
    emit_read_sample(ctx);
    0
}

fn record_connect_attempt(ctx: TracePointContext) {
    let Some(attempt) = connect_attempt_from_tracepoint(&ctx) else {
        return;
    };
    let key = bpf_get_current_pid_tgid();
    let _ = TRAFFIC_PROBE_PENDING_CONNECTS.insert(&key, &attempt, 0);
}

fn emit_connect_observation(ctx: TracePointContext) {
    let key = bpf_get_current_pid_tgid();
    let Some(attempt) = (unsafe { TRAFFIC_PROBE_PENDING_CONNECTS.get(&key).copied() }) else {
        return;
    };
    let _ = TRAFFIC_PROBE_PENDING_CONNECTS.remove(&key);
    let Some(connect) = connect_observation_from_result(&ctx, attempt) else {
        return;
    };
    let metadata = process_metadata(&ctx);
    let lease = open_socket_fd_lease(metadata.tgid, connect.observation.fd);
    let observation = connect
        .observation
        .with_descriptor_lease(lease.fd_table_epoch, lease.fd_generation);
    let event = EbpfConnectTracepointRecord::connect_tracepoint_observed(
        metadata.pid,
        metadata.tgid,
        metadata.uid,
        metadata.gid,
        metadata.command,
        observation,
        connect.flags,
    );
    submit_process_event(&event);
}

fn record_accept_attempt(ctx: TracePointContext) {
    let Some(attempt) = accept_attempt_from_tracepoint(&ctx) else {
        return;
    };
    let key = bpf_get_current_pid_tgid();
    let _ = TRAFFIC_PROBE_PENDING_ACCEPTS.insert(&key, &attempt, 0);
}

fn emit_accept_observation(ctx: TracePointContext) {
    let key = bpf_get_current_pid_tgid();
    let Some(attempt) = (unsafe { TRAFFIC_PROBE_PENDING_ACCEPTS.get(&key).copied() }) else {
        return;
    };
    let _ = TRAFFIC_PROBE_PENDING_ACCEPTS.remove(&key);
    let Some(accept) = accept_observation_from_result(&ctx, attempt) else {
        return;
    };
    let metadata = process_metadata(&ctx);
    let lease = open_socket_fd_lease(metadata.tgid, accept.observation.fd);
    let observation = accept
        .observation
        .with_descriptor_lease(lease.fd_table_epoch, lease.fd_generation);
    let event = EbpfAcceptTracepointRecord::accept_tracepoint_observed(
        metadata.pid,
        metadata.tgid,
        metadata.uid,
        metadata.gid,
        metadata.command,
        observation,
        accept.flags,
    );
    submit_process_event(&event);
}

fn emit_close_attempt(ctx: TracePointContext) {
    let Some(close) = close_observation_from_tracepoint(&ctx) else {
        return;
    };
    let metadata = process_metadata(&ctx);
    let Some(fd_generation) = close_socket_fd_generation(metadata.tgid, close.fd) else {
        return;
    };
    let close = EbpfCloseObservation::observed(close.fd, fd_generation);
    untrack_socket_fd(close.fd);
    let event = EbpfCloseTracepointRecord::close_tracepoint_observed(
        metadata.pid,
        metadata.tgid,
        metadata.uid,
        metadata.gid,
        metadata.command,
        close,
    );
    submit_process_event(&event);
}

fn emit_close_range_attempt(ctx: TracePointContext) {
    let close_range = close_range_observation_from_tracepoint(&ctx);
    invalidate_current_fd_table();
    let Some(close_range) = close_range else {
        return;
    };
    let metadata = process_metadata(&ctx);
    let event = EbpfCloseRangeTracepointRecord::close_range_tracepoint_observed(
        metadata.pid,
        metadata.tgid,
        metadata.uid,
        metadata.gid,
        metadata.command,
        close_range,
    );
    submit_process_event(&event);
}

fn emit_process_exit(ctx: TracePointContext) {
    let metadata = process_metadata(&ctx);
    let event = EbpfProcessLifecycleRecord::process_exit_observed(
        metadata.pid,
        metadata.tgid,
        metadata.uid,
        metadata.gid,
        metadata.command,
    );
    submit_process_event(&event);
}

fn emit_process_exec(ctx: TracePointContext) {
    let metadata = process_metadata(&ctx);
    let event = EbpfProcessLifecycleRecord::process_exec_observed(
        metadata.pid,
        metadata.tgid,
        metadata.uid,
        metadata.gid,
        metadata.command,
    );
    submit_process_event(&event);
}

fn record_write_attempt(ctx: TracePointContext) {
    let Some(source) = write_source_from_tracepoint(&ctx) else {
        return;
    };
    record_write_payload_attempt(source);
}

fn record_writev_attempt(ctx: TracePointContext) {
    let Some(source) = writev_source_from_tracepoint(&ctx) else {
        return;
    };
    record_write_payload_attempt(source);
}

fn record_sendmsg_attempt(ctx: TracePointContext) {
    let Some(source) = sendmsg_source_from_tracepoint(&ctx) else {
        return;
    };
    record_write_payload_attempt(source);
}

fn record_sendfile_attempt(ctx: TracePointContext) {
    let Some(fd) = sendfile_out_fd_from_tracepoint(&ctx) else {
        return;
    };
    record_kernel_transfer_write_gap(fd);
}

fn record_write_payload_attempt(source: payload::PayloadAttemptSource) {
    let Some(lease) = allowed_socket_payload_lease(source.fd, EBPF_SOCKET_PAYLOAD_ALLOW_WRITE)
    else {
        return;
    };
    let Some(pending) = pending_write_scratch() else {
        return;
    };
    if capture_write_sample_from_source(source, pending).is_none() {
        return;
    }
    pending.fd_generation = lease.fd_generation;
    let key = bpf_get_current_pid_tgid();
    let _ = TRAFFIC_PROBE_PENDING_WRITES.insert(&key, pending, 0);
}

fn record_kernel_transfer_write_gap(fd: i32) {
    let Some(lease) = allowed_socket_payload_lease(fd, EBPF_SOCKET_PAYLOAD_ALLOW_WRITE) else {
        return;
    };
    let Some(pending) = pending_write_scratch() else {
        return;
    };
    capture_kernel_transfer_write_gap(fd, pending);
    pending.fd_generation = lease.fd_generation;
    let key = bpf_get_current_pid_tgid();
    let _ = TRAFFIC_PROBE_PENDING_WRITES.insert(&key, pending, 0);
}

fn emit_write_sample(ctx: TracePointContext) {
    let key = bpf_get_current_pid_tgid();
    let Some(pending_ptr) = TRAFFIC_PROBE_PENDING_WRITES.get_ptr_mut(&key) else {
        return;
    };
    let pending = unsafe { &mut *pending_ptr };
    if allowed_socket_payload_lease(pending.fd, EBPF_SOCKET_PAYLOAD_ALLOW_WRITE)
        .is_none_or(|lease| lease.fd_generation != pending.fd_generation)
    {
        let _ = TRAFFIC_PROBE_PENDING_WRITES.remove(&key);
        return;
    }
    if trim_write_sample_to_result(&ctx, pending).is_none() {
        let _ = TRAFFIC_PROBE_PENDING_WRITES.remove(&key);
        return;
    };
    let Some(event) = scratch_event() else {
        let _ = TRAFFIC_PROBE_PENDING_WRITES.remove(&key);
        return;
    };
    event.clear_sample();
    if !copy_captured_write_prefix(event, pending) {
        let _ = TRAFFIC_PROBE_PENDING_WRITES.remove(&key);
        return;
    }
    event.overwrite_socket_write_sampled_metadata(
        process_metadata(&ctx),
        pending_write_metadata(pending),
        pending.flags,
    );
    submit_process_event(event);
    let _ = TRAFFIC_PROBE_PENDING_WRITES.remove(&key);
}

fn record_read_attempt(ctx: TracePointContext) {
    let Some(source) = read_source_from_tracepoint(&ctx) else {
        return;
    };
    record_read_payload_attempt(source);
}

fn record_readv_attempt(ctx: TracePointContext) {
    let Some(source) = readv_source_from_tracepoint(&ctx) else {
        return;
    };
    record_read_payload_attempt(source);
}

fn record_recvmsg_attempt(ctx: TracePointContext) {
    let Some(source) = recvmsg_source_from_tracepoint(&ctx) else {
        return;
    };
    record_read_payload_attempt(source);
}

fn record_read_payload_attempt(source: payload::PayloadAttemptSource) {
    let Some(lease) = allowed_socket_payload_lease(source.fd, EBPF_SOCKET_PAYLOAD_ALLOW_READ)
    else {
        return;
    };
    let Some(mut attempt) = pending_read_attempt_from_source(source) else {
        return;
    };
    attempt.fd_generation = lease.fd_generation;
    let key = bpf_get_current_pid_tgid();
    let _ = TRAFFIC_PROBE_PENDING_READS.insert(&key, &attempt, 0);
}

fn emit_read_sample(ctx: TracePointContext) {
    let key = bpf_get_current_pid_tgid();
    let Some(attempt) = (unsafe { TRAFFIC_PROBE_PENDING_READS.get(&key).copied() }) else {
        return;
    };
    if allowed_socket_payload_lease(attempt.fd, EBPF_SOCKET_PAYLOAD_ALLOW_READ)
        .is_none_or(|lease| lease.fd_generation != attempt.fd_generation)
    {
        let _ = TRAFFIC_PROBE_PENDING_READS.remove(&key);
        return;
    }
    let Some(event) = read_scratch_event() else {
        let _ = TRAFFIC_PROBE_PENDING_READS.remove(&key);
        return;
    };
    if capture_read_sample_from_result(&ctx, attempt, event).is_none() {
        let _ = TRAFFIC_PROBE_PENDING_READS.remove(&key);
        return;
    }
    submit_process_event(event);
    let _ = TRAFFIC_PROBE_PENDING_READS.remove(&key);
}

fn submit_process_event<T>(event: &T) {
    if TRAFFIC_PROBE_EVENTS.output(event, 0).is_err() {
        record_process_output_loss();
    }
}

fn record_process_output_loss() {
    let Some(losses) = TRAFFIC_PROBE_PROCESS_OUTPUT_LOSSES.get_ptr_mut(0) else {
        return;
    };
    unsafe {
        *losses = (*losses).saturating_add(1);
    }
}

fn record_tracepoint_firing(role: EbpfProcessTracepointRole) {
    let Some(firings) = TRAFFIC_PROBE_PROCESS_TRACEPOINT_FIRINGS.get_ptr_mut(role.counter_index())
    else {
        return;
    };
    unsafe {
        *firings = (*firings).saturating_add(1);
    }
}

fn pending_write_scratch() -> Option<&'static mut EbpfPendingSocketWriteSample> {
    let ptr = TRAFFIC_PROBE_PENDING_WRITE_SCRATCH.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}

fn scratch_event() -> Option<&'static mut EbpfSocketWriteSampleRecord> {
    let ptr = TRAFFIC_PROBE_PROCESS_EVENT_SCRATCH.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}

fn read_scratch_event() -> Option<&'static mut EbpfSocketReadSampleRecord> {
    let ptr = TRAFFIC_PROBE_PROCESS_READ_EVENT_SCRATCH.get_ptr_mut(0)?;
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

#[derive(Clone, Copy)]
struct SocketFdLease {
    fd_table_epoch: u64,
    fd_generation: u64,
}

fn allowed_socket_payload_lease(fd: i32, direction: u8) -> Option<SocketFdLease> {
    if fd < 0 {
        return None;
    }
    let tgid = current_tgid();
    let key = EbpfSocketFdKey::new(tgid, fd);
    if let Some(allowance) = unsafe { TRAFFIC_PROBE_ALLOWED_SOCKET_FDS.get(&key).copied() } {
        if allowance.fd_table_epoch != 0
            && allowance.fd_generation != 0
            && allowance.allows(direction)
            && current_fd_table_epoch(tgid).is_some_and(|epoch| epoch == allowance.fd_table_epoch)
            && current_active_socket_fd_generation(tgid, fd)
                .is_some_and(|generation| generation == allowance.fd_generation)
        {
            return Some(SocketFdLease {
                fd_table_epoch: allowance.fd_table_epoch,
                fd_generation: allowance.fd_generation,
            });
        }
    }
    allowed_process_payload_lease(tgid, fd, direction)
}

fn allowed_process_payload_lease(tgid: u32, fd: i32, direction: u8) -> Option<SocketFdLease> {
    let allowance = unsafe { TRAFFIC_PROBE_ALLOWED_PROCESS_TGIDS.get(&tgid).copied() }?;
    if !allowance.allows(direction) {
        return None;
    }
    Some(SocketFdLease {
        fd_table_epoch: current_fd_table_epoch(tgid)?,
        fd_generation: current_active_socket_fd_generation(tgid, fd)?,
    })
}

fn revoke_current_process_payload_allowance() {
    let tgid = current_tgid();
    let _ = TRAFFIC_PROBE_ALLOWED_PROCESS_TGIDS.remove(&tgid);
}

fn untrack_socket_fd(fd: i32) {
    if fd < 0 {
        return;
    }
    let key = EbpfSocketFdKey::new(current_tgid(), fd);
    let _ = TRAFFIC_PROBE_ALLOWED_SOCKET_FDS.remove(&key);
}

fn invalidate_current_fd_table() {
    let tgid = current_tgid();
    let next_epoch = next_fd_table_epoch(tgid);
    let _ = TRAFFIC_PROBE_FD_TABLE_EPOCHS.insert(&tgid, &next_epoch, 0);
}

fn ensure_fd_table_epoch(tgid: u32) -> u64 {
    if let Some(epoch) = current_fd_table_epoch(tgid) {
        return epoch;
    }
    let epoch = next_fd_table_epoch(tgid);
    if TRAFFIC_PROBE_FD_TABLE_EPOCHS
        .insert(&tgid, &epoch, 0)
        .is_ok()
    {
        epoch
    } else {
        0
    }
}

fn open_socket_fd_lease(tgid: u32, fd: i32) -> SocketFdLease {
    SocketFdLease {
        fd_table_epoch: ensure_fd_table_epoch(tgid),
        fd_generation: next_socket_fd_generation(tgid, fd).unwrap_or(0),
    }
}

fn next_socket_fd_generation(tgid: u32, fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    let key = EbpfSocketFdKey::new(tgid, fd);
    let next_generation = next_active_socket_fd_generation(current_socket_fd_generation(tgid, fd));
    TRAFFIC_PROBE_SOCKET_FD_GENERATIONS
        .insert(&key, &next_generation, 0)
        .ok()?;
    Some(next_generation)
}

fn close_socket_fd_generation(tgid: u32, fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    let generation = current_active_socket_fd_generation(tgid, fd)?;
    let inactive_generation = inactive_socket_fd_generation(generation);
    let key = EbpfSocketFdKey::new(tgid, fd);
    let _ = TRAFFIC_PROBE_SOCKET_FD_GENERATIONS.insert(&key, &inactive_generation, 0);
    Some(generation)
}

fn current_active_socket_fd_generation(tgid: u32, fd: i32) -> Option<u64> {
    let generation = current_socket_fd_generation(tgid, fd)?;
    is_active_socket_fd_generation(generation).then_some(generation)
}

fn current_socket_fd_generation(tgid: u32, fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    unsafe {
        TRAFFIC_PROBE_SOCKET_FD_GENERATIONS
            .get(&EbpfSocketFdKey::new(tgid, fd))
            .copied()
    }
}

fn next_active_socket_fd_generation(current: Option<u64>) -> u64 {
    let mut next_generation = current.unwrap_or(0).wrapping_add(1);
    if next_generation == 0 {
        next_generation = 1;
    }
    if !is_active_socket_fd_generation(next_generation) {
        next_generation = next_generation.wrapping_add(1);
        if next_generation == 0 {
            next_generation = 1;
        }
    }
    next_generation
}

fn inactive_socket_fd_generation(active_generation: u64) -> u64 {
    let mut inactive_generation = active_generation.wrapping_add(1);
    if inactive_generation == 0 {
        inactive_generation = 2;
    }
    if is_active_socket_fd_generation(inactive_generation) {
        inactive_generation = inactive_generation.wrapping_add(1);
        if inactive_generation == 0 {
            inactive_generation = 2;
        }
    }
    inactive_generation
}

fn is_active_socket_fd_generation(generation: u64) -> bool {
    generation != 0 && generation & 1 == 1
}

fn next_fd_table_epoch(tgid: u32) -> u64 {
    let mut next_epoch = current_fd_table_epoch(tgid).unwrap_or(0).wrapping_add(1);
    if next_epoch == 0 {
        next_epoch = 1;
    }
    next_epoch
}

fn current_fd_table_epoch(tgid: u32) -> Option<u64> {
    unsafe { TRAFFIC_PROBE_FD_TABLE_EPOCHS.get(&tgid).copied() }
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
            EbpfSocketWriteSample::new(0, 0, 0, 0, [0x7f; EBPF_SOCKET_WRITE_SAMPLE_BYTES]),
            0,
        );
        let mut pending = EbpfPendingSocketWriteSample {
            fd: 7,
            original_len: 3,
            fd_generation: 10,
            captured_len: 3,
            flags: 0,
            _reserved: 0,
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

    #[test]
    fn socket_fd_generation_parity_tracks_active_descriptors() {
        assert_eq!(next_active_socket_fd_generation(None), 1);
        assert_eq!(next_active_socket_fd_generation(Some(1)), 3);
        assert_eq!(inactive_socket_fd_generation(3), 4);
        assert_eq!(next_active_socket_fd_generation(Some(4)), 5);
        assert!(is_active_socket_fd_generation(5));
        assert!(!is_active_socket_fd_generation(4));
        assert!(!is_active_socket_fd_generation(0));
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

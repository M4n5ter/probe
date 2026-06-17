use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, LruHashMap, PerCpuArray},
    programs::{ProbeContext, RetProbeContext},
};
use ebpf_abi::{
    EBPF_TLS_CALL_KIND_CLEAR, EBPF_TLS_CALL_KIND_LEN_RETURN, EBPF_TLS_CALL_KIND_SET_FD,
    EBPF_TLS_CALL_KIND_SIZE_POINTER, EBPF_TLS_CALLS_MAX_ENTRIES,
    EBPF_TLS_EVENT_SCRATCH_MAX_ENTRIES, EBPF_TLS_FDS_MAX_ENTRIES, EBPF_TLS_OFFSETS_MAX_ENTRIES,
    EBPF_TLS_PLAINTEXT_FD_VALID, EBPF_TLS_PLAINTEXT_READ_FAILED, EBPF_TLS_PLAINTEXT_SAMPLE_BYTES,
    EBPF_TLS_PLAINTEXT_TRUNCATED, EBPF_TLS_STATE_EPOCH_KEY, EBPF_TLS_STATE_EPOCHS_MAX_ENTRIES,
    EbpfTlsCallKey, EbpfTlsCallState, EbpfTlsDirection, EbpfTlsFdKey, EbpfTlsOffsetKey,
    EbpfTlsPlaintextEvent, EbpfTlsPlaintextEventMetadata, EbpfTlsPlaintextMetadata,
};

#[map(name = "SSSA_TLS_CALLS")]
static SSSA_TLS_CALLS: HashMap<EbpfTlsCallKey, EbpfTlsCallState> =
    HashMap::with_max_entries(EBPF_TLS_CALLS_MAX_ENTRIES, 0);

#[map(name = "SSSA_TLS_FDS")]
static SSSA_TLS_FDS: LruHashMap<EbpfTlsFdKey, i32> =
    LruHashMap::with_max_entries(EBPF_TLS_FDS_MAX_ENTRIES, 0);

#[map(name = "SSSA_TLS_OFFSETS")]
static SSSA_TLS_OFFSETS: LruHashMap<EbpfTlsOffsetKey, u64> =
    LruHashMap::with_max_entries(EBPF_TLS_OFFSETS_MAX_ENTRIES, 0);

#[map(name = "SSSA_TLS_STATE_EPOCHS")]
static SSSA_TLS_STATE_EPOCHS: HashMap<u32, u64> =
    HashMap::with_max_entries(EBPF_TLS_STATE_EPOCHS_MAX_ENTRIES, 0);

#[map(name = "SSSA_TLS_EVENT_SCRATCH")]
static SSSA_TLS_EVENT_SCRATCH: PerCpuArray<EbpfTlsPlaintextEvent> =
    PerCpuArray::with_max_entries(EBPF_TLS_EVENT_SCRATCH_MAX_ENTRIES, 0);

#[uprobe]
pub fn sssa_ssl_set_fd(ctx: ProbeContext) -> u32 {
    ssl_set_fd_enter(ctx);
    0
}

#[uretprobe]
pub fn sssa_ssl_set_fd_exit(ctx: RetProbeContext) -> u32 {
    ssl_set_fd_exit(ctx);
    0
}

#[uprobe]
pub fn sssa_ssl_clear(ctx: ProbeContext) -> u32 {
    ssl_clear_enter(ctx);
    0
}

#[uretprobe]
pub fn sssa_ssl_clear_exit(ctx: RetProbeContext) -> u32 {
    ssl_clear_exit(ctx);
    0
}

#[uprobe]
pub fn sssa_ssl_free(ctx: ProbeContext) -> u32 {
    ssl_free(ctx);
    0
}

#[uprobe]
pub fn sssa_ssl_read_enter(ctx: ProbeContext) -> u32 {
    ssl_read_enter(ctx);
    0
}

#[uretprobe]
pub fn sssa_ssl_read_exit(ctx: RetProbeContext) -> u32 {
    ssl_read_exit(ctx);
    0
}

#[uprobe]
pub fn sssa_ssl_write_enter(ctx: ProbeContext) -> u32 {
    ssl_write_enter(ctx);
    0
}

#[uretprobe]
pub fn sssa_ssl_write_exit(ctx: RetProbeContext) -> u32 {
    ssl_write_exit(ctx);
    0
}

#[uprobe]
pub fn sssa_ssl_read_ex_enter(ctx: ProbeContext) -> u32 {
    ssl_read_ex_enter(ctx);
    0
}

#[uretprobe]
pub fn sssa_ssl_read_ex_exit(ctx: RetProbeContext) -> u32 {
    ssl_read_ex_exit(ctx);
    0
}

#[uprobe]
pub fn sssa_ssl_write_ex_enter(ctx: ProbeContext) -> u32 {
    ssl_write_ex_enter(ctx);
    0
}

#[uretprobe]
pub fn sssa_ssl_write_ex_exit(ctx: RetProbeContext) -> u32 {
    ssl_write_ex_exit(ctx);
    0
}

fn ssl_set_fd_enter(ctx: ProbeContext) {
    let Some(ssl_pointer) = non_null_arg(&ctx, 0) else {
        return;
    };
    let Some(fd) = ctx.arg::<i32>(1) else {
        return;
    };
    if fd < 0 {
        return;
    }
    store_call(EbpfTlsCallState::fd_association(ssl_pointer, fd));
}

fn ssl_set_fd_exit(ctx: RetProbeContext) {
    let Some(state) = take_fd_association_call() else {
        return;
    };
    let Some(success) = ctx.ret::<i32>() else {
        return;
    };
    if success != 1 || state.fd < 0 {
        return;
    }
    let tgid = current_tgid();
    if !state_epoch_is_current(state.state_epoch) {
        return;
    }
    associate_fd(tgid, state.state_epoch, state.ssl_pointer, state.fd);
}

fn ssl_clear_enter(ctx: ProbeContext) {
    let Some(ssl_pointer) = non_null_arg(&ctx, 0) else {
        return;
    };
    store_call(EbpfTlsCallState::clear(ssl_pointer));
}

fn ssl_clear_exit(ctx: RetProbeContext) {
    let Some(state) = take_clear_call() else {
        return;
    };
    let Some(success) = ctx.ret::<i32>() else {
        return;
    };
    if success == 1 {
        let tgid = current_tgid();
        if !state_epoch_is_current(state.state_epoch) {
            return;
        }
        reset_offsets(tgid, state.state_epoch, state.ssl_pointer);
    }
}

fn ssl_free(ctx: ProbeContext) {
    let Some(ssl_pointer) = non_null_arg(&ctx, 0) else {
        return;
    };
    let tgid = current_tgid();
    let Some(state_epoch) = current_state_epoch() else {
        return;
    };
    cleanup_tls_state(tgid, state_epoch, ssl_pointer);
}

fn ssl_read_enter(ctx: ProbeContext) {
    record_len_return_call(ctx, EbpfTlsDirection::Inbound);
}

fn ssl_write_enter(ctx: ProbeContext) {
    record_len_return_call(ctx, EbpfTlsDirection::Outbound);
}

fn ssl_read_exit(ctx: RetProbeContext) {
    complete_len_return_call(ctx);
}

fn ssl_write_exit(ctx: RetProbeContext) {
    complete_len_return_call(ctx);
}

fn ssl_read_ex_enter(ctx: ProbeContext) {
    record_size_pointer_call(ctx, EbpfTlsDirection::Inbound);
}

fn ssl_write_ex_enter(ctx: ProbeContext) {
    record_size_pointer_call(ctx, EbpfTlsDirection::Outbound);
}

fn ssl_read_ex_exit(ctx: RetProbeContext) {
    complete_size_pointer_call(ctx);
}

fn ssl_write_ex_exit(ctx: RetProbeContext) {
    complete_size_pointer_call(ctx);
}

fn record_len_return_call(ctx: ProbeContext, direction: EbpfTlsDirection) {
    let Some(ssl_pointer) = non_null_arg(&ctx, 0) else {
        return;
    };
    let Some(buffer_pointer) = non_null_arg(&ctx, 1) else {
        return;
    };
    let Some(requested_len) = positive_i32_arg(&ctx, 2) else {
        return;
    };
    store_call(EbpfTlsCallState::len_return_plaintext(
        ssl_pointer,
        buffer_pointer,
        requested_len,
        direction,
    ));
}

fn record_size_pointer_call(ctx: ProbeContext, direction: EbpfTlsDirection) {
    let Some(ssl_pointer) = non_null_arg(&ctx, 0) else {
        return;
    };
    let Some(buffer_pointer) = non_null_arg(&ctx, 1) else {
        return;
    };
    let Some(requested_len) = ctx.arg::<usize>(2) else {
        return;
    };
    let Some(length_pointer) = non_null_arg(&ctx, 3) else {
        return;
    };
    store_call(EbpfTlsCallState::size_pointer_plaintext(
        ssl_pointer,
        buffer_pointer,
        length_pointer,
        clamp_usize_to_u32(requested_len),
        direction,
    ));
}

fn complete_len_return_call(ctx: RetProbeContext) {
    let Some(state) = take_plaintext_call(EBPF_TLS_CALL_KIND_LEN_RETURN) else {
        return;
    };
    let Some(returned_len) = ctx.ret::<i32>() else {
        return;
    };
    if returned_len <= 0 {
        return;
    }
    if !state_epoch_is_current(state.state_epoch) {
        return;
    }
    emit_plaintext_event(&ctx, state, state.bounded_len(returned_len as u32));
}

fn complete_size_pointer_call(ctx: RetProbeContext) {
    let Some(state) = take_plaintext_call(EBPF_TLS_CALL_KIND_SIZE_POINTER) else {
        return;
    };
    let Some(success) = ctx.ret::<i32>() else {
        return;
    };
    if success != 1 {
        return;
    }
    if !state_epoch_is_current(state.state_epoch) {
        return;
    }
    let Some(returned_len) = read_size_pointer(state.length_pointer) else {
        emit_read_failed_event(&ctx, state);
        return;
    };
    let returned_len = clamp_usize_to_u32(returned_len);
    let original_len = state.bounded_len(returned_len);
    if original_len == 0 {
        return;
    }
    emit_plaintext_event(&ctx, state, original_len);
}

#[derive(Clone, Copy)]
struct FdAssociationCall {
    ssl_pointer: u64,
    state_epoch: u64,
    fd: i32,
}

#[derive(Clone, Copy)]
struct ClearCall {
    ssl_pointer: u64,
    state_epoch: u64,
}

#[derive(Clone, Copy)]
struct PlaintextCall {
    ssl_pointer: u64,
    state_epoch: u64,
    buffer_pointer: u64,
    length_pointer: u64,
    requested_len: u32,
    direction: EbpfTlsDirection,
}

impl FdAssociationCall {
    fn from_state(state: EbpfTlsCallState) -> Option<Self> {
        (state.call_kind == EBPF_TLS_CALL_KIND_SET_FD).then_some(Self {
            ssl_pointer: state.ssl_pointer,
            state_epoch: state.state_epoch,
            fd: state.fd,
        })
    }
}

impl ClearCall {
    fn from_state(state: EbpfTlsCallState) -> Option<Self> {
        (state.call_kind == EBPF_TLS_CALL_KIND_CLEAR).then_some(Self {
            ssl_pointer: state.ssl_pointer,
            state_epoch: state.state_epoch,
        })
    }
}

impl PlaintextCall {
    fn from_state(state: EbpfTlsCallState, call_kind: u8) -> Option<Self> {
        if state.call_kind != call_kind {
            return None;
        }
        Some(Self {
            ssl_pointer: state.ssl_pointer,
            state_epoch: state.state_epoch,
            buffer_pointer: state.buffer_pointer,
            length_pointer: state.length_pointer,
            requested_len: state.requested_len,
            direction: EbpfTlsDirection::from_wire_value(state.direction)?,
        })
    }

    fn bounded_len(self, returned_len: u32) -> u32 {
        core::cmp::min(returned_len, self.requested_len)
    }
}

fn store_call(mut state: EbpfTlsCallState) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(state_epoch) = current_state_epoch() else {
        return;
    };
    state.state_epoch = state_epoch;
    let key = EbpfTlsCallKey::new(pid_tgid);
    let _ = SSSA_TLS_CALLS.insert(&key, &state, 0);
}

fn take_call() -> Option<EbpfTlsCallState> {
    let key = EbpfTlsCallKey::new(bpf_get_current_pid_tgid());
    let state = unsafe { SSSA_TLS_CALLS.get(&key).copied() };
    let _ = SSSA_TLS_CALLS.remove(&key);
    state
}

fn take_fd_association_call() -> Option<FdAssociationCall> {
    FdAssociationCall::from_state(take_call()?)
}

fn take_clear_call() -> Option<ClearCall> {
    ClearCall::from_state(take_call()?)
}

fn take_plaintext_call(call_kind: u8) -> Option<PlaintextCall> {
    PlaintextCall::from_state(take_call()?, call_kind)
}

fn emit_read_failed_event(ctx: &impl EbpfContext, state: PlaintextCall) {
    let Some(event) = scratch_event() else {
        return;
    };
    event.clear_payload();
    emit_event(ctx, state, 0, 0, EBPF_TLS_PLAINTEXT_READ_FAILED, event);
}

fn emit_plaintext_event(ctx: &impl EbpfContext, state: PlaintextCall, original_len: u32) {
    let Some(event) = scratch_event() else {
        return;
    };
    event.clear_payload();
    let mut flags = 0;
    let captured_len = read_payload_sample(
        state.buffer_pointer,
        original_len,
        event.payload_mut(),
        &mut flags,
    );
    emit_event(ctx, state, original_len, captured_len, flags, event);
}

fn emit_event(
    ctx: &impl EbpfContext,
    state: PlaintextCall,
    original_len: u32,
    captured_len: u16,
    mut flags: u16,
    event: &mut EbpfTlsPlaintextEvent,
) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let tgid = (pid_tgid >> 32) as u32;
    if !state_epoch_is_current(state.state_epoch) {
        return;
    }
    let (fd, fd_flags) = fd_for(tgid, state.state_epoch, state.ssl_pointer);
    flags |= fd_flags;
    let stream_offset = next_stream_offset(
        tgid,
        state.state_epoch,
        state.ssl_pointer,
        state.direction,
        original_len,
    );
    let direction = state.direction.wire_value();
    event.overwrite_libssl_plaintext_sampled_metadata(EbpfTlsPlaintextEventMetadata {
        pid: pid_tgid as u32,
        tgid,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        command: ctx.command().unwrap_or_default(),
        flags,
        observation: EbpfTlsPlaintextMetadata {
            ssl_pointer: state.ssl_pointer,
            fd,
            direction,
            stream_offset,
            original_len,
            captured_len,
        },
    });
    unsafe {
        crate::submit_tls_plaintext_event(event as *const EbpfTlsPlaintextEvent);
    }
}

fn read_payload_sample(
    buffer_pointer: u64,
    original_len: u32,
    payload: &mut [u8; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES],
    flags: &mut u16,
) -> u16 {
    if original_len == 0 {
        return 0;
    }
    if original_len > EBPF_TLS_PLAINTEXT_SAMPLE_BYTES as u32 {
        *flags |= EBPF_TLS_PLAINTEXT_TRUNCATED;
    }
    let captured_len = core::cmp::min(original_len, EBPF_TLS_PLAINTEXT_SAMPLE_BYTES as u32) as u16;
    let Some(sample) = payload.get_mut(..usize::from(captured_len)) else {
        *flags |= EBPF_TLS_PLAINTEXT_READ_FAILED;
        return 0;
    };
    if unsafe { bpf_probe_read_user_buf(buffer_pointer as *const u8, sample) }.is_err() {
        *flags |= EBPF_TLS_PLAINTEXT_READ_FAILED;
        return 0;
    }
    captured_len
}

fn scratch_event() -> Option<&'static mut EbpfTlsPlaintextEvent> {
    let ptr = SSSA_TLS_EVENT_SCRATCH.get_ptr_mut(0)?;
    Some(unsafe { &mut *ptr })
}

fn fd_for(tgid: u32, state_epoch: u64, ssl_pointer: u64) -> (i32, u16) {
    let key = EbpfTlsFdKey::new(tgid, state_epoch, ssl_pointer);
    match unsafe { SSSA_TLS_FDS.get(&key) } {
        Some(fd) => (*fd, EBPF_TLS_PLAINTEXT_FD_VALID),
        None => (-1, 0),
    }
}

fn next_stream_offset(
    tgid: u32,
    state_epoch: u64,
    ssl_pointer: u64,
    direction: EbpfTlsDirection,
    original_len: u32,
) -> u64 {
    let key = EbpfTlsOffsetKey::new(tgid, direction.wire_value(), state_epoch, ssl_pointer);
    let current = unsafe { SSSA_TLS_OFFSETS.get(&key).copied().unwrap_or(0) };
    let next = current.saturating_add(u64::from(original_len));
    let _ = SSSA_TLS_OFFSETS.insert(&key, &next, 0);
    current
}

fn associate_fd(tgid: u32, state_epoch: u64, ssl_pointer: u64, fd: i32) {
    reset_offsets(tgid, state_epoch, ssl_pointer);
    let key = EbpfTlsFdKey::new(tgid, state_epoch, ssl_pointer);
    let _ = SSSA_TLS_FDS.insert(&key, &fd, 0);
}

fn cleanup_tls_state(tgid: u32, state_epoch: u64, ssl_pointer: u64) {
    reset_offsets(tgid, state_epoch, ssl_pointer);
    let key = EbpfTlsFdKey::new(tgid, state_epoch, ssl_pointer);
    let _ = SSSA_TLS_FDS.remove(&key);
}

fn reset_offsets(tgid: u32, state_epoch: u64, ssl_pointer: u64) {
    remove_offset(tgid, state_epoch, ssl_pointer, EbpfTlsDirection::Inbound);
    remove_offset(tgid, state_epoch, ssl_pointer, EbpfTlsDirection::Outbound);
}

fn remove_offset(tgid: u32, state_epoch: u64, ssl_pointer: u64, direction: EbpfTlsDirection) {
    let key = EbpfTlsOffsetKey::new(tgid, direction.wire_value(), state_epoch, ssl_pointer);
    let _ = SSSA_TLS_OFFSETS.remove(&key);
}

fn current_state_epoch() -> Option<u64> {
    let key = EBPF_TLS_STATE_EPOCH_KEY;
    let epoch = unsafe { SSSA_TLS_STATE_EPOCHS.get(&key).copied()? };
    (epoch != 0).then_some(epoch)
}

fn state_epoch_is_current(state_epoch: u64) -> bool {
    match current_state_epoch() {
        Some(current_epoch) => current_epoch == state_epoch,
        None => false,
    }
}

fn read_size_pointer(length_pointer: u64) -> Option<usize> {
    unsafe { bpf_probe_read_user(length_pointer as *const usize).ok() }
}

fn non_null_arg(ctx: &ProbeContext, index: usize) -> Option<u64> {
    let value = ctx.arg::<u64>(index)?;
    (value != 0).then_some(value)
}

fn positive_i32_arg(ctx: &ProbeContext, index: usize) -> Option<u32> {
    let value = ctx.arg::<i32>(index)?;
    (value > 0).then_some(value as u32)
}

fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

fn clamp_usize_to_u32(value: usize) -> u32 {
    core::cmp::min(value, u32::MAX as usize) as u32
}

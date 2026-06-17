use aya_ebpf::{helpers::bpf_probe_read_user_buf, programs::TracePointContext};

const SYSCALL_FD_OFFSET: usize = 16;
const SYSCALL_USER_BUFFER_OFFSET: usize = 24;
const SYSCALL_COUNT_OFFSET: usize = 32;
const SYSCALL_EXIT_RETURN_OFFSET: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SingleBufferPayloadAttempt {
    pub fd: i32,
    pub user_buffer: u64,
    pub requested_len: u64,
}

pub(crate) fn single_buffer_payload_attempt_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<SingleBufferPayloadAttempt> {
    let fd = tracepoint_u64(ctx, SYSCALL_FD_OFFSET)? as i32;
    if fd < 0 {
        return None;
    }
    let user_buffer = tracepoint_u64(ctx, SYSCALL_USER_BUFFER_OFFSET)?;
    if user_buffer == 0 {
        return None;
    }
    let requested_len = tracepoint_u64(ctx, SYSCALL_COUNT_OFFSET)?;
    if requested_len == 0 {
        return None;
    }
    Some(SingleBufferPayloadAttempt {
        fd,
        user_buffer,
        requested_len,
    })
}

pub(crate) fn syscall_result_from_tracepoint(ctx: &TracePointContext) -> Option<i64> {
    tracepoint_i64(ctx, SYSCALL_EXIT_RETURN_OFFSET)
}

pub(crate) fn read_user_payload_prefix(
    user_buffer: u64,
    original_len: u32,
    buffer: &mut [u8],
    flags: &mut u16,
    truncated_flag: u16,
    read_failed_flag: u16,
) -> u16 {
    if original_len as usize > buffer.len() {
        *flags |= truncated_flag;
    }
    let captured_len = core::cmp::min(original_len as usize, buffer.len()) as u16;
    let Some(sample) = buffer.get_mut(..usize::from(captured_len)) else {
        *flags |= read_failed_flag;
        return 0;
    };
    if unsafe { bpf_probe_read_user_buf(user_buffer as *const u8, sample) }.is_err() {
        *flags |= read_failed_flag;
        return 0;
    }
    captured_len
}

pub(crate) fn clamp_u64_to_u32(value: u64) -> u32 {
    core::cmp::min(value, u64::from(u32::MAX)) as u32
}

fn tracepoint_u64(ctx: &TracePointContext, offset: usize) -> Option<u64> {
    // Offsets must match Linux tracefs syscall argument format; privileged e2e validation is required.
    unsafe { ctx.read_at::<u64>(offset) }.ok()
}

fn tracepoint_i64(ctx: &TracePointContext, offset: usize) -> Option<i64> {
    // Offsets must match Linux tracefs syscall exit format; privileged e2e validation is required.
    unsafe { ctx.read_at::<i64>(offset) }.ok()
}

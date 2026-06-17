use aya_ebpf::{helpers::bpf_probe_read_user_buf, programs::TracePointContext};

const SYSCALL_FD_OFFSET: usize = 16;
const SYSCALL_USER_BUFFER_OFFSET: usize = 24;
const SYSCALL_COUNT_OFFSET: usize = 32;
const SYSCALL_EXIT_RETURN_OFFSET: usize = 16;
// Linux x86_64 userspace ABI layout for iovec and msghdr msg_iov/msg_iovlen.
const USER_IOVEC_BASE_OFFSET: u64 = 0;
const USER_IOVEC_LEN_OFFSET: u64 = 8;
const USER_MSGHDR_IOV_OFFSET: u64 = 16;
const USER_MSGHDR_IOVLEN_OFFSET: u64 = 24;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PayloadBufferAttempt {
    pub fd: i32,
    pub user_buffer: u64,
    pub readable_len: u64,
    pub logical_len: PayloadLogicalLen,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadLogicalLen {
    Known(u64),
    UnknownUntilExit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PayloadAttemptSource {
    pub fd: i32,
    user_pointer: u64,
    count: u64,
    kind: PayloadAttemptKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadAttemptKind {
    SingleBuffer,
    Iovec,
    Msghdr,
}

pub(crate) fn single_buffer_payload_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    let fd = tracepoint_fd(ctx)?;
    let user_buffer = tracepoint_u64(ctx, SYSCALL_USER_BUFFER_OFFSET)?;
    if user_buffer == 0 {
        return None;
    }
    let requested_len = tracepoint_u64(ctx, SYSCALL_COUNT_OFFSET)?;
    if requested_len == 0 {
        return None;
    }
    Some(PayloadAttemptSource {
        fd,
        user_pointer: user_buffer,
        count: requested_len,
        kind: PayloadAttemptKind::SingleBuffer,
    })
}

pub(crate) fn iovec_payload_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    let fd = tracepoint_fd(ctx)?;
    let user_iovec = tracepoint_u64(ctx, SYSCALL_USER_BUFFER_OFFSET)?;
    let iovlen = tracepoint_u64(ctx, SYSCALL_COUNT_OFFSET)?;
    if user_iovec == 0 || iovlen == 0 {
        return None;
    }
    Some(PayloadAttemptSource {
        fd,
        user_pointer: user_iovec,
        count: iovlen,
        kind: PayloadAttemptKind::Iovec,
    })
}

pub(crate) fn msghdr_payload_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    let fd = tracepoint_fd(ctx)?;
    let user_msghdr = tracepoint_u64(ctx, SYSCALL_USER_BUFFER_OFFSET)?;
    if user_msghdr == 0 {
        return None;
    }
    Some(PayloadAttemptSource {
        fd,
        user_pointer: user_msghdr,
        count: 0,
        kind: PayloadAttemptKind::Msghdr,
    })
}

pub(crate) fn payload_attempt_from_source(
    source: PayloadAttemptSource,
) -> Option<PayloadBufferAttempt> {
    match source.kind {
        PayloadAttemptKind::SingleBuffer => Some(PayloadBufferAttempt {
            fd: source.fd,
            user_buffer: source.user_pointer,
            readable_len: source.count,
            logical_len: PayloadLogicalLen::Known(source.count),
        }),
        PayloadAttemptKind::Iovec => {
            payload_attempt_from_iovec(source.fd, source.user_pointer, source.count)
        }
        PayloadAttemptKind::Msghdr => {
            let user_iovec = read_user_u64(source.user_pointer + USER_MSGHDR_IOV_OFFSET)?;
            let iovlen = read_user_u64(source.user_pointer + USER_MSGHDR_IOVLEN_OFFSET)?;
            payload_attempt_from_iovec(source.fd, user_iovec, iovlen)
        }
    }
}

fn payload_attempt_from_iovec(
    fd: i32,
    user_iovec: u64,
    iovlen: u64,
) -> Option<PayloadBufferAttempt> {
    if user_iovec == 0 || iovlen == 0 {
        return None;
    }
    let user_buffer = read_user_u64(user_iovec + USER_IOVEC_BASE_OFFSET)?;
    let readable_len = read_user_u64(user_iovec + USER_IOVEC_LEN_OFFSET)?;
    if user_buffer == 0 && readable_len > 0 {
        return None;
    }
    // A zero-length first iovec can still be followed by later iovecs; keep an attempt
    // so the syscall exit path can emit a degraded gap for returned bytes.
    Some(PayloadBufferAttempt {
        fd,
        user_buffer,
        readable_len,
        logical_len: PayloadLogicalLen::UnknownUntilExit,
    })
}

pub(crate) fn syscall_result_from_tracepoint(ctx: &TracePointContext) -> Option<i64> {
    tracepoint_i64(ctx, SYSCALL_EXIT_RETURN_OFFSET)
}

pub(crate) fn read_user_payload_prefix(
    user_buffer: u64,
    readable_len: u32,
    logical_len: u32,
    buffer: &mut [u8],
    flags: &mut u16,
    truncated_flag: u16,
    read_failed_flag: u16,
) -> u16 {
    if logical_len as usize > buffer.len() || readable_len < logical_len {
        *flags |= truncated_flag;
    }
    let captured_len = core::cmp::min(readable_len as usize, buffer.len()) as u16;
    if captured_len == 0 {
        return 0;
    }
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

fn read_user_u64(address: u64) -> Option<u64> {
    let bytes = read_user_bytes::<8>(address)?;
    Some(u64::from_ne_bytes(bytes))
}

fn read_user_bytes<const N: usize>(address: u64) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    unsafe { bpf_probe_read_user_buf(address as *const u8, &mut bytes) }.ok()?;
    Some(bytes)
}

fn tracepoint_u64(ctx: &TracePointContext, offset: usize) -> Option<u64> {
    // Offsets must match Linux tracefs syscall argument format; privileged e2e validation is required.
    unsafe { ctx.read_at::<u64>(offset) }.ok()
}

fn tracepoint_fd(ctx: &TracePointContext) -> Option<i32> {
    let fd = tracepoint_u64(ctx, SYSCALL_FD_OFFSET)? as i32;
    if fd < 0 {
        return None;
    }
    Some(fd)
}

fn tracepoint_i64(ctx: &TracePointContext, offset: usize) -> Option<i64> {
    // Offsets must match Linux tracefs syscall exit format; privileged e2e validation is required.
    unsafe { ctx.read_at::<i64>(offset) }.ok()
}

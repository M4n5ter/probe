use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_probe_read_user_buf, r#gen},
    programs::TracePointContext,
};

const SYSCALL_FD_OFFSET: usize = 16;
const SYSCALL_USER_BUFFER_OFFSET: usize = 24;
const SYSCALL_COUNT_OFFSET: usize = 32;
const SYSCALL_EXIT_RETURN_OFFSET: usize = 16;
// Linux x86_64 userspace ABI layout for iovec and msghdr msg_iov/msg_iovlen.
const USER_IOVEC_BASE_OFFSET: u64 = 0;
const USER_IOVEC_LEN_OFFSET: u64 = 8;
const USER_MSGHDR_IOV_OFFSET: u64 = 16;
const USER_MSGHDR_IOVLEN_OFFSET: u64 = 24;
const USER_IOVEC_BYTES: u64 = 16;
const PAYLOAD_IOVEC_SCAN_LIMIT: u64 = 3;
const PAYLOAD_IOVEC_SECOND_CHUNK_OFFSET: usize = 64;
const PAYLOAD_IOVEC_THIRD_CHUNK_OFFSET: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PayloadBufferAttempt {
    pub fd: i32,
    pub user_buffer: u64,
    pub readable_len: u64,
    pub logical_len: PayloadLogicalLen,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PayloadIovecAttempt {
    pub fd: i32,
    pub user_iovec: u64,
    pub iovlen: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadSamplePlan {
    Buffer(PayloadBufferAttempt),
    Iovec(PayloadIovecAttempt),
}

impl PayloadSamplePlan {
    pub(crate) fn fd(self) -> i32 {
        match self {
            Self::Buffer(attempt) => attempt.fd,
            Self::Iovec(attempt) => attempt.fd,
        }
    }

    pub(crate) fn logical_len(self) -> PayloadLogicalLen {
        match self {
            Self::Buffer(attempt) => attempt.logical_len,
            Self::Iovec(_) => PayloadLogicalLen::UnknownUntilExit,
        }
    }
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

pub(crate) const fn payload_read_flag_bits(truncated_flag: u16, read_failed_flag: u16) -> u32 {
    truncated_flag as u32 | ((read_failed_flag as u32) << 16)
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

#[inline(always)]
pub(crate) fn payload_sample_plan_from_source(
    source: PayloadAttemptSource,
) -> Option<PayloadSamplePlan> {
    match source.kind {
        PayloadAttemptKind::SingleBuffer => Some(PayloadSamplePlan::Buffer(PayloadBufferAttempt {
            fd: source.fd,
            user_buffer: source.user_pointer,
            readable_len: source.count,
            logical_len: PayloadLogicalLen::Known(source.count),
        })),
        PayloadAttemptKind::Iovec => {
            iovec_payload_attempt(source.fd, source.user_pointer, source.count)
        }
        PayloadAttemptKind::Msghdr => {
            let user_iovec = read_user_u64(source.user_pointer + USER_MSGHDR_IOV_OFFSET)?;
            let iovlen = read_user_u64(source.user_pointer + USER_MSGHDR_IOVLEN_OFFSET)?;
            iovec_payload_attempt(source.fd, user_iovec, iovlen)
        }
    }
}

#[inline(always)]
fn iovec_payload_attempt(fd: i32, user_iovec: u64, iovlen: u64) -> Option<PayloadSamplePlan> {
    if user_iovec == 0 || iovlen == 0 {
        return None;
    }
    Some(PayloadSamplePlan::Iovec(PayloadIovecAttempt {
        fd,
        user_iovec,
        iovlen,
    }))
}

pub(crate) fn syscall_result_from_tracepoint(ctx: &TracePointContext) -> Option<i64> {
    tracepoint_i64(ctx, SYSCALL_EXIT_RETURN_OFFSET)
}

#[inline(always)]
pub(crate) fn read_user_payload_prefix<const SAMPLE_BYTES: usize>(
    user_buffer: u64,
    readable_len: u32,
    logical_len: u32,
    buffer: &mut [u8; SAMPLE_BYTES],
    flags: &mut u16,
    truncated_flag: u16,
    read_failed_flag: u16,
) -> u16 {
    if logical_len as usize > SAMPLE_BYTES || readable_len < logical_len {
        *flags |= truncated_flag;
    }
    let mut captured_len = readable_len;
    if captured_len > SAMPLE_BYTES as u32 {
        captured_len = SAMPLE_BYTES as u32;
    }
    let captured_len = captured_len as u16;
    if captured_len == 0 {
        return 0;
    }
    // The lower-level helper keeps the size bound visible to the verifier.
    let read_result = unsafe {
        r#gen::bpf_probe_read_user(
            buffer.as_mut_ptr() as *mut c_void,
            u32::from(captured_len),
            user_buffer as *const c_void,
        )
    };
    if read_result != 0 {
        *flags |= read_failed_flag;
        return 0;
    }
    captured_len
}

#[inline(always)]
pub(crate) fn read_payload_prefix_from_attempt<const SAMPLE_BYTES: usize>(
    attempt: PayloadBufferAttempt,
    expected_len_or_zero: u32,
    buffer: &mut [u8; SAMPLE_BYTES],
    flags: &mut u16,
    read_flag_bits: u32,
) -> u16 {
    let truncated_flag = (read_flag_bits & 0xffff) as u16;
    let read_failed_flag = (read_flag_bits >> 16) as u16;
    let copy_len = if expected_len_or_zero == 0 {
        clamp_usize_to_u32(SAMPLE_BYTES)
    } else {
        expected_len_or_zero
    };
    if copy_len == 0 {
        return 0;
    }
    let readable_len = core::cmp::min(clamp_u64_to_u32(attempt.readable_len), copy_len);
    let logical_len = if expected_len_or_zero == 0 {
        readable_len
    } else {
        expected_len_or_zero
    };
    read_user_payload_prefix(
        attempt.user_buffer,
        readable_len,
        logical_len,
        buffer,
        flags,
        truncated_flag,
        read_failed_flag,
    )
}

#[inline(always)]
pub(crate) fn read_payload_prefix_from_plan<const SAMPLE_BYTES: usize>(
    plan: PayloadSamplePlan,
    expected_len_or_zero: u32,
    buffer: &mut [u8; SAMPLE_BYTES],
    flags: &mut u16,
    read_flag_bits: u32,
) -> u16 {
    match plan {
        PayloadSamplePlan::Buffer(attempt) => read_payload_prefix_from_attempt(
            attempt,
            expected_len_or_zero,
            buffer,
            flags,
            read_flag_bits,
        ),
        PayloadSamplePlan::Iovec(attempt) => read_payload_prefix_from_iovec(
            attempt,
            expected_len_or_zero,
            buffer,
            flags,
            read_flag_bits,
        ),
    }
}

#[inline(always)]
pub(crate) fn read_payload_prefix_from_iovec<const SAMPLE_BYTES: usize>(
    attempt: PayloadIovecAttempt,
    expected_len_or_zero: u32,
    buffer: &mut [u8; SAMPLE_BYTES],
    flags: &mut u16,
    read_flag_bits: u32,
) -> u16 {
    let truncated_flag = (read_flag_bits & 0xffff) as u16;
    let read_failed_flag = (read_flag_bits >> 16) as u16;
    let sample_capacity = clamp_usize_to_u32(SAMPLE_BYTES);
    let copy_limit = if expected_len_or_zero == 0 {
        sample_capacity
    } else {
        core::cmp::min(expected_len_or_zero, sample_capacity)
    };
    if copy_limit == 0 {
        return 0;
    }

    let iovecs_to_scan = core::cmp::min(attempt.iovlen, PAYLOAD_IOVEC_SCAN_LIMIT);
    let mut index = 0u64;
    let mut captured = 0u32;
    while index < PAYLOAD_IOVEC_SCAN_LIMIT {
        if index >= iovecs_to_scan {
            break;
        }
        let Some((user_buffer, readable_len)) = read_iovec_entry(attempt.user_iovec, index) else {
            *flags |= read_failed_flag;
            return 0;
        };
        if readable_len == 0 {
            index += 1;
            continue;
        }
        if user_buffer == 0 {
            *flags |= read_failed_flag;
            return 0;
        }
        let remaining = copy_limit.saturating_sub(captured);
        if remaining == 0 {
            break;
        }
        let readable_len = core::cmp::min(clamp_u64_to_u32(readable_len), remaining);
        if readable_len == 0 {
            index += 1;
            continue;
        }
        let read_result = match captured as usize {
            0 => read_user_payload_chunk_at::<SAMPLE_BYTES, 0>(user_buffer, readable_len, buffer),
            PAYLOAD_IOVEC_SECOND_CHUNK_OFFSET => read_user_payload_chunk_at::<
                SAMPLE_BYTES,
                PAYLOAD_IOVEC_SECOND_CHUNK_OFFSET,
            >(user_buffer, readable_len, buffer),
            PAYLOAD_IOVEC_THIRD_CHUNK_OFFSET => read_user_payload_chunk_at::<
                SAMPLE_BYTES,
                PAYLOAD_IOVEC_THIRD_CHUNK_OFFSET,
            >(user_buffer, readable_len, buffer),
            _ => break,
        };
        if read_result == 0 {
            *flags |= read_failed_flag;
            return 0;
        }
        captured = captured.saturating_add(u32::from(read_result));
        if captured >= copy_limit {
            break;
        }
        index += 1;
    }

    if expected_len_or_zero != 0 && captured < expected_len_or_zero {
        *flags |= truncated_flag;
    }
    captured as u16
}

pub(crate) fn clamp_u64_to_u32(value: u64) -> u32 {
    core::cmp::min(value, u64::from(u32::MAX)) as u32
}

fn clamp_usize_to_u32(value: usize) -> u32 {
    core::cmp::min(value, u32::MAX as usize) as u32
}

fn read_user_u64(address: u64) -> Option<u64> {
    let bytes = read_user_bytes::<8>(address)?;
    Some(u64::from_ne_bytes(bytes))
}

#[inline(always)]
fn read_user_payload_chunk_at<const SAMPLE_BYTES: usize, const OUTPUT_OFFSET: usize>(
    user_buffer: u64,
    readable_len: u32,
    buffer: &mut [u8; SAMPLE_BYTES],
) -> u16 {
    let output_offset = OUTPUT_OFFSET as u32;
    if readable_len == 0 || output_offset >= SAMPLE_BYTES as u32 {
        return 0;
    }
    let capacity = (SAMPLE_BYTES as u32).saturating_sub(output_offset);
    let captured_len = core::cmp::min(readable_len, capacity) as u16;
    if captured_len == 0 {
        return 0;
    }
    let read_result = unsafe {
        r#gen::bpf_probe_read_user(
            buffer.as_mut_ptr().add(OUTPUT_OFFSET) as *mut c_void,
            u32::from(captured_len),
            user_buffer as *const c_void,
        )
    };
    if read_result != 0 {
        return 0;
    }
    captured_len
}

fn read_iovec_entry(user_iovec: u64, index: u64) -> Option<(u64, u64)> {
    let iovec_address = user_iovec.checked_add(index.saturating_mul(USER_IOVEC_BYTES))?;
    let user_buffer = read_user_u64(iovec_address + USER_IOVEC_BASE_OFFSET)?;
    let readable_len = read_user_u64(iovec_address + USER_IOVEC_LEN_OFFSET)?;
    Some((user_buffer, readable_len))
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

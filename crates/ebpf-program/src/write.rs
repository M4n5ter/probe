use aya_ebpf::{helpers::bpf_probe_read_user_buf, programs::TracePointContext};
use ebpf_abi::{
    EBPF_SOCKET_WRITE_READ_FAILED, EBPF_SOCKET_WRITE_SAMPLE_BYTES, EBPF_SOCKET_WRITE_TRUNCATED,
    EbpfPendingWrite, EbpfSocketWriteMetadata,
};

const WRITE_FD_OFFSET: usize = 16;
const WRITE_USER_BUFFER_OFFSET: usize = 24;
const WRITE_COUNT_OFFSET: usize = 32;
const WRITE_EXIT_RETURN_OFFSET: usize = 16;

pub(crate) struct WriteSampleResult {
    pub metadata: EbpfSocketWriteMetadata,
    pub flags: u16,
}

pub(crate) fn pending_write_from_tracepoint(ctx: &TracePointContext) -> Option<EbpfPendingWrite> {
    let fd = tracepoint_u64(ctx, WRITE_FD_OFFSET)? as i32;
    if fd < 0 {
        return None;
    }
    let user_buffer = tracepoint_u64(ctx, WRITE_USER_BUFFER_OFFSET)?;
    if user_buffer == 0 {
        return None;
    }
    let requested_len = tracepoint_u64(ctx, WRITE_COUNT_OFFSET)?;
    if requested_len == 0 {
        return None;
    }
    Some(EbpfPendingWrite::new(fd, user_buffer, requested_len))
}

pub(crate) fn socket_write_sample_from_tracepoint(
    ctx: &TracePointContext,
    pending: EbpfPendingWrite,
    buffer: &mut [u8],
) -> Option<WriteSampleResult> {
    let returned_len = tracepoint_i64(ctx, WRITE_EXIT_RETURN_OFFSET)?;
    if returned_len <= 0 {
        return None;
    }
    let written_len = core::cmp::min(returned_len as u64, pending.requested_len);
    let original_len = clamp_u64_to_u32(written_len);
    if original_len == 0 {
        return None;
    }
    let mut flags = 0;
    let captured_len = read_write_sample(pending.user_buffer, original_len, buffer, &mut flags);
    Some(WriteSampleResult {
        metadata: EbpfSocketWriteMetadata {
            fd: pending.fd,
            original_len,
            captured_len,
        },
        flags,
    })
}

fn read_write_sample(
    user_buffer: u64,
    original_len: u32,
    buffer: &mut [u8],
    flags: &mut u16,
) -> u16 {
    if original_len > EBPF_SOCKET_WRITE_SAMPLE_BYTES as u32 {
        *flags |= EBPF_SOCKET_WRITE_TRUNCATED;
    }
    let captured_len = core::cmp::min(original_len, EBPF_SOCKET_WRITE_SAMPLE_BYTES as u32) as u16;
    let Some(sample) = buffer.get_mut(..usize::from(captured_len)) else {
        *flags |= EBPF_SOCKET_WRITE_READ_FAILED;
        return 0;
    };
    if unsafe { bpf_probe_read_user_buf(user_buffer as *const u8, sample) }.is_err() {
        *flags |= EBPF_SOCKET_WRITE_READ_FAILED;
        return 0;
    }
    captured_len
}

fn tracepoint_u64(ctx: &TracePointContext, offset: usize) -> Option<u64> {
    // Offsets must match tracefs sys_enter_write/sys_exit_write format; privileged e2e validation is required.
    unsafe { ctx.read_at::<u64>(offset) }.ok()
}

fn tracepoint_i64(ctx: &TracePointContext, offset: usize) -> Option<i64> {
    // Offsets must match tracefs sys_enter_write/sys_exit_write format; privileged e2e validation is required.
    unsafe { ctx.read_at::<i64>(offset) }.ok()
}

fn clamp_u64_to_u32(value: u64) -> u32 {
    core::cmp::min(value, u64::from(u32::MAX)) as u32
}

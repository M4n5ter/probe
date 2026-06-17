use aya_ebpf::{helpers::bpf_probe_read_user_buf, programs::TracePointContext};
use ebpf_abi::{
    EBPF_SOCKET_READ_READ_FAILED, EBPF_SOCKET_READ_SAMPLE_BYTES, EBPF_SOCKET_READ_TRUNCATED,
    EbpfPendingSocketReadAttempt, EbpfSocketReadMetadata, EbpfSocketReadSampleRecord,
};

const READ_FD_OFFSET: usize = 16;
const READ_USER_BUFFER_OFFSET: usize = 24;
const READ_COUNT_OFFSET: usize = 32;
const READ_EXIT_RETURN_OFFSET: usize = 16;

pub(crate) fn read_attempt_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<EbpfPendingSocketReadAttempt> {
    let fd = tracepoint_u64(ctx, READ_FD_OFFSET)? as i32;
    if fd < 0 {
        return None;
    }
    let user_buffer = tracepoint_u64(ctx, READ_USER_BUFFER_OFFSET)?;
    if user_buffer == 0 {
        return None;
    }
    let requested_len = tracepoint_u64(ctx, READ_COUNT_OFFSET)?;
    if requested_len == 0 {
        return None;
    }
    Some(EbpfPendingSocketReadAttempt {
        fd,
        requested_len: clamp_u64_to_u32(requested_len),
        user_buffer,
    })
}

pub(crate) fn capture_read_sample_from_result(
    ctx: &TracePointContext,
    attempt: EbpfPendingSocketReadAttempt,
    event: &mut EbpfSocketReadSampleRecord,
) -> Option<u16> {
    let returned_len = tracepoint_i64(ctx, READ_EXIT_RETURN_OFFSET)?;
    if returned_len <= 0 {
        return None;
    }
    let original_len = clamp_u64_to_u32(core::cmp::min(
        returned_len as u64,
        u64::from(attempt.requested_len),
    ));
    if original_len == 0 {
        return None;
    }
    let mut flags = 0;
    event.clear_sample();
    let captured_len = read_payload_sample(
        attempt.user_buffer,
        original_len,
        event.socket_read_buffer_mut(),
        &mut flags,
    );
    event.overwrite_socket_read_sampled_metadata(
        super::process_metadata(ctx),
        EbpfSocketReadMetadata {
            fd: attempt.fd,
            original_len,
            captured_len,
        },
        flags,
    );
    Some(captured_len)
}

fn read_payload_sample(
    user_buffer: u64,
    original_len: u32,
    buffer: &mut [u8],
    flags: &mut u16,
) -> u16 {
    if original_len > EBPF_SOCKET_READ_SAMPLE_BYTES as u32 {
        *flags |= EBPF_SOCKET_READ_TRUNCATED;
    }
    let captured_len = core::cmp::min(original_len, EBPF_SOCKET_READ_SAMPLE_BYTES as u32) as u16;
    let Some(sample) = buffer.get_mut(..usize::from(captured_len)) else {
        *flags |= EBPF_SOCKET_READ_READ_FAILED;
        return 0;
    };
    if unsafe { bpf_probe_read_user_buf(user_buffer as *const u8, sample) }.is_err() {
        *flags |= EBPF_SOCKET_READ_READ_FAILED;
        return 0;
    }
    captured_len
}

fn tracepoint_u64(ctx: &TracePointContext, offset: usize) -> Option<u64> {
    // Offsets must match tracefs sys_enter_read/sys_exit_read format; privileged e2e validation is required.
    unsafe { ctx.read_at::<u64>(offset) }.ok()
}

fn tracepoint_i64(ctx: &TracePointContext, offset: usize) -> Option<i64> {
    // Offsets must match tracefs sys_enter_read/sys_exit_read format; privileged e2e validation is required.
    unsafe { ctx.read_at::<i64>(offset) }.ok()
}

fn clamp_u64_to_u32(value: u64) -> u32 {
    core::cmp::min(value, u64::from(u32::MAX)) as u32
}

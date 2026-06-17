use aya_ebpf::programs::TracePointContext;
use ebpf_abi::{
    EBPF_SOCKET_READ_READ_FAILED, EBPF_SOCKET_READ_TRUNCATED, EbpfPendingSocketReadAttempt,
    EbpfSocketReadMetadata, EbpfSocketReadSampleRecord,
};

use super::payload::{
    clamp_u64_to_u32, read_user_payload_prefix, single_buffer_payload_attempt_from_tracepoint,
    syscall_result_from_tracepoint,
};

pub(crate) fn read_attempt_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<EbpfPendingSocketReadAttempt> {
    let attempt = single_buffer_payload_attempt_from_tracepoint(ctx)?;
    Some(EbpfPendingSocketReadAttempt {
        fd: attempt.fd,
        requested_len: clamp_u64_to_u32(attempt.requested_len),
        user_buffer: attempt.user_buffer,
    })
}

pub(crate) fn capture_read_sample_from_result(
    ctx: &TracePointContext,
    attempt: EbpfPendingSocketReadAttempt,
    event: &mut EbpfSocketReadSampleRecord,
) -> Option<u16> {
    let returned_len = syscall_result_from_tracepoint(ctx)?;
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
    let captured_len = read_user_payload_prefix(
        attempt.user_buffer,
        original_len,
        event.socket_read_buffer_mut(),
        &mut flags,
        EBPF_SOCKET_READ_TRUNCATED,
        EBPF_SOCKET_READ_READ_FAILED,
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

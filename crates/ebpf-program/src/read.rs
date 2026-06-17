use aya_ebpf::programs::TracePointContext;
use ebpf_abi::{
    EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN, EBPF_SOCKET_READ_READ_FAILED,
    EBPF_SOCKET_READ_TRUNCATED, EbpfPendingSocketReadAttempt, EbpfSocketReadMetadata,
    EbpfSocketReadSampleRecord,
};

use super::payload::{
    PayloadAttemptSource, PayloadBufferAttempt, PayloadLogicalLen, clamp_u64_to_u32,
    iovec_payload_source_from_tracepoint, msghdr_payload_source_from_tracepoint,
    payload_attempt_from_source, read_user_payload_prefix,
    single_buffer_payload_source_from_tracepoint, syscall_result_from_tracepoint,
};

pub(crate) fn read_source_from_tracepoint(ctx: &TracePointContext) -> Option<PayloadAttemptSource> {
    single_buffer_payload_source_from_tracepoint(ctx)
}

pub(crate) fn readv_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    iovec_payload_source_from_tracepoint(ctx)
}

pub(crate) fn recvmsg_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    msghdr_payload_source_from_tracepoint(ctx)
}

pub(crate) fn pending_read_attempt_from_source(
    source: PayloadAttemptSource,
) -> Option<EbpfPendingSocketReadAttempt> {
    let attempt = payload_attempt_from_source(source)?;
    Some(pending_read_attempt(attempt))
}

fn pending_read_attempt(attempt: PayloadBufferAttempt) -> EbpfPendingSocketReadAttempt {
    let (requested_len, logical_len_flags) = match attempt.logical_len {
        PayloadLogicalLen::Known(logical_len) => (clamp_u64_to_u32(logical_len), 0),
        PayloadLogicalLen::UnknownUntilExit => (0, EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN),
    };
    EbpfPendingSocketReadAttempt {
        fd: attempt.fd,
        requested_len,
        readable_len: clamp_u64_to_u32(attempt.readable_len),
        logical_len_flags,
        user_buffer: attempt.user_buffer,
    }
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
    let original_len = read_original_len(attempt, returned_len);
    if original_len == 0 {
        return None;
    }
    let mut flags = 0;
    event.clear_sample();
    let captured_len = read_user_payload_prefix(
        attempt.user_buffer,
        core::cmp::min(attempt.readable_len, original_len),
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

fn read_original_len(attempt: EbpfPendingSocketReadAttempt, returned_len: i64) -> u32 {
    let returned_len = returned_len as u64;
    if attempt.logical_len_flags & EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN != 0 {
        return clamp_u64_to_u32(returned_len);
    }
    clamp_u64_to_u32(core::cmp::min(
        returned_len,
        u64::from(attempt.requested_len),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_original_len_clamps_known_request_to_requested_len() {
        let attempt = pending_read(5, 5, 0);

        assert_eq!(read_original_len(attempt, 9), 5);
    }

    #[test]
    fn read_original_len_uses_returned_len_for_vector_unknown_len() {
        let attempt = pending_read(0, 0, EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN);

        assert_eq!(read_original_len(attempt, 9), 9);
    }

    fn pending_read(
        requested_len: u32,
        readable_len: u32,
        logical_len_flags: u32,
    ) -> EbpfPendingSocketReadAttempt {
        EbpfPendingSocketReadAttempt {
            fd: 7,
            requested_len,
            readable_len,
            logical_len_flags,
            user_buffer: 0,
        }
    }
}

use aya_ebpf::programs::TracePointContext;
use ebpf_abi::{
    EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN, EBPF_PENDING_SOCKET_READ_SOURCE_IOVEC,
    EBPF_SOCKET_READ_READ_FAILED, EBPF_SOCKET_READ_TRUNCATED, EbpfPendingSocketReadAttempt,
    EbpfSocketReadMetadata, EbpfSocketReadSampleRecord,
};

use super::payload::{
    PayloadAttemptSource, PayloadBufferAttempt, PayloadFdKind, PayloadIovecAttempt,
    PayloadLogicalLen, PayloadSamplePlan, clamp_u64_to_u32, iovec_payload_source_from_tracepoint,
    msghdr_payload_source_from_tracepoint, payload_read_flag_bits, payload_sample_plan_from_source,
    read_payload_prefix_from_attempt, read_payload_prefix_from_iovec,
    single_buffer_payload_source_from_tracepoint, syscall_result_from_tracepoint,
};

pub(crate) fn read_source_from_tracepoint(ctx: &TracePointContext) -> Option<PayloadAttemptSource> {
    single_buffer_payload_source_from_tracepoint(ctx, PayloadFdKind::Generic)
}

pub(crate) fn recvfrom_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    single_buffer_payload_source_from_tracepoint(ctx, PayloadFdKind::Socket)
}

pub(crate) fn readv_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    iovec_payload_source_from_tracepoint(ctx, PayloadFdKind::Generic)
}

pub(crate) fn recvmsg_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    msghdr_payload_source_from_tracepoint(ctx)
}

pub(crate) fn pending_read_attempt_from_source(
    source: PayloadAttemptSource,
) -> Option<EbpfPendingSocketReadAttempt> {
    let plan = payload_sample_plan_from_source(source)?;
    Some(pending_read_attempt(plan))
}

fn pending_read_attempt(plan: PayloadSamplePlan) -> EbpfPendingSocketReadAttempt {
    match plan {
        PayloadSamplePlan::Buffer(attempt) => pending_read_buffer_attempt(attempt),
        PayloadSamplePlan::Iovec(attempt) => pending_read_iovec_attempt(attempt),
    }
}

fn pending_read_buffer_attempt(attempt: PayloadBufferAttempt) -> EbpfPendingSocketReadAttempt {
    let (requested_len, logical_len_flags) = match attempt.logical_len {
        PayloadLogicalLen::Known(logical_len) => (clamp_u64_to_u32(logical_len), 0),
        PayloadLogicalLen::UnknownUntilExit => (0, EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN),
    };
    EbpfPendingSocketReadAttempt {
        fd: attempt.fd,
        requested_len,
        fd_generation: 0,
        readable_len: clamp_u64_to_u32(attempt.readable_len),
        logical_len_flags,
        user_buffer: attempt.user_buffer,
    }
}

fn pending_read_iovec_attempt(attempt: PayloadIovecAttempt) -> EbpfPendingSocketReadAttempt {
    let logical_len_flags =
        EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN | EBPF_PENDING_SOCKET_READ_SOURCE_IOVEC;
    EbpfPendingSocketReadAttempt {
        fd: attempt.fd,
        requested_len: 0,
        fd_generation: 0,
        readable_len: clamp_u64_to_u32(attempt.iovlen),
        logical_len_flags,
        user_buffer: attempt.user_iovec,
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
    let captured_len = capture_read_payload_prefix(attempt, original_len, event, &mut flags);
    event.overwrite_socket_read_sampled_metadata(
        super::process_metadata(ctx),
        EbpfSocketReadMetadata {
            fd: attempt.fd,
            original_len,
            fd_generation: attempt.fd_generation,
            captured_len,
        },
        flags,
    );
    Some(captured_len)
}

fn capture_read_payload_prefix(
    attempt: EbpfPendingSocketReadAttempt,
    original_len: u32,
    event: &mut EbpfSocketReadSampleRecord,
    flags: &mut u16,
) -> u16 {
    let read_flag_bits =
        payload_read_flag_bits(EBPF_SOCKET_READ_TRUNCATED, EBPF_SOCKET_READ_READ_FAILED);
    if attempt.logical_len_flags & EBPF_PENDING_SOCKET_READ_SOURCE_IOVEC != 0 {
        return read_payload_prefix_from_iovec(
            PayloadIovecAttempt {
                fd: attempt.fd,
                user_iovec: attempt.user_buffer,
                iovlen: u64::from(attempt.readable_len),
            },
            original_len,
            event.socket_read_buffer_mut(),
            flags,
            read_flag_bits,
        );
    }
    read_payload_prefix_from_attempt(
        PayloadBufferAttempt {
            fd: attempt.fd,
            user_buffer: attempt.user_buffer,
            readable_len: u64::from(attempt.readable_len),
            logical_len: PayloadLogicalLen::Known(u64::from(original_len)),
        },
        original_len,
        event.socket_read_buffer_mut(),
        flags,
        read_flag_bits,
    )
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

    #[test]
    fn pending_iovec_attempt_keeps_iovec_source_for_exit_sampling() {
        let attempt = pending_read_iovec_attempt(PayloadIovecAttempt {
            fd: 7,
            user_iovec: 0x1000,
            iovlen: 9,
        });

        assert_eq!(attempt.fd, 7);
        assert_eq!(attempt.fd_generation, 0);
        assert_eq!(attempt.requested_len, 0);
        assert_eq!(attempt.readable_len, 9);
        assert_eq!(
            attempt.logical_len_flags,
            EBPF_PENDING_SOCKET_READ_LOGICAL_LEN_UNKNOWN | EBPF_PENDING_SOCKET_READ_SOURCE_IOVEC
        );
        assert_eq!(attempt.user_buffer, 0x1000);
        assert_eq!(read_original_len(attempt, 11), 11);
    }

    fn pending_read(
        requested_len: u32,
        readable_len: u32,
        logical_len_flags: u32,
    ) -> EbpfPendingSocketReadAttempt {
        EbpfPendingSocketReadAttempt {
            fd: 7,
            requested_len,
            fd_generation: 0,
            readable_len,
            logical_len_flags,
            user_buffer: 0,
        }
    }
}

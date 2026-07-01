use aya_ebpf::programs::TracePointContext;
use ebpf_abi::{
    EBPF_SOCKET_WRITE_KERNEL_TRANSFER, EBPF_SOCKET_WRITE_READ_FAILED,
    EBPF_SOCKET_WRITE_SAMPLE_BYTES, EBPF_SOCKET_WRITE_TRUNCATED, EbpfPendingSocketWriteSample,
    EbpfSocketWriteMetadata,
};

use super::payload::{
    PayloadAttemptSource, PayloadLogicalLen, PayloadSamplePlan, clamp_u64_to_u32,
    iovec_payload_source_from_tracepoint, msghdr_payload_source_from_tracepoint,
    payload_read_flag_bits, payload_sample_plan_from_source, read_payload_prefix_from_plan,
    single_buffer_payload_source_from_tracepoint, syscall_result_from_tracepoint,
};

const SENDFILE_OUT_FD_OFFSET: usize = 16;

pub(crate) fn write_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    single_buffer_payload_source_from_tracepoint(ctx)
}

pub(crate) fn writev_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    iovec_payload_source_from_tracepoint(ctx)
}

pub(crate) fn sendmsg_source_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<PayloadAttemptSource> {
    msghdr_payload_source_from_tracepoint(ctx)
}

pub(crate) fn sendfile_out_fd_from_tracepoint(ctx: &TracePointContext) -> Option<i32> {
    let fd = unsafe { ctx.read_at::<u64>(SENDFILE_OUT_FD_OFFSET) }.ok()? as i32;
    (fd >= 0).then_some(fd)
}

pub(crate) fn capture_write_sample_from_source(
    source: PayloadAttemptSource,
    pending: &mut EbpfPendingSocketWriteSample,
) -> Option<()> {
    let plan = payload_sample_plan_from_source(source)?;
    capture_write_sample_from_plan(plan, pending);
    Some(())
}

pub(crate) fn capture_kernel_transfer_write_gap(
    fd: i32,
    pending: &mut EbpfPendingSocketWriteSample,
) {
    reset_pending_write_sample(pending, fd, 0, 0, EBPF_SOCKET_WRITE_KERNEL_TRANSFER);
}

fn capture_write_sample_from_plan(
    plan: PayloadSamplePlan,
    pending: &mut EbpfPendingSocketWriteSample,
) {
    let mut flags = 0;
    let expected_len = match plan.logical_len() {
        PayloadLogicalLen::Known(logical_len) => Some(clamp_u64_to_u32(logical_len)),
        PayloadLogicalLen::UnknownUntilExit => None,
    };
    let pending_original_len = expected_len.unwrap_or(0);
    reset_pending_write_sample(pending, plan.fd(), pending_original_len, 0, flags);
    pending.captured_len = read_payload_prefix_from_plan(
        plan,
        expected_len.unwrap_or(0),
        &mut pending.buffer,
        &mut flags,
        payload_read_flag_bits(EBPF_SOCKET_WRITE_TRUNCATED, EBPF_SOCKET_WRITE_READ_FAILED),
    );
    pending.flags = flags;
}

pub(crate) fn trim_write_sample_to_result(
    ctx: &TracePointContext,
    pending: &mut EbpfPendingSocketWriteSample,
) -> Option<()> {
    let returned_len = syscall_result_from_tracepoint(ctx)?;
    trim_write_sample_to_returned_len(pending, returned_len)
}

fn trim_write_sample_to_returned_len(
    pending: &mut EbpfPendingSocketWriteSample,
    returned_len: i64,
) -> Option<()> {
    if returned_len <= 0 {
        return None;
    }
    let payload_kind = pending_write_payload_kind(pending);
    let previous = pending_write_metadata(pending);
    let written_len = if previous.original_len == 0 {
        returned_len as u64
    } else {
        core::cmp::min(returned_len as u64, u64::from(previous.original_len))
    };
    let original_len = clamp_u64_to_u32(written_len);
    if original_len == 0 {
        return None;
    }
    let mut flags = 0;
    pending.original_len = original_len;
    match payload_kind {
        PendingWritePayloadKind::Captured => {
            pending.captured_len =
                core::cmp::min(u32::from(previous.captured_len), original_len) as u16;
            if u32::from(pending.captured_len) < pending.original_len {
                flags |= EBPF_SOCKET_WRITE_TRUNCATED;
            }
        }
        PendingWritePayloadKind::ReadFailed => {
            clear_pending_payload(pending);
            flags |= EBPF_SOCKET_WRITE_READ_FAILED;
        }
        PendingWritePayloadKind::KernelTransfer => {
            clear_pending_payload(pending);
            flags |= EBPF_SOCKET_WRITE_KERNEL_TRANSFER;
        }
    }
    pending.flags = flags;
    Some(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingWritePayloadKind {
    Captured,
    ReadFailed,
    KernelTransfer,
}

fn pending_write_payload_kind(pending: &EbpfPendingSocketWriteSample) -> PendingWritePayloadKind {
    if pending.flags & EBPF_SOCKET_WRITE_KERNEL_TRANSFER != 0 {
        return PendingWritePayloadKind::KernelTransfer;
    }
    if pending.flags & EBPF_SOCKET_WRITE_READ_FAILED != 0 {
        return PendingWritePayloadKind::ReadFailed;
    }
    PendingWritePayloadKind::Captured
}

pub(crate) fn pending_write_metadata(
    pending: &EbpfPendingSocketWriteSample,
) -> EbpfSocketWriteMetadata {
    EbpfSocketWriteMetadata {
        fd: pending.fd,
        original_len: pending.original_len,
        fd_generation: pending.fd_generation,
        captured_len: pending.captured_len,
    }
}

fn reset_pending_write_sample(
    pending: &mut EbpfPendingSocketWriteSample,
    fd: i32,
    original_len: u32,
    captured_len: u16,
    flags: u16,
) {
    pending.fd = fd;
    pending.original_len = original_len;
    pending.fd_generation = 0;
    pending.captured_len = captured_len;
    pending.flags = flags;
    pending._reserved = 0;
    pending.buffer = [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES];
}

fn clear_pending_payload(pending: &mut EbpfPendingSocketWriteSample) {
    pending.captured_len = 0;
    pending.buffer = [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES];
}

#[cfg(test)]
mod tests {
    use ebpf_abi::{
        EBPF_SOCKET_WRITE_KERNEL_TRANSFER, EBPF_SOCKET_WRITE_READ_FAILED,
        EBPF_SOCKET_WRITE_SAMPLE_BYTES, EBPF_SOCKET_WRITE_TRUNCATED,
    };

    use super::*;

    #[test]
    fn trim_write_sample_keeps_enter_payload_within_returned_len() {
        let mut pending = pending_write(10, b"GET /", 0);

        trim_write_sample_to_returned_len(&mut pending, 7).expect("positive write finalizes");

        assert_eq!(pending.original_len, 7);
        assert_eq!(pending.captured_len, 5);
        assert_eq!(&pending.buffer[..5], b"GET /");
        assert_eq!(pending.flags, EBPF_SOCKET_WRITE_TRUNCATED);
    }

    #[test]
    fn trim_write_sample_clamps_payload_when_partial_write_splits_captured_prefix() {
        let mut pending = pending_write(10, b"GET /", 0);

        trim_write_sample_to_returned_len(&mut pending, 3).expect("positive write finalizes");

        assert_eq!(pending.original_len, 3);
        assert_eq!(pending.captured_len, 3);
        assert_eq!(&pending.buffer[..3], b"GET");
        assert_eq!(pending.flags, 0);
    }

    #[test]
    fn trim_write_sample_preserves_buffer_read_failure_without_payload() {
        let mut pending = pending_write(10, b"", EBPF_SOCKET_WRITE_READ_FAILED);

        trim_write_sample_to_returned_len(&mut pending, 4).expect("positive write finalizes");

        assert_eq!(pending.original_len, 4);
        assert_eq!(pending.captured_len, 0);
        assert!(pending.buffer.iter().all(|byte| *byte == 0));
        assert_eq!(pending.flags, EBPF_SOCKET_WRITE_READ_FAILED);
    }

    #[test]
    fn trim_write_sample_keeps_vector_gap_when_no_prefix_was_read() {
        let mut pending = pending_write(0, b"", 0);

        trim_write_sample_to_returned_len(&mut pending, 9).expect("positive write finalizes");

        assert_eq!(pending.original_len, 9);
        assert_eq!(pending.captured_len, 0);
        assert_eq!(pending.flags, EBPF_SOCKET_WRITE_TRUNCATED);
    }

    #[test]
    fn trim_write_sample_preserves_kernel_transfer_gap_without_payload() {
        let mut pending = pending_write(0, b"", EBPF_SOCKET_WRITE_KERNEL_TRANSFER);

        trim_write_sample_to_returned_len(&mut pending, 9).expect("positive write finalizes");

        assert_eq!(pending.original_len, 9);
        assert_eq!(pending.captured_len, 0);
        assert!(pending.buffer.iter().all(|byte| *byte == 0));
        assert_eq!(pending.flags, EBPF_SOCKET_WRITE_KERNEL_TRANSFER);
    }

    #[test]
    fn trim_write_sample_ignores_failed_write() {
        let mut pending = pending_write(10, b"GET /", 0);

        let finalized = trim_write_sample_to_returned_len(&mut pending, -1);

        assert!(finalized.is_none());
        assert_eq!(pending.original_len, 10);
        assert_eq!(pending.captured_len, 5);
    }

    fn pending_write(
        original_len: u32,
        captured: &[u8],
        flags: u16,
    ) -> EbpfPendingSocketWriteSample {
        let mut pending = EbpfPendingSocketWriteSample {
            fd: 0,
            original_len: 0,
            fd_generation: 0,
            captured_len: 0,
            flags: 0,
            _reserved: 0,
            buffer: [0; EBPF_SOCKET_WRITE_SAMPLE_BYTES],
        };
        reset_pending_write_sample(&mut pending, 7, original_len, captured.len() as u16, flags);
        pending.buffer[..captured.len()].copy_from_slice(captured);
        pending
    }
}

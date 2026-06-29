use aya_ebpf::programs::TracePointContext;
use ebpf_abi::{EbpfCloseObservation, EbpfCloseRangeObservation};

const CLOSE_FD_OFFSET: usize = 16;
const CLOSE_RANGE_FIRST_FD_OFFSET: usize = 16;
const CLOSE_RANGE_LAST_FD_OFFSET: usize = 24;
const CLOSE_RANGE_FLAGS_OFFSET: usize = 32;

pub fn close_observation_from_tracepoint(ctx: &TracePointContext) -> Option<EbpfCloseObservation> {
    Some(EbpfCloseObservation::observed(
        tracepoint_u64(ctx, CLOSE_FD_OFFSET)? as i32,
        0,
    ))
}

pub fn close_range_observation_from_tracepoint(
    ctx: &TracePointContext,
) -> Option<EbpfCloseRangeObservation> {
    let first_fd = tracepoint_u64(ctx, CLOSE_RANGE_FIRST_FD_OFFSET)?;
    let last_fd = tracepoint_u64(ctx, CLOSE_RANGE_LAST_FD_OFFSET)?;
    let flags = tracepoint_u64(ctx, CLOSE_RANGE_FLAGS_OFFSET)?;
    close_range_observation(first_fd, last_fd, flags)
}

fn close_range_observation(
    first_fd: u64,
    last_fd: u64,
    flags: u64,
) -> Option<EbpfCloseRangeObservation> {
    if first_fd > u32::MAX as u64 || last_fd > u32::MAX as u64 || flags > u32::MAX as u64 {
        return None;
    }

    let first_fd = first_fd as u32;
    let last_fd = last_fd as u32;
    let flags = flags as u32;
    if first_fd > last_fd {
        return None;
    }
    if flags != 0 {
        // CLOEXEC does not close now; UNSHARE changes fd-table identity before closing;
        // unknown future flags are ambiguous, so they fail closed too.
        return None;
    }

    Some(EbpfCloseRangeObservation::observed(first_fd, last_fd))
}

fn tracepoint_u64(ctx: &TracePointContext, offset: usize) -> Option<u64> {
    // Offsets must match tracefs syscall enter formats; privileged e2e validation is required.
    unsafe { ctx.read_at::<u64>(offset) }.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_range_observation_accepts_plain_immediate_close_ranges() {
        assert_eq!(
            close_range_observation(3, 10, 0),
            Some(EbpfCloseRangeObservation::observed(3, 10))
        );
    }

    #[test]
    fn close_range_observation_rejects_non_closing_or_ambiguous_ranges() {
        assert!(close_range_observation(10, 3, 0).is_none());
        assert!(close_range_observation(3, 10, 1 << 1).is_none());
        assert!(close_range_observation(3, 10, 1 << 2).is_none());
        assert!(close_range_observation(3, 10, 1).is_none());
        assert!(close_range_observation(u64::from(u32::MAX) + 1, 10, 0).is_none());
        assert!(close_range_observation(3, u64::from(u32::MAX) + 1, 0).is_none());
        assert!(close_range_observation(3, 10, u64::from(u32::MAX) + 1).is_none());
    }
}

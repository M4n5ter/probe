use aya_ebpf::programs::TracePointContext;
use ebpf_abi::EbpfCloseObservation;

const CLOSE_FD_OFFSET: usize = 16;

pub fn close_observation_from_tracepoint(ctx: &TracePointContext) -> Option<EbpfCloseObservation> {
    Some(EbpfCloseObservation::observed(
        tracepoint_u64(ctx, CLOSE_FD_OFFSET)? as i32,
    ))
}

fn tracepoint_u64(ctx: &TracePointContext, offset: usize) -> Option<u64> {
    // Offsets must match tracefs sys_enter_close format; privileged e2e validation is required.
    unsafe { ctx.read_at::<u64>(offset) }.ok()
}

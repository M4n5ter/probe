#![no_std]
#![no_main]

mod close;
mod connect;

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ebpf_abi::{EBPF_RING_BUFFER_BYTES, EbpfProcessProbeEvent};

use close::close_observation_from_tracepoint;
use connect::connect_observation_from_tracepoint;

#[map(name = "SSSA_EVENTS")]
static SSSA_EVENTS: RingBuf = RingBuf::with_byte_size(EBPF_RING_BUFFER_BYTES, 0);

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
pub fn sssa_sys_enter_connect(ctx: TracePointContext) -> u32 {
    emit_connect_attempt(ctx);
    0
}

#[tracepoint(name = "sys_enter_close", category = "syscalls")]
pub fn sssa_sys_enter_close(ctx: TracePointContext) -> u32 {
    emit_close_attempt(ctx);
    0
}

fn emit_connect_attempt(ctx: TracePointContext) {
    let connect = connect_observation_from_tracepoint(&ctx);
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let command = ctx.command().unwrap_or_default();
    let event = EbpfProcessProbeEvent::connect_tracepoint_observed(
        pid_tgid as u32,
        (pid_tgid >> 32) as u32,
        uid_gid as u32,
        (uid_gid >> 32) as u32,
        command,
        connect.observation,
        connect.flags,
    );
    submit_process_event(event);
}

fn emit_close_attempt(ctx: TracePointContext) {
    let Some(close) = close_observation_from_tracepoint(&ctx) else {
        return;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let command = ctx.command().unwrap_or_default();
    let event = EbpfProcessProbeEvent::close_tracepoint_observed(
        pid_tgid as u32,
        (pid_tgid >> 32) as u32,
        uid_gid as u32,
        (uid_gid >> 32) as u32,
        command,
        close,
    );
    submit_process_event(event);
}

fn submit_process_event(event: EbpfProcessProbeEvent) {
    let Some(mut entry) = SSSA_EVENTS.reserve::<EbpfProcessProbeEvent>(0) else {
        return;
    };
    entry.write(event);
    entry.submit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

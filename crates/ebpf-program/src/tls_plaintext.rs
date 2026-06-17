#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

mod tls;

use aya_ebpf::{
    macros::map,
    maps::{PerCpuArray, RingBuf},
};
use ebpf_abi::{EBPF_RING_BUFFER_BYTES, EBPF_TLS_OUTPUT_LOSSES_MAX_ENTRIES, EbpfTlsPlaintextEvent};

#[map(name = "SSSA_EVENTS")]
static SSSA_EVENTS: RingBuf = RingBuf::with_byte_size(EBPF_RING_BUFFER_BYTES, 0);

#[map(name = "SSSA_TLS_OUTPUT_LOSSES")]
static SSSA_TLS_OUTPUT_LOSSES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(EBPF_TLS_OUTPUT_LOSSES_MAX_ENTRIES, 0);

pub(crate) unsafe fn submit_tls_plaintext_event(event: *const EbpfTlsPlaintextEvent) {
    let Some(mut entry) = SSSA_EVENTS.reserve::<EbpfTlsPlaintextEvent>(0) else {
        record_tls_output_loss();
        return;
    };
    unsafe {
        core::ptr::copy_nonoverlapping(event, entry.as_mut_ptr(), 1);
    }
    entry.submit(0);
}

fn record_tls_output_loss() {
    let Some(losses) = SSSA_TLS_OUTPUT_LOSSES.get_ptr_mut(0) else {
        return;
    };
    unsafe {
        *losses = (*losses).saturating_add(1);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

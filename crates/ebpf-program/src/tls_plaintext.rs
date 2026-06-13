#![no_std]
#![no_main]

mod tls;

use aya_ebpf::{macros::map, maps::RingBuf};
use ebpf_abi::{EBPF_RING_BUFFER_BYTES, EbpfTlsPlaintextEvent};

#[map(name = "SSSA_EVENTS")]
static SSSA_EVENTS: RingBuf = RingBuf::with_byte_size(EBPF_RING_BUFFER_BYTES, 0);

pub(crate) unsafe fn submit_tls_plaintext_event(event: *const EbpfTlsPlaintextEvent) {
    let Some(mut entry) = SSSA_EVENTS.reserve::<EbpfTlsPlaintextEvent>(0) else {
        return;
    };
    unsafe {
        core::ptr::copy_nonoverlapping(event, entry.as_mut_ptr(), 1);
    }
    entry.submit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

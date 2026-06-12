#![no_std]

#[cfg(test)]
extern crate std;

pub mod contract;
pub mod event;

pub use contract::{
    EBPF_CONNECT_PROGRAM_NAME, EBPF_CONNECT_TRACEPOINT_CATEGORY, EBPF_CONNECT_TRACEPOINT_NAME,
    EBPF_EVENTS_MAP_NAME,
};
pub use event::{
    EBPF_ABI_REVISION, EBPF_ADDRESS_FAMILY_INET, EBPF_ADDRESS_FAMILY_INET6,
    EBPF_ADDRESS_FAMILY_UNSPEC, EBPF_CONNECT_REMOTE_ENDPOINT_VALID,
    EBPF_CONNECT_SOCKADDR_READ_FAILED, EBPF_CONNECT_UNSUPPORTED_ADDRESS_FAMILY, EBPF_MAGIC,
    EBPF_PROCESS_PROBE_EVENT_BYTES, EBPF_RING_BUFFER_BYTES, EbpfConnectObservation,
    EbpfEventDecodeError, EbpfEventHeader, EbpfEventKind, EbpfProcessProbeEvent,
    decode_process_probe_event, encode_process_probe_event,
};

use crate::{ConfigViolation, LibpcapCaptureConfig};

pub(super) fn validate(libpcap: &LibpcapCaptureConfig, violations: &mut Vec<ConfigViolation>) {
    if libpcap.bpf_filter.trim().is_empty() {
        violations.push(ConfigViolation {
            field: "capture.libpcap.bpf_filter".to_string(),
            reason: "libpcap BPF filter cannot be empty".to_string(),
        });
    }
    if libpcap.snaplen <= 0 {
        violations.push(ConfigViolation {
            field: "capture.libpcap.snaplen".to_string(),
            reason: "libpcap snaplen must be positive".to_string(),
        });
    }
    if libpcap.read_timeout_ms < 0 {
        violations.push(ConfigViolation {
            field: "capture.libpcap.read_timeout_ms".to_string(),
            reason: "libpcap read timeout cannot be negative".to_string(),
        });
    }
    if libpcap
        .buffer_size
        .is_some_and(|buffer_size| buffer_size <= 0)
    {
        violations.push(ConfigViolation {
            field: "capture.libpcap.buffer_size".to_string(),
            reason: "libpcap buffer size must be positive when set".to_string(),
        });
    }
}

use crate::{
    CaptureConfig, CaptureSelection, ConfigViolation, LibpcapCaptureConfig, LiveCaptureBackend,
};

pub(super) fn validate(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    if capture.selection == CaptureSelection::Auto && capture.fallback_backends.is_empty() {
        violations.push(ConfigViolation {
            field: "capture.fallback_backends".to_string(),
            reason: "auto capture selection requires at least one live fallback backend"
                .to_string(),
        });
    }
    if capture_uses_libpcap(capture) {
        validate_libpcap_capture(&capture.libpcap, violations);
    }
    validate_plaintext_feed_capture(capture, violations);
}

fn capture_uses_libpcap(capture: &CaptureConfig) -> bool {
    match capture.selection {
        CaptureSelection::Libpcap => true,
        CaptureSelection::Auto => capture
            .fallback_backends
            .contains(&LiveCaptureBackend::Libpcap),
        CaptureSelection::Ebpf | CaptureSelection::PlaintextFeed | CaptureSelection::Replay => {
            false
        }
    }
}

fn validate_libpcap_capture(libpcap: &LibpcapCaptureConfig, violations: &mut Vec<ConfigViolation>) {
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

fn validate_plaintext_feed_capture(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    match capture.selection {
        CaptureSelection::PlaintextFeed => {
            if capture.plaintext_feed.path.is_none() {
                violations.push(ConfigViolation {
                    field: "capture.plaintext_feed.path".to_string(),
                    reason: "plaintext feed capture requires a JSON-lines feed path".to_string(),
                });
            }
        }
        CaptureSelection::Auto
        | CaptureSelection::Ebpf
        | CaptureSelection::Libpcap
        | CaptureSelection::Replay => {
            if capture.plaintext_feed.path.is_some() {
                violations.push(ConfigViolation {
                    field: "capture.plaintext_feed.path".to_string(),
                    reason: "plaintext feed path is only valid when capture.selection = \"plaintext_feed\""
                        .to_string(),
                });
            }
        }
    }
}

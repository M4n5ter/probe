use crate::{CaptureConfig, CaptureSelection, ConfigViolation, LiveCaptureBackend};

pub(super) fn validate(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    if capture.selection == CaptureSelection::Auto && capture.fallback_backends.is_empty() {
        violations.push(ConfigViolation {
            field: "capture.fallback_backends".to_string(),
            reason: "auto capture selection requires at least one live fallback backend"
                .to_string(),
        });
    }
}

pub(super) fn uses_libpcap(capture: &CaptureConfig) -> bool {
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

use crate::{CaptureBackend, CaptureConfig, CaptureSelection, ConfigViolation, LiveCaptureBackend};

pub(super) fn validate(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    if capture.selection == CaptureSelection::Auto && capture.fallback_backends.is_empty() {
        violations.push(ConfigViolation {
            field: "capture.fallback_backends".to_string(),
            reason: "auto capture selection requires at least one live fallback backend"
                .to_string(),
        });
    }
    let mut seen = Vec::new();
    for backend in &capture.fallback_backends {
        if seen.contains(backend) {
            violations.push(ConfigViolation {
                field: "capture.fallback_backends".to_string(),
                reason: format!("capture fallback backend {backend:?} is duplicated"),
            });
        } else {
            seen.push(*backend);
        }
    }
}

pub(super) fn uses_libpcap(capture: &CaptureConfig) -> bool {
    match capture.selection.explicit_backend() {
        Some(CaptureBackend::Libpcap) => true,
        Some(_) => false,
        None => capture
            .fallback_backends
            .contains(&LiveCaptureBackend::Libpcap),
    }
}

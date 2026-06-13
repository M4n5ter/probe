use crate::{CaptureConfig, CaptureSelection, ConfigViolation};

pub(super) fn validate(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
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

use crate::{CaptureBackend, CaptureConfig, ConfigViolation};

pub(super) fn validate(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    match capture.selection.explicit_backend() {
        Some(CaptureBackend::CaptureEventFeed) => {
            if capture.capture_event_feed.path.is_none() {
                violations.push(ConfigViolation {
                    field: "capture.capture_event_feed.path".to_string(),
                    reason: "capture event feed requires a JSON-lines capture event path"
                        .to_string(),
                });
            }
        }
        Some(_) | None => {
            if capture.capture_event_feed.path.is_some() {
                violations.push(ConfigViolation {
                    field: "capture.capture_event_feed.path".to_string(),
                    reason: "capture event feed path is only valid when capture.selection = \"capture_event_feed\""
                        .to_string(),
                });
            }
            if capture.capture_event_feed.follow.is_some() {
                violations.push(ConfigViolation {
                    field: "capture.capture_event_feed.follow".to_string(),
                    reason: "capture event feed follow mode is only valid when capture.selection = \"capture_event_feed\""
                        .to_string(),
                });
            }
        }
    }
}

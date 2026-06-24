mod capture_event_feed;
mod libpcap;
mod plaintext_feed;
mod selection;

use crate::{CaptureConfig, ConfigViolation};

pub(super) fn validate(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    selection::validate(capture, violations);
    if selection::uses_libpcap(capture) {
        libpcap::validate(&capture.libpcap, violations);
    }
    plaintext_feed::validate(capture, violations);
    capture_event_feed::validate(capture, violations);
}

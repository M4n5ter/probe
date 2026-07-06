#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataPathFailureKind {
    CapturePrivilegesMissing,
    NoLiveCaptureBackend,
    MitmNoAttributedTcpListener,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DataPathFailureHint {
    pub(super) summary: &'static str,
    pub(super) capture: &'static str,
    pub(super) next: &'static str,
}

impl DataPathFailureKind {
    pub(super) fn hint(self) -> DataPathFailureHint {
        match self {
            Self::CapturePrivilegesMissing => DataPathFailureHint {
                summary: "kernel capture privileges are missing",
                capture: "live capture needs root or Linux capabilities",
                next: "run as root, or grant CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN/CAP_NET_RAW",
            },
            Self::NoLiveCaptureBackend => DataPathFailureHint {
                summary: "no live capture backend is available",
                capture: "eBPF/libpcap live capture failed to open",
                next: "open diagnostics, install required kernel support, or configure MITM",
            },
            Self::MitmNoAttributedTcpListener => DataPathFailureHint {
                summary: "MITM process classifier did not find a listener for the selector",
                capture: "transparent MITM needs a process with an attributed TCP listener",
                next: "select a listening process or switch to auto/eBPF/libpcap",
            },
        }
    }
}

pub(crate) fn classify_runtime_detach_message(message: &str) -> Option<DataPathFailureKind> {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("transparent process classifier found no attributed tcp listeners") {
        return Some(DataPathFailureKind::MitmNoAttributedTcpListener);
    }
    if message_mentions_live_capture(&normalized)
        && message_mentions_capture_permission(&normalized)
    {
        return Some(DataPathFailureKind::CapturePrivilegesMissing);
    }
    if normalized.contains("no live capture provider is available")
        || normalized.contains("all auto live capture providers failed")
    {
        return Some(DataPathFailureKind::NoLiveCaptureBackend);
    }
    None
}

fn message_mentions_live_capture(message: &str) -> bool {
    if message.contains("capture_event_feed") || message.contains("plaintext_feed") {
        return false;
    }
    message.contains("capture backend")
        || message.contains("live capture")
        || message.contains("ebpf")
        || message.contains("libpcap")
}

fn message_mentions_capture_permission(message: &str) -> bool {
    message.contains("operation not permitted")
        || message.contains("permission denied")
        || message.contains("failed to create map")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_requires_capture_context_for_permission_denied() {
        assert_eq!(
            classify_runtime_detach_message("TLS material store failed: permission denied"),
            None
        );
    }

    #[test]
    fn classification_detects_capture_permission_failures() {
        assert_eq!(
            classify_runtime_detach_message(
                "capture provider libpcap failed: socket: Permission denied"
            ),
            Some(DataPathFailureKind::CapturePrivilegesMissing)
        );
        assert_eq!(
            classify_runtime_detach_message(
                "capture backend Ebpf failed: failed to create map TRAFFIC_PROBE_EVENTS"
            ),
            Some(DataPathFailureKind::CapturePrivilegesMissing)
        );
    }

    #[test]
    fn classification_does_not_treat_passive_feed_permissions_as_kernel_capture_privileges() {
        assert_eq!(
            classify_runtime_detach_message(
                "capture provider capture_event_feed failed: permission denied"
            ),
            None
        );
        assert_eq!(
            classify_runtime_detach_message(
                "capture provider plaintext_feed failed: permission denied"
            ),
            None
        );
    }

    #[test]
    fn classification_detects_live_capture_and_mitm_classifier_failures() {
        assert_eq!(
            classify_runtime_detach_message("no live capture provider is available"),
            Some(DataPathFailureKind::NoLiveCaptureBackend)
        );
        assert_eq!(
            classify_runtime_detach_message(
                "transparent process classifier found no attributed TCP listeners matching the process selector"
            ),
            Some(DataPathFailureKind::MitmNoAttributedTcpListener)
        );
    }
}

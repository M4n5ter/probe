use std::path::Path;

use capture::CaptureEvent;
use e2e_support::mitm_bridge;
use probe_core::EventEnvelope;

use super::backend::{MitmBackendKind, MitmBridgeCase};

pub(super) const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-mitm-bridge";
pub(super) const POLICY_ID: &str = "mitm-bridge-e2e-policy";
pub(super) const POLICY_VERSION: &str = "e2e";
pub(super) const ENFORCEMENT_MANIFEST_ID: &str = "e2e-mitm-policy-hook-enforcement";
pub(super) const ENFORCEMENT_MANIFEST_VERSION: &str = "e2e";
pub(super) const EXPECTED_POLICY_VERSION: &str = "mitm-bridge-e2e-policy@e2e";
pub(super) const POLICY_ALERT_PREFIX: &str = "mitm bridge policy observed ";
pub(super) const POLICY_HOOK_REASON_PREFIX: &str = "mitm bridge policy hook delegated ";
pub(super) const POLICY_HOOK_RESPONSE_REASON: &str = "e2e MITM policy hook delegated deny";
pub(super) const REQUESTS: usize = 1;
pub(super) const REQUEST_BODY_BYTES: usize = 64;
pub(super) const RESPONSE_BODY_BYTES: usize = 32;
pub(super) const WRITE_CHUNKS: usize = 2;

pub(super) fn initialize_bridge_feed(
    case: MitmBridgeCase,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match case.backend() {
        MitmBackendKind::External => {
            mitm_bridge::create_empty_capture_event_feed(path).map_err(Into::into)
        }
        MitmBackendKind::ManagedProcess => Ok(()),
    }
}

pub(super) fn append_bridge_feed_from_harness(
    case: MitmBridgeCase,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match case.backend() {
        MitmBackendKind::External => mitm_bridge::append_capture_event_feed(path),
        MitmBackendKind::ManagedProcess => Ok(()),
    }
}

pub(super) fn is_bridge_ingress_bytes(event: &CaptureEvent) -> bool {
    mitm_bridge::is_ingress_bytes(event)
}

pub(super) fn is_bridge_flow(envelope: &EventEnvelope) -> bool {
    mitm_bridge::is_flow(envelope)
}

pub(super) fn expected_policy_alert_messages() -> std::collections::BTreeSet<String> {
    expected_libpcap_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .chain([expected_bridge_policy_alert_message()])
        .collect()
}

pub(super) fn expected_libpcap_targets() -> std::collections::BTreeSet<String> {
    (0..REQUESTS)
        .map(|request| format!("/traffic-probe-e2e/{request}"))
        .collect()
}

pub(super) fn expected_policy_alert_message(target: String) -> String {
    format!("{POLICY_ALERT_PREFIX}{target}")
}

pub(super) fn expected_bridge_policy_alert_message() -> String {
    format!("{POLICY_ALERT_PREFIX}{}", mitm_bridge::REQUEST_TARGET)
}

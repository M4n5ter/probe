use std::path::Path;

use capture::CaptureEvent;
use e2e_support::mitm_bridge;
use probe_core::{CaptureProviderKind, CaptureSource, Direction, EventEnvelope};

use super::{
    case::{MitmBackendKind, MitmBridgeCase, MitmBridgeDirection},
    data_plane,
};

pub(super) const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-mitm-bridge";
pub(super) const POLICY_ID: &str = "mitm-bridge-e2e-policy";
pub(super) const POLICY_VERSION: &str = "e2e";
pub(super) const ENFORCEMENT_MANIFEST_ID: &str = "e2e-mitm-policy-hook-enforcement";
pub(super) const ENFORCEMENT_MANIFEST_VERSION: &str = "e2e";
pub(super) const EXPECTED_POLICY_VERSION: &str = "mitm-bridge-e2e-policy@e2e";
pub(super) const POLICY_ALERT_PREFIX: &str = "mitm bridge policy observed ";
pub(super) const POLICY_HOOK_REASON_PREFIX: &str = "mitm bridge policy hook delegated ";
pub(super) const POLICY_HOOK_RESPONSE_REASON: &str = mitm_bridge::POLICY_HOOK_RESPONSE_REASON;
pub(super) const POLICY_HOOK_PRODUCT_PROXY_RESPONSE_REASON: &str =
    "mitm bridge policy hook delegated /mitm-bridge/e2e";
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
        MitmBackendKind::ManagedProcess | MitmBackendKind::ProductProxy => Ok(()),
    }
}

pub(super) fn append_bridge_feed_from_harness(
    case: MitmBridgeCase,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match case.backend() {
        MitmBackendKind::External => mitm_bridge::append_capture_event_feed(path),
        MitmBackendKind::ManagedProcess | MitmBackendKind::ProductProxy => Ok(()),
    }
}

pub(super) fn product_proxy_deny_response_bytes() -> Vec<u8> {
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        POLICY_HOOK_PRODUCT_PROXY_RESPONSE_REASON.len(),
        POLICY_HOOK_PRODUCT_PROXY_RESPONSE_REASON
    )
    .into_bytes()
}

pub(super) fn is_bridge_ingress_bytes(case: MitmBridgeCase, event: &CaptureEvent) -> bool {
    if case.backend() != MitmBackendKind::ProductProxy {
        return mitm_bridge::is_ingress_bytes(event);
    }
    is_l7_mitm_plaintext_bytes(
        event,
        product_proxy_request_direction(case),
        data_plane::scenario(case).request_bytes().as_ref(),
    )
}

pub(super) fn is_product_proxy_allow_request_bytes(
    case: MitmBridgeCase,
    event: &CaptureEvent,
) -> bool {
    is_l7_mitm_plaintext_bytes(
        event,
        product_proxy_request_direction(case),
        data_plane::scenario(case).allow_request_bytes().as_ref(),
    )
}

pub(super) fn is_product_proxy_deny_response_bytes(
    case: MitmBridgeCase,
    event: &CaptureEvent,
) -> bool {
    is_l7_mitm_plaintext_bytes(
        event,
        product_proxy_response_direction(case),
        product_proxy_deny_response_bytes().as_slice(),
    )
}

pub(super) fn is_bridge_flow(case: MitmBridgeCase, envelope: &EventEnvelope) -> bool {
    if case.backend() != MitmBackendKind::ProductProxy {
        return mitm_bridge::is_flow(envelope);
    }
    is_l7_mitm_plaintext_origin(envelope)
}

fn is_l7_mitm_plaintext_bytes(event: &CaptureEvent, direction: Direction, expected: &[u8]) -> bool {
    matches!(
        event,
        CaptureEvent::Bytes(bytes)
            if bytes.origin.source() == CaptureSource::L7MitmPlaintext
                && bytes.origin.provider() == CaptureProviderKind::Interception
                && bytes.direction == direction
                && bytes.bytes.as_ref() == expected
    )
}

fn is_l7_mitm_plaintext_origin(envelope: &EventEnvelope) -> bool {
    envelope.origin().source() == CaptureSource::L7MitmPlaintext
        && envelope.origin().provider() == CaptureProviderKind::Interception
}

pub(super) fn product_proxy_request_direction(case: MitmBridgeCase) -> Direction {
    match case.direction() {
        MitmBridgeDirection::Inbound => Direction::Inbound,
        MitmBridgeDirection::Outbound => Direction::Outbound,
    }
}

pub(super) fn product_proxy_response_direction(case: MitmBridgeCase) -> Direction {
    match product_proxy_request_direction(case) {
        Direction::Inbound => Direction::Outbound,
        Direction::Outbound => Direction::Inbound,
    }
}

pub(super) fn expected_policy_alert_messages_for_case(
    case: MitmBridgeCase,
) -> std::collections::BTreeSet<String> {
    expected_libpcap_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .chain([expected_bridge_policy_alert_message(case)])
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

pub(super) fn expected_bridge_policy_alert_message(case: MitmBridgeCase) -> String {
    format!(
        "{POLICY_ALERT_PREFIX}{}",
        data_plane::scenario(case).request_target()
    )
}

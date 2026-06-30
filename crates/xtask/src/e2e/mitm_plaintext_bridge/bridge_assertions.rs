use probe_core::{EventEnvelope, EventKind};

use super::{
    backend::MitmBridgeCase,
    feed::{EXPECTED_POLICY_VERSION, expected_bridge_policy_alert_message, is_bridge_flow},
};
use crate::e2e::harness::e2e_error;

pub(super) fn assert_expected_bridge_policy_alert(
    case: MitmBridgeCase,
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let bridge_alert = expected_bridge_policy_alert_message(case);
    let matches = envelopes
        .iter()
        .filter(|envelope| {
            is_bridge_flow(case, envelope)
                && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
                && matches!(
                    envelope.kind(),
                    EventKind::PolicyAlert(alert) if alert.message == bridge_alert
                )
        })
        .count();
    if matches == 1 {
        return Ok(());
    }
    Err(e2e_error(format!(
        "expected exactly one MITM bridge policy alert {bridge_alert:?}, got {matches}"
    ))
    .into())
}

pub(super) fn assert_no_bridge_protocol_errors(
    case: MitmBridgeCase,
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes.iter().any(|envelope| {
        is_bridge_flow(case, envelope) && matches!(envelope.kind(), EventKind::ProtocolError(_))
    }) {
        return Err(e2e_error("MITM bridge produced a protocol error").into());
    }
    Ok(())
}

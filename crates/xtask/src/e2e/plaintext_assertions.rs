use capture::CaptureEvent;
use probe_core::{CaptureProviderKind, CaptureSource, Direction, EventEnvelope, EventKind};
use storage::StoredEvent;

use super::{
    harness::{decode_capture_event, e2e_error},
    plaintext_scenario::PlaintextFeedCase,
};

pub(crate) fn decode_capture_events(
    events: &[StoredEvent],
    expected_count: usize,
    context: &str,
) -> Result<Vec<CaptureEvent>, Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    if capture_events.len() == expected_count {
        return Ok(capture_events);
    }
    Err(e2e_error(format!(
        "expected {expected_count} ordered {context} ingress events, got {}",
        capture_events.len()
    ))
    .into())
}

pub(crate) fn assert_connection_opened(
    event: &CaptureEvent,
    scenario: &PlaintextFeedCase,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        event,
        CaptureEvent::ConnectionOpened { origin, flow, .. }
            if is_expected_plaintext_origin(origin.source(), origin.provider())
                && flow.id.0 == scenario.expected_flow_id()
    ) {
        return Ok(());
    }
    Err(e2e_error(format!("missing {context} ingress connection_opened event")).into())
}

pub(crate) fn assert_connection_closed(
    event: &CaptureEvent,
    scenario: &PlaintextFeedCase,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        event,
        CaptureEvent::ConnectionClosed { origin, flow, .. }
            if is_expected_plaintext_origin(origin.source(), origin.provider())
                && flow.id.0 == scenario.expected_flow_id()
    ) {
        return Ok(());
    }
    Err(e2e_error(format!("missing {context} ingress connection_closed event")).into())
}

pub(crate) fn assert_bytes_event(
    event: &CaptureEvent,
    scenario: &PlaintextFeedCase,
    direction: Direction,
    stream_offset: u64,
    expected: &[u8],
    context: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        event,
        CaptureEvent::Bytes(bytes)
            if is_expected_plaintext_origin(bytes.origin.source(), bytes.origin.provider())
                && bytes.flow.id.0 == scenario.expected_flow_id()
                && bytes.direction == direction
                && bytes.stream_offset == stream_offset
                && bytes.bytes.as_ref() == expected
    ) {
        return Ok(());
    }
    Err(e2e_error(format!(
        "missing expected {context} ingress {label} bytes event"
    ))
    .into())
}

pub(crate) fn export_event_position(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedCase,
    context: &str,
    label: &str,
    matches_kind: impl Fn(&EventKind) -> bool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let matching_positions = envelopes
        .iter()
        .enumerate()
        .filter_map(|(position, envelope)| {
            (scenario.matches_export_flow(envelope) && matches_kind(envelope.kind()))
                .then_some(position)
        })
        .collect::<Vec<_>>();
    let [position] = matching_positions.as_slice() else {
        return Err(e2e_error(format!(
            "expected exactly one {context} export event for {label}, got {} at positions {matching_positions:?}",
            matching_positions.len()
        ))
        .into());
    };
    Ok(*position)
}

pub(crate) fn has_header(headers: &[(String, String)], name: &str, value: &str) -> bool {
    headers
        .iter()
        .any(|(header_name, header_value)| header_name == name && header_value == value)
}

pub(crate) fn assert_policy_alert(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedCase,
    expected_policy_version: &str,
    context: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let matching_alerts = envelopes
        .iter()
        .filter(|envelope| {
            scenario.matches_export_flow(envelope)
                && envelope.policy_version() == Some(expected_policy_version)
                && matches!(
                    envelope.kind(),
                    EventKind::PolicyAlert(alert) if alert.message == message
                )
        })
        .count();
    if matching_alerts == 1 {
        return Ok(());
    }
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert) => Some(alert.message.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    Err(e2e_error(format!(
        "expected exactly one {context} policy alert {message:?}, got {matching_alerts}; observed alerts {observed:?}"
    ))
    .into())
}

pub(crate) fn assert_no_protocol_errors(
    envelopes: &[EventEnvelope],
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes
        .iter()
        .any(|envelope| matches!(envelope.kind(), EventKind::ProtocolError(_)))
    {
        return Err(e2e_error(format!(
            "{context} plaintext feed produced a protocol error"
        ))
        .into());
    }
    Ok(())
}

pub(crate) fn assert_no_http_body_chunks_after(
    envelopes: &[EventEnvelope],
    start_index: usize,
    context: &str,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes
        .iter()
        .skip(start_index + 1)
        .any(|envelope| matches!(envelope.kind(), EventKind::HttpBodyChunk(_)))
    {
        return Err(e2e_error(format!(
            "{context} payload was parsed as HTTP body after {reason}"
        ))
        .into());
    }
    Ok(())
}

fn is_expected_plaintext_origin(source: CaptureSource, provider: CaptureProviderKind) -> bool {
    source == CaptureSource::ExternalPlaintextFeed && provider == CaptureProviderKind::Plaintext
}

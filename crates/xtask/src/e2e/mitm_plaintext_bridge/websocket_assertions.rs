use probe_core::{Direction, EventEnvelope, EventKind, WebSocketMessageOpcode, WebSocketOpcode};

use super::{
    bridge_assertions::{assert_expected_bridge_policy_alert, assert_no_bridge_protocol_errors},
    case::MitmBridgeCase,
    feed::{is_bridge_flow, product_proxy_request_direction, product_proxy_response_direction},
    websocket,
};
use crate::e2e::{
    harness::e2e_error,
    plaintext_assertions::has_header,
    websocket_expectations::{FRAME_PAYLOAD, FRAME_PAYLOAD_FINGERPRINT, FRAME_PAYLOAD_LEN},
};

pub(super) fn assert_expected_websocket_bridge_export(
    case: MitmBridgeCase,
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let request_direction = product_proxy_request_direction(case);
    let response_direction = product_proxy_response_direction(case);
    let request_index = bridge_event_position(case, envelopes, "WebSocket HTTP request", |kind| {
        matches!(
            kind,
            EventKind::HttpRequestHeaders(headers)
                if headers.direction == request_direction
                    && headers.method.as_deref() == Some("GET")
                    && headers.target.as_deref() == Some(websocket::TARGET)
        )
    })?;
    let response_index =
        bridge_event_position(case, envelopes, "WebSocket HTTP 101 response", |kind| {
            matches!(
                kind,
                EventKind::HttpResponseHeaders(headers)
                    if headers.direction == response_direction
                        && headers.status == Some(101)
                        && has_header(&headers.headers, "sec-websocket-accept", websocket::ACCEPT)
                        && has_header(
                            &headers.headers,
                            "sec-websocket-protocol",
                            websocket::SUBPROTOCOL_NAME,
                        )
            )
        })?;
    let handoff_index = bridge_event_position(case, envelopes, "WebSocket handoff", |kind| {
        matches_websocket_handoff(kind, response_direction)
    })?;
    let frame_index = bridge_event_position(case, envelopes, "WebSocket frame", |kind| {
        matches_websocket_text_frame(kind, response_direction)
    })?;
    let message_index = bridge_event_position(case, envelopes, "WebSocket message", |kind| {
        matches_websocket_text_message(kind, response_direction)
    })?;
    assert_bridge_event_order(
        case,
        &[
            ("WebSocket HTTP request", request_index),
            ("WebSocket HTTP 101 response", response_index),
            ("WebSocket handoff", handoff_index),
            ("WebSocket frame", frame_index),
            ("WebSocket message", message_index),
        ],
    )?;
    assert_expected_bridge_policy_alert(case, envelopes)?;
    assert_no_bridge_protocol_errors(case, envelopes)
}

fn matches_websocket_handoff(kind: &EventKind, response_direction: Direction) -> bool {
    matches!(
        kind,
        EventKind::WebSocketHandoff(handoff)
            if handoff.direction == response_direction
                && handoff.target.as_deref() == Some(websocket::TARGET)
                && handoff.subprotocol.as_deref() == Some(websocket::SUBPROTOCOL_NAME)
    )
}

fn matches_websocket_text_frame(kind: &EventKind, response_direction: Direction) -> bool {
    matches!(
        kind,
        EventKind::WebSocketFrame(frame)
            if frame.direction == response_direction
                && frame.frame_sequence == 1
                && frame.fin
                && !frame.masked
                && matches!(frame.opcode, WebSocketOpcode::Text)
                && frame.payload_len == FRAME_PAYLOAD_LEN
                && frame.payload_fingerprint.as_slice()
                    == FRAME_PAYLOAD_FINGERPRINT.as_slice()
    )
}

fn matches_websocket_text_message(kind: &EventKind, response_direction: Direction) -> bool {
    matches!(
        kind,
        EventKind::WebSocketMessage(message)
            if message.direction == response_direction
                && message.message_sequence == 1
                && message.first_frame_sequence == 1
                && message.final_frame_sequence == 1
                && matches!(message.opcode, WebSocketMessageOpcode::Text)
                && message.payload_len == FRAME_PAYLOAD_LEN
                && message.payload.as_ref() == FRAME_PAYLOAD
                && message.payload_fingerprint.as_slice()
                    == FRAME_PAYLOAD_FINGERPRINT.as_slice()
    )
}

fn bridge_event_position(
    case: MitmBridgeCase,
    envelopes: &[EventEnvelope],
    label: &str,
    matches_kind: impl Fn(&EventKind) -> bool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let matching_positions = envelopes
        .iter()
        .enumerate()
        .filter_map(|(position, envelope)| {
            (is_bridge_flow(case, envelope) && matches_kind(envelope.kind())).then_some(position)
        })
        .collect::<Vec<_>>();
    let [position] = matching_positions.as_slice() else {
        return Err(e2e_error(format!(
            "expected exactly one MITM bridge export event for {label}, got {} at positions {matching_positions:?}",
            matching_positions.len()
        ))
        .into());
    };
    Ok(*position)
}

fn assert_bridge_event_order(
    case: MitmBridgeCase,
    positions: &[(&str, usize)],
) -> Result<(), Box<dyn std::error::Error>> {
    if positions.windows(2).all(|pair| pair[0].1 < pair[1].1) {
        return Ok(());
    }
    let order = positions
        .iter()
        .map(|(label, position)| format!("{label}={position}"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(e2e_error(format!(
        "{} MITM bridge export order was {order}",
        case.case_name()
    ))
    .into())
}

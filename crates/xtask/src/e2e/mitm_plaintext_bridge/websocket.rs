use super::tls::SERVER_NAME;
use crate::e2e::websocket_expectations::{
    FRAME_PAYLOAD, REQUEST_TARGET, RFC_SAMPLE_WEBSOCKET_ACCEPT, RFC_SAMPLE_WEBSOCKET_KEY,
    SUBPROTOCOL,
};

pub(super) const TARGET: &str = REQUEST_TARGET;
pub(super) const SUBPROTOCOL_NAME: &str = SUBPROTOCOL;
pub(super) const ACCEPT: &str = RFC_SAMPLE_WEBSOCKET_ACCEPT;

pub(super) fn upgrade_request_bytes() -> Vec<u8> {
    format!(
        "GET {REQUEST_TARGET} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {RFC_SAMPLE_WEBSOCKET_KEY}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n"
    )
    .into_bytes()
}

pub(super) fn upgrade_response_bytes() -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {RFC_SAMPLE_WEBSOCKET_ACCEPT}\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n"
    )
    .into_bytes()
}

pub(super) fn text_frame_bytes() -> Vec<u8> {
    let len = u8::try_from(FRAME_PAYLOAD.len())
        .expect("e2e websocket frame payload must fit short frame");
    let mut frame = Vec::with_capacity(2 + FRAME_PAYLOAD.len());
    frame.push(0x81);
    frame.push(len);
    frame.extend_from_slice(FRAME_PAYLOAD);
    frame
}

pub(super) fn response_with_frame_bytes() -> Vec<u8> {
    let mut response = upgrade_response_bytes();
    response.extend_from_slice(&text_frame_bytes());
    response
}

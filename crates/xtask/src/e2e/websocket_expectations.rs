pub(crate) const REQUEST_TARGET: &str = "/chat";
pub(crate) const SUBPROTOCOL: &str = "chat";
pub(crate) const RFC_SAMPLE_WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
pub(crate) const RFC_SAMPLE_WEBSOCKET_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
pub(crate) const FRAME_PAYLOAD: &[u8] = b"hi";
pub(crate) const FRAME_PAYLOAD_BYTES: usize = FRAME_PAYLOAD.len();
pub(crate) const FRAME_PAYLOAD_LEN: u64 = FRAME_PAYLOAD_BYTES as u64;
pub(crate) const FRAME_PAYLOAD_FINGERPRINT: [u8; 16] = [
    133, 5, 46, 154, 171, 27, 103, 182, 98, 45, 148, 160, 132, 65, 176, 159,
];

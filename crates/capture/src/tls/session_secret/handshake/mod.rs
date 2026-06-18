mod hello;
mod message;
mod observer;
mod record;

pub use observer::{
    Tls13SessionSecretHandshakeObservation, Tls13SessionSecretHandshakeObservationKind,
    Tls13SessionSecretHandshakeObserver,
};

const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const TLS_CHANGE_CIPHER_SPEC_CONTENT_TYPE: u8 = 20;
const TLS10_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x01];
const TLS_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_RECORD_PAYLOAD_BYTES: usize = 64 * 1024;
const TLS_HANDSHAKE_OBSERVER_MAX_ACTIVE_STREAMS: usize = 1024;
const TLS_CLIENT_HELLO: u8 = 1;
const TLS_SERVER_HELLO: u8 = 2;
const TLS_SUPPORTED_VERSIONS_EXTENSION: u16 = 0x002b;
const TLS13_VERSION: [u8; 2] = [0x03, 0x04];

fn supported_legacy_record_version(version: &[u8]) -> bool {
    version == TLS_LEGACY_RECORD_VERSION || version == TLS10_LEGACY_RECORD_VERSION
}

fn u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}

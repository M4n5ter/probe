use super::super::frame::{TLS_RECORD_HEADER_BYTES, TlsRecordHeader};
use super::{
    TLS_CHANGE_CIPHER_SPEC_CONTENT_TYPE, TLS_HANDSHAKE_CONTENT_TYPE,
    TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_RECORD_PAYLOAD_BYTES, supported_legacy_record_version,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BufferedHandshakeRecord<'a> {
    Incomplete,
    Invalid,
    Ignored { len: usize, terminal: bool },
    Handshake { len: usize, payload: &'a [u8] },
}

pub(super) fn buffered_record(buffer: &[u8]) -> Option<BufferedHandshakeRecord<'_>> {
    let header = TlsRecordHeader::from_buffer(buffer)?;
    if !supported_legacy_record_version(&header.legacy_version()) {
        return Some(BufferedHandshakeRecord::Invalid);
    }
    let declared_bytes = header.payload_len();
    if declared_bytes > TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_RECORD_PAYLOAD_BYTES {
        return Some(BufferedHandshakeRecord::Invalid);
    }
    let len = TLS_RECORD_HEADER_BYTES + declared_bytes;
    if buffer.len() < len {
        return Some(BufferedHandshakeRecord::Incomplete);
    }
    match header.content_type() {
        TLS_HANDSHAKE_CONTENT_TYPE => Some(BufferedHandshakeRecord::Handshake {
            len,
            payload: &buffer[TLS_RECORD_HEADER_BYTES..len],
        }),
        TLS_CHANGE_CIPHER_SPEC_CONTENT_TYPE => Some(BufferedHandshakeRecord::Ignored {
            len,
            terminal: false,
        }),
        _ => Some(BufferedHandshakeRecord::Ignored {
            len,
            terminal: true,
        }),
    }
}

pub(super) fn could_start_tls_handshake_stream(prefix: &[u8]) -> bool {
    let Some(content_type) = prefix.first() else {
        return false;
    };
    if !matches!(
        *content_type,
        TLS_HANDSHAKE_CONTENT_TYPE | TLS_CHANGE_CIPHER_SPEC_CONTENT_TYPE
    ) {
        return false;
    }
    if prefix.get(1).is_some_and(|major| *major != 0x03) {
        return false;
    }
    if prefix.len() >= 3 && !supported_legacy_record_version(&prefix[1..3]) {
        return false;
    }
    let Some(header) = TlsRecordHeader::from_buffer(prefix) else {
        return true;
    };
    header.payload_len() <= TLS_HANDSHAKE_OBSERVER_MAX_BUFFERED_RECORD_PAYLOAD_BYTES
}

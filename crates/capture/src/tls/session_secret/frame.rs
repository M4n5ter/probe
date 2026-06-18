use super::decrypt::Tls13DecryptError;

pub(in crate::tls::session_secret) const TLS13_RECORD_HEADER_BYTES: usize = 5;
pub(in crate::tls::session_secret) const TLS13_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
pub(in crate::tls::session_secret) const TLS13_OUTER_APPLICATION_DATA: u8 = 0x17;
pub(in crate::tls::session_secret) const TLS13_MAX_FRAGMENT_BYTES: usize = 16 * 1024;
pub(in crate::tls::session_secret) const TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES: usize =
    TLS13_MAX_FRAGMENT_BYTES + 256;

#[derive(Debug, Clone, Copy)]
pub(in crate::tls::session_secret) struct Tls13RecordFrame<'a> {
    aad: [u8; TLS13_RECORD_HEADER_BYTES],
    encrypted_payload: &'a [u8],
}

impl<'a> Tls13RecordFrame<'a> {
    pub(in crate::tls::session_secret) fn parse(
        record: &'a [u8],
    ) -> Result<Self, Tls13DecryptError> {
        let header = record
            .get(..TLS13_RECORD_HEADER_BYTES)
            .ok_or(Tls13DecryptError::IncompleteRecordHeader)?;
        validate_tls13_record_header(header)?;
        let declared_bytes = tls13_record_payload_len(header);
        let encrypted_payload = record
            .get(TLS13_RECORD_HEADER_BYTES..)
            .expect("header length was validated");
        if encrypted_payload.len() != declared_bytes {
            return Err(Tls13DecryptError::RecordLengthMismatch {
                declared_bytes,
                actual_bytes: encrypted_payload.len(),
            });
        }
        validate_tls13_record_payload_len(encrypted_payload.len())?;
        Ok(Self {
            aad: header
                .try_into()
                .expect("TLS record header has fixed length"),
            encrypted_payload,
        })
    }

    pub(in crate::tls::session_secret) fn aad(&self) -> [u8; TLS13_RECORD_HEADER_BYTES] {
        self.aad
    }

    pub(in crate::tls::session_secret) fn encrypted_payload(&self) -> &'a [u8] {
        self.encrypted_payload
    }

    pub(in crate::tls::session_secret) fn buffered(buffer: &[u8]) -> Tls13BufferedRecord {
        let Some(header) = buffer.get(..TLS13_RECORD_HEADER_BYTES) else {
            return Tls13BufferedRecord::Incomplete;
        };
        let declared_bytes = tls13_record_payload_len(header);
        if let Err(error) = validate_tls13_record_payload_len(declared_bytes) {
            return Tls13BufferedRecord::Invalid { error };
        }
        let len = TLS13_RECORD_HEADER_BYTES + declared_bytes;
        if buffer.len() < len {
            Tls13BufferedRecord::Incomplete
        } else {
            Tls13BufferedRecord::Complete { len }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tls::session_secret) enum Tls13BufferedRecord {
    Incomplete,
    Complete { len: usize },
    Invalid { error: Tls13DecryptError },
}

fn validate_tls13_record_header(header: &[u8]) -> Result<(), Tls13DecryptError> {
    if header[0] != TLS13_OUTER_APPLICATION_DATA {
        return Err(Tls13DecryptError::UnsupportedOuterContentType {
            content_type: header[0],
        });
    }
    if header[1..3] != TLS13_LEGACY_RECORD_VERSION {
        return Err(Tls13DecryptError::UnsupportedLegacyVersion {
            version: u16::from_be_bytes([header[1], header[2]]),
        });
    }
    Ok(())
}

fn validate_tls13_record_payload_len(payload_len: usize) -> Result<(), Tls13DecryptError> {
    if payload_len > TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES {
        return Err(Tls13DecryptError::EncryptedPayloadTooLarge {
            actual_bytes: payload_len,
            max_bytes: TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES,
        });
    }
    Ok(())
}

fn tls13_record_payload_len(header: &[u8]) -> usize {
    u16::from_be_bytes([header[3], header[4]]) as usize
}

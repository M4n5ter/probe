use bytes::Bytes;
use ring::{aead, hkdf};
use thiserror::Error;

use super::{
    TlsCipherSuite, TlsSessionSecretKind, TlsSessionSecretProtocol, TlsSessionSecretRecord,
};

const TLS13_RECORD_HEADER_BYTES: usize = 5;
const TLS13_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const TLS13_OUTER_APPLICATION_DATA: u8 = 0x17;
const TLS13_AEAD_TAG_BYTES: usize = 16;
const TLS13_NONCE_BYTES: usize = 12;
const TLS13_MAX_FRAGMENT_BYTES: usize = 16 * 1024;
const TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES: usize = TLS13_MAX_FRAGMENT_BYTES + 256;
const TLS13_MAX_INNER_PLAINTEXT_BYTES: usize =
    TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES - TLS13_AEAD_TAG_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13InnerContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Other(u8),
}

impl Tls13InnerContentType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
            Self::Other(value) => value,
        }
    }

    pub fn is_application_data(self) -> bool {
        matches!(self, Self::ApplicationData)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13DecryptedRecord {
    content_type: Tls13InnerContentType,
    plaintext: Bytes,
}

impl Tls13DecryptedRecord {
    pub fn content_type(&self) -> Tls13InnerContentType {
        self.content_type
    }

    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub fn into_plaintext(self) -> Bytes {
        self.plaintext
    }
}

pub struct Tls13ApplicationDataDecryptor {
    suite: Tls13AeadSuite,
    secret_kind: TlsSessionSecretKind,
    key: aead::LessSafeKey,
    static_iv: [u8; TLS13_NONCE_BYTES],
    sequence_number: u64,
}

impl Tls13ApplicationDataDecryptor {
    pub fn from_session_secret_record(
        record: &TlsSessionSecretRecord,
    ) -> Result<Self, Tls13DecryptError> {
        if record.protocol() != TlsSessionSecretProtocol::Tls13 {
            return Err(Tls13DecryptError::UnsupportedProtocol {
                protocol: record.protocol(),
            });
        }
        let secret_kind = record.secret_kind();
        if !matches!(
            secret_kind,
            TlsSessionSecretKind::ClientApplicationTraffic
                | TlsSessionSecretKind::ServerApplicationTraffic
        ) {
            return Err(Tls13DecryptError::UnsupportedSecretKind { secret_kind });
        }
        let cipher_suite = record
            .cipher_suite()
            .ok_or(Tls13DecryptError::MissingCipherSuite)?;
        let suite = Tls13AeadSuite::from_cipher_suite(cipher_suite)
            .ok_or_else(|| Tls13DecryptError::unsupported_cipher_suite(cipher_suite))?;
        let secret = record.secret();
        if secret.len() != suite.secret_len {
            return Err(Tls13DecryptError::InvalidTrafficSecretLength {
                expected_bytes: suite.secret_len,
                actual_bytes: secret.len(),
            });
        }
        let key_bytes =
            derive_tls13_secret_bytes(secret.as_bytes(), suite.hkdf, b"key", suite.key_len)?;
        let static_iv_vec =
            derive_tls13_secret_bytes(secret.as_bytes(), suite.hkdf, b"iv", TLS13_NONCE_BYTES)?;
        let static_iv = static_iv_vec
            .try_into()
            .expect("TLS 1.3 traffic IV length is fixed");
        let key = aead::UnboundKey::new(suite.aead, &key_bytes)
            .map(aead::LessSafeKey::new)
            .map_err(|_| Tls13DecryptError::CryptoInitializationFailed)?;
        Ok(Self {
            suite,
            secret_kind,
            key,
            static_iv,
            sequence_number: 0,
        })
    }

    pub fn cipher_suite(&self) -> TlsCipherSuite {
        self.suite.cipher_suite
    }

    pub fn secret_kind(&self) -> TlsSessionSecretKind {
        self.secret_kind
    }

    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    pub fn set_sequence_number(&mut self, sequence_number: u64) {
        self.sequence_number = sequence_number;
    }

    pub fn decrypt_next_record(
        &mut self,
        record: &[u8],
    ) -> Result<Tls13DecryptedRecord, Tls13DecryptError> {
        let sequence_number = self.sequence_number;
        let next_sequence_number = sequence_number
            .checked_add(1)
            .ok_or(Tls13DecryptError::SequenceNumberExhausted)?;
        let decrypted = self.decrypt_record_at(sequence_number, record)?;
        self.sequence_number = next_sequence_number;
        Ok(decrypted)
    }

    pub fn decrypt_record_at(
        &self,
        sequence_number: u64,
        record: &[u8],
    ) -> Result<Tls13DecryptedRecord, Tls13DecryptError> {
        let record = Tls13EncryptedRecord::parse(record)?;
        let mut payload = record.encrypted_payload.to_vec();
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce(sequence_number));
        let plaintext = self
            .key
            .open_in_place(nonce, aead::Aad::from(record.aad), &mut payload)
            .map_err(|_| Tls13DecryptError::AeadOpenFailed)?;
        let plain_len = plaintext.len();
        payload.truncate(plain_len);
        split_tls13_inner_plaintext(payload)
    }

    fn nonce(&self, sequence_number: u64) -> [u8; TLS13_NONCE_BYTES] {
        let mut nonce = self.static_iv;
        for (nonce_byte, sequence_byte) in nonce[4..].iter_mut().zip(sequence_number.to_be_bytes())
        {
            *nonce_byte ^= sequence_byte;
        }
        nonce
    }
}

impl std::fmt::Debug for Tls13ApplicationDataDecryptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Tls13ApplicationDataDecryptor")
            .field("cipher_suite", &self.suite.cipher_suite)
            .field("secret_kind", &self.secret_kind)
            .field("sequence_number", &self.sequence_number)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Tls13DecryptError {
    #[error(
        "TLS session secret protocol {protocol:?} is not supported for TLS 1.3 record decryption"
    )]
    UnsupportedProtocol { protocol: TlsSessionSecretProtocol },
    #[error("TLS session secret kind {secret_kind:?} is not an application traffic secret")]
    UnsupportedSecretKind { secret_kind: TlsSessionSecretKind },
    #[error("TLS 1.3 record decryption requires cipher_suite metadata")]
    MissingCipherSuite,
    #[error("TLS cipher suite 0x{code:04x} is not supported for TLS 1.3 record decryption")]
    UnsupportedCipherSuite { code: u16 },
    #[error(
        "TLS traffic secret has invalid length: expected {expected_bytes} bytes, got {actual_bytes} bytes"
    )]
    InvalidTrafficSecretLength {
        expected_bytes: usize,
        actual_bytes: usize,
    },
    #[error("TLS 1.3 protected record is shorter than the record header")]
    IncompleteRecordHeader,
    #[error(
        "TLS 1.3 protected record outer content type 0x{content_type:02x} is not application_data"
    )]
    UnsupportedOuterContentType { content_type: u8 },
    #[error("TLS 1.3 protected record legacy version 0x{version:04x} is not TLS 1.2")]
    UnsupportedLegacyVersion { version: u16 },
    #[error(
        "TLS 1.3 protected record length mismatch: header declares {declared_bytes} payload bytes, record carries {actual_bytes}"
    )]
    RecordLengthMismatch {
        declared_bytes: usize,
        actual_bytes: usize,
    },
    #[error(
        "TLS 1.3 protected record encrypted payload is too short: expected at least {min_bytes} bytes, got {actual_bytes}"
    )]
    EncryptedPayloadTooShort {
        min_bytes: usize,
        actual_bytes: usize,
    },
    #[error(
        "TLS 1.3 protected record encrypted payload exceeds maximum fragment size: got {actual_bytes} bytes, max {max_bytes}"
    )]
    EncryptedPayloadTooLarge {
        actual_bytes: usize,
        max_bytes: usize,
    },
    #[error(
        "TLS 1.3 decrypted inner plaintext exceeds maximum fragment size: got {actual_bytes} bytes, max {max_bytes}"
    )]
    DecryptedRecordTooLarge {
        actual_bytes: usize,
        max_bytes: usize,
    },
    #[error("TLS 1.3 decrypted inner plaintext does not contain a non-zero content type")]
    MissingInnerContentType,
    #[error("TLS 1.3 record authentication failed")]
    AeadOpenFailed,
    #[error("TLS 1.3 record sequence number is exhausted")]
    SequenceNumberExhausted,
    #[error("TLS 1.3 HKDF-Expand-Label failed")]
    HkdfExpandFailed,
    #[error("TLS 1.3 AEAD key initialization failed")]
    CryptoInitializationFailed,
}

impl Tls13DecryptError {
    fn unsupported_cipher_suite(cipher_suite: TlsCipherSuite) -> Self {
        Self::UnsupportedCipherSuite {
            code: cipher_suite.code(),
        }
    }
}

impl From<u8> for Tls13InnerContentType {
    fn from(value: u8) -> Self {
        match value {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tls13AeadSuite {
    cipher_suite: TlsCipherSuite,
    hkdf: hkdf::Algorithm,
    aead: &'static aead::Algorithm,
    key_len: usize,
    secret_len: usize,
}

impl Tls13AeadSuite {
    fn from_cipher_suite(cipher_suite: TlsCipherSuite) -> Option<Self> {
        let suite = match cipher_suite.code() {
            0x1301 => Self {
                cipher_suite,
                hkdf: hkdf::HKDF_SHA256,
                aead: &aead::AES_128_GCM,
                key_len: 16,
                secret_len: 32,
            },
            0x1302 => Self {
                cipher_suite,
                hkdf: hkdf::HKDF_SHA384,
                aead: &aead::AES_256_GCM,
                key_len: 32,
                secret_len: 48,
            },
            0x1303 => Self {
                cipher_suite,
                hkdf: hkdf::HKDF_SHA256,
                aead: &aead::CHACHA20_POLY1305,
                key_len: 32,
                secret_len: 32,
            },
            _ => return None,
        };
        Some(suite)
    }
}

struct Tls13EncryptedRecord<'a> {
    aad: [u8; TLS13_RECORD_HEADER_BYTES],
    encrypted_payload: &'a [u8],
}

impl<'a> Tls13EncryptedRecord<'a> {
    fn parse(record: &'a [u8]) -> Result<Self, Tls13DecryptError> {
        let header = record
            .get(..TLS13_RECORD_HEADER_BYTES)
            .ok_or(Tls13DecryptError::IncompleteRecordHeader)?;
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
        let declared_bytes = u16::from_be_bytes([header[3], header[4]]) as usize;
        let encrypted_payload = record
            .get(TLS13_RECORD_HEADER_BYTES..)
            .expect("header length was validated");
        if encrypted_payload.len() != declared_bytes {
            return Err(Tls13DecryptError::RecordLengthMismatch {
                declared_bytes,
                actual_bytes: encrypted_payload.len(),
            });
        }
        if encrypted_payload.len() < TLS13_AEAD_TAG_BYTES + 1 {
            return Err(Tls13DecryptError::EncryptedPayloadTooShort {
                min_bytes: TLS13_AEAD_TAG_BYTES + 1,
                actual_bytes: encrypted_payload.len(),
            });
        }
        if encrypted_payload.len() > TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES {
            return Err(Tls13DecryptError::EncryptedPayloadTooLarge {
                actual_bytes: encrypted_payload.len(),
                max_bytes: TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES,
            });
        }
        Ok(Self {
            aad: header
                .try_into()
                .expect("TLS record header has fixed length"),
            encrypted_payload,
        })
    }
}

fn split_tls13_inner_plaintext(
    plaintext: Vec<u8>,
) -> Result<Tls13DecryptedRecord, Tls13DecryptError> {
    if plaintext.len() > TLS13_MAX_INNER_PLAINTEXT_BYTES {
        return Err(Tls13DecryptError::DecryptedRecordTooLarge {
            actual_bytes: plaintext.len(),
            max_bytes: TLS13_MAX_INNER_PLAINTEXT_BYTES,
        });
    }
    let Some((content_type_index, content_type)) = plaintext
        .iter()
        .enumerate()
        .rev()
        .find(|(_, byte)| **byte != 0)
    else {
        return Err(Tls13DecryptError::MissingInnerContentType);
    };
    if content_type_index > TLS13_MAX_FRAGMENT_BYTES {
        return Err(Tls13DecryptError::DecryptedRecordTooLarge {
            actual_bytes: content_type_index,
            max_bytes: TLS13_MAX_FRAGMENT_BYTES,
        });
    }
    Ok(Tls13DecryptedRecord {
        content_type: Tls13InnerContentType::from(*content_type),
        plaintext: Bytes::from(plaintext[..content_type_index].to_vec()),
    })
}

fn derive_tls13_secret_bytes(
    secret: &[u8],
    algorithm: hkdf::Algorithm,
    label: &[u8],
    len: usize,
) -> Result<Vec<u8>, Tls13DecryptError> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let output_len = (len as u16).to_be_bytes();
    let label_len = ((LABEL_PREFIX.len() + label.len()) as u8).to_be_bytes();
    let context_len = [0_u8];
    let info = &[
        &output_len[..],
        &label_len[..],
        LABEL_PREFIX,
        label,
        &context_len[..],
    ];
    let prk = hkdf::Prk::new_less_safe(algorithm, secret);
    let mut output = vec![0; len];
    prk.expand(info, HkdfOutputLen(len))
        .and_then(|okm| okm.fill(&mut output))
        .map_err(|_| Tls13DecryptError::HkdfExpandFailed)?;
    Ok(output)
}

#[derive(Debug, Clone, Copy)]
struct HkdfOutputLen(usize);

impl hkdf::KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::super::TlsSessionSecretStore;
    use super::*;
    use crate::tls::decode_hex;

    const CLIENT_RANDOM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SHA256_TRAFFIC_SECRET: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SHA384_TRAFFIC_SECRET: &str = concat!(
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f"
    );
    const OPENSSL_AES_128_GCM_RECORD: &str = concat!(
        "1703030035",
        "624db31e844203eed70ed895907c1dba83b7983bed37e448fef63e37",
        "a1918fb3d23e8ec8696562f3744f95453557cff5fec855a1fe"
    );
    const OPENSSL_AES_256_GCM_RECORD: &str = concat!(
        "1703030035",
        "0f722b1c3a79daf6a0f775aeab0e247af4f48c69bb7587a7e1863e443",
        "ed96684818d5daa0c208d2fd3ecb84f90aa4404ddbf1b92d5"
    );
    const OPENSSL_CHACHA20_POLY1305_RECORD: &str = concat!(
        "1703030035",
        "f5eb3fde2801d692de5eb88cefa11e37b4c5395b58bac6894cfba0af05ba",
        "bf005b816476a454121c73af5258b1af28491fb2682b3c"
    );
    const PLAINTEXT: &[u8] = b"GET /tls13 HTTP/1.1\r\nhost: e2e\r\n\r\n";

    #[test]
    fn decrypts_supported_tls13_application_records_from_session_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        for vector in [
            CipherVector {
                cipher_suite: "0x1301",
                secret: SHA256_TRAFFIC_SECRET,
                record: OPENSSL_AES_128_GCM_RECORD,
            },
            CipherVector {
                cipher_suite: "0x1302",
                secret: SHA384_TRAFFIC_SECRET,
                record: OPENSSL_AES_256_GCM_RECORD,
            },
            CipherVector {
                cipher_suite: "0x1303",
                secret: SHA256_TRAFFIC_SECRET,
                record: OPENSSL_CHACHA20_POLY1305_RECORD,
            },
        ] {
            let record = session_secret_record(
                TlsSessionSecretProtocol::Tls13,
                TlsSessionSecretKind::ClientApplicationTraffic,
                Some(vector.cipher_suite),
                vector.secret,
            )?;
            let mut decryptor = Tls13ApplicationDataDecryptor::from_session_secret_record(&record)?;

            let decrypted = decryptor.decrypt_next_record(&hex(vector.record))?;

            assert_eq!(
                decrypted.content_type(),
                Tls13InnerContentType::ApplicationData
            );
            assert!(decrypted.content_type().is_application_data());
            assert_eq!(decrypted.plaintext(), PLAINTEXT);
            assert_eq!(decryptor.sequence_number(), 1);
            let rendered = format!("{decryptor:?}");
            assert!(rendered.contains("sequence_number"));
            assert!(!rendered.contains(vector.secret));
        }
        Ok(())
    }

    #[test]
    fn record_authentication_failure_does_not_advance_sequence()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            Some("0x1301"),
            SHA256_TRAFFIC_SECRET,
        )?;
        let mut decryptor = Tls13ApplicationDataDecryptor::from_session_secret_record(&record)?;
        let mut wire_record = hex(OPENSSL_AES_128_GCM_RECORD);
        let last = wire_record.last_mut().expect("record has tag");
        *last ^= 0x01;

        let error = decryptor
            .decrypt_next_record(&wire_record)
            .expect_err("tag corruption must fail authentication");

        assert_eq!(error, Tls13DecryptError::AeadOpenFailed);
        assert_eq!(decryptor.sequence_number(), 0);
        Ok(())
    }

    #[test]
    fn rejects_non_application_traffic_secret_kind() -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientHandshakeTraffic,
            Some("0x1301"),
            SHA256_TRAFFIC_SECRET,
        )?;

        let error = Tls13ApplicationDataDecryptor::from_session_secret_record(&record)
            .expect_err("handshake secret is outside this decryptor boundary");

        assert_eq!(
            error,
            Tls13DecryptError::UnsupportedSecretKind {
                secret_kind: TlsSessionSecretKind::ClientHandshakeTraffic,
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_missing_cipher_suite_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            None,
            SHA256_TRAFFIC_SECRET,
        )?;

        let error = Tls13ApplicationDataDecryptor::from_session_secret_record(&record)
            .expect_err("application traffic secret without cipher suite is ambiguous");

        assert_eq!(error, Tls13DecryptError::MissingCipherSuite);
        Ok(())
    }

    #[test]
    fn rejects_invalid_traffic_secret_length() -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            Some("0x1301"),
            "aa",
        )?;

        let error = Tls13ApplicationDataDecryptor::from_session_secret_record(&record)
            .expect_err("AES-128-GCM/SHA-256 traffic secret must be hash length");

        assert_eq!(
            error,
            Tls13DecryptError::InvalidTrafficSecretLength {
                expected_bytes: 32,
                actual_bytes: 1,
            }
        );
        Ok(())
    }

    #[test]
    fn decrypts_full_fragment_with_tls13_padding() -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            Some("0x1301"),
            SHA256_TRAFFIC_SECRET,
        )?;
        let mut decryptor = Tls13ApplicationDataDecryptor::from_session_secret_record(&record)?;
        let mut inner_plaintext = vec![b'a'; TLS13_MAX_FRAGMENT_BYTES];
        inner_plaintext.push(Tls13InnerContentType::ApplicationData.as_u8());
        inner_plaintext.push(0);

        let wire_record = protected_record("0x1301", SHA256_TRAFFIC_SECRET, 0, &inner_plaintext)?;
        let decrypted = decryptor.decrypt_next_record(&wire_record)?;

        assert_eq!(
            decrypted.content_type(),
            Tls13InnerContentType::ApplicationData
        );
        assert_eq!(decrypted.plaintext().len(), TLS13_MAX_FRAGMENT_BYTES);
        assert!(decrypted.plaintext().iter().all(|byte| *byte == b'a'));
        assert_eq!(decryptor.sequence_number(), 1);
        Ok(())
    }

    #[test]
    fn rejects_encrypted_payload_above_tls13_record_limit() -> Result<(), Box<dyn std::error::Error>>
    {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            Some("0x1301"),
            SHA256_TRAFFIC_SECRET,
        )?;
        let decryptor = Tls13ApplicationDataDecryptor::from_session_secret_record(&record)?;
        let actual_bytes = TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES + 1;
        let mut oversized = vec![
            TLS13_OUTER_APPLICATION_DATA,
            TLS13_LEGACY_RECORD_VERSION[0],
            TLS13_LEGACY_RECORD_VERSION[1],
            (actual_bytes >> 8) as u8,
            actual_bytes as u8,
        ];
        oversized.resize(TLS13_RECORD_HEADER_BYTES + actual_bytes, 0);

        let error = decryptor
            .decrypt_record_at(0, &oversized)
            .expect_err("oversized TLS 1.3 protected record must fail before decrypt");

        assert_eq!(
            error,
            Tls13DecryptError::EncryptedPayloadTooLarge {
                actual_bytes,
                max_bytes: TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES,
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_malformed_record_without_guessing() -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            Some("0x1301"),
            SHA256_TRAFFIC_SECRET,
        )?;
        let decryptor = Tls13ApplicationDataDecryptor::from_session_secret_record(&record)?;
        let malformed = hex("160303001100");

        let error = decryptor
            .decrypt_record_at(0, &malformed)
            .expect_err("handshake outer type is not a TLS 1.3 protected record");

        assert_eq!(
            error,
            Tls13DecryptError::UnsupportedOuterContentType { content_type: 0x16 }
        );
        Ok(())
    }

    fn session_secret_record(
        protocol: TlsSessionSecretProtocol,
        secret_kind: TlsSessionSecretKind,
        cipher_suite: Option<&str>,
        secret: &str,
    ) -> Result<TlsSessionSecretRecord, Box<dyn std::error::Error>> {
        let protocol = match protocol {
            TlsSessionSecretProtocol::Tls12 => "tls12",
            TlsSessionSecretProtocol::Tls13 => "tls13",
        };
        let secret_kind = match secret_kind {
            TlsSessionSecretKind::Master => "master_secret",
            TlsSessionSecretKind::ClientHandshakeTraffic => "client_handshake_traffic_secret",
            TlsSessionSecretKind::ServerHandshakeTraffic => "server_handshake_traffic_secret",
            TlsSessionSecretKind::ClientApplicationTraffic => "client_application_traffic_secret",
            TlsSessionSecretKind::ServerApplicationTraffic => "server_application_traffic_secret",
            TlsSessionSecretKind::Exporter => "exporter_secret",
        };
        let cipher_suite = cipher_suite
            .map(|cipher_suite| format!(r#","cipher_suite":"{cipher_suite}""#))
            .unwrap_or_default();
        let material = format!(
            r#"{{"protocol":"{protocol}","secret_kind":"{secret_kind}","client_random":"{CLIENT_RANDOM}","secret":"{secret}"{cipher_suite}}}"#
        );
        let store = TlsSessionSecretStore::parse(material.as_bytes())?;
        Ok(store.records()[0].clone())
    }

    fn protected_record(
        cipher_suite: &str,
        secret: &str,
        sequence_number: u64,
        inner_plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            Some(cipher_suite),
            secret,
        )?;
        let cipher_suite = record
            .cipher_suite()
            .expect("test record carries cipher suite");
        let suite =
            Tls13AeadSuite::from_cipher_suite(cipher_suite).expect("test suite is supported");
        let traffic_secret = record.secret().as_bytes();
        let key_bytes =
            derive_tls13_secret_bytes(traffic_secret, suite.hkdf, b"key", suite.key_len)?;
        let static_iv: [u8; TLS13_NONCE_BYTES] =
            derive_tls13_secret_bytes(traffic_secret, suite.hkdf, b"iv", TLS13_NONCE_BYTES)?
                .try_into()
                .expect("TLS 1.3 traffic IV length is fixed");
        let key = aead::UnboundKey::new(suite.aead, &key_bytes)
            .map(aead::LessSafeKey::new)
            .map_err(|_| "failed to initialize test AEAD key")?;
        let payload_len = inner_plaintext.len() + TLS13_AEAD_TAG_BYTES;
        let mut wire_record = vec![
            TLS13_OUTER_APPLICATION_DATA,
            TLS13_LEGACY_RECORD_VERSION[0],
            TLS13_LEGACY_RECORD_VERSION[1],
            (payload_len >> 8) as u8,
            payload_len as u8,
        ];
        let aad: [u8; TLS13_RECORD_HEADER_BYTES] = wire_record[..TLS13_RECORD_HEADER_BYTES]
            .try_into()
            .expect("TLS record header has fixed length");
        let mut payload = inner_plaintext.to_vec();
        let tag = key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(test_nonce(static_iv, sequence_number)),
                aead::Aad::from(aad),
                &mut payload,
            )
            .map_err(|_| "failed to seal test TLS record")?;
        wire_record.extend_from_slice(&payload);
        wire_record.extend_from_slice(tag.as_ref());
        Ok(wire_record)
    }

    fn test_nonce(
        mut static_iv: [u8; TLS13_NONCE_BYTES],
        sequence_number: u64,
    ) -> [u8; TLS13_NONCE_BYTES] {
        for (nonce_byte, sequence_byte) in
            static_iv[4..].iter_mut().zip(sequence_number.to_be_bytes())
        {
            *nonce_byte ^= sequence_byte;
        }
        static_iv
    }

    fn hex(value: &str) -> Vec<u8> {
        decode_hex(value).expect("test vector must be hex")
    }

    #[derive(Debug, Clone, Copy)]
    struct CipherVector {
        cipher_suite: &'static str,
        secret: &'static str,
        record: &'static str,
    }
}

use capture::{Tls13ApplicationDataDecryptor, TlsKeyLog, TlsSessionSecretStore};

use super::super::harness::e2e_error;

pub(super) const EXPECTED_METHOD: &str = "GET";

const CLIENT_RANDOM_BYTES: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const SERVER_RANDOM_BYTES: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const SHA256_TRAFFIC_SECRET: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const SYNTHETIC_APPLICATION_RECORD: &[u8] = &[
    0x17, 0x03, 0x03, 0x00, 0x35, 0x62, 0x4d, 0xb3, 0x1e, 0x84, 0x42, 0x03, 0xee, 0xd7, 0x0e, 0xd8,
    0x95, 0x90, 0x7c, 0x1d, 0xba, 0x83, 0xb7, 0x98, 0x3b, 0xed, 0x37, 0xe4, 0x48, 0xfe, 0xf6, 0x3e,
    0x37, 0xa1, 0x91, 0x8f, 0xb3, 0xd2, 0x3e, 0x8e, 0xc8, 0x69, 0x65, 0x62, 0xf3, 0x74, 0x4f, 0x95,
    0x45, 0x35, 0x57, 0xcf, 0xf5, 0xfe, 0xc8, 0x55, 0xa1, 0xfe,
];
const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
const TLS_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_SERVER_HELLO: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SyntheticTls13AutoBindingFixture;

impl SyntheticTls13AutoBindingFixture {
    pub(super) fn validate(self) -> Result<(), Box<dyn std::error::Error>> {
        let material = self.session_secret_material_jsonl();
        let store = TlsSessionSecretStore::parse(material.as_bytes())?;
        let record = store
            .records()
            .first()
            .ok_or_else(|| e2e_error("synthetic TLS fixture material is empty"))?;
        if record.client_random().as_bytes() != &CLIENT_RANDOM_BYTES {
            return Err(e2e_error("synthetic TLS fixture material client_random drifted").into());
        }
        let mut decryptor = Tls13ApplicationDataDecryptor::from_session_secret_record(record)?;
        let decrypted = decryptor.decrypt_next_record(self.application_record())?;
        let expected_plaintext = self.expected_plaintext();
        if !decrypted.content_type().is_application_data()
            || decrypted.plaintext() != expected_plaintext.as_slice()
        {
            return Err(e2e_error(
                "synthetic TLS fixture record does not match expected plaintext",
            )
            .into());
        }
        if self.key_log_material()
            != format!(
                "{}{}",
                self.partial_key_log_material(),
                self.key_log_material_tail()
            )
        {
            return Err(e2e_error("synthetic TLS fixture keylog material is inconsistent").into());
        }
        let partial_key_log =
            TlsKeyLog::parse_live_snapshot(self.partial_key_log_material().as_bytes())?;
        if !partial_key_log.entries().is_empty() {
            return Err(e2e_error(
                "synthetic TLS fixture partial keylog line produced committed entries",
            )
            .into());
        }
        let key_log = TlsKeyLog::parse_live_snapshot(self.key_log_material().as_bytes())?;
        let key_log_store =
            TlsSessionSecretStore::from_tls_key_log(&key_log)?.ok_or_else(|| {
                e2e_error(
                    "synthetic TLS fixture keylog material produced no session-secret records",
                )
            })?;
        let key_log_record = key_log_store
            .records()
            .first()
            .ok_or_else(|| e2e_error("synthetic TLS fixture keylog store is empty"))?;
        if key_log_record.client_random().as_bytes() != &CLIENT_RANDOM_BYTES {
            return Err(e2e_error("synthetic TLS fixture keylog client_random drifted").into());
        }
        if key_log_record.cipher_suite().is_some() {
            return Err(e2e_error(
                "synthetic TLS fixture keylog record unexpectedly contains cipher_suite",
            )
            .into());
        }
        Ok(())
    }

    pub(super) fn session_secret_material_jsonl(self) -> String {
        let client_random = hex_encode(&CLIENT_RANDOM_BYTES);
        let cipher_suite = format!("0x{TLS_AES_128_GCM_SHA256:04x}");
        format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","cipher_suite":"{cipher_suite}","secret":"{SHA256_TRAFFIC_SECRET}"}}
"#
        )
    }

    pub(super) fn client_hello_record(self) -> Vec<u8> {
        tls_handshake_record(TLS_CLIENT_HELLO, tls_client_hello_body())
    }

    pub(super) fn server_hello_record(self) -> Vec<u8> {
        tls_handshake_record(TLS_SERVER_HELLO, tls_server_hello_body())
    }

    pub(super) fn application_record(self) -> &'static [u8] {
        SYNTHETIC_APPLICATION_RECORD
    }

    pub(super) fn key_log_material(self) -> String {
        format!(
            "{}{SHA256_TRAFFIC_SECRET}\n",
            self.partial_key_log_material()
        )
    }

    pub(super) fn partial_key_log_material(self) -> String {
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} ",
            hex_encode(&CLIENT_RANDOM_BYTES)
        )
    }

    pub(super) fn key_log_material_tail(self) -> String {
        format!("{SHA256_TRAFFIC_SECRET}\n")
    }

    pub(super) fn expected_plaintext(self) -> Vec<u8> {
        format!(
            "{EXPECTED_METHOD} {} HTTP/1.1\r\nhost: e2e\r\n\r\n",
            self.target()
        )
        .into_bytes()
    }

    pub(super) fn target(self) -> &'static str {
        "/tls13"
    }

    pub(super) fn policy_alert(self) -> String {
        format!("tls session secret policy observed {}", self.target())
    }
}

fn tls_handshake_record(handshake_type: u8, body: Vec<u8>) -> Vec<u8> {
    let mut handshake = vec![
        handshake_type,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);
    tls_record(
        TLS_HANDSHAKE_CONTENT_TYPE,
        TLS_LEGACY_RECORD_VERSION,
        handshake,
    )
}

fn tls_client_hello_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&CLIENT_RANDOM_BYTES);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&[1, 0]);
    let extensions = supported_versions_client_extension();
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    body
}

fn tls_server_hello_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&SERVER_RANDOM_BYTES);
    body.push(0);
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
    body.push(0);
    let extensions = supported_versions_server_extension();
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    body
}

fn supported_versions_client_extension() -> Vec<u8> {
    vec![
        0x00,
        0x2b,
        0x00,
        0x03,
        0x02,
        TLS13_VERSION[0],
        TLS13_VERSION[1],
    ]
}

fn supported_versions_server_extension() -> Vec<u8> {
    vec![0x00, 0x2b, 0x00, 0x02, TLS13_VERSION[0], TLS13_VERSION[1]]
}

fn tls_record(content_type: u8, version: [u8; 2], payload: Vec<u8>) -> Vec<u8> {
    let mut record = vec![
        content_type,
        version[0],
        version[1],
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ];
    record.extend_from_slice(&payload);
    record
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

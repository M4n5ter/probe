use std::collections::BTreeMap;

use serde::Serialize;
use thiserror::Error;

use super::super::{TlsMaterialLookup, TlsRandom, TlsSecret, decode_hex, hex_len, resolve_lookup};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKeyLog {
    entries: Vec<TlsKeyLogEntry>,
}

impl TlsKeyLog {
    pub fn parse(bytes: &[u8]) -> Result<Self, TlsKeyLogParseError> {
        let content = std::str::from_utf8(bytes).map_err(|_| TlsKeyLogParseError::InvalidUtf8)?;
        let mut entries = Vec::new();
        for (index, line) in content.lines().enumerate() {
            let line_number = index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            entries.push(TlsKeyLogEntry::parse(line_number, line)?);
        }
        Ok(Self { entries })
    }

    pub fn parse_live_snapshot(bytes: &[u8]) -> Result<Self, TlsKeyLogParseError> {
        Self::parse(complete_live_snapshot_bytes(bytes))
    }

    pub fn entries(&self) -> &[TlsKeyLogEntry] {
        &self.entries
    }

    pub fn lookup_secret_for_label_and_context(
        &self,
        label: &TlsKeyLogLabel,
        context: &[u8],
    ) -> TlsMaterialLookup<'_, TlsSecret> {
        resolve_lookup(
            self.entries
                .iter()
                .filter(|entry| entry.label == *label && entry.context.as_ref() == context)
                .map(TlsKeyLogEntry::secret),
        )
    }

    pub fn lookup_secret_for_label_and_random(
        &self,
        label: &TlsKeyLogLabel,
        random: &TlsRandom,
    ) -> TlsMaterialLookup<'_, TlsSecret> {
        self.lookup_secret_for_label_and_context(label, random.as_bytes())
    }

    pub fn summary(&self) -> TlsKeyLogSummary {
        let mut labels = BTreeMap::<String, u64>::new();
        for entry in &self.entries {
            *labels.entry(entry.label.as_str().to_string()).or_default() += 1;
        }
        TlsKeyLogSummary {
            entries: self.entries.len() as u64,
            labels: labels
                .into_iter()
                .map(|(label, count)| TlsKeyLogLabelCount { label, count })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKeyLogEntry {
    label: TlsKeyLogLabel,
    context: Box<[u8]>,
    secret: TlsSecret,
}

impl TlsKeyLogEntry {
    fn parse(line_number: usize, line: &str) -> Result<Self, TlsKeyLogParseError> {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let [label, context, secret] = fields.as_slice() else {
            return Err(TlsKeyLogParseError::InvalidFieldCount { line_number });
        };
        let label = TlsKeyLogLabel::parse(label)
            .ok_or(TlsKeyLogParseError::InvalidLabel { line_number })?;
        let context_len = hex_len(context).ok_or(TlsKeyLogParseError::InvalidHex {
            line_number,
            field: TlsKeyLogField::Context,
        })?;
        if let Some(expected_bytes) = label.expected_context_len()
            && context_len != expected_bytes
        {
            return Err(TlsKeyLogParseError::InvalidContextLength {
                line_number,
                label: label.as_str().to_string(),
                expected_bytes,
                actual_bytes: context_len,
            });
        }
        let context = decode_hex(context)
            .expect("context was validated before decoding")
            .into_boxed_slice();
        let secret = TlsSecret::from_hex(secret).ok_or(TlsKeyLogParseError::InvalidHex {
            line_number,
            field: TlsKeyLogField::Secret,
        })?;
        Ok(Self {
            label,
            context,
            secret,
        })
    }

    pub fn label(&self) -> &TlsKeyLogLabel {
        &self.label
    }

    pub fn context(&self) -> &[u8] {
        &self.context
    }

    pub fn secret(&self) -> &TlsSecret {
        &self.secret
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlsKeyLogLabel {
    Rsa,
    ClientRandom,
    ClientEarlyTrafficSecret,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientTrafficSecret0,
    ServerTrafficSecret0,
    ExporterSecret,
    EarlyExporterSecret,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsKeyLogSummary {
    pub entries: u64,
    pub labels: Vec<TlsKeyLogLabelCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsKeyLogLabelCount {
    pub label: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TlsKeyLogParseError {
    #[error("TLS key log file is not valid UTF-8")]
    InvalidUtf8,
    #[error("TLS key log line {line_number} must have exactly 3 fields")]
    InvalidFieldCount { line_number: usize },
    #[error("TLS key log line {line_number} has invalid label")]
    InvalidLabel { line_number: usize },
    #[error("TLS key log line {line_number} has invalid hex in {field}")]
    InvalidHex {
        line_number: usize,
        field: TlsKeyLogField,
    },
    #[error(
        "TLS key log line {line_number} has invalid {label} context length: expected {expected_bytes} bytes, got {actual_bytes} bytes"
    )]
    InvalidContextLength {
        line_number: usize,
        label: String,
        expected_bytes: usize,
        actual_bytes: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsKeyLogField {
    Context,
    Secret,
}

impl TlsKeyLogSummary {
    pub fn parse(bytes: &[u8]) -> Result<Self, TlsKeyLogParseError> {
        TlsKeyLog::parse(bytes).map(|key_log| key_log.summary())
    }
}

impl TlsKeyLogLabel {
    pub fn parse(label: &str) -> Option<Self> {
        let label = match label {
            "RSA" => Self::Rsa,
            "CLIENT_RANDOM" => Self::ClientRandom,
            "CLIENT_EARLY_TRAFFIC_SECRET" => Self::ClientEarlyTrafficSecret,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Self::ClientHandshakeTrafficSecret,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => Self::ServerHandshakeTrafficSecret,
            "CLIENT_TRAFFIC_SECRET_0" => Self::ClientTrafficSecret0,
            "SERVER_TRAFFIC_SECRET_0" => Self::ServerTrafficSecret0,
            "EXPORTER_SECRET" => Self::ExporterSecret,
            "EARLY_EXPORTER_SECRET" => Self::EarlyExporterSecret,
            other if is_valid_label(other) => Self::Other(other.to_string()),
            _ => return None,
        };
        Some(label)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Rsa => "RSA",
            Self::ClientRandom => "CLIENT_RANDOM",
            Self::ClientEarlyTrafficSecret => "CLIENT_EARLY_TRAFFIC_SECRET",
            Self::ClientHandshakeTrafficSecret => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            Self::ServerHandshakeTrafficSecret => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            Self::ClientTrafficSecret0 => "CLIENT_TRAFFIC_SECRET_0",
            Self::ServerTrafficSecret0 => "SERVER_TRAFFIC_SECRET_0",
            Self::ExporterSecret => "EXPORTER_SECRET",
            Self::EarlyExporterSecret => "EARLY_EXPORTER_SECRET",
            Self::Other(label) => label,
        }
    }

    pub fn expected_context_len(&self) -> Option<usize> {
        match self {
            Self::Rsa | Self::Other(_) => None,
            Self::ClientRandom
            | Self::ClientEarlyTrafficSecret
            | Self::ClientHandshakeTrafficSecret
            | Self::ServerHandshakeTrafficSecret
            | Self::ClientTrafficSecret0
            | Self::ServerTrafficSecret0
            | Self::ExporterSecret
            | Self::EarlyExporterSecret => Some(32),
        }
    }
}

impl std::fmt::Display for TlsKeyLogField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Context => formatter.write_str("context"),
            Self::Secret => formatter.write_str("secret"),
        }
    }
}

fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn complete_live_snapshot_bytes(bytes: &[u8]) -> &[u8] {
    if ends_with_lf(bytes) {
        return bytes;
    }
    bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|last_newline| &bytes[..=last_newline])
        .unwrap_or_default()
}

fn ends_with_lf(bytes: &[u8]) -> bool {
    bytes.last().is_some_and(|byte| *byte == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nss_key_log_file_and_summarizes_without_serializing_secret_bytes() {
        let key_log = TlsKeyLog::parse(
            b"
# comment
CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
SERVER_TRAFFIC_SECRET_0 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
FUTURE_SECRET_LABEL 01 ff
",
        )
        .expect("valid key log");
        let summary = key_log.summary();

        assert_eq!(summary.entries, 3);
        assert_eq!(
            summary.labels,
            vec![
                TlsKeyLogLabelCount {
                    label: "CLIENT_RANDOM".to_string(),
                    count: 1
                },
                TlsKeyLogLabelCount {
                    label: "FUTURE_SECRET_LABEL".to_string(),
                    count: 1
                },
                TlsKeyLogLabelCount {
                    label: "SERVER_TRAFFIC_SECRET_0".to_string(),
                    count: 1
                }
            ]
        );
        let random =
            TlsRandom::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("valid random");
        let TlsMaterialLookup::Found(secret) =
            key_log.lookup_secret_for_label_and_random(&TlsKeyLogLabel::ClientRandom, &random)
        else {
            panic!("client random secret must be uniquely available");
        };
        assert_eq!(secret.len(), 48);
        assert!(!format!("{secret:?}").contains("111111"));
    }

    #[test]
    fn lookup_reports_ambiguous_duplicate_contexts() {
        let material = b"
CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 1111
CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 2222
";
        let key_log = TlsKeyLog::parse(material).expect("valid key log");
        let random =
            TlsRandom::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("valid random");

        let lookup =
            key_log.lookup_secret_for_label_and_random(&TlsKeyLogLabel::ClientRandom, &random);

        assert_eq!(lookup, TlsMaterialLookup::Ambiguous { matches: 2 });
    }

    #[test]
    fn rejects_key_log_lines_without_secret_values() {
        let error = TlsKeyLogSummary::parse(
            b"CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
        )
        .expect_err("missing secret must fail");

        assert_eq!(
            error,
            TlsKeyLogParseError::InvalidFieldCount { line_number: 1 }
        );
    }

    #[test]
    fn rejects_non_hex_secrets_without_leaking_the_value() {
        let error = TlsKeyLogSummary::parse(
            b"CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f not-a-secret\n",
        )
        .expect_err("invalid secret must fail");

        assert_eq!(
            error,
            TlsKeyLogParseError::InvalidHex {
                line_number: 1,
                field: TlsKeyLogField::Secret,
            }
        );
        assert!(!error.to_string().contains("not-a-secret"));
    }

    #[test]
    fn rejects_wrong_client_random_length_for_nss_labels() {
        let error = TlsKeyLogSummary::parse(b"CLIENT_RANDOM 000102 aa\n")
            .expect_err("short client random must fail");

        assert_eq!(
            error,
            TlsKeyLogParseError::InvalidContextLength {
                line_number: 1,
                label: "CLIENT_RANDOM".to_string(),
                expected_bytes: 32,
                actual_bytes: 3,
            }
        );
    }

    #[test]
    fn live_snapshot_ignores_unterminated_tail_even_when_tail_is_syntactically_valid() {
        let material = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_0 {} aa",
            "00".repeat(32),
            "11".repeat(32),
            "22".repeat(32)
        );

        let key_log =
            TlsKeyLog::parse_live_snapshot(material.as_bytes()).expect("valid live snapshot");

        assert_eq!(key_log.entries().len(), 1);
        assert_eq!(key_log.entries()[0].secret().as_bytes(), vec![0x11; 32]);
    }

    #[test]
    fn live_snapshot_treats_trailing_cr_as_unterminated_tail() {
        let material = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\r\nCLIENT_TRAFFIC_SECRET_0 {} aa\r",
            "00".repeat(32),
            "11".repeat(32),
            "22".repeat(32)
        );

        let key_log =
            TlsKeyLog::parse_live_snapshot(material.as_bytes()).expect("valid live snapshot");

        assert_eq!(key_log.entries().len(), 1);
        assert_eq!(key_log.entries()[0].secret().as_bytes(), vec![0x11; 32]);
    }

    #[test]
    fn live_snapshot_without_any_complete_line_is_empty() {
        let material = format!("CLIENT_TRAFFIC_SECRET_0 {} aa", "00".repeat(32),);

        let key_log =
            TlsKeyLog::parse_live_snapshot(material.as_bytes()).expect("empty live snapshot");

        assert!(key_log.entries().is_empty());
    }
}

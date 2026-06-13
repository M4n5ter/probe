use std::collections::BTreeMap;

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TlsKeyLogLabel {
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
        let content = std::str::from_utf8(bytes).map_err(|_| TlsKeyLogParseError::InvalidUtf8)?;
        let mut entries = 0_u64;
        let mut labels = BTreeMap::<String, u64>::new();
        for (index, line) in content.lines().enumerate() {
            let line_number = index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let label = parse_entry_label(line_number, line)?;
            entries += 1;
            *labels.entry(label.wire_name()).or_default() += 1;
        }
        Ok(Self {
            entries,
            labels: labels
                .into_iter()
                .map(|(label, count)| TlsKeyLogLabelCount { label, count })
                .collect(),
        })
    }
}

fn parse_entry_label(
    line_number: usize,
    line: &str,
) -> Result<TlsKeyLogLabel, TlsKeyLogParseError> {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    let [label, context, secret] = fields.as_slice() else {
        return Err(TlsKeyLogParseError::InvalidFieldCount { line_number });
    };
    let label =
        TlsKeyLogLabel::parse(label).ok_or(TlsKeyLogParseError::InvalidLabel { line_number })?;
    let context_len = hex_len(context, line_number, TlsKeyLogField::Context)?;
    hex_len(secret, line_number, TlsKeyLogField::Secret)?;
    if let Some(expected_bytes) = label.expected_context_len()
        && context_len != expected_bytes
    {
        return Err(TlsKeyLogParseError::InvalidContextLength {
            line_number,
            label: label.wire_name(),
            expected_bytes,
            actual_bytes: context_len,
        });
    }
    Ok(label)
}

impl TlsKeyLogLabel {
    fn parse(label: &str) -> Option<Self> {
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

    fn wire_name(&self) -> String {
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
        .to_string()
    }

    fn expected_context_len(&self) -> Option<usize> {
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

fn hex_len(
    value: &str,
    line_number: usize,
    field: TlsKeyLogField,
) -> Result<usize, TlsKeyLogParseError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TlsKeyLogParseError::InvalidHex { line_number, field });
    }
    Ok(value.len() / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nss_key_log_file_without_retaining_secret_bytes() {
        let summary = TlsKeyLogSummary::parse(
            b"
# comment
CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
SERVER_TRAFFIC_SECRET_0 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
FUTURE_SECRET_LABEL 01 ff
",
        )
        .expect("valid key log");

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
}

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const RANDOM_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsSessionSecretSummary {
    entries: u64,
    protocols: Vec<TlsSessionSecretProtocolCount>,
    secret_kinds: Vec<TlsSessionSecretKindCount>,
    secret_min_bytes: u64,
    secret_max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsSessionSecretProtocolCount {
    protocol: TlsSessionSecretProtocol,
    count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsSessionSecretKindCount {
    secret_kind: TlsSessionSecretKind,
    count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind}")]
pub struct TlsSessionSecretParseError {
    kind: TlsSessionSecretParseErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TlsSessionSecretParseErrorKind {
    InvalidUtf8,
    NoEntries,
    InvalidJson {
        line_number: usize,
        column: usize,
        kind: TlsSessionSecretJsonErrorKind,
    },
    InvalidHex {
        line_number: usize,
        field: TlsSessionSecretField,
    },
    InvalidFieldLength {
        line_number: usize,
        field: TlsSessionSecretField,
        expected_bytes: usize,
        actual_bytes: usize,
    },
    InvalidSecretKindForProtocol {
        line_number: usize,
    },
    InvalidCipherSuite {
        line_number: usize,
    },
    InvalidTimeRange {
        line_number: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsSessionSecretField {
    ClientRandom,
    ServerRandom,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsSessionSecretJsonErrorKind {
    Io,
    Syntax,
    Data,
    Eof,
}

impl TlsSessionSecretSummary {
    pub fn parse(bytes: &[u8]) -> Result<Self, TlsSessionSecretParseError> {
        let content =
            std::str::from_utf8(bytes).map_err(|_| TlsSessionSecretParseError::invalid_utf8())?;
        let mut entries = 0_u64;
        let mut protocol_counts = BTreeMap::<TlsSessionSecretProtocol, u64>::new();
        let mut secret_kind_counts = BTreeMap::<TlsSessionSecretKind, u64>::new();
        let mut secret_min_bytes = u64::MAX;
        let mut secret_max_bytes = 0_u64;

        for (index, line) in content.lines().enumerate() {
            let line_number = index + 1;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record = TlsSessionSecretRecordWire::parse(line_number, line)?;
            let secret_bytes = record.validate(line_number)? as u64;

            entries += 1;
            *protocol_counts.entry(record.protocol).or_default() += 1;
            *secret_kind_counts.entry(record.secret_kind).or_default() += 1;
            secret_min_bytes = secret_min_bytes.min(secret_bytes);
            secret_max_bytes = secret_max_bytes.max(secret_bytes);
        }

        if entries == 0 {
            return Err(TlsSessionSecretParseError::no_entries());
        }

        Ok(Self {
            entries,
            protocols: protocol_counts
                .into_iter()
                .map(|(protocol, count)| TlsSessionSecretProtocolCount { protocol, count })
                .collect(),
            secret_kinds: secret_kind_counts
                .into_iter()
                .map(|(secret_kind, count)| TlsSessionSecretKindCount { secret_kind, count })
                .collect(),
            secret_min_bytes,
            secret_max_bytes,
        })
    }
}

impl TlsSessionSecretParseError {
    fn new(kind: TlsSessionSecretParseErrorKind) -> Self {
        Self { kind }
    }

    fn invalid_utf8() -> Self {
        Self::new(TlsSessionSecretParseErrorKind::InvalidUtf8)
    }

    fn no_entries() -> Self {
        Self::new(TlsSessionSecretParseErrorKind::NoEntries)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsSessionSecretRecordWire {
    protocol: TlsSessionSecretProtocol,
    secret_kind: TlsSessionSecretKind,
    client_random: String,
    secret: String,
    #[serde(default)]
    server_random: Option<String>,
    #[serde(default)]
    cipher_suite: Option<String>,
    #[serde(default)]
    not_before_unix_ns: Option<u64>,
    #[serde(default)]
    not_after_unix_ns: Option<u64>,
}

impl TlsSessionSecretRecordWire {
    fn parse(line_number: usize, line: &str) -> Result<Self, TlsSessionSecretParseError> {
        serde_json::from_str(line).map_err(|source| {
            TlsSessionSecretParseError::new(TlsSessionSecretParseErrorKind::InvalidJson {
                line_number,
                column: source.column(),
                kind: source.classify().into(),
            })
        })
    }

    fn validate(&self, line_number: usize) -> Result<usize, TlsSessionSecretParseError> {
        if !self.secret_kind.is_valid_for(self.protocol) {
            return Err(TlsSessionSecretParseError::new(
                TlsSessionSecretParseErrorKind::InvalidSecretKindForProtocol { line_number },
            ));
        }
        validate_fixed_hex_len(
            &self.client_random,
            line_number,
            TlsSessionSecretField::ClientRandom,
            RANDOM_BYTES,
        )?;
        if let Some(server_random) = &self.server_random {
            validate_fixed_hex_len(
                server_random,
                line_number,
                TlsSessionSecretField::ServerRandom,
                RANDOM_BYTES,
            )?;
        }
        if let Some(cipher_suite) = &self.cipher_suite {
            validate_cipher_suite(line_number, cipher_suite)?;
        }
        if let (Some(not_before), Some(not_after)) =
            (self.not_before_unix_ns, self.not_after_unix_ns)
            && not_after < not_before
        {
            return Err(TlsSessionSecretParseError::new(
                TlsSessionSecretParseErrorKind::InvalidTimeRange { line_number },
            ));
        }
        hex_len(&self.secret, line_number, TlsSessionSecretField::Secret)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TlsSessionSecretProtocol {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum TlsSessionSecretKind {
    #[serde(rename = "master_secret")]
    Master,
    #[serde(rename = "client_handshake_traffic_secret")]
    ClientHandshakeTraffic,
    #[serde(rename = "server_handshake_traffic_secret")]
    ServerHandshakeTraffic,
    #[serde(rename = "client_application_traffic_secret")]
    ClientApplicationTraffic,
    #[serde(rename = "server_application_traffic_secret")]
    ServerApplicationTraffic,
    #[serde(rename = "exporter_secret")]
    Exporter,
}

impl TlsSessionSecretKind {
    fn is_valid_for(self, protocol: TlsSessionSecretProtocol) -> bool {
        match protocol {
            TlsSessionSecretProtocol::Tls12 => matches!(self, Self::Master),
            TlsSessionSecretProtocol::Tls13 => matches!(
                self,
                Self::ClientHandshakeTraffic
                    | Self::ServerHandshakeTraffic
                    | Self::ClientApplicationTraffic
                    | Self::ServerApplicationTraffic
                    | Self::Exporter
            ),
        }
    }
}

impl std::fmt::Display for TlsSessionSecretParseErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUtf8 => formatter.write_str("TLS session secret file is not valid UTF-8"),
            Self::NoEntries => {
                formatter.write_str("TLS session secret file has no session secret records")
            }
            Self::InvalidJson {
                line_number,
                column,
                kind,
            } => write!(
                formatter,
                "TLS session secret line {line_number} is not valid JSON: {kind} at column {column}"
            ),
            Self::InvalidHex { line_number, field } => write!(
                formatter,
                "TLS session secret line {line_number} has invalid hex in {field}"
            ),
            Self::InvalidFieldLength {
                line_number,
                field,
                expected_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "TLS session secret line {line_number} has invalid {field} length: expected {expected_bytes} bytes, got {actual_bytes} bytes"
            ),
            Self::InvalidSecretKindForProtocol { line_number } => write!(
                formatter,
                "TLS session secret line {line_number} has secret_kind that is not valid for protocol"
            ),
            Self::InvalidCipherSuite { line_number } => write!(
                formatter,
                "TLS session secret line {line_number} has invalid cipher_suite format"
            ),
            Self::InvalidTimeRange { line_number } => write!(
                formatter,
                "TLS session secret line {line_number} has not_after_unix_ns before not_before_unix_ns"
            ),
        }
    }
}

impl std::fmt::Display for TlsSessionSecretField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientRandom => formatter.write_str("client_random"),
            Self::ServerRandom => formatter.write_str("server_random"),
            Self::Secret => formatter.write_str("secret"),
        }
    }
}

impl std::fmt::Display for TlsSessionSecretJsonErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => formatter.write_str("io"),
            Self::Syntax => formatter.write_str("syntax"),
            Self::Data => formatter.write_str("data"),
            Self::Eof => formatter.write_str("eof"),
        }
    }
}

impl From<serde_json::error::Category> for TlsSessionSecretJsonErrorKind {
    fn from(category: serde_json::error::Category) -> Self {
        match category {
            serde_json::error::Category::Io => Self::Io,
            serde_json::error::Category::Syntax => Self::Syntax,
            serde_json::error::Category::Data => Self::Data,
            serde_json::error::Category::Eof => Self::Eof,
        }
    }
}

fn validate_fixed_hex_len(
    value: &str,
    line_number: usize,
    field: TlsSessionSecretField,
    expected_bytes: usize,
) -> Result<(), TlsSessionSecretParseError> {
    let actual_bytes = hex_len(value, line_number, field)?;
    if actual_bytes != expected_bytes {
        return Err(TlsSessionSecretParseError::new(
            TlsSessionSecretParseErrorKind::InvalidFieldLength {
                line_number,
                field,
                expected_bytes,
                actual_bytes,
            },
        ));
    }
    Ok(())
}

fn validate_cipher_suite(
    line_number: usize,
    cipher_suite: &str,
) -> Result<(), TlsSessionSecretParseError> {
    let Some(hex) = cipher_suite.strip_prefix("0x") else {
        return Err(TlsSessionSecretParseError::new(
            TlsSessionSecretParseErrorKind::InvalidCipherSuite { line_number },
        ));
    };
    if hex.len() != 4 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(TlsSessionSecretParseError::new(
            TlsSessionSecretParseErrorKind::InvalidCipherSuite { line_number },
        ));
    }
    Ok(())
}

fn hex_len(
    value: &str,
    line_number: usize,
    field: TlsSessionSecretField,
) -> Result<usize, TlsSessionSecretParseError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TlsSessionSecretParseError::new(
            TlsSessionSecretParseErrorKind::InvalidHex { line_number, field },
        ));
    }
    Ok(value.len() / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jsonl_session_secret_file_without_retaining_secret_bytes() {
        let client_random_a = "00".repeat(RANDOM_BYTES);
        let client_random_b = "11".repeat(RANDOM_BYTES);
        let server_random = "22".repeat(RANDOM_BYTES);
        let client_secret = "aa".repeat(32);
        let master_secret = "bb".repeat(48);
        let material = format!(
            r#"
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random_a}","server_random":"{server_random}","cipher_suite":"0x1301","secret":"{client_secret}","not_before_unix_ns":10,"not_after_unix_ns":20}}
{{"protocol":"tls12","secret_kind":"master_secret","client_random":"{client_random_b}","secret":"{master_secret}"}}
"#
        );

        let summary =
            TlsSessionSecretSummary::parse(material.as_bytes()).expect("valid session secret file");

        assert_eq!(summary.entries, 2);
        assert_eq!(
            summary.protocols,
            vec![
                TlsSessionSecretProtocolCount {
                    protocol: TlsSessionSecretProtocol::Tls12,
                    count: 1
                },
                TlsSessionSecretProtocolCount {
                    protocol: TlsSessionSecretProtocol::Tls13,
                    count: 1
                }
            ]
        );
        assert_eq!(
            summary.secret_kinds,
            vec![
                TlsSessionSecretKindCount {
                    secret_kind: TlsSessionSecretKind::Master,
                    count: 1
                },
                TlsSessionSecretKindCount {
                    secret_kind: TlsSessionSecretKind::ClientApplicationTraffic,
                    count: 1
                }
            ]
        );
        assert_eq!(summary.secret_min_bytes, 32);
        assert_eq!(summary.secret_max_bytes, 48);
    }

    #[test]
    fn rejects_empty_session_secret_file() {
        let error = TlsSessionSecretSummary::parse(b"\n\n")
            .expect_err("empty explicit session secret material must fail");

        assert_eq!(error.kind, TlsSessionSecretParseErrorKind::NoEntries);
    }

    #[test]
    fn rejects_invalid_secret_hex_without_leaking_secret_value() {
        let client_random = "00".repeat(RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"not-a-secret"}}"#
        );

        let error = TlsSessionSecretSummary::parse(material.as_bytes())
            .expect_err("invalid secret must fail");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidHex {
                line_number: 1,
                field: TlsSessionSecretField::Secret
            }
        );
        assert!(!error.to_string().contains("not-a-secret"));
    }

    #[test]
    fn rejects_invalid_json_without_leaking_input_fragments() {
        let client_random = "00".repeat(RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"sensitive-protocol-value","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa"}}"#
        );

        let error = TlsSessionSecretSummary::parse(material.as_bytes())
            .expect_err("invalid JSON data must fail");

        assert!(matches!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidJson {
                line_number: 1,
                column: 1..,
                kind: TlsSessionSecretJsonErrorKind::Data,
            }
        ));
        assert!(!error.to_string().contains("sensitive-protocol-value"));
    }

    #[test]
    fn rejects_wrong_client_random_length() {
        let error = TlsSessionSecretSummary::parse(
            br#"{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"000102","secret":"aa"}"#,
        )
        .expect_err("short client random must fail");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidFieldLength {
                line_number: 1,
                field: TlsSessionSecretField::ClientRandom,
                expected_bytes: RANDOM_BYTES,
                actual_bytes: 3,
            }
        );
    }

    #[test]
    fn rejects_invalid_time_range() {
        let client_random = "00".repeat(RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa","not_before_unix_ns":20,"not_after_unix_ns":10}}"#
        );

        let error = TlsSessionSecretSummary::parse(material.as_bytes())
            .expect_err("inverted validity window must fail");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidTimeRange { line_number: 1 }
        );
    }

    #[test]
    fn rejects_tls12_record_with_tls13_traffic_secret_kind() {
        let client_random = "00".repeat(RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"tls12","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa"}}"#
        );

        let error = TlsSessionSecretSummary::parse(material.as_bytes())
            .expect_err("TLS 1.2 cannot carry TLS 1.3 traffic secrets");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidSecretKindForProtocol { line_number: 1 }
        );
    }

    #[test]
    fn rejects_tls13_record_with_tls12_master_secret_kind() {
        let client_random = "00".repeat(RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"master_secret","client_random":"{client_random}","secret":"aa"}}"#
        );

        let error = TlsSessionSecretSummary::parse(material.as_bytes())
            .expect_err("TLS 1.3 cannot carry a TLS 1.2 master secret");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidSecretKindForProtocol { line_number: 1 }
        );
    }
}

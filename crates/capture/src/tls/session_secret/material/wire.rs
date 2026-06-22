use serde::Deserialize;
use thiserror::Error;

use crate::tls::{TLS_RANDOM_BYTES, TlsRandom, TlsSecret, hex_len};

use super::record::{
    TlsCipherSuite, TlsSessionSecretKind, TlsSessionSecretProtocol, TlsSessionSecretRecord,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind}")]
pub struct TlsSessionSecretParseError {
    pub(super) kind: TlsSessionSecretParseErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TlsSessionSecretParseErrorKind {
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
pub(super) enum TlsSessionSecretField {
    ClientRandom,
    ServerRandom,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TlsSessionSecretJsonErrorKind {
    Io,
    Syntax,
    Data,
    Eof,
}

impl TlsSessionSecretParseError {
    pub(super) fn new(kind: TlsSessionSecretParseErrorKind) -> Self {
        Self { kind }
    }

    pub(super) fn invalid_utf8() -> Self {
        Self::new(TlsSessionSecretParseErrorKind::InvalidUtf8)
    }

    pub(super) fn no_entries() -> Self {
        Self::new(TlsSessionSecretParseErrorKind::NoEntries)
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TlsSessionSecretRecordWire {
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
    pub(super) fn parse(
        line_number: usize,
        line: &str,
    ) -> Result<Self, TlsSessionSecretParseError> {
        serde_json::from_str(line).map_err(|source| {
            TlsSessionSecretParseError::new(TlsSessionSecretParseErrorKind::InvalidJson {
                line_number,
                column: source.column(),
                kind: source.classify().into(),
            })
        })
    }

    pub(super) fn decode(
        &self,
        line_number: usize,
    ) -> Result<TlsSessionSecretRecord, TlsSessionSecretParseError> {
        if !self.secret_kind.is_valid_for(self.protocol) {
            return Err(TlsSessionSecretParseError::new(
                TlsSessionSecretParseErrorKind::InvalidSecretKindForProtocol { line_number },
            ));
        }
        let client_random = parse_random_field(
            &self.client_random,
            line_number,
            TlsSessionSecretField::ClientRandom,
        )?;
        let server_random = self
            .server_random
            .as_deref()
            .map(|server_random| {
                parse_random_field(
                    server_random,
                    line_number,
                    TlsSessionSecretField::ServerRandom,
                )
            })
            .transpose()?;
        let cipher_suite = self
            .cipher_suite
            .as_deref()
            .map(|cipher_suite| parse_cipher_suite(line_number, cipher_suite))
            .transpose()?;
        validate_time_range(line_number, self.not_before_unix_ns, self.not_after_unix_ns)?;
        let secret = TlsSecret::from_hex(&self.secret).ok_or_else(|| {
            TlsSessionSecretParseError::new(TlsSessionSecretParseErrorKind::InvalidHex {
                line_number,
                field: TlsSessionSecretField::Secret,
            })
        })?;

        Ok(TlsSessionSecretRecord {
            protocol: self.protocol,
            secret_kind: self.secret_kind,
            client_random,
            server_random,
            cipher_suite,
            secret,
            not_before_unix_ns: self.not_before_unix_ns,
            not_after_unix_ns: self.not_after_unix_ns,
        })
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

fn parse_random_field(
    value: &str,
    line_number: usize,
    field: TlsSessionSecretField,
) -> Result<TlsRandom, TlsSessionSecretParseError> {
    validate_fixed_hex_len(value, line_number, field, TLS_RANDOM_BYTES)?;
    Ok(TlsRandom::from_hex(value).expect("random was validated before decoding"))
}

fn validate_fixed_hex_len(
    value: &str,
    line_number: usize,
    field: TlsSessionSecretField,
    expected_bytes: usize,
) -> Result<(), TlsSessionSecretParseError> {
    let actual_bytes = hex_len(value).ok_or_else(|| {
        TlsSessionSecretParseError::new(TlsSessionSecretParseErrorKind::InvalidHex {
            line_number,
            field,
        })
    })?;
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

fn parse_cipher_suite(
    line_number: usize,
    cipher_suite: &str,
) -> Result<TlsCipherSuite, TlsSessionSecretParseError> {
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
    let code = u16::from_str_radix(hex, 16).map_err(|_| {
        TlsSessionSecretParseError::new(TlsSessionSecretParseErrorKind::InvalidCipherSuite {
            line_number,
        })
    })?;
    Ok(TlsCipherSuite::from_code(code))
}

fn validate_time_range(
    line_number: usize,
    not_before_unix_ns: Option<u64>,
    not_after_unix_ns: Option<u64>,
) -> Result<(), TlsSessionSecretParseError> {
    if let (Some(not_before), Some(not_after)) = (not_before_unix_ns, not_after_unix_ns)
        && not_after < not_before
    {
        return Err(TlsSessionSecretParseError::new(
            TlsSessionSecretParseErrorKind::InvalidTimeRange { line_number },
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_secret_hex_without_leaking_secret_value() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"not-a-secret"}}"#
        );

        let error = decode_line(&material).expect_err("invalid secret must fail");

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
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"sensitive-protocol-value","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa"}}"#
        );

        let error = match TlsSessionSecretRecordWire::parse(1, &material) {
            Ok(_) => panic!("invalid JSON data must fail"),
            Err(error) => error,
        };

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
        let error = decode_line(
            r#"{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"000102","secret":"aa"}"#,
        )
        .expect_err("short client random must fail");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidFieldLength {
                line_number: 1,
                field: TlsSessionSecretField::ClientRandom,
                expected_bytes: TLS_RANDOM_BYTES,
                actual_bytes: 3,
            }
        );
    }

    #[test]
    fn rejects_invalid_time_range() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa","not_before_unix_ns":20,"not_after_unix_ns":10}}"#
        );

        let error = decode_line(&material).expect_err("inverted validity window must fail");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidTimeRange { line_number: 1 }
        );
    }

    #[test]
    fn rejects_tls12_record_with_tls13_traffic_secret_kind() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"tls12","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa"}}"#
        );

        let error =
            decode_line(&material).expect_err("TLS 1.2 cannot carry TLS 1.3 traffic secrets");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidSecretKindForProtocol { line_number: 1 }
        );
    }

    #[test]
    fn rejects_tls13_record_with_tls12_master_secret_kind() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"master_secret","client_random":"{client_random}","secret":"aa"}}"#
        );

        let error =
            decode_line(&material).expect_err("TLS 1.3 cannot carry a TLS 1.2 master secret");

        assert_eq!(
            error.kind,
            TlsSessionSecretParseErrorKind::InvalidSecretKindForProtocol { line_number: 1 }
        );
    }

    fn decode_line(line: &str) -> Result<TlsSessionSecretRecord, TlsSessionSecretParseError> {
        TlsSessionSecretRecordWire::parse(1, line)?.decode(1)
    }
}

use probe_core::RESERVED_WEBHOOK_HEADERS;

use crate::{ConfigViolation, ExporterConfig};

pub(super) fn validate_header(
    exporter: &ExporterConfig,
    name: &str,
    value: &str,
    violations: &mut Vec<ConfigViolation>,
) {
    if name.trim().is_empty() {
        violations.push(ConfigViolation {
            field: format!("exporters.{}.headers", exporter.id),
            reason: "exporter header name cannot be empty".to_string(),
        });
    } else if !valid_exporter_header_name(name) {
        violations.push(ConfigViolation {
            field: format!("exporters.{}.headers.{}", exporter.id, name),
            reason: "exporter header name is not a valid HTTP token".to_string(),
        });
    }
    if RESERVED_WEBHOOK_HEADERS
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
    {
        violations.push(ConfigViolation {
            field: format!("exporters.{}.headers.{}", exporter.id, name),
            reason: "exporter header is reserved by the webhook protocol".to_string(),
        });
    }
    if value.contains(['\r', '\n']) {
        violations.push(ConfigViolation {
            field: format!("exporters.{}.headers.{}", exporter.id, name),
            reason: "exporter header value cannot contain CR or LF".to_string(),
        });
    }
}

fn valid_exporter_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(valid_http_token_byte)
}

fn valid_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

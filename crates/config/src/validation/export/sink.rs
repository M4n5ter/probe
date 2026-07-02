use std::collections::{BTreeMap, HashSet};

use http::uri::PathAndQuery;

use crate::{
    ConfigViolation, ExporterConfig, ExporterTransportConfig, TlsConfig, TlsMaterialKind,
    validation::export::{headers, tls},
};
use url::Url;

const REPLAY_WEBHOOK_SINK_ID: &str = "replay-webhook";

pub(in crate::validation) fn validate_exporters(
    exporters: &[ExporterConfig],
    tls_config: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    let tls_materials_by_id = crate::tls::materials_by_id(tls_config);
    let mut ids = HashSet::new();
    for exporter in exporters {
        if exporter.id.trim().is_empty() {
            violations.push(ConfigViolation {
                field: "exporters.id".to_string(),
                reason: "exporter id cannot be empty".to_string(),
            });
        }
        if exporter.id == REPLAY_WEBHOOK_SINK_ID {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.id", exporter.id),
                reason: "exporter id is reserved for replay CLI webhook output".to_string(),
            });
        }
        if !exporter.id.is_empty() && !ids.insert(exporter.id.as_str()) {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.id", exporter.id),
                reason: "exporter id must be unique because it is used as the sink cursor key"
                    .to_string(),
            });
        }
        validate_transport(exporter, &tls_materials_by_id, violations);
        if exporter.worker.batches_per_tick == Some(0) {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.worker.batches_per_tick", exporter.id),
                reason: "exporter worker batches_per_tick must be positive when set".to_string(),
            });
        }
    }
}

fn validate_transport(
    exporter: &ExporterConfig,
    tls_materials_by_id: &BTreeMap<&str, TlsMaterialKind>,
    violations: &mut Vec<ConfigViolation>,
) {
    match &exporter.transport {
        ExporterTransportConfig::Webhook {
            endpoint,
            headers: configured_headers,
            tls: configured_tls,
        } => {
            for (name, value) in configured_headers {
                headers::validate_header(exporter, name, value, violations);
            }
            validate_webhook_endpoint(exporter, endpoint, violations);
            tls::validate_exporter_tls(
                exporter,
                endpoint,
                configured_tls,
                tls_materials_by_id,
                violations,
            );
        }
        ExporterTransportConfig::File { path } => {
            if path.as_os_str().is_empty() {
                violations.push(ConfigViolation {
                    field: format!("exporters.{}.path", exporter.id),
                    reason: "file exporter path cannot be empty".to_string(),
                });
            }
        }
        ExporterTransportConfig::UnixHttp {
            socket_path,
            endpoint,
            headers: configured_headers,
        } => {
            for (name, value) in configured_headers {
                headers::validate_header(exporter, name, value, violations);
            }
            validate_unix_http_socket_path(exporter, socket_path, violations);
            validate_unix_http_endpoint(exporter, endpoint, violations);
        }
    }
}

fn validate_unix_http_socket_path(
    exporter: &ExporterConfig,
    path: &std::path::Path,
    violations: &mut Vec<ConfigViolation>,
) {
    let field = format!("exporters.{}.socket_path", exporter.id);
    if path.as_os_str().is_empty() {
        violations.push(ConfigViolation {
            field,
            reason: "unix_http exporter socket_path cannot be empty".to_string(),
        });
        return;
    }
    if !path.is_absolute() {
        violations.push(ConfigViolation {
            field,
            reason: "unix_http exporter socket_path must be absolute".to_string(),
        });
    }
}

fn validate_unix_http_endpoint(
    exporter: &ExporterConfig,
    endpoint: &str,
    violations: &mut Vec<ConfigViolation>,
) {
    let field = format!("exporters.{}.endpoint", exporter.id);
    if endpoint.trim().is_empty() {
        violations.push(ConfigViolation {
            field,
            reason: "unix_http endpoint cannot be empty".to_string(),
        });
        return;
    }
    if !endpoint.starts_with('/') {
        violations.push(ConfigViolation {
            field,
            reason: "unix_http endpoint must be an absolute path with optional query".to_string(),
        });
        return;
    }
    if endpoint.starts_with("//") {
        violations.push(ConfigViolation {
            field,
            reason: "unix_http endpoint must not start with //".to_string(),
        });
        return;
    }
    if endpoint.contains('#') {
        violations.push(ConfigViolation {
            field,
            reason: "unix_http endpoint must not contain a fragment".to_string(),
        });
        return;
    }
    if endpoint.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        violations.push(ConfigViolation {
            field,
            reason: "unix_http endpoint must not contain control characters or spaces".to_string(),
        });
        return;
    }
    if let Err(error) = endpoint.parse::<PathAndQuery>() {
        violations.push(ConfigViolation {
            field,
            reason: format!("unix_http endpoint must be a valid HTTP path and query: {error}"),
        });
    }
}

fn validate_webhook_endpoint(
    exporter: &ExporterConfig,
    endpoint: &str,
    violations: &mut Vec<ConfigViolation>,
) {
    let field = format!("exporters.{}.endpoint", exporter.id);
    if endpoint.trim().is_empty() {
        violations.push(ConfigViolation {
            field,
            reason: "webhook endpoint cannot be empty".to_string(),
        });
        return;
    }

    let Ok(url) = Url::parse(endpoint) else {
        violations.push(ConfigViolation {
            field,
            reason: "webhook endpoint must be an absolute URL".to_string(),
        });
        return;
    };
    if !url.username().is_empty() || url.password().is_some() {
        violations.push(ConfigViolation {
            field,
            reason: "webhook endpoint must not contain credentials".to_string(),
        });
        return;
    }
    if !matches!(url.scheme(), "http" | "https") {
        violations.push(ConfigViolation {
            field,
            reason: "webhook endpoint must use HTTP or HTTPS".to_string(),
        });
        return;
    }
    if url.host_str().is_none() {
        violations.push(ConfigViolation {
            field,
            reason: "webhook endpoint must include a host".to_string(),
        });
    }
}

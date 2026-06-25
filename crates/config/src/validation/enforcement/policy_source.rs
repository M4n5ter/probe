use url::Url;

use crate::{
    ConfigViolation, EnforcementPolicySourceConfig, RemoteEnforcementPolicyBodyLimitBytes,
    RemoteEnforcementPolicyBodyLimitError,
};

pub(super) fn validate(
    source: &EnforcementPolicySourceConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    match source {
        EnforcementPolicySourceConfig::None => {}
        EnforcementPolicySourceConfig::File { path } => {
            if path.as_os_str().is_empty() {
                violations.push(ConfigViolation {
                    field: "enforcement.policy.source.path".to_string(),
                    reason: "enforcement policy file path cannot be empty".to_string(),
                });
            }
        }
        EnforcementPolicySourceConfig::Directory { path } => {
            if path.as_os_str().is_empty() {
                violations.push(ConfigViolation {
                    field: "enforcement.policy.source.path".to_string(),
                    reason: "enforcement policy directory path cannot be empty".to_string(),
                });
            }
        }
        EnforcementPolicySourceConfig::Remote {
            endpoint,
            max_body_bytes,
        } => {
            if endpoint.trim().is_empty() {
                violations.push(ConfigViolation {
                    field: "enforcement.policy.source.endpoint".to_string(),
                    reason: "remote enforcement policy endpoint cannot be empty".to_string(),
                });
            } else {
                validate_remote_endpoint(endpoint, violations);
            }
            validate_remote_body_limit(*max_body_bytes, violations);
        }
    }
}

fn validate_remote_endpoint(endpoint: &str, violations: &mut Vec<ConfigViolation>) {
    let Ok(url) = Url::parse(endpoint) else {
        violations.push(ConfigViolation {
            field: "enforcement.policy.source.endpoint".to_string(),
            reason: "remote enforcement policy endpoint must be an absolute URL".to_string(),
        });
        return;
    };

    if !url.username().is_empty() || url.password().is_some() {
        violations.push(ConfigViolation {
            field: "enforcement.policy.source.endpoint".to_string(),
            reason: "remote enforcement policy endpoint must not contain credentials".to_string(),
        });
    }
    if remote_endpoint_uses_allowed_transport(&url) {
        return;
    }
    violations.push(ConfigViolation {
        field: "enforcement.policy.source.endpoint".to_string(),
        reason:
            "remote enforcement policy endpoint must use HTTPS, except loopback HTTP for local testing"
                .to_string(),
    });
}

fn remote_endpoint_uses_allowed_transport(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(loopback_host),
        _ => false,
    }
}

fn loopback_host(host: &str) -> bool {
    let normalized = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    normalized.eq_ignore_ascii_case("localhost")
        || normalized
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn validate_remote_body_limit(max_body_bytes: Option<u64>, violations: &mut Vec<ConfigViolation>) {
    if let Err(error) = RemoteEnforcementPolicyBodyLimitBytes::from_config(max_body_bytes) {
        violations.push(ConfigViolation {
            field: "enforcement.policy.source.max_body_bytes".to_string(),
            reason: remote_body_limit_violation_reason(error),
        });
    }
}

fn remote_body_limit_violation_reason(error: RemoteEnforcementPolicyBodyLimitError) -> String {
    match error {
        RemoteEnforcementPolicyBodyLimitError::Zero => {
            "remote enforcement policy max_body_bytes must be greater than zero".to_string()
        }
        RemoteEnforcementPolicyBodyLimitError::ExceedsMaximum { max, .. } => {
            format!("remote enforcement policy max_body_bytes cannot exceed {max}")
        }
    }
}

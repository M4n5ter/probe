use url::Url;

use crate::{ConfigViolation, EnforcementConfig, EnforcementPolicySourceConfig};

pub(super) fn validate(enforcement: &EnforcementConfig, violations: &mut Vec<ConfigViolation>) {
    match &enforcement.policy.source {
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
        EnforcementPolicySourceConfig::Remote { endpoint } => {
            if endpoint.trim().is_empty() {
                violations.push(ConfigViolation {
                    field: "enforcement.policy.source.endpoint".to_string(),
                    reason: "remote enforcement policy endpoint cannot be empty".to_string(),
                });
            } else {
                validate_remote_enforcement_policy_endpoint(endpoint, violations);
            }
        }
    }
}

fn validate_remote_enforcement_policy_endpoint(
    endpoint: &str,
    violations: &mut Vec<ConfigViolation>,
) {
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
    if remote_policy_endpoint_uses_allowed_transport(&url) {
        return;
    }
    violations.push(ConfigViolation {
        field: "enforcement.policy.source.endpoint".to_string(),
        reason:
            "remote enforcement policy endpoint must use HTTPS, except loopback HTTP for local testing"
                .to_string(),
    });
}

fn remote_policy_endpoint_uses_allowed_transport(url: &Url) -> bool {
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

use crate::{
    ConfigViolation, EnforcementPolicySourceConfig, RemoteEnforcementPolicyBodyLimitBytes,
    RemoteEnforcementPolicyBodyLimitError,
};

use super::super::remote_endpoint::validate_remote_endpoint;

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
                validate_remote_endpoint(
                    endpoint,
                    "enforcement.policy.source.endpoint",
                    "remote enforcement policy",
                    violations,
                );
            }
            validate_remote_body_limit(*max_body_bytes, violations);
        }
    }
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

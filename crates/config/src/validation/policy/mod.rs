use std::collections::BTreeSet;

use crate::{
    ConfigViolation, PolicyConfig, PolicySourceConfig, RemotePolicyBundleBodyLimitBytes,
    RemotePolicyBundleBodyLimitError,
};

use super::remote_endpoint::validate_remote_endpoint;

pub(super) fn validate(policies: &[PolicyConfig], violations: &mut Vec<ConfigViolation>) {
    let mut seen_ids = BTreeSet::new();
    for policy in policies {
        if !seen_ids.insert(policy.id.as_str()) {
            violations.push(ConfigViolation {
                field: "policies".to_string(),
                reason: format!("policy id must be unique: {}", policy.id),
            });
        }
        if policy.enabled {
            validate_policy_source(policy, violations);
        }
    }
}

fn validate_policy_source(policy: &PolicyConfig, violations: &mut Vec<ConfigViolation>) {
    match &policy.source {
        PolicySourceConfig::LocalDirectory { path } => {
            if path.as_os_str().is_empty() {
                violations.push(ConfigViolation {
                    field: format!("policies.{}.source.path", policy.id),
                    reason: "enabled policy must set a policy bundle directory path".to_string(),
                });
            }
        }
        PolicySourceConfig::RemoteBundle {
            endpoint,
            max_body_bytes,
        } => {
            let endpoint_field = format!("policies.{}.source.endpoint", policy.id);
            if endpoint.trim().is_empty() {
                violations.push(ConfigViolation {
                    field: endpoint_field,
                    reason: "remote policy bundle endpoint cannot be empty".to_string(),
                });
            } else {
                validate_remote_endpoint(
                    endpoint,
                    endpoint_field,
                    "remote policy bundle",
                    violations,
                );
            }
            validate_remote_body_limit(policy, *max_body_bytes, violations);
        }
    }
}

fn validate_remote_body_limit(
    policy: &PolicyConfig,
    max_body_bytes: Option<u64>,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Err(error) = RemotePolicyBundleBodyLimitBytes::from_config(max_body_bytes) {
        violations.push(ConfigViolation {
            field: format!("policies.{}.source.max_body_bytes", policy.id),
            reason: remote_body_limit_violation_reason(error),
        });
    }
}

fn remote_body_limit_violation_reason(error: RemotePolicyBundleBodyLimitError) -> String {
    match error {
        RemotePolicyBundleBodyLimitError::Zero => {
            "remote policy bundle max_body_bytes must be greater than zero".to_string()
        }
        RemotePolicyBundleBodyLimitError::ExceedsMaximum { max, .. } => {
            format!("remote policy bundle max_body_bytes cannot exceed {max}")
        }
    }
}

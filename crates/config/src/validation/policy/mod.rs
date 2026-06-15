use std::collections::BTreeSet;

use crate::{ConfigViolation, PolicyConfig};

pub(super) fn validate(policies: &[PolicyConfig], violations: &mut Vec<ConfigViolation>) {
    let mut seen_ids = BTreeSet::new();
    for policy in policies {
        if !seen_ids.insert(policy.id.as_str()) {
            violations.push(ConfigViolation {
                field: "policies".to_string(),
                reason: format!("policy id must be unique: {}", policy.id),
            });
        }
        if policy.enabled && policy.path.as_os_str().is_empty() {
            violations.push(ConfigViolation {
                field: format!("policies.{}.path", policy.id),
                reason: "enabled policy must set a policy bundle directory path".to_string(),
            });
        }
    }
}

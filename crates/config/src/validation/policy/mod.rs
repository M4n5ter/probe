use crate::{ConfigViolation, PolicyConfig};

pub(super) fn validate(policies: &[PolicyConfig], violations: &mut Vec<ConfigViolation>) {
    if policies.iter().filter(|policy| policy.enabled).count() > 1 {
        violations.push(ConfigViolation {
            field: "policies".to_string(),
            reason: "runtime config currently supports at most one enabled policy bundle"
                .to_string(),
        });
    }
    for policy in policies {
        if policy.enabled && policy.path.as_os_str().is_empty() {
            violations.push(ConfigViolation {
                field: format!("policies.{}.path", policy.id),
                reason: "enabled policy must set a policy bundle directory path".to_string(),
            });
        }
    }
}

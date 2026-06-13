mod policy_source;

use crate::{ConfigViolation, EnforcementConfig};

pub(super) fn validate(enforcement: &EnforcementConfig, violations: &mut Vec<ConfigViolation>) {
    policy_source::validate(&enforcement.policy.source, violations);
}

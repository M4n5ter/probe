mod interception;
mod policy_source;

use crate::{ConfigViolation, EnforcementConfig};

pub(super) fn validate(enforcement: &EnforcementConfig, violations: &mut Vec<ConfigViolation>) {
    interception::validate(&enforcement.interception, violations);
    policy_source::validate(&enforcement.policy.source, violations);
}

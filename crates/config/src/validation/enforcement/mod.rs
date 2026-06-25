mod interception;
mod policy_source;

use crate::{ConfigViolation, EnforcementConfig, TlsConfig};

pub(super) fn validate(
    enforcement: &EnforcementConfig,
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    interception::validate(&enforcement.interception, tls, violations);
    policy_source::validate(&enforcement.policy.source, violations);
}

pub(crate) fn validate_l7_mitm_contract(
    enforcement: &EnforcementConfig,
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    interception::validate_l7_mitm_contract(&enforcement.interception, tls, violations);
}

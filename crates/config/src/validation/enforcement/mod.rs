mod interception;
mod policy_source;

use probe_core::EnforcementMode;

use crate::{ConfigViolation, EnforcementConfig, EnforcementPolicySourceConfig, TlsConfig};

pub(super) fn validate(
    enforcement: &EnforcementConfig,
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    interception::validate(&enforcement.interception, tls, violations);
    policy_source::validate(&enforcement.policy.source, violations);
    validate_enforce_policy_source(enforcement, violations);
    policy_source::validate_reload(
        &enforcement.policy.source,
        &enforcement.policy.reload,
        violations,
    );
}

pub(crate) fn validate_l7_mitm_contract(
    enforcement: &EnforcementConfig,
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    interception::validate_l7_mitm_contract(&enforcement.interception, tls, violations);
}

fn validate_enforce_policy_source(
    enforcement: &EnforcementConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if enforcement.mode == EnforcementMode::Enforce
        && matches!(
            enforcement.policy.source,
            EnforcementPolicySourceConfig::None
        )
    {
        violations.push(ConfigViolation {
            field: "enforcement.policy.source.kind".to_string(),
            reason: "enforce mode requires an explicit enforcement policy source".to_string(),
        });
    }
}

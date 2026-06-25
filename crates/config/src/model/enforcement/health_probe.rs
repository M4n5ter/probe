use super::{TransparentInterceptionIntentViolation, intent_violation};

pub const DEFAULT_TCP_HEALTH_PROBE_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_TCP_HEALTH_PROBE_TIMEOUT_MS: u64 = 200;
pub const DEFAULT_TCP_HEALTH_PROBE_FAILURE_THRESHOLD: u32 = 3;
pub const MIN_TCP_HEALTH_PROBE_INTERVAL_MS: u64 = 100;
pub const MAX_TCP_HEALTH_PROBE_INTERVAL_MS: u64 = 60_000;
pub const MIN_TCP_HEALTH_PROBE_TIMEOUT_MS: u64 = 10;
pub const MAX_TCP_HEALTH_PROBE_TIMEOUT_MS: u64 = 5_000;
pub const MIN_TCP_HEALTH_PROBE_FAILURE_THRESHOLD: u32 = 1;
pub const MAX_TCP_HEALTH_PROBE_FAILURE_THRESHOLD: u32 = 100;

pub(super) fn validate_tcp_health_probe_timing(
    fields: TcpHealthProbeTimingFields,
    label: &str,
    interval_ms: u64,
    timeout_ms: u64,
    failure_threshold: u32,
    violations: &mut Vec<TransparentInterceptionIntentViolation>,
) {
    validate_tcp_health_probe_range(
        fields.interval_ms,
        interval_ms,
        MIN_TCP_HEALTH_PROBE_INTERVAL_MS,
        MAX_TCP_HEALTH_PROBE_INTERVAL_MS,
        &format!("{label} interval"),
        violations,
    );
    validate_tcp_health_probe_range(
        fields.timeout_ms,
        timeout_ms,
        MIN_TCP_HEALTH_PROBE_TIMEOUT_MS,
        MAX_TCP_HEALTH_PROBE_TIMEOUT_MS,
        &format!("{label} timeout"),
        violations,
    );
    validate_tcp_health_probe_range(
        fields.failure_threshold,
        u64::from(failure_threshold),
        u64::from(MIN_TCP_HEALTH_PROBE_FAILURE_THRESHOLD),
        u64::from(MAX_TCP_HEALTH_PROBE_FAILURE_THRESHOLD),
        &format!("{label} failure threshold"),
        violations,
    );
    if timeout_ms > interval_ms {
        violations.push(intent_violation(
            fields.timeout_ms,
            format!("{label} timeout must not exceed interval"),
        ));
    }
}

pub(super) struct TcpHealthProbeTimingFields {
    pub interval_ms: &'static str,
    pub timeout_ms: &'static str,
    pub failure_threshold: &'static str,
}

fn validate_tcp_health_probe_range(
    field: &'static str,
    value: u64,
    min: u64,
    max: u64,
    label: &str,
    violations: &mut Vec<TransparentInterceptionIntentViolation>,
) {
    if !(min..=max).contains(&value) {
        violations.push(intent_violation(
            field,
            format!("{label} must be between {min} and {max}"),
        ));
    }
}

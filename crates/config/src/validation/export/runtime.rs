use crate::{ConfigViolation, ExportRuntimeConfig, ExportWorkerScheduleConfig};

pub(in crate::validation) fn validate_runtime(
    export: &ExportRuntimeConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if !export.worker.enabled {
        return;
    }
    let ExportWorkerScheduleConfig::FixedIntervalBounded {
        interval_ms,
        batches_per_sink_per_tick,
        sink_timeout_ms,
        failure_backoff,
    } = export.worker.schedule;
    for (field, value, reason) in [
        (
            "export.worker.schedule.interval_ms",
            interval_ms,
            "export worker interval must be positive when the worker is enabled",
        ),
        (
            "export.worker.schedule.batches_per_sink_per_tick",
            batches_per_sink_per_tick,
            "export worker per-sink batch budget must be positive when the worker is enabled",
        ),
        (
            "export.worker.schedule.sink_timeout_ms",
            sink_timeout_ms,
            "export worker sink timeout must be positive when the worker is enabled",
        ),
        (
            "export.worker.schedule.failure_backoff.initial_ms",
            failure_backoff.initial_ms,
            "export worker failure backoff initial delay must be positive when the worker is enabled",
        ),
        (
            "export.worker.schedule.failure_backoff.max_ms",
            failure_backoff.max_ms,
            "export worker failure backoff max delay must be positive when the worker is enabled",
        ),
    ] {
        if value == 0 {
            violations.push(ConfigViolation {
                field: field.to_string(),
                reason: reason.to_string(),
            });
        }
    }
    if failure_backoff.multiplier == 0 {
        violations.push(ConfigViolation {
            field: "export.worker.schedule.failure_backoff.multiplier".to_string(),
            reason: "export worker failure backoff multiplier must be positive when the worker is enabled"
                .to_string(),
        });
    }
    if failure_backoff.max_ms < failure_backoff.initial_ms {
        violations.push(ConfigViolation {
            field: "export.worker.schedule.failure_backoff.max_ms".to_string(),
            reason: "export worker failure backoff max delay must be greater than or equal to the initial delay".to_string(),
        });
    }
}

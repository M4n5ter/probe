use crate::{ConfigViolation, StorageConfig};

pub(in crate::validation) fn validate(
    storage: &StorageConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    let retention = &storage.retention.export;
    if matches!(retention.max_age_ms, Some(0)) {
        violations.push(ConfigViolation {
            field: "storage.retention.export.max_age_ms".to_string(),
            reason: "export retention max age must be positive when configured".to_string(),
        });
    }
    if retention.sweep_interval_ms == 0 {
        violations.push(ConfigViolation {
            field: "storage.retention.export.sweep_interval_ms".to_string(),
            reason: "export retention sweep interval must be positive".to_string(),
        });
    }
    if retention.prune_batch_limit == 0 {
        violations.push(ConfigViolation {
            field: "storage.retention.export.prune_batch_limit".to_string(),
            reason: "export retention prune batch limit must be positive".to_string(),
        });
    }
}

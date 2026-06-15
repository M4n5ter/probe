use crate::{
    ConfigViolation, ExportQueueRetentionConfig, IngressJournalRetentionConfig, StorageConfig,
};

pub(in crate::validation) fn validate(
    storage: &StorageConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    validate_ingress_retention(&storage.retention.ingress, violations);
    validate_export_retention(&storage.retention.export, violations);
}

fn validate_ingress_retention(
    retention: &IngressJournalRetentionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    validate_retention_knobs(
        "storage.retention.ingress",
        "ingress retention",
        retention.max_age_ms,
        retention.max_records,
        retention.sweep_interval_ms,
        retention.prune_batch_limit,
        violations,
    );
}

fn validate_export_retention(
    retention: &ExportQueueRetentionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    validate_retention_knobs(
        "storage.retention.export",
        "export retention",
        retention.max_age_ms,
        retention.max_records,
        retention.sweep_interval_ms,
        retention.prune_batch_limit,
        violations,
    );
}

fn validate_retention_knobs(
    field_prefix: &str,
    label: &str,
    max_age_ms: Option<u64>,
    max_records: Option<u64>,
    sweep_interval_ms: u64,
    prune_batch_limit: u64,
    violations: &mut Vec<ConfigViolation>,
) {
    if matches!(max_age_ms, Some(0)) {
        violations.push(ConfigViolation {
            field: format!("{field_prefix}.max_age_ms"),
            reason: format!("{label} max age must be positive when configured"),
        });
    }
    if matches!(max_records, Some(0)) {
        violations.push(ConfigViolation {
            field: format!("{field_prefix}.max_records"),
            reason: format!("{label} max records must be positive when configured"),
        });
    }
    if sweep_interval_ms == 0 {
        violations.push(ConfigViolation {
            field: format!("{field_prefix}.sweep_interval_ms"),
            reason: format!("{label} sweep interval must be positive"),
        });
    }
    if prune_batch_limit == 0 {
        violations.push(ConfigViolation {
            field: format!("{field_prefix}.prune_batch_limit"),
            reason: format!("{label} prune batch limit must be positive"),
        });
    }
}

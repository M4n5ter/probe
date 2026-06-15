use probe_config::*;

#[test]
fn validation_rejects_zero_export_retention_knobs() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[storage.retention.export]
max_age_ms = 0
max_records = 0
sweep_interval_ms = 0
prune_batch_limit = 0
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("zero export retention knobs must fail validation");

    assert_violation(
        &error,
        "storage.retention.export.max_age_ms",
        "export retention max age must be positive when configured",
    );
    assert_violation(
        &error,
        "storage.retention.export.max_records",
        "export retention max records must be positive when configured",
    );
    assert_violation(
        &error,
        "storage.retention.export.prune_batch_limit",
        "export retention prune batch limit must be positive",
    );
    assert_violation(
        &error,
        "storage.retention.export.sweep_interval_ms",
        "export retention sweep interval must be positive",
    );
    Ok(())
}

#[test]
fn validation_rejects_zero_ingress_retention_knobs() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[storage.retention.ingress]
max_age_ms = 0
max_records = 0
sweep_interval_ms = 0
prune_batch_limit = 0
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("zero ingress retention knobs must fail validation");

    assert_violation(
        &error,
        "storage.retention.ingress.max_age_ms",
        "ingress retention max age must be positive when configured",
    );
    assert_violation(
        &error,
        "storage.retention.ingress.max_records",
        "ingress retention max records must be positive when configured",
    );
    assert_violation(
        &error,
        "storage.retention.ingress.prune_batch_limit",
        "ingress retention prune batch limit must be positive",
    );
    assert_violation(
        &error,
        "storage.retention.ingress.sweep_interval_ms",
        "ingress retention sweep interval must be positive",
    );
    Ok(())
}

fn assert_violation(error: &ConfigError, field: &str, reason: &str) {
    let ConfigError::Validation(error) = error else {
        panic!("expected config validation error, got {error:?}");
    };
    assert!(
        error
            .violations()
            .iter()
            .any(|violation| violation.field == field && violation.reason == reason),
        "expected validation violation {field}: {reason}; got {:?}",
        error.violations()
    );
}

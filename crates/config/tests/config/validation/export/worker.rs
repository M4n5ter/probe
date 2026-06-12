use probe_config::*;

#[test]
fn validation_rejects_zero_enabled_export_worker_knobs() -> Result<(), Box<dyn std::error::Error>> {
    let enabled = AgentConfig::from_toml_str(
        r#"
[export.worker]
enabled = true

[export.worker.schedule]
mode = "fixed_interval_bounded"
interval_ms = 0
batches_per_sink_per_tick = 0
sink_timeout_ms = 0

[export.worker.schedule.failure_backoff]
initial_ms = 0
max_ms = 0
multiplier = 0
"#,
    )?;

    let error = enabled
        .validate_basic()
        .expect_err("enabled export worker must have a positive interval");
    assert_violation(
        &error,
        "export.worker.schedule.interval_ms",
        "export worker interval must be positive when the worker is enabled",
    );
    assert_violation(
        &error,
        "export.worker.schedule.batches_per_sink_per_tick",
        "export worker per-sink batch budget must be positive when the worker is enabled",
    );
    assert_violation(
        &error,
        "export.worker.schedule.sink_timeout_ms",
        "export worker sink timeout must be positive when the worker is enabled",
    );
    assert_violation(
        &error,
        "export.worker.schedule.failure_backoff.initial_ms",
        "export worker failure backoff initial delay must be positive when the worker is enabled",
    );
    assert_violation(
        &error,
        "export.worker.schedule.failure_backoff.max_ms",
        "export worker failure backoff max delay must be positive when the worker is enabled",
    );
    assert_violation(
        &error,
        "export.worker.schedule.failure_backoff.multiplier",
        "export worker failure backoff multiplier must be positive when the worker is enabled",
    );

    let disabled = AgentConfig::from_toml_str(
        r#"
[export.worker]
enabled = false

[export.worker.schedule]
mode = "fixed_interval_bounded"
interval_ms = 0
batches_per_sink_per_tick = 0
sink_timeout_ms = 0

[export.worker.schedule.failure_backoff]
initial_ms = 0
max_ms = 0
multiplier = 0
"#,
    )?;
    disabled.validate_basic()?;
    Ok(())
}

#[test]
fn validation_rejects_export_worker_backoff_max_below_initial()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[export.worker]
enabled = true

[export.worker.schedule]
mode = "fixed_interval_bounded"

[export.worker.schedule.failure_backoff]
initial_ms = 1000
max_ms = 999
multiplier = 2
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("backoff max must not be below initial delay");
    assert_violation(
        &error,
        "export.worker.schedule.failure_backoff.max_ms",
        "export worker failure backoff max delay must be greater than or equal to the initial delay",
    );
    Ok(())
}

#[test]
fn validation_rejects_zero_exporter_worker_batch_quota() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.worker]
batches_per_tick = 0
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("per-sink exporter batch quota must be positive");
    assert!(
        error
            .to_string()
            .contains("exporter worker batches_per_tick must be positive")
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

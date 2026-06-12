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
failure_backoff_ms = 0
"#,
    )?;

    let error = enabled
        .validate_basic()
        .expect_err("enabled export worker must have a positive interval");
    assert!(
        error
            .to_string()
            .contains("export worker interval must be positive")
    );
    assert!(
        error
            .to_string()
            .contains("export worker per-sink batch budget must be positive")
    );
    assert!(
        error
            .to_string()
            .contains("export worker sink timeout must be positive")
    );
    assert!(
        error
            .to_string()
            .contains("export worker failure backoff must be positive")
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
failure_backoff_ms = 0
"#,
    )?;
    disabled.validate_basic()?;
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

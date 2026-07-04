use probe_config::*;

#[test]
fn validation_accepts_runtime_reload_watcher_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[runtime_reload]
watch_config = true
debounce_ms = 250
"#,
    )?;

    config.validate_basic()?;
    assert!(config.runtime_reload.watch_config);
    assert_eq!(config.runtime_reload.debounce_ms, 250);
    Ok(())
}

#[test]
fn validation_accepts_explicit_runtime_reload_watcher_opt_out()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[runtime_reload]
watch_config = false
"#,
    )?;

    config.validate_basic()?;
    assert!(!config.runtime_reload.watch_config);
    assert_eq!(
        config.runtime_reload.debounce_ms,
        DEFAULT_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_runtime_reload_debounce() -> Result<(), Box<dyn std::error::Error>> {
    for debounce_ms in [
        MIN_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS - 1,
        MAX_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS + 1,
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[runtime_reload]
watch_config = true
debounce_ms = {debounce_ms}
"#,
        ))?;
        let error = config
            .validate_basic()
            .expect_err("runtime reload debounce range should be enforced");

        assert!(
            error
                .to_string()
                .contains("runtime config reload watcher debounce_ms must be between"),
            "{error}"
        );
    }
    Ok(())
}

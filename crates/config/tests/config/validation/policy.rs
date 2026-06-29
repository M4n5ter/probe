use probe_config::*;

#[test]
fn validation_allows_multiple_enabled_policies() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[policies]]
id = "a"
enabled = true

[policies.source]
kind = "local_directory"
path = "/tmp/a.bundle"

[[policies]]
id = "b"
enabled = true

[policies.source]
kind = "remote_bundle"
endpoint = "https://control.example/policies/b"
max_body_bytes = 33554432
"#,
    )?;

    config.validate_basic()?;
    Ok(())
}

#[test]
fn validation_rejects_duplicate_policy_ids() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[policies]]
id = "guard"
enabled = true

[policies.source]
kind = "local_directory"
path = "/tmp/a.bundle"

[[policies]]
id = "guard"
enabled = false

[policies.source]
kind = "local_directory"
path = "/tmp/b.bundle"
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("duplicate policy ids must be rejected");

    assert!(
        error
            .to_string()
            .contains("policy id must be unique: guard"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_policy_sources() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[policies]]
id = "guard"
enabled = true

[policies.source]
kind = "local_directory"
path = ""
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("enabled local policy source path must be rejected");

    assert!(
        error
            .to_string()
            .contains("enabled policy must set a policy bundle directory path"),
        "unexpected error: {error}"
    );

    for (endpoint, reason) in [
        (
            "http://control.example/policies/guard",
            "remote policy bundle endpoint must use HTTPS",
        ),
        (
            "ftp://control.example/policies/guard",
            "remote policy bundle endpoint must use HTTPS",
        ),
        (
            "control.example/policies/guard",
            "remote policy bundle endpoint must be an absolute URL",
        ),
        (
            "https://user:password@control.example/policies/guard",
            "remote policy bundle endpoint must not contain credentials",
        ),
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[[policies]]
id = "guard"
enabled = true

[policies.source]
kind = "remote_bundle"
endpoint = "{endpoint}"
"#
        ))?;
        let error = config
            .validate_basic()
            .expect_err("invalid remote policy endpoint must be rejected");
        assert!(
            error.to_string().contains(reason),
            "expected {reason:?} in {error}"
        );
    }

    for (max_body_bytes, reason) in [
        (
            0,
            "remote policy bundle max_body_bytes must be greater than zero",
        ),
        (
            MAX_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES + 1,
            "remote policy bundle max_body_bytes cannot exceed",
        ),
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[[policies]]
id = "guard"
enabled = true

[policies.source]
kind = "remote_bundle"
endpoint = "https://control.example/policies/guard"
max_body_bytes = {max_body_bytes}
"#
        ))?;
        let error = config
            .validate_basic()
            .expect_err("invalid remote policy body limit must be rejected");
        assert!(
            error.to_string().contains(reason),
            "expected {reason:?} in {error}"
        );
    }
    Ok(())
}

#[test]
fn validation_accepts_policy_reload_watcher_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[policy_reload]
watch_local_bundles = true
debounce_ms = 250

[[policies]]
id = "guard"
enabled = true

[policies.source]
kind = "local_directory"
path = "/tmp/guard.bundle"
"#,
    )?;

    config.validate_basic()?;
    assert!(config.policy_reload.watch_local_bundles);
    assert_eq!(config.policy_reload.debounce_ms, 250);
    Ok(())
}

#[test]
fn validation_rejects_invalid_policy_reload_debounce() -> Result<(), Box<dyn std::error::Error>> {
    for debounce_ms in [
        MIN_POLICY_RELOAD_WATCH_DEBOUNCE_MS - 1,
        MAX_POLICY_RELOAD_WATCH_DEBOUNCE_MS + 1,
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[policy_reload]
watch_local_bundles = true
debounce_ms = {debounce_ms}
"#
        ))?;

        let error = config
            .validate_basic()
            .expect_err("invalid policy reload debounce must be rejected");
        assert!(
            error
                .to_string()
                .contains("policy reload watcher debounce_ms must be between"),
            "unexpected error: {error}"
        );
    }
    Ok(())
}

use probe_config::*;

#[test]
fn validation_allows_multiple_enabled_policies() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[policies]]
id = "a"
enabled = true
path = "/tmp/a.bundle"

[[policies]]
id = "b"
enabled = true
path = "/tmp/b.bundle"
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
path = "/tmp/a.bundle"

[[policies]]
id = "guard"
enabled = false
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

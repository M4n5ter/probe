use probe_config::*;

#[test]
fn validation_rejects_multiple_enabled_policies() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[policies]]
id = "a"
enabled = true
path = "/tmp/a.lua"

[[policies]]
id = "b"
enabled = true
path = "/tmp/b.lua"
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("multiple enabled policies must be rejected before run");

    assert!(
        error
            .to_string()
            .contains("at most one enabled policy bundle")
    );
    Ok(())
}

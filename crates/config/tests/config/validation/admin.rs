use probe_config::*;

#[test]
fn validation_rejects_invalid_admin_socket_path() -> Result<(), Box<dyn std::error::Error>> {
    let empty = AgentConfig::from_toml_str(
        r#"
[admin]
enabled = true
socket_path = ""
"#,
    )?;
    let error = empty
        .validate_basic()
        .expect_err("enabled admin socket requires a path");
    assert!(
        error
            .to_string()
            .contains("enabled admin socket requires a socket path")
    );

    let relative = AgentConfig::from_toml_str(
        r#"
[admin]
enabled = true
socket_path = "admin.sock"
"#,
    )?;
    let error = relative
        .validate_basic()
        .expect_err("admin socket path must be absolute");
    assert!(
        error
            .to_string()
            .contains("admin socket path must be absolute")
    );
    Ok(())
}

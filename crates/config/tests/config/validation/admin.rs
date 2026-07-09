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

#[test]
fn validation_rejects_invalid_prometheus_listener() -> Result<(), Box<dyn std::error::Error>> {
    let without_admin = AgentConfig::from_toml_str(
        r#"
[admin]
enabled = false

[admin.prometheus]
enabled = true
"#,
    )?;
    let error = without_admin
        .validate_basic()
        .expect_err("prometheus listener requires admin to be enabled");
    assert!(
        error
            .to_string()
            .contains("prometheus metrics listener requires admin.enabled = true")
    );

    let non_loopback = AgentConfig::from_toml_str(
        r#"
[admin]
enabled = true
socket_path = "/run/traffic-probe/admin.sock"

[admin.prometheus]
enabled = true
listen_addr = "0.0.0.0:9464"
"#,
    )?;
    let error = non_loopback
        .validate_basic()
        .expect_err("prometheus listener must be loopback-only");
    assert!(
        error
            .to_string()
            .contains("prometheus metrics listener must bind to a loopback address")
    );

    let zero_port = AgentConfig::from_toml_str(
        r#"
[admin]
enabled = true
socket_path = "/run/traffic-probe/admin.sock"

[admin.prometheus]
enabled = true
listen_addr = "127.0.0.1:0"
"#,
    )?;
    let error = zero_port
        .validate_basic()
        .expect_err("prometheus listener requires a configured port");
    assert!(
        error
            .to_string()
            .contains("prometheus metrics listener requires a non-zero port")
    );
    Ok(())
}

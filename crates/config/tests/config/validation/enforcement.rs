use probe_config::*;

#[test]
fn validation_rejects_invalid_enforcement_policy_source_config()
-> Result<(), Box<dyn std::error::Error>> {
    let empty_file = AgentConfig::from_toml_str(
        r#"
[enforcement.policy.source]
kind = "file"
path = ""
"#,
    )?;

    let error = empty_file
        .validate_basic()
        .expect_err("enforcement policy source path must be validated");

    assert!(
        error
            .to_string()
            .contains("enforcement policy file path cannot be empty")
    );

    for endpoint in [
        "https://control.example/enforcement",
        "http://127.0.0.1:8080/enforcement",
        "http://[::1]:8080/enforcement",
        "http://localhost:8080/enforcement",
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[enforcement.policy.source]
kind = "remote"
endpoint = "{endpoint}"
"#
        ))?;
        config.validate_basic()?;
    }

    for (endpoint, reason) in [
        (
            "http://control.example/enforcement",
            "remote enforcement policy endpoint must use HTTPS",
        ),
        (
            "ftp://control.example/enforcement",
            "remote enforcement policy endpoint must use HTTPS",
        ),
        (
            "control.example/enforcement",
            "remote enforcement policy endpoint must be an absolute URL",
        ),
        (
            "https://user:password@control.example/enforcement",
            "remote enforcement policy endpoint must not contain credentials",
        ),
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[enforcement.policy.source]
kind = "remote"
endpoint = "{endpoint}"
"#
        ))?;
        let error = config
            .validate_basic()
            .expect_err("invalid remote enforcement endpoint must be rejected");
        assert!(
            error.to_string().contains(reason),
            "expected {reason:?} in {error}"
        );
    }
    Ok(())
}

#[test]
fn validation_rejects_incomplete_transparent_interception_config()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy"
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("invalid transparent interception config must be rejected");

    assert!(
        error
            .to_string()
            .contains("transparent interception requires a non-zero proxy listen port")
    );
    Ok(())
}

#[test]
fn validation_rejects_managed_relay_without_inbound_tproxy()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_mitm"

[enforcement.interception.proxy]
mode = "managed_tcp_relay"
listen_port = 15001
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("managed relay must be tied to inbound TPROXY");

    assert!(
        error
            .to_string()
            .contains("managed TCP relay proxy mode is only valid for inbound TPROXY interception")
    );
    Ok(())
}

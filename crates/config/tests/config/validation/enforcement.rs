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

[enforcement.interception.nftables]
table_name = "bad-name"
mark = 0
route_table = 0
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
    assert!(
        error.to_string().contains(
            "transparent interception nftables mark must be the reserved sssa_probe mark"
        )
    );
    assert!(error.to_string().contains(
        "transparent interception policy route table must be the reserved sssa_probe table"
    ));
    assert!(error.to_string().contains(
        "transparent interception nftables table name must be the reserved sssa_probe table"
    ));
    Ok(())
}

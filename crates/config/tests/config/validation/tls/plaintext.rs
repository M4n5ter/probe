use probe_config::*;

#[test]
fn validation_rejects_invalid_tls_plaintext_material_refs() -> Result<(), Box<dyn std::error::Error>>
{
    let missing_ref = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
enabled = true
provider = "keylog"
key_log_refs = ["missing"]
"#,
    )?;
    let missing_ref_error = missing_ref
        .validate_basic()
        .expect_err("plaintext material refs must exist");
    assert!(
        missing_ref_error
            .to_string()
            .contains("TLS plaintext material ref missing does not exist")
    );

    let wrong_kind = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
enabled = true
provider = "keylog"
key_log_refs = ["session-secret"]

[[tls.materials]]
id = "session-secret"
kind = "session_secret_file"
path = "/tmp/session-secret.jsonl"
"#,
    )?;
    let wrong_kind_error = wrong_kind
        .validate_basic()
        .expect_err("plaintext key log refs must point at key log material");
    assert!(wrong_kind_error.to_string().contains("expected KeyLogFile"));

    let empty_ref = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
enabled = true
provider = "keylog"
session_secret_refs = [""]
"#,
    )?;
    let empty_ref_error = empty_ref
        .validate_basic()
        .expect_err("plaintext material refs must not be empty");
    assert!(
        empty_ref_error
            .to_string()
            .contains("TLS plaintext material reference cannot be empty")
    );

    let libssl_ref = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
enabled = true
provider = "libssl_uprobe"
key_log_refs = ["ssl-keys"]

[[tls.materials]]
id = "ssl-keys"
kind = "key_log_file"
path = "/tmp/sslkeylog.log"
"#,
    )?;
    let libssl_ref_error = libssl_ref
        .validate_basic()
        .expect_err("libssl uprobes must not accept key log refs");
    assert!(
        libssl_ref_error
            .to_string()
            .contains("libssl_uprobe plaintext provider does not use key log materials")
    );

    let disabled_libssl_ref = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
key_log_refs = ["ssl-keys"]

[[tls.materials]]
id = "ssl-keys"
kind = "key_log_file"
path = "/tmp/sslkeylog.log"
"#,
    )?;
    let disabled_libssl_ref_error = disabled_libssl_ref
        .validate_basic()
        .expect_err("libssl refs must be rejected even when plaintext is disabled");
    assert!(
        disabled_libssl_ref_error
            .to_string()
            .contains("libssl_uprobe plaintext provider does not use key log materials")
    );
    Ok(())
}

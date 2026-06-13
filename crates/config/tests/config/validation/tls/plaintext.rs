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

#[test]
fn validation_rejects_invalid_libssl_uprobe_object_path_config()
-> Result<(), Box<dyn std::error::Error>> {
    let empty_object_path = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
provider = "libssl_uprobe"
libssl_uprobe_object_path = ""
"#,
    )?;
    let error = empty_object_path
        .validate_basic()
        .expect_err("libssl uprobe object path must not be empty");
    assert!(
        error
            .to_string()
            .contains("libssl uprobe eBPF object path cannot be empty")
    );

    let keylog_object_path = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
provider = "keylog"
libssl_uprobe_object_path = "/opt/sssa/ebpf-tls-plaintext.bpf.o"
"#,
    )?;
    let error = keylog_object_path
        .validate_basic()
        .expect_err("libssl uprobe object path belongs to the libssl provider");
    assert!(
        error
            .to_string()
            .contains("only valid when tls.plaintext.provider = \"libssl_uprobe\"")
    );
    Ok(())
}

#[test]
fn validation_rejects_zero_tls_plaintext_reconcile_interval()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
reconcile_interval_ms = 0
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("TLS plaintext reconcile interval must be positive");

    assert!(
        error
            .to_string()
            .contains("TLS plaintext reconcile interval must be positive")
    );
    Ok(())
}

#[test]
fn validation_rejects_oversized_tls_plaintext_reconcile_interval()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(&format!(
        r#"
[tls.plaintext]
reconcile_interval_ms = {}
"#,
        MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS + 1
    ))?;

    let error = config
        .validate_basic()
        .expect_err("TLS plaintext reconcile interval must stay within the supported bound");

    assert!(
        error
            .to_string()
            .contains("TLS plaintext reconcile interval must be at most 3600000 ms")
    );
    Ok(())
}

use probe_config::*;

#[test]
fn parses_tls_plaintext_decrypt_hint_material_refs() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
enabled = true
reconcile_interval_ms = 2500
key_log_refs = ["ssl-keys"]
session_secret_refs = ["session-secrets"]

[[tls.materials]]
id = "ssl-keys"
kind = "key_log_file"
path = "/var/lib/sssa-probe/sslkeylog.log"

[[tls.materials]]
id = "session-secrets"
kind = "session_secret_file"
path = "/var/lib/sssa-probe/session-secrets.jsonl"
"#,
    )?;

    assert_eq!(config.tls.plaintext.reconcile_interval_ms, 2500);
    assert_eq!(config.tls.plaintext.key_log_refs, vec!["ssl-keys"]);
    assert_eq!(
        config.tls.plaintext.session_secret_refs,
        vec!["session-secrets"]
    );
    config.validate_basic()?;
    Ok(())
}

#[test]
fn rejects_tls_plaintext_provider_field() {
    let result = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
provider = "libssl_uprobe"
"#,
    );

    assert!(result.is_err());
}

#[test]
fn tls_plaintext_reconcile_interval_uses_default() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
enabled = true
"#,
    )?;

    assert_eq!(
        config.tls.plaintext.reconcile_interval_ms,
        DEFAULT_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS
    );
    Ok(())
}

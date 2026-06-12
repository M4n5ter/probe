use probe_config::*;

#[test]
fn parses_tls_plaintext_material_refs() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[tls.plaintext]
enabled = true
provider = "keylog"
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

    assert_eq!(config.tls.plaintext.provider, TlsPlaintextProvider::Keylog);
    assert_eq!(config.tls.plaintext.key_log_refs, vec!["ssl-keys"]);
    assert_eq!(
        config.tls.plaintext.session_secret_refs,
        vec!["session-secrets"]
    );
    config.validate_basic()?;
    Ok(())
}

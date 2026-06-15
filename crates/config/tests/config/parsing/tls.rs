use probe_config::*;

#[test]
fn parses_tls_plaintext_decrypt_hint_material_refs() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[tls.plaintext.instrumentation]
enabled = true
reconcile_interval_ms = 2500

[tls.plaintext.decrypt_hints]
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

    assert_eq!(
        config.tls.plaintext.instrumentation.reconcile_interval_ms,
        2500
    );
    assert_eq!(
        config.tls.plaintext.decrypt_hints.key_log_refs,
        vec!["ssl-keys"]
    );
    assert_eq!(
        config.tls.plaintext.decrypt_hints.session_secret_refs,
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
fn rejects_removed_flat_tls_plaintext_fields() {
    let removed_configs = [
        (
            "enabled",
            r#"
[tls.plaintext]
enabled = true
"#,
        ),
        (
            "selector",
            r#"
[tls.plaintext.selector]
op = "match"

[tls.plaintext.selector.term.process]
pids = [4242]
names = []
exe_path_globs = []
cmdline_regexes = []
systemd_services = []
container_ids = []

[tls.plaintext.selector.term.traffic]
local_ports = [443]
remote_ports = []
directions = []
remote_addresses = []
"#,
        ),
        (
            "libssl_uprobe_object_path",
            r#"
[tls.plaintext]
libssl_uprobe_object_path = "/opt/sssa/ebpf-tls-plaintext.bpf.o"
"#,
        ),
        (
            "reconcile_interval_ms",
            r#"
[tls.plaintext]
reconcile_interval_ms = 2500
"#,
        ),
        (
            "key_log_refs",
            r#"
[tls.plaintext]
key_log_refs = ["ssl-keys"]
"#,
        ),
        (
            "session_secret_refs",
            r#"
[tls.plaintext]
session_secret_refs = ["session-secrets"]
"#,
        ),
    ];

    for (removed_field, config) in removed_configs {
        let result = AgentConfig::from_toml_str(config);

        assert!(result.is_err(), "{removed_field} should be rejected");
    }
}

#[test]
fn tls_plaintext_reconcile_interval_uses_default() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[tls.plaintext.instrumentation]
enabled = true
"#,
    )?;

    assert_eq!(
        config.tls.plaintext.instrumentation.reconcile_interval_ms,
        DEFAULT_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS
    );
    Ok(())
}

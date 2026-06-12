use probe_config::*;

#[test]
fn validation_rejects_incomplete_client_tls_identity() -> Result<(), Box<dyn std::error::Error>> {
    let missing_key = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.tls]
client_certificate_refs = ["client-cert"]

[[tls.materials]]
id = "client-cert"
kind = "client_certificate"
path = "/tmp/client.pem"
"#,
    )?;
    let missing_key_error = missing_key
        .validate_basic()
        .expect_err("client certificate must require a private key");
    assert!(
        missing_key_error
            .to_string()
            .contains("client certificate refs require a client private key ref")
    );

    let missing_certificate = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.tls]
client_private_key_ref = "client-key"

[[tls.materials]]
id = "client-key"
kind = "client_private_key"
path = "/tmp/client.key"
"#,
    )?;
    let missing_certificate_error = missing_certificate
        .validate_basic()
        .expect_err("client private key must require a certificate");
    assert!(
        missing_certificate_error
            .to_string()
            .contains("client private key ref requires at least one client certificate ref")
    );

    let wrong_kind = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.tls]
trust_anchor_refs = ["client-cert"]

[[tls.materials]]
id = "client-cert"
kind = "client_certificate"
path = "/tmp/client.pem"
"#,
    )?;
    let wrong_kind_error = wrong_kind
        .validate_basic()
        .expect_err("trust anchor ref must point at a trust anchor material");
    assert!(
        wrong_kind_error
            .to_string()
            .contains("expected TrustAnchor")
    );

    let http_tls = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "http://collector.example/batches"

[exporters.tls]
trust_anchor_refs = ["collector-ca"]

[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/tmp/ca.pem"
"#,
    )?;
    let http_tls_error = http_tls
        .validate_basic()
        .expect_err("TLS refs on plain HTTP webhook must be rejected");
    assert!(
        http_tls_error
            .to_string()
            .contains("exporter TLS material refs require an HTTPS webhook endpoint")
    );
    Ok(())
}

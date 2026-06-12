use probe_config::*;

#[test]
fn validation_rejects_empty_tls_material_path() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[tls.materials]]
kind = "trust_anchor"
path = ""
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("TLS material paths must be explicit");

    assert!(error.to_string().contains("tls.materials[0].path"));
    assert!(
        error
            .to_string()
            .contains("TLS material path cannot be empty")
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_tls_material_registry_refs() -> Result<(), Box<dyn std::error::Error>>
{
    let duplicate_ids = AgentConfig::from_toml_str(
        r#"
[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/tmp/ca-1.pem"

[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/tmp/ca-2.pem"
"#,
    )?;
    let duplicate_error = duplicate_ids
        .validate_basic()
        .expect_err("TLS material ids must be unique");
    assert!(
        duplicate_error
            .to_string()
            .contains("TLS material id must be unique")
    );

    let missing_ref = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.tls]
trust_anchor_refs = ["missing-ca"]
"#,
    )?;
    let missing_ref_error = missing_ref
        .validate_basic()
        .expect_err("exporter TLS refs must point at registered material ids");
    assert!(
        missing_ref_error
            .to_string()
            .contains("TLS material ref missing-ca does not exist")
    );
    Ok(())
}

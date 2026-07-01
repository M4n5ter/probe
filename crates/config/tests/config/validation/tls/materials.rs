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

#[test]
fn validation_rejects_invalid_tls_material_filesystem_roots()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[tls.material_store.filesystem]
allowed_roots = ["relative", "/", "/etc/traffic-probe/../tls", "/etc/traffic-probe/tls", "/etc/traffic-probe/tls"]
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("invalid TLS material filesystem roots must fail");
    let rendered = error.to_string();

    assert!(rendered.contains("tls.material_store.filesystem.allowed_roots[0]"));
    assert!(rendered.contains("must be absolute"));
    assert!(rendered.contains("tls.material_store.filesystem.allowed_roots[1]"));
    assert!(rendered.contains("cannot be /"));
    assert!(rendered.contains("tls.material_store.filesystem.allowed_roots[2]"));
    assert!(rendered.contains("cannot contain parent directory components"));
    assert!(rendered.contains("tls.material_store.filesystem.allowed_roots[4]"));
    assert!(rendered.contains("must be unique"));
    Ok(())
}

#[test]
fn validation_rejects_material_paths_outside_configured_filesystem_roots()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[tls.material_store.filesystem]
allowed_roots = ["/etc/traffic-probe/tls"]

[[tls.materials]]
id = "relative-ca"
kind = "trust_anchor"
path = "relative.pem"

[[tls.materials]]
id = "outside-ca"
kind = "trust_anchor"
path = "/etc/traffic-probe/other/ca.pem"

[[tls.materials]]
id = "escape-ca"
kind = "trust_anchor"
path = "/etc/traffic-probe/tls/../other/ca.pem"
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("material paths outside configured roots must fail");
    let rendered = error.to_string();

    assert!(rendered.contains("tls.materials[0].path"));
    assert!(rendered.contains("must be absolute"));
    assert!(rendered.contains("tls.materials[1].path"));
    assert!(rendered.contains("must be inside one configured filesystem root"));
    assert!(rendered.contains("tls.materials[2].path"));
    assert!(rendered.contains("must be inside one configured filesystem root"));
    Ok(())
}

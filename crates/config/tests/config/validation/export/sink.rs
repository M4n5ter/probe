use probe_config::*;

#[test]
fn parsing_rejects_unimplemented_exporter_transport() {
    let result = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "grpc"
endpoint = "https://collector.example/batches"
"#,
    );

    assert!(result.is_err());
}

#[test]
fn validation_rejects_reserved_exporter_headers() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
headers = { idempotency-key = "override" }
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("reserved webhook header must be rejected");

    assert!(error.to_string().contains("exporter header is reserved"));
    Ok(())
}

#[test]
fn validation_rejects_duplicate_and_reserved_exporter_ids() -> Result<(), Box<dyn std::error::Error>>
{
    let duplicate = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/one"

[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/two"
"#,
    )?;
    let duplicate_error = duplicate
        .validate_basic()
        .expect_err("duplicate exporter ids must be rejected");
    assert!(
        duplicate_error
            .to_string()
            .contains("exporter id must be unique")
    );

    let reserved = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "replay-webhook"
transport = "webhook"
endpoint = "https://collector.example/replay"
"#,
    )?;
    let reserved_error = reserved
        .validate_basic()
        .expect_err("replay-webhook sink id must be reserved");
    assert!(
        reserved_error
            .to_string()
            .contains("reserved for replay CLI")
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_exporter_headers() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
headers = { "bad header" = "value", good = "bad\nvalue" }
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("invalid webhook headers must be rejected");

    assert!(
        error
            .to_string()
            .contains("exporter header name is not a valid HTTP token")
    );
    assert!(
        error
            .to_string()
            .contains("exporter header value cannot contain CR or LF")
    );
    Ok(())
}

#[test]
fn validation_rejects_empty_file_exporter_path() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "local-file"
transport = "file"
path = ""
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("empty file exporter path must be rejected");

    assert!(
        error
            .to_string()
            .contains("file exporter path cannot be empty")
    );
    Ok(())
}

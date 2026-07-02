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
fn validation_rejects_invalid_webhook_endpoint_urls() -> Result<(), Box<dyn std::error::Error>> {
    for (endpoint, reason) in [
        ("/relative", "webhook endpoint must be an absolute URL"),
        (
            "collector.example/batches",
            "webhook endpoint must be an absolute URL",
        ),
        (
            "https://user:password@collector.example/batches",
            "webhook endpoint must not contain credentials",
        ),
        (
            "ftp://collector.example/batches",
            "webhook endpoint must use HTTP or HTTPS",
        ),
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "{endpoint}"
"#
        ))?;

        let error = config
            .validate_basic()
            .expect_err("invalid webhook endpoint must be rejected");
        assert!(
            error.to_string().contains(reason),
            "expected {reason:?} in {error}"
        );
    }
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

#[test]
fn validation_rejects_invalid_unix_http_exporter_target() -> Result<(), Box<dyn std::error::Error>>
{
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "local-sidecar"
transport = "unix_http"
socket_path = "collector.sock"
endpoint = "batches"
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("invalid unix_http exporter target must be rejected");

    assert!(
        error
            .to_string()
            .contains("unix_http exporter socket_path must be absolute")
    );
    assert!(
        error
            .to_string()
            .contains("unix_http endpoint must be an absolute path")
    );
    Ok(())
}

#[test]
fn parsing_rejects_transport_specific_exporter_fields() -> Result<(), Box<dyn std::error::Error>> {
    let file_with_endpoint = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "local-file"
transport = "file"
path = "/tmp/traffic-probe-export.jsonl"
endpoint = "/batches"
"#,
    );
    assert!(file_with_endpoint.is_err());

    let unix_http_with_tls = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "local-sidecar"
transport = "unix_http"
socket_path = "/var/lib/traffic-probe/run/collector.sock"
endpoint = "/batches"

[exporters.tls]
trust_anchor_refs = ["collector-ca"]
"#,
    );
    assert!(unix_http_with_tls.is_err());

    let webhook_with_socket_path = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "webhook"
transport = "webhook"
endpoint = "https://collector.example/batches"
socket_path = "/var/lib/traffic-probe/run/collector.sock"
"#,
    );
    assert!(webhook_with_socket_path.is_err());
    Ok(())
}

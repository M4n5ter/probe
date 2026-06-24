use probe_config::*;

#[test]
fn validation_rejects_invalid_capture_runtime_fields() -> Result<(), Box<dyn std::error::Error>> {
    let empty_fallback = AgentConfig::from_toml_str(
        r#"
[capture]
fallback_backends = []
"#,
    )?;

    let empty_fallback_error = empty_fallback
        .validate_basic()
        .expect_err("auto capture requires a live backend");
    assert!(
        empty_fallback_error
            .to_string()
            .contains("auto capture selection requires at least one live fallback backend")
    );

    let duplicate_fallback = AgentConfig::from_toml_str(
        r#"
[capture]
fallback_backends = ["ebpf", "ebpf", "libpcap"]
"#,
    )?;

    let duplicate_fallback_error = duplicate_fallback
        .validate_basic()
        .expect_err("duplicate fallback backends must be rejected");
    assert!(
        duplicate_fallback_error
            .to_string()
            .contains("capture fallback backend Ebpf is duplicated")
    );

    let config = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "libpcap"

[capture.libpcap]
bpf_filter = " "
snaplen = 0
read_timeout_ms = -1
buffer_size = 0
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("capture fields must be validated");

    assert!(
        error
            .to_string()
            .contains("libpcap BPF filter cannot be empty")
    );
    assert!(
        error
            .to_string()
            .contains("libpcap snaplen must be positive")
    );
    assert!(
        error
            .to_string()
            .contains("libpcap read timeout cannot be negative")
    );
    assert!(
        error
            .to_string()
            .contains("libpcap buffer size must be positive")
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_plaintext_feed_config() -> Result<(), Box<dyn std::error::Error>> {
    let unused_path = AgentConfig::from_toml_str(
        r#"
[capture.plaintext_feed]
path = "/tmp/feed.jsonl"
"#,
    )?;
    let error = unused_path
        .validate_basic()
        .expect_err("plaintext feed path must belong to the selected backend");
    assert!(error.to_string().contains("capture.plaintext_feed.path"));

    let missing_path = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "plaintext_feed"
"#,
    )?;
    let error = missing_path
        .validate_basic()
        .expect_err("external feed must set a path");
    assert!(error.to_string().contains("capture.plaintext_feed.path"));

    let conflicting_tls_instrumentation = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "plaintext_feed"

[capture.plaintext_feed]
path = "/tmp/feed.jsonl"

[tls.plaintext.instrumentation]
enabled = true
"#,
    )?;
    let error = conflicting_tls_instrumentation
        .validate_basic()
        .expect_err("plaintext feed selection must not also enable TLS instrumentation");
    assert!(
        error
            .to_string()
            .contains("tls.plaintext.instrumentation.enabled")
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_capture_event_feed_config() -> Result<(), Box<dyn std::error::Error>>
{
    let unused_path = AgentConfig::from_toml_str(
        r#"
[capture.capture_event_feed]
path = "/tmp/capture-events.jsonl"
"#,
    )?;
    let error = unused_path
        .validate_basic()
        .expect_err("capture event feed path must belong to the selected backend");
    assert!(
        error
            .to_string()
            .contains("capture.capture_event_feed.path")
    );

    let unused_follow = AgentConfig::from_toml_str(
        r#"
[capture.capture_event_feed]
follow = true
"#,
    )?;
    let error = unused_follow
        .validate_basic()
        .expect_err("capture event feed follow mode must belong to the selected backend");
    assert!(
        error
            .to_string()
            .contains("capture.capture_event_feed.follow")
    );

    let unused_explicit_false_follow = AgentConfig::from_toml_str(
        r#"
[capture.capture_event_feed]
follow = false
"#,
    )?;
    let error = unused_explicit_false_follow
        .validate_basic()
        .expect_err("explicit capture event feed follow mode must belong to the selected backend");
    assert!(
        error
            .to_string()
            .contains("capture.capture_event_feed.follow")
    );

    let missing_path = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "capture_event_feed"
"#,
    )?;
    let error = missing_path
        .validate_basic()
        .expect_err("capture event feed must set a path");
    assert!(
        error
            .to_string()
            .contains("capture.capture_event_feed.path")
    );
    Ok(())
}

#[test]
fn validation_ignores_unused_libpcap_fields() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "replay"

[capture.libpcap]
bpf_filter = " "
snaplen = 0
"#,
    )?;

    config.validate_basic()?;
    Ok(())
}

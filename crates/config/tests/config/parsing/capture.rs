use std::path::PathBuf;

use probe_config::*;

#[test]
fn parses_external_plaintext_feed_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "plaintext_feed"

[capture.plaintext_feed]
path = "/tmp/sssa-plaintext-feed.jsonl"
"#,
    )?;

    assert_eq!(config.capture.selection, CaptureSelection::PlaintextFeed);
    assert_eq!(
        config.capture.plaintext_feed.path,
        Some(PathBuf::from("/tmp/sssa-plaintext-feed.jsonl"))
    );
    config.validate_basic()?;
    Ok(())
}

#[test]
fn parses_capture_event_feed_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "capture_event_feed"

[capture.capture_event_feed]
path = "/tmp/sssa-capture-events.jsonl"
follow = true
"#,
    )?;

    assert_eq!(config.capture.selection, CaptureSelection::CaptureEventFeed);
    assert_eq!(
        config.capture.capture_event_feed.path,
        Some(PathBuf::from("/tmp/sssa-capture-events.jsonl"))
    );
    assert_eq!(config.capture.capture_event_feed.follow, Some(true));
    config.validate_basic()?;
    Ok(())
}

#[test]
fn parses_ebpf_object_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "ebpf"

[capture.ebpf]
object_path = "/opt/sssa/sssa_probe.bpf.o"
"#,
    )?;

    assert_eq!(config.capture.selection, CaptureSelection::Ebpf);
    assert_eq!(
        config.capture.ebpf.object_path,
        Some(PathBuf::from("/opt/sssa/sssa_probe.bpf.o"))
    );
    config.validate_basic()?;
    Ok(())
}

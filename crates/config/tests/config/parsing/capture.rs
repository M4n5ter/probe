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

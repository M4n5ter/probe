use probe_config::*;
use probe_core::Action;

#[test]
fn parses_enforcement_policy_manifest_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = toml::from_str::<EnforcementPolicyManifest>(
        r#"
id = "managed-apps"
version = "2026-06-12"
"#,
    )?;

    assert_eq!(manifest.id, "managed-apps");
    assert_eq!(manifest.version, "2026-06-12");
    assert_eq!(
        manifest.protective_actions.actions(),
        &[Action::Deny, Action::Reset, Action::Quarantine]
    );
    assert!(manifest.selector.is_none());
    Ok(())
}

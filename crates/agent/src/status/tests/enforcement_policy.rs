use probe_config::{EnforcementPolicyManifest, EnforcementPolicySourceConfig};
use probe_core::{Action, ProtectiveActionProfile, Selector};
use serde_json::json;

use super::*;

#[test]
fn status_snapshot_reports_metadata_only_enforcement_policy_source()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("status-enforcement-policy")?;
    let manifest_path = temp.join("enforcement.toml");
    let manifest = EnforcementPolicyManifest {
        id: "managed-apps".to_string(),
        version: "v1".to_string(),
        selector: Some(Selector::default()),
        protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
    };
    fs::write(&manifest_path, toml::to_string(&manifest)?)?;
    let mut config = config_with_storage_path(temp.join("spool"));
    config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
        path: manifest_path,
    };
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert_eq!(
        snapshot.enforcement.effective_selector_configured,
        Some(true)
    );
    assert!(!snapshot.enforcement.config_selector_configured);
    assert_eq!(
        snapshot.enforcement.manifest_selector_configured,
        Some(true)
    );
    assert_eq!(
        snapshot.enforcement.policy.source.mode,
        EnforcementPolicySourceStatusMode::MetadataOnly
    );
    let manifest_status = snapshot
        .enforcement
        .policy
        .source
        .manifest
        .as_ref()
        .expect("manifest metadata should be reported");
    assert_eq!(manifest_status.id, "managed-apps");
    assert_eq!(manifest_status.version, "v1");
    assert!(manifest_status.selector_configured);
    assert_eq!(
        manifest_status.protective_actions.actions(),
        &[Action::Deny]
    );
    assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
    assert!(snapshot.health.reasons.iter().any(|reason| {
        reason.contains("enforcement policy")
            && reason.contains("status does not execute enforcement actions")
    }));

    let value = serde_json::to_value(&snapshot)?;
    assert_eq!(
        value["enforcement"]["policy"]["source"]["mode"],
        json!("metadata_only")
    );
    assert_eq!(
        value["enforcement"]["policy"]["source"]["manifest"]["protective_actions"],
        json!(["deny"])
    );
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[test]
fn missing_enforcement_policy_directory_manifest_makes_status_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("status-missing-enforcement-manifest")?;
    let mut config = config_with_storage_path(temp.join("spool"));
    config.enforcement.policy.source = EnforcementPolicySourceConfig::Directory {
        path: temp.join("enforcement.d"),
    };
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert_eq!(
        snapshot.enforcement.policy.source.mode,
        EnforcementPolicySourceStatusMode::Unavailable
    );
    assert_eq!(snapshot.enforcement.effective_selector_configured, None);
    assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
    assert!(snapshot.health.reasons.iter().any(|reason| {
        reason.contains("enforcement policy") && reason.contains("does not exist")
    }));
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[test]
fn invalid_enforcement_policy_manifest_makes_status_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("status-invalid-enforcement-manifest")?;
    let manifest_path = temp.join("enforcement.toml");
    fs::write(
        &manifest_path,
        r#"
id = "managed-apps"
version = "v1"
protective_actions = ["alert"]
"#,
    )?;
    let mut config = config_with_storage_path(temp.join("spool"));
    config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
        path: manifest_path,
    };
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert_eq!(
        snapshot.enforcement.policy.source.mode,
        EnforcementPolicySourceStatusMode::Unavailable
    );
    assert_eq!(snapshot.enforcement.effective_selector_configured, None);
    assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
    assert!(snapshot.health.reasons.iter().any(|reason| {
        reason.contains("enforcement policy")
            && reason.contains("not a protective enforcement action")
    }));
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[test]
fn remote_enforcement_policy_source_makes_status_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut config = config_with_storage_path("/tmp/sssa-spool".into());
    config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
        endpoint: "https://control.example/enforcement".to_string(),
    };
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert_eq!(
        snapshot.enforcement.policy.source.mode,
        EnforcementPolicySourceStatusMode::Unavailable
    );
    assert_eq!(snapshot.enforcement.effective_selector_configured, None);
    assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
    assert!(
        snapshot
            .health
            .reasons
            .iter()
            .any(|reason| { reason.contains("remote enforcement policy source is reserved") })
    );
    Ok(())
}

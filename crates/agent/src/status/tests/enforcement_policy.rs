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
    let EnforcementPolicySourceStatusSnapshot::LocalMetadata {
        reason: _,
        manifest: manifest_status,
    } = &snapshot.enforcement.policy.source
    else {
        panic!("local enforcement source should report manifest metadata");
    };
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
        json!("local_metadata")
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

    assert!(matches!(
        snapshot.enforcement.policy.source,
        EnforcementPolicySourceStatusSnapshot::Unavailable { .. }
    ));
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

    assert!(matches!(
        snapshot.enforcement.policy.source,
        EnforcementPolicySourceStatusSnapshot::Unavailable { .. }
    ));
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
fn remote_enforcement_policy_source_is_metadata_only_in_offline_status()
-> Result<(), Box<dyn std::error::Error>> {
    let mut config = config_with_storage_path("/tmp/sssa-spool".into());
    config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
        endpoint: "https://control.example/enforcement".to_string(),
    };
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert!(matches!(
        snapshot.enforcement.policy.source,
        EnforcementPolicySourceStatusSnapshot::RemoteConfigured { .. }
    ));
    assert_eq!(snapshot.enforcement.effective_selector_configured, None);
    assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
    assert!(
        snapshot
            .health
            .reasons
            .iter()
            .any(|reason| { reason.contains("offline status does not fetch remote policy") })
    );
    Ok(())
}

#[test]
fn remote_enforcement_policy_source_preserves_config_selector_in_offline_status()
-> Result<(), Box<dyn std::error::Error>> {
    let mut config = config_with_storage_path("/tmp/sssa-spool".into());
    config.enforcement.selector = Some(Selector::default());
    config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
        endpoint: "https://control.example/enforcement".to_string(),
    };
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert!(matches!(
        snapshot.enforcement.policy.source,
        EnforcementPolicySourceStatusSnapshot::RemoteConfigured { .. }
    ));
    assert_eq!(
        snapshot.enforcement.effective_selector_configured,
        Some(true)
    );
    Ok(())
}

#[test]
fn loaded_remote_enforcement_policy_status_reports_source_origin()
-> Result<(), Box<dyn std::error::Error>> {
    let endpoint = "https://control.example/enforcement".to_string();
    let mut config = config_with_storage_path("/tmp/sssa-spool".into());
    config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
        endpoint: endpoint.clone(),
    };
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();
    let manifest = EnforcementPolicyManifest {
        id: "managed-apps".to_string(),
        version: "remote-v1".to_string(),
        selector: None,
        protective_actions: ProtectiveActionProfile::new([Action::Reset])?,
    };

    let snapshot = build_status_snapshot_at_with_runtime(
        &plan,
        spool,
        42,
        RuntimeStatusInput {
            enforcement_policy_source: Some(LoadedEnforcementPolicySource::remote(
                endpoint.clone(),
                manifest,
            )),
        },
    );

    let EnforcementPolicySourceStatusSnapshot::Loaded {
        source: LoadedEnforcementPolicySourceStatusSnapshot::Remote { endpoint: actual },
        manifest,
    } = &snapshot.enforcement.policy.source
    else {
        panic!("remote loaded enforcement source should keep its origin");
    };
    assert_eq!(actual, &endpoint);
    assert_eq!(manifest.id, "managed-apps");
    assert_eq!(manifest.version, "remote-v1");
    assert_eq!(manifest.protective_actions.actions(), &[Action::Reset]);
    assert_eq!(snapshot.health.mode, RuntimeMode::Available);

    let value = serde_json::to_value(&snapshot)?;
    assert_eq!(
        value["enforcement"]["policy"]["source"]["mode"],
        json!("loaded")
    );
    assert_eq!(
        value["enforcement"]["policy"]["source"]["source"]["kind"],
        json!("remote")
    );
    assert_eq!(
        value["enforcement"]["policy"]["source"]["source"]["endpoint"],
        json!(endpoint)
    );
    Ok(())
}

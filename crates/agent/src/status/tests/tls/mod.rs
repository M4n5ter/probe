use serde_json::json;

use super::*;

#[test]
fn status_snapshot_reports_metadata_only_tls_materials() -> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("status-tls-material")?;
    let material_path = temp.join("ca.pem");
    fs::write(&material_path, b"test trust anchor")?;
    let mut config = config_with_storage_path(temp.join("spool"));
    config.tls.materials = vec![probe_config::TlsMaterialConfig {
        id: Some("collector-ca".to_string()),
        kind: probe_config::TlsMaterialKind::TrustAnchor,
        path: material_path.clone(),
    }];
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert_eq!(snapshot.tls.materials.len(), 1);
    let material = &snapshot.tls.materials[0];
    assert_eq!(material.path, material_path);
    assert_eq!(material.purpose, TlsMaterialPurpose::TrustOrIdentity);
    assert_eq!(material.source.mode, RuntimeMode::Available);
    assert_eq!(material.source.check, TlsMaterialSourceCheck::MetadataOnly);
    assert_eq!(snapshot.health.mode, RuntimeMode::Available);
    let value = serde_json::to_value(&snapshot)?;
    assert_eq!(
        value["tls"]["materials"][0]["source"]["check"],
        json!("metadata_only")
    );
    assert_eq!(
        value["tls"]["materials"][0]["purpose"],
        json!("trust_or_identity")
    );
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[test]
fn status_snapshot_reports_tls_plaintext_capability() -> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("status-tls-plaintext-capability")?;
    let mut config = config_with_storage_path(temp.join("spool"));
    config.tls.plaintext.enabled = true;
    config.tls.plaintext.provider = probe_config::TlsPlaintextProvider::LibsslUprobe;
    config.tls.plaintext.selector = Some(Selector::default());
    let plan = runtime_plan_from_config(
        config,
        vec![CapabilityState::available(CapabilityKind::LibsslUprobe)],
    )?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert!(snapshot.tls.plaintext.enabled);
    assert_eq!(
        snapshot.tls.plaintext.provider,
        probe_config::TlsPlaintextProvider::LibsslUprobe
    );
    assert!(snapshot.tls.plaintext.selector_configured);
    assert_eq!(
        snapshot.tls.plaintext.capability,
        TlsPlaintextCapabilityStatusSnapshot::Required {
            capability: CapabilityKind::LibsslUprobe,
            mode: RuntimeMode::Available,
        }
    );
    assert!(snapshot.tls.plaintext.key_logs.is_empty());
    assert!(snapshot.tls.plaintext.session_secrets.is_empty());
    let value = serde_json::to_value(&snapshot)?;
    assert_eq!(
        value["tls"]["plaintext"]["capability"]["kind"],
        json!("required")
    );
    assert_eq!(
        value["tls"]["plaintext"]["capability"]["capability"],
        json!("libssl_uprobe")
    );
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[test]
fn status_snapshot_reports_configured_tls_plaintext_material_refs()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("status-tls-plaintext-materials")?;
    let key_log_path = temp.join("sslkeylog.log");
    let session_secret_path = temp.join("session-secrets.jsonl");
    fs::write(&key_log_path, b"client random")?;
    fs::write(&session_secret_path, b"{\"secret\":\"test\"}\n")?;
    let mut config = config_with_storage_path(temp.join("spool"));
    config.tls.plaintext.provider = probe_config::TlsPlaintextProvider::Keylog;
    config.tls.plaintext.key_log_refs = vec!["ssl-keys".to_string()];
    config.tls.plaintext.session_secret_refs = vec!["session-secrets".to_string()];
    config.tls.materials = vec![
        probe_config::TlsMaterialConfig {
            id: Some("ssl-keys".to_string()),
            kind: probe_config::TlsMaterialKind::KeyLogFile,
            path: key_log_path.clone(),
        },
        probe_config::TlsMaterialConfig {
            id: Some("session-secrets".to_string()),
            kind: probe_config::TlsMaterialKind::SessionSecretFile,
            path: session_secret_path.clone(),
        },
    ];
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    assert_eq!(
        snapshot.tls.plaintext.capability,
        TlsPlaintextCapabilityStatusSnapshot::NotRequired
    );
    assert_eq!(snapshot.tls.plaintext.key_logs.len(), 1);
    assert_eq!(snapshot.tls.plaintext.key_logs[0].id, "ssl-keys");
    assert_eq!(
        snapshot.tls.plaintext.key_logs[0].kind,
        probe_config::TlsMaterialKind::KeyLogFile
    );
    assert_eq!(snapshot.tls.plaintext.key_logs[0].path, key_log_path);
    assert_eq!(
        snapshot.tls.plaintext.key_logs[0].source.mode,
        RuntimeMode::Available
    );
    assert_eq!(snapshot.tls.plaintext.session_secrets.len(), 1);
    assert_eq!(
        snapshot.tls.plaintext.session_secrets[0].id,
        "session-secrets"
    );
    assert_eq!(
        snapshot.tls.plaintext.session_secrets[0].path,
        session_secret_path
    );
    assert_eq!(
        snapshot.tls.plaintext.session_secrets[0].source.check,
        TlsMaterialSourceCheck::MetadataOnly
    );
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[test]
fn missing_tls_material_is_reported_without_forcing_health()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("status-missing-tls-material")?;
    let missing_path = temp.join("missing.keys");
    let mut config = config_with_storage_path(temp.join("spool"));
    config.tls.materials = vec![probe_config::TlsMaterialConfig {
        id: Some("keylog".to_string()),
        kind: probe_config::TlsMaterialKind::KeyLogFile,
        path: missing_path,
    }];
    let plan = runtime_plan_from_config(config, Vec::new())?;
    let spool = available_empty_spool();

    let snapshot = build_status_snapshot_at(&plan, spool, 42);

    let material = &snapshot.tls.materials[0];
    assert_eq!(material.purpose, TlsMaterialPurpose::DecryptHint);
    assert_eq!(material.source.mode, RuntimeMode::Unavailable);
    assert!(
        material
            .source
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("does not exist"))
    );
    assert_eq!(snapshot.health.mode, RuntimeMode::Available);
    fs::remove_dir_all(temp)?;
    Ok(())
}

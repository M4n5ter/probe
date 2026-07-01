use std::path::PathBuf;

use capture::{TlsKeyLog, TlsKeyLogSummary, TlsSessionSecretStore, TlsSessionSecretSummary};
use probe_config::TlsMaterialKind;
use runtime::{RuntimePlan, TlsPlaintextMaterialPlan};
use serde::Serialize;
use thiserror::Error;

use crate::tls_material::{
    FilesystemTlsMaterialStore, TlsMaterialFileStore, TlsMaterialFileStoreError,
};
use crate::tls_plaintext::{
    TlsDecryptHintError, TlsSessionSecretAutoBindingMaterials, TlsSessionSecretAutoBindingPlan,
    load_tls_session_secret_auto_binding_material,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TlsCheckSnapshot {
    plaintext: TlsPlaintextCheckSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsPlaintextCheckSnapshot {
    instrumentation: TlsPlaintextInstrumentationCheckSnapshot,
    decrypt_hints: TlsDecryptHintCheckSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsPlaintextInstrumentationCheckSnapshot {
    enabled: bool,
    libssl_uprobe_object_path: Option<PathBuf>,
    reconcile_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsDecryptHintCheckSnapshot {
    key_logs: Vec<TlsPlaintextMaterialCheckSnapshot>,
    session_secrets: Vec<TlsPlaintextMaterialCheckSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsPlaintextMaterialCheckSnapshot {
    id: String,
    kind: TlsMaterialKind,
    path: PathBuf,
    check: TlsPlaintextMaterialContentCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum TlsPlaintextMaterialContentCheck {
    SslKeyLog {
        summary: TlsKeyLogSummary,
    },
    Pending {
        reason: TlsPlaintextMaterialPendingReason,
    },
    SessionSecretFile {
        summary: TlsSessionSecretSummary,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TlsPlaintextMaterialPendingReason {
    NotFound,
    Empty,
}

#[derive(Debug, Error)]
pub(crate) enum TlsCheckError {
    #[error("TLS plaintext material {id} ({kind:?}) at {path} is invalid: {reason}")]
    PlaintextMaterial {
        id: String,
        kind: TlsMaterialKind,
        path: PathBuf,
        reason: String,
    },
    #[error("TLS plaintext decrypt hints are invalid: {reason}")]
    DecryptHints { reason: String },
}

pub(in crate::check) fn check_tls(plan: &RuntimePlan) -> Result<TlsCheckSnapshot, TlsCheckError> {
    let file_store = FilesystemTlsMaterialStore::from_plan(&plan.tls_material_store);
    check_tls_with_file_store(plan, &file_store)
}

fn check_tls_with_file_store(
    plan: &RuntimePlan,
    file_store: &impl TlsMaterialFileStore,
) -> Result<TlsCheckSnapshot, TlsCheckError> {
    let plaintext = &plan.tls.plaintext;
    let instrumentation = &plaintext.instrumentation;
    let decrypt_hints = &plaintext.decrypt_hints;
    let auto_binding_plan = TlsSessionSecretAutoBindingPlan::for_runtime(plan);
    let live_auto_binding_materials = auto_binding_plan.enabled_materials();
    let key_logs = check_key_log_materials(
        &decrypt_hints.key_logs,
        key_log_check_mode(live_auto_binding_materials),
        file_store,
    )?;
    let session_secrets = check_session_secret_materials(
        &decrypt_hints.session_secrets,
        session_secret_check_mode(live_auto_binding_materials),
        file_store,
    )?;
    check_live_auto_binding_materials(auto_binding_plan, file_store)?;

    Ok(TlsCheckSnapshot {
        plaintext: TlsPlaintextCheckSnapshot {
            instrumentation: TlsPlaintextInstrumentationCheckSnapshot {
                enabled: instrumentation.enabled,
                libssl_uprobe_object_path: instrumentation.libssl_uprobe_object_path.clone(),
                reconcile_interval_ms: instrumentation.reconcile_interval_ms,
            },
            decrypt_hints: TlsDecryptHintCheckSnapshot {
                key_logs,
                session_secrets,
            },
        },
    })
}

fn check_key_log_materials(
    materials: &[TlsPlaintextMaterialPlan],
    mode: KeyLogCheckMode,
    file_store: &impl TlsMaterialFileStore,
) -> Result<Vec<TlsPlaintextMaterialCheckSnapshot>, TlsCheckError> {
    materials
        .iter()
        .map(|material| check_key_log_material(material, mode, file_store))
        .collect()
}

fn check_key_log_material(
    material: &TlsPlaintextMaterialPlan,
    mode: KeyLogCheckMode,
    file_store: &impl TlsMaterialFileStore,
) -> Result<TlsPlaintextMaterialCheckSnapshot, TlsCheckError> {
    let bytes = match file_store.read_tls_material(&material.path) {
        Ok(bytes) => bytes,
        Err(TlsMaterialFileStoreError::NotFound) if mode == KeyLogCheckMode::LiveTail => {
            return Ok(pending_check_snapshot(
                material,
                TlsPlaintextMaterialPendingReason::NotFound,
            ));
        }
        Err(source) => return Err(tls_plaintext_material_error(material, source)),
    };
    let key_log = if mode == KeyLogCheckMode::LiveTail {
        TlsKeyLog::parse_live_snapshot(&bytes)
    } else {
        TlsKeyLog::parse(&bytes)
    }
    .map_err(|source| tls_plaintext_material_error(material, source))?;
    Ok(key_log_check_snapshot(material, key_log.summary()))
}

fn key_log_check_snapshot(
    material: &TlsPlaintextMaterialPlan,
    summary: TlsKeyLogSummary,
) -> TlsPlaintextMaterialCheckSnapshot {
    TlsPlaintextMaterialCheckSnapshot {
        id: material.id.clone(),
        kind: material.kind,
        path: material.path.clone(),
        check: TlsPlaintextMaterialContentCheck::SslKeyLog { summary },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyLogCheckMode {
    Static,
    LiveTail,
}

fn key_log_check_mode(
    materials: Option<TlsSessionSecretAutoBindingMaterials<'_>>,
) -> KeyLogCheckMode {
    if materials.is_some_and(|materials| !materials.key_logs().is_empty()) {
        KeyLogCheckMode::LiveTail
    } else {
        KeyLogCheckMode::Static
    }
}

fn check_session_secret_materials(
    materials: &[TlsPlaintextMaterialPlan],
    mode: SessionSecretCheckMode,
    file_store: &impl TlsMaterialFileStore,
) -> Result<Vec<TlsPlaintextMaterialCheckSnapshot>, TlsCheckError> {
    materials
        .iter()
        .map(|material| check_session_secret_material(material, mode, file_store))
        .collect()
}

fn check_session_secret_material(
    material: &TlsPlaintextMaterialPlan,
    mode: SessionSecretCheckMode,
    file_store: &impl TlsMaterialFileStore,
) -> Result<TlsPlaintextMaterialCheckSnapshot, TlsCheckError> {
    let bytes = match file_store.read_tls_material(&material.path) {
        Ok(bytes) => bytes,
        Err(TlsMaterialFileStoreError::NotFound)
            if mode == SessionSecretCheckMode::LiveAutoBinding =>
        {
            return Ok(pending_check_snapshot(
                material,
                TlsPlaintextMaterialPendingReason::NotFound,
            ));
        }
        Err(source) => return Err(tls_plaintext_material_error(material, source)),
    };
    if mode == SessionSecretCheckMode::LiveAutoBinding && tls_material_is_empty(&bytes) {
        return Ok(pending_check_snapshot(
            material,
            TlsPlaintextMaterialPendingReason::Empty,
        ));
    }
    let store = TlsSessionSecretStore::parse(&bytes)
        .map_err(|source| tls_plaintext_material_error(material, source))?;
    Ok(session_secret_check_snapshot(material, store.summary()))
}

fn session_secret_check_snapshot(
    material: &TlsPlaintextMaterialPlan,
    summary: TlsSessionSecretSummary,
) -> TlsPlaintextMaterialCheckSnapshot {
    TlsPlaintextMaterialCheckSnapshot {
        id: material.id.clone(),
        kind: material.kind,
        path: material.path.clone(),
        check: TlsPlaintextMaterialContentCheck::SessionSecretFile { summary },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionSecretCheckMode {
    Static,
    LiveAutoBinding,
}

fn session_secret_check_mode(
    materials: Option<TlsSessionSecretAutoBindingMaterials<'_>>,
) -> SessionSecretCheckMode {
    if materials.is_some_and(|materials| !materials.session_secrets().is_empty()) {
        SessionSecretCheckMode::LiveAutoBinding
    } else {
        SessionSecretCheckMode::Static
    }
}

fn check_live_auto_binding_materials(
    plan: TlsSessionSecretAutoBindingPlan<'_>,
    file_store: &impl TlsMaterialFileStore,
) -> Result<(), TlsCheckError> {
    let Some(materials) = plan.enabled_materials() else {
        return Ok(());
    };
    load_tls_session_secret_auto_binding_material(&materials.to_owned_materials(), file_store)
        .map(|_| ())
        .map_err(TlsCheckError::from)
}

fn pending_check_snapshot(
    material: &TlsPlaintextMaterialPlan,
    reason: TlsPlaintextMaterialPendingReason,
) -> TlsPlaintextMaterialCheckSnapshot {
    TlsPlaintextMaterialCheckSnapshot {
        id: material.id.clone(),
        kind: material.kind,
        path: material.path.clone(),
        check: TlsPlaintextMaterialContentCheck::Pending { reason },
    }
}

fn tls_material_is_empty(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

fn tls_plaintext_material_error(
    material: &TlsPlaintextMaterialPlan,
    source: impl std::fmt::Display,
) -> TlsCheckError {
    TlsCheckError::PlaintextMaterial {
        id: material.id.clone(),
        kind: material.kind,
        path: material.path.clone(),
        reason: source.to_string(),
    }
}

impl From<TlsDecryptHintError> for TlsCheckError {
    fn from(error: TlsDecryptHintError) -> Self {
        match error {
            TlsDecryptHintError::Material {
                id,
                kind,
                path,
                reason,
            } => Self::PlaintextMaterial {
                id,
                kind,
                path,
                reason,
            },
            TlsDecryptHintError::MaterialSet { reason } => Self::DecryptHints { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, TlsMaterialConfig, TlsMaterialKind,
    };
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};
    use serde_json::json;

    use super::*;
    use crate::check::{CheckError, build_check_report};

    #[tokio::test]
    async fn check_report_validates_tls_plaintext_material_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-tls-plaintext-materials")?;
        let key_log_path = temp.join("sslkeylog.log");
        let session_secret_path = temp.join("session-secret.bin");
        write_private_file(
            &key_log_path,
            b"CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\n",
        )?;
        let session_secret_material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{}","cipher_suite":"0x1301","secret":"{}"}}"#,
            "00".repeat(32),
            "aa".repeat(32)
        );
        write_private_file(&session_secret_path, session_secret_material)?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-keys".to_string()];
        config.tls.plaintext.decrypt_hints.session_secret_refs =
            vec!["session-secrets".to_string()];
        config.tls.materials.extend([
            TlsMaterialConfig {
                id: Some("ssl-keys".to_string()),
                kind: TlsMaterialKind::KeyLogFile,
                path: key_log_path,
            },
            TlsMaterialConfig {
                id: Some("session-secrets".to_string()),
                kind: TlsMaterialKind::SessionSecretFile,
                path: session_secret_path,
            },
        ]);
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        let value = serde_json::to_value(report)?;
        assert_eq!(
            value["tls"]["plaintext"]["instrumentation"]["enabled"],
            json!(false)
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["id"],
            json!("ssl-keys")
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["check"]["kind"],
            json!("ssl_key_log")
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["check"]["summary"]["entries"],
            json!(1)
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["check"]["summary"]["labels"]
                [0]["label"],
            json!("CLIENT_RANDOM")
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"][0]["check"]["kind"],
            json!("session_secret_file")
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"][0]["check"]["summary"]["entries"],
            json!(1)
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"][0]["check"]["summary"]["protocols"]
                [0]["protocol"],
            json!("tls13")
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"][0]["check"]["summary"]["secret_kinds"]
                [0]["secret_kind"],
            json!("client_application_traffic_secret")
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"][0]["check"]["summary"]["secret_min_bytes"],
            json!(32)
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_accepts_key_log_only_live_auto_binding_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-keylog-only-live-auto-binding")?;
        let key_log_path = temp.join("sslkeylog.log");
        write_private_file(
            &key_log_path,
            format!(
                "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                "00".repeat(32),
                "aa".repeat(32)
            ),
        )?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-keys".to_string()];
        config.tls.materials.push(TlsMaterialConfig {
            id: Some("ssl-keys".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: key_log_path,
        });
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        let value = serde_json::to_value(report)?;
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["check"]["summary"]["labels"]
                [0]["label"],
            json!("CLIENT_TRAFFIC_SECRET_0")
        );
        assert!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_ignores_live_key_log_trailing_partial_line()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-live-keylog-partial-tail")?;
        let key_log_path = temp.join("sslkeylog.log");
        write_private_file(
            &key_log_path,
            format!(
                "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_0 {} aa",
                "00".repeat(32),
                "aa".repeat(32),
                "11".repeat(32)
            ),
        )?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-keys".to_string()];
        config.tls.materials.push(TlsMaterialConfig {
            id: Some("ssl-keys".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: key_log_path,
        });
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        let value = serde_json::to_value(report)?;
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["check"]["summary"]["entries"],
            json!(1)
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["check"]["summary"]["labels"]
                [0]["label"],
            json!("CLIENT_TRAFFIC_SECRET_0")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_accepts_missing_live_key_log_as_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-missing-live-keylog")?;
        let mut config = AgentConfig::default();
        config.tls.material_store.filesystem.allowed_roots = vec![temp.clone()];
        config.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-keys".to_string()];
        config.tls.materials.push(TlsMaterialConfig {
            id: Some("ssl-keys".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: temp.join("sslkeylog.log"),
        });
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        let value = serde_json::to_value(report)?;
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["check"]["kind"],
            json!("pending")
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["key_logs"][0]["check"]["reason"],
            json!("not_found")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_accepts_missing_live_session_secret_as_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-missing-live-session-secret")?;
        let mut config = AgentConfig::default();
        config.tls.material_store.filesystem.allowed_roots = vec![temp.clone()];
        config.tls.plaintext.decrypt_hints.session_secret_refs =
            vec!["session-secrets".to_string()];
        config.tls.materials.push(TlsMaterialConfig {
            id: Some("session-secrets".to_string()),
            kind: TlsMaterialKind::SessionSecretFile,
            path: temp.join("session-secrets.jsonl"),
        });
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        let value = serde_json::to_value(report)?;
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"][0]["check"]["kind"],
            json!("pending")
        );
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"][0]["check"]["reason"],
            json!("not_found")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_reports_libssl_uprobe_runtime_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into());
        config.tls.plaintext.instrumentation.reconcile_interval_ms = 2_500;
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        let value = serde_json::to_value(report)?;
        assert_eq!(
            value["tls"]["plaintext"]["instrumentation"]["libssl_uprobe_object_path"],
            json!("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o")
        );
        assert_eq!(
            value["tls"]["plaintext"]["instrumentation"]["reconcile_interval_ms"],
            json!(2500)
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_invalid_tls_key_log_material_without_leaking_secret_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-invalid-tls-keylog")?;
        let key_log_path = temp.join("sslkeylog.log");
        write_private_file(
            &key_log_path,
            b"CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f not-a-secret\n",
        )?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-keys".to_string()];
        config.tls.materials.push(TlsMaterialConfig {
            id: Some("ssl-keys".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: key_log_path,
        });
        let plan = runtime_plan(config)?;

        let error = build_check_report(plan, None)
            .await
            .expect_err("invalid key log file must fail explicit check");

        assert!(matches!(
            error,
            CheckError::Tls(TlsCheckError::PlaintextMaterial { .. })
        ));
        assert!(error.to_string().contains("invalid hex in secret"));
        assert!(
            !error.to_string().contains("not-a-secret"),
            "check errors must not leak TLS secret field values"
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_invalid_tls_session_secret_material_without_leaking_secret_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-invalid-tls-session-secret")?;
        let session_secret_path = temp.join("session-secrets.jsonl");
        write_private_file(
            &session_secret_path,
            format!(
                r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{}","secret":"not-a-secret"}}"#,
                "00".repeat(32)
            ),
        )?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.session_secret_refs =
            vec!["session-secrets".to_string()];
        config.tls.materials.push(TlsMaterialConfig {
            id: Some("session-secrets".to_string()),
            kind: TlsMaterialKind::SessionSecretFile,
            path: session_secret_path,
        });
        let plan = runtime_plan(config)?;

        let error = build_check_report(plan, None)
            .await
            .expect_err("invalid session secret file must fail explicit check");

        assert!(matches!(
            error,
            CheckError::Tls(TlsCheckError::PlaintextMaterial { .. })
        ));
        assert!(error.to_string().contains("invalid hex in secret"));
        assert!(
            !error.to_string().contains("not-a-secret"),
            "check errors must not leak TLS secret field values"
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_overlapping_tls_session_secret_materials()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-overlapping-tls-session-secrets")?;
        let first_path = temp.join("session-secrets-a.jsonl");
        let second_path = temp.join("session-secrets-b.jsonl");
        write_private_file(
            &first_path,
            session_secret_material_with_window("00", "aa", 10, 30),
        )?;
        write_private_file(
            &second_path,
            session_secret_material_with_window("00", "bb", 20, 40),
        )?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.session_secret_refs = vec![
            "session-secrets-a".to_string(),
            "session-secrets-b".to_string(),
        ];
        config.tls.materials.extend([
            TlsMaterialConfig {
                id: Some("session-secrets-a".to_string()),
                kind: TlsMaterialKind::SessionSecretFile,
                path: first_path,
            },
            TlsMaterialConfig {
                id: Some("session-secrets-b".to_string()),
                kind: TlsMaterialKind::SessionSecretFile,
                path: second_path,
            },
        ]);
        let plan = runtime_plan(config)?;

        let error = build_check_report(plan, None)
            .await
            .expect_err("overlapping session secret material must fail explicit check");

        assert!(matches!(
            error,
            CheckError::Tls(TlsCheckError::DecryptHints { .. })
        ));
        assert!(
            error
                .to_string()
                .contains("overlapping TLS session secret records")
        );
        assert!(!error.to_string().contains(&"aa".repeat(32)));
        assert!(!error.to_string().contains(&"bb".repeat(32)));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_session_secret_refs_without_live_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-session-secret-without-live-material")?;
        let session_secret_path = temp.join("session-secrets.jsonl");
        write_private_file(
            &session_secret_path,
            format!(
                r#"{{"protocol":"tls12","secret_kind":"master_secret","client_random":"{}","secret":"{}"}}"#,
                "00".repeat(32),
                "bb".repeat(48),
            ),
        )?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.session_secret_refs =
            vec!["session-secrets".to_string()];
        config.tls.materials.push(TlsMaterialConfig {
            id: Some("session-secrets".to_string()),
            kind: TlsMaterialKind::SessionSecretFile,
            path: session_secret_path,
        });
        let plan = runtime_plan(config)?;

        let error = build_check_report(plan, None)
            .await
            .expect_err("session_secret_refs without live application material must fail check");

        assert!(matches!(
            error,
            CheckError::Tls(TlsCheckError::DecryptHints { .. })
        ));
        assert!(error.to_string().contains("session_secret_refs"));
        assert!(error.to_string().contains("usable by live auto-binding"));
        assert!(!error.to_string().contains(&"bb".repeat(48)));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_summarizes_session_secret_refs_when_auto_binding_is_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-plaintext-feed-session-secret-summary")?;
        let session_secret_path = temp.join("session-secrets.jsonl");
        write_private_file(
            &session_secret_path,
            format!(
                r#"{{"protocol":"tls12","secret_kind":"master_secret","client_random":"{}","secret":"{}"}}"#,
                "00".repeat(32),
                "bb".repeat(48),
            ),
        )?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(temp.join("feed.jsonl"));
        config.tls.plaintext.decrypt_hints.session_secret_refs =
            vec!["session-secrets".to_string()];
        config.tls.materials.push(TlsMaterialConfig {
            id: Some("session-secrets".to_string()),
            kind: TlsMaterialKind::SessionSecretFile,
            path: session_secret_path,
        });
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        let value = serde_json::to_value(report)?;
        assert_eq!(
            value["tls"]["plaintext"]["decrypt_hints"]["session_secrets"][0]["check"]["summary"]["protocols"]
                [0]["protocol"],
            json!("tls12")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(config, &runtime_registry())
    }

    fn runtime_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::available(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                ),
                CaptureProviderDescriptor::available(
                    CaptureBackend::PlaintextFeed,
                    CaptureProviderBuilder::PlaintextFeed,
                ),
                CaptureProviderDescriptor::available(
                    CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                ),
            ],
            vec![
                CapabilityState::available(CapabilityKind::Http1),
                CapabilityState::available(CapabilityKind::Sse),
                CapabilityState::available(CapabilityKind::WebSocketHandoff),
                CapabilityState::available(CapabilityKind::WebSocketFrame),
                CapabilityState::available(CapabilityKind::DryRunEnforcement),
            ],
        )
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), std::io::Error> {
        fs::write(path, contents)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }

    fn session_secret_material_with_window(
        client_random_byte: &str,
        secret_byte: &str,
        not_before_unix_ns: u64,
        not_after_unix_ns: u64,
    ) -> String {
        format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{}","cipher_suite":"0x1301","secret":"{}","not_before_unix_ns":{not_before_unix_ns},"not_after_unix_ns":{not_after_unix_ns}}}"#,
            client_random_byte.repeat(32),
            secret_byte.repeat(32),
        )
    }
}

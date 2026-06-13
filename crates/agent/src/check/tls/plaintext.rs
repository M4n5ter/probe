use std::path::PathBuf;

use capture::TlsKeyLogSummary;
use probe_config::{TlsMaterialKind, TlsPlaintextProvider};
use runtime::{RuntimePlan, TlsPlaintextMaterialPlan};
use serde::Serialize;
use thiserror::Error;

use crate::tls_material::{FilesystemTlsMaterialStore, TlsMaterialFileStore};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TlsCheckSnapshot {
    plaintext: TlsPlaintextCheckSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsPlaintextCheckSnapshot {
    enabled: bool,
    provider: TlsPlaintextProvider,
    libssl_uprobe_object_path: Option<PathBuf>,
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
    SslKeyLog { summary: TlsKeyLogSummary },
    ReservedSessionSecret { bytes: u64 },
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
}

pub(in crate::check) fn check_tls(plan: &RuntimePlan) -> Result<TlsCheckSnapshot, TlsCheckError> {
    check_tls_with_file_store(plan, &FilesystemTlsMaterialStore)
}

fn check_tls_with_file_store(
    plan: &RuntimePlan,
    file_store: &impl TlsMaterialFileStore,
) -> Result<TlsCheckSnapshot, TlsCheckError> {
    let plaintext = &plan.tls.plaintext;
    Ok(TlsCheckSnapshot {
        plaintext: TlsPlaintextCheckSnapshot {
            enabled: plaintext.enabled,
            provider: plaintext.provider,
            libssl_uprobe_object_path: plaintext.libssl_uprobe_object_path.clone(),
            key_logs: check_key_log_materials(&plaintext.key_logs, file_store)?,
            session_secrets: check_session_secret_materials(
                &plaintext.session_secrets,
                file_store,
            )?,
        },
    })
}

fn check_key_log_materials(
    materials: &[TlsPlaintextMaterialPlan],
    file_store: &impl TlsMaterialFileStore,
) -> Result<Vec<TlsPlaintextMaterialCheckSnapshot>, TlsCheckError> {
    materials
        .iter()
        .map(|material| {
            let bytes = read_plaintext_material(material, file_store)?;
            let summary = TlsKeyLogSummary::parse(&bytes)
                .map_err(|source| tls_plaintext_material_error(material, source))?;
            Ok(TlsPlaintextMaterialCheckSnapshot {
                id: material.id.clone(),
                kind: material.kind,
                path: material.path.clone(),
                check: TlsPlaintextMaterialContentCheck::SslKeyLog { summary },
            })
        })
        .collect()
}

fn check_session_secret_materials(
    materials: &[TlsPlaintextMaterialPlan],
    file_store: &impl TlsMaterialFileStore,
) -> Result<Vec<TlsPlaintextMaterialCheckSnapshot>, TlsCheckError> {
    materials
        .iter()
        .map(|material| {
            let bytes = read_plaintext_material(material, file_store)?;
            Ok(TlsPlaintextMaterialCheckSnapshot {
                id: material.id.clone(),
                kind: material.kind,
                path: material.path.clone(),
                check: TlsPlaintextMaterialContentCheck::ReservedSessionSecret {
                    bytes: bytes.len() as u64,
                },
            })
        })
        .collect()
}

fn read_plaintext_material(
    material: &TlsPlaintextMaterialPlan,
    file_store: &impl TlsMaterialFileStore,
) -> Result<Vec<u8>, TlsCheckError> {
    file_store
        .read_tls_material(&material.path)
        .map_err(|source| tls_plaintext_material_error(material, source))
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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use probe_config::{
        AgentConfig, CaptureBackend, TlsMaterialConfig, TlsMaterialKind, TlsPlaintextProvider,
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
        fs::write(
            &key_log_path,
            b"CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\n",
        )?;
        fs::write(&session_secret_path, b"reserved-session-secret")?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.provider = TlsPlaintextProvider::Keylog;
        config.tls.plaintext.key_log_refs = vec!["ssl-keys".to_string()];
        config.tls.plaintext.session_secret_refs = vec!["session-secrets".to_string()];
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
        assert_eq!(value["tls"]["plaintext"]["enabled"], json!(false));
        assert_eq!(value["tls"]["plaintext"]["provider"], json!("keylog"));
        assert_eq!(
            value["tls"]["plaintext"]["key_logs"][0]["id"],
            json!("ssl-keys")
        );
        assert_eq!(
            value["tls"]["plaintext"]["key_logs"][0]["check"]["kind"],
            json!("ssl_key_log")
        );
        assert_eq!(
            value["tls"]["plaintext"]["key_logs"][0]["check"]["summary"]["entries"],
            json!(1)
        );
        assert_eq!(
            value["tls"]["plaintext"]["key_logs"][0]["check"]["summary"]["labels"][0]["label"],
            json!("CLIENT_RANDOM")
        );
        assert_eq!(
            value["tls"]["plaintext"]["session_secrets"][0]["check"]["kind"],
            json!("reserved_session_secret")
        );
        assert_eq!(
            value["tls"]["plaintext"]["session_secrets"][0]["check"]["bytes"],
            json!(23)
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_report_reports_libssl_uprobe_object_path_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.tls.plaintext.libssl_uprobe_object_path =
            Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());
        let plan = runtime_plan(config)?;

        let report = build_check_report(plan, None).await?;

        let value = serde_json::to_value(report)?;
        assert_eq!(
            value["tls"]["plaintext"]["libssl_uprobe_object_path"],
            json!("/opt/sssa/ebpf-tls-plaintext.bpf.o")
        );
        Ok(())
    }

    #[tokio::test]
    async fn check_report_rejects_invalid_tls_key_log_material_without_leaking_secret_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-invalid-tls-keylog")?;
        let key_log_path = temp.join("sslkeylog.log");
        fs::write(
            &key_log_path,
            b"CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f not-a-secret\n",
        )?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.provider = TlsPlaintextProvider::Keylog;
        config.tls.plaintext.key_log_refs = vec!["ssl-keys".to_string()];
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

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(config, &runtime_registry())
    }

    fn runtime_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
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
}

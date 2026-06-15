use std::path::{Path, PathBuf};

use probe_config::TlsMaterialKind;
use probe_core::{CapabilityKind, CapabilityMatrix, RuntimeMode};
use runtime::{RuntimePlan, TlsPlaintextCapabilityPlan, TlsPlaintextMaterialPlan};
use serde::Serialize;

use crate::tls_material::{FilesystemTlsMaterialStore, TlsMaterialFileStore};
use crate::tls_plaintext::TlsPlaintextRuntimeSnapshot;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsStatusSnapshot {
    pub plaintext: TlsPlaintextStatusSnapshot,
    pub materials: Vec<TlsMaterialStatusSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextStatusSnapshot {
    pub instrumentation: TlsPlaintextInstrumentationStatusSnapshot,
    pub decrypt_hints: TlsDecryptHintStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextInstrumentationStatusSnapshot {
    pub enabled: bool,
    pub selector_configured: bool,
    pub libssl_uprobe_object_path: Option<PathBuf>,
    pub reconcile_interval_ms: u64,
    pub capability: TlsPlaintextCapabilityStatusSnapshot,
    pub runtime: Option<TlsPlaintextRuntimeSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsDecryptHintStatusSnapshot {
    pub key_logs: Vec<TlsPlaintextMaterialStatusSnapshot>,
    pub session_secrets: Vec<TlsPlaintextMaterialStatusSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TlsPlaintextCapabilityStatusSnapshot {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextMaterialStatusSnapshot {
    pub id: String,
    pub kind: TlsMaterialKind,
    pub path: PathBuf,
    pub source: TlsMaterialSourceStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsMaterialStatusSnapshot {
    pub kind: TlsMaterialKind,
    pub path: PathBuf,
    pub purpose: TlsMaterialPurpose,
    pub source: TlsMaterialSourceStatusSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMaterialPurpose {
    TrustOrIdentity,
    DecryptHint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsMaterialSourceStatusSnapshot {
    pub check: TlsMaterialSourceCheck,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMaterialSourceCheck {
    MetadataOnly,
}

pub(in crate::status) fn tls_status(
    plan: &RuntimePlan,
    capabilities: &CapabilityMatrix,
    runtime: Option<TlsPlaintextRuntimeSnapshot>,
) -> TlsStatusSnapshot {
    TlsStatusSnapshot {
        plaintext: plaintext_status(plan, capabilities, runtime),
        materials: plan
            .config
            .tls
            .materials
            .iter()
            .map(|material| TlsMaterialStatusSnapshot {
                kind: material.kind,
                path: material.path.clone(),
                purpose: material_purpose(material.kind),
                source: material_source_status(&material.path),
            })
            .collect(),
    }
}

fn plaintext_status(
    plan: &RuntimePlan,
    capabilities: &CapabilityMatrix,
    runtime: Option<TlsPlaintextRuntimeSnapshot>,
) -> TlsPlaintextStatusSnapshot {
    let plaintext = &plan.tls.plaintext;
    let instrumentation = &plaintext.instrumentation;
    let capability = match &instrumentation.capability {
        TlsPlaintextCapabilityPlan::NotRequired => {
            TlsPlaintextCapabilityStatusSnapshot::NotRequired
        }
        TlsPlaintextCapabilityPlan::Required { capability, .. } => {
            TlsPlaintextCapabilityStatusSnapshot::Required {
                capability: *capability,
                mode: capabilities.mode(*capability),
            }
        }
    };

    TlsPlaintextStatusSnapshot {
        instrumentation: TlsPlaintextInstrumentationStatusSnapshot {
            enabled: instrumentation.enabled,
            selector_configured: instrumentation.selector_configured,
            libssl_uprobe_object_path: instrumentation.libssl_uprobe_object_path.clone(),
            reconcile_interval_ms: instrumentation.reconcile_interval_ms,
            capability,
            runtime,
        },
        decrypt_hints: TlsDecryptHintStatusSnapshot {
            key_logs: plaintext_material_statuses(&plaintext.decrypt_hints.key_logs),
            session_secrets: plaintext_material_statuses(&plaintext.decrypt_hints.session_secrets),
        },
    }
}

fn plaintext_material_statuses(
    materials: &[TlsPlaintextMaterialPlan],
) -> Vec<TlsPlaintextMaterialStatusSnapshot> {
    materials
        .iter()
        .map(|material| TlsPlaintextMaterialStatusSnapshot {
            id: material.id.clone(),
            kind: material.kind,
            path: material.path.clone(),
            source: material_source_status(&material.path),
        })
        .collect()
}

fn material_purpose(kind: TlsMaterialKind) -> TlsMaterialPurpose {
    match kind {
        TlsMaterialKind::TrustAnchor
        | TlsMaterialKind::ClientCertificate
        | TlsMaterialKind::ClientPrivateKey => TlsMaterialPurpose::TrustOrIdentity,
        TlsMaterialKind::KeyLogFile | TlsMaterialKind::SessionSecretFile => {
            TlsMaterialPurpose::DecryptHint
        }
    }
}

pub(in crate::status) fn material_source_status(path: &Path) -> TlsMaterialSourceStatusSnapshot {
    let (mode, reason) = inspect_material_source(path, &FilesystemTlsMaterialStore);

    TlsMaterialSourceStatusSnapshot {
        check: TlsMaterialSourceCheck::MetadataOnly,
        mode,
        reason,
    }
}

fn inspect_material_source(
    path: &Path,
    file_store: &impl TlsMaterialFileStore,
) -> (RuntimeMode, Option<String>) {
    match file_store.inspect_tls_material(path) {
        Ok(()) => (RuntimeMode::Available, None),
        Err(error) => (RuntimeMode::Unavailable, Some(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode, Selector};
    use serde_json::json;

    use super::super::super::plan_fixture::{
        config_with_storage_path, runtime_plan_from_config, test_dir,
    };
    use super::*;

    #[test]
    fn tls_status_reports_metadata_only_materials() -> Result<(), Box<dyn std::error::Error>> {
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

        let status = tls_status(&plan, &plan.capabilities, None);

        assert_eq!(status.materials.len(), 1);
        let material = &status.materials[0];
        assert_eq!(material.path, material_path);
        assert_eq!(material.purpose, TlsMaterialPurpose::TrustOrIdentity);
        assert_eq!(material.source.mode, RuntimeMode::Available);
        assert_eq!(material.source.check, TlsMaterialSourceCheck::MetadataOnly);
        let value = serde_json::to_value(&status)?;
        assert_eq!(
            value["materials"][0]["source"]["check"],
            json!("metadata_only")
        );
        assert_eq!(value["materials"][0]["purpose"], json!("trust_or_identity"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn tls_status_reports_plaintext_capability() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-tls-plaintext-capability")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.capture.selection = probe_config::CaptureSelection::Libpcap;
        config.tls.plaintext.instrumentation.enabled = true;
        config.tls.plaintext.instrumentation.selector = Some(Selector::default());
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());
        config.tls.plaintext.instrumentation.reconcile_interval_ms = 2_500;
        let plan = runtime_plan_from_config(
            config,
            vec![CapabilityState::available(CapabilityKind::LibsslUprobe)],
        )?;

        let status = tls_status(&plan, &plan.capabilities, None);

        let instrumentation = &status.plaintext.instrumentation;
        assert!(instrumentation.enabled);
        assert!(instrumentation.selector_configured);
        assert_eq!(
            instrumentation.libssl_uprobe_object_path,
            Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into())
        );
        assert_eq!(instrumentation.reconcile_interval_ms, 2_500);
        assert_eq!(
            instrumentation.capability,
            TlsPlaintextCapabilityStatusSnapshot::Required {
                capability: CapabilityKind::LibsslUprobe,
                mode: RuntimeMode::Available,
            }
        );
        assert!(status.plaintext.decrypt_hints.key_logs.is_empty());
        assert!(status.plaintext.decrypt_hints.session_secrets.is_empty());
        let value = serde_json::to_value(&status)?;
        assert_eq!(
            value["plaintext"]["instrumentation"]["capability"]["kind"],
            json!("required")
        );
        assert_eq!(
            value["plaintext"]["instrumentation"]["capability"]["capability"],
            json!("libssl_uprobe")
        );
        assert_eq!(
            value["plaintext"]["instrumentation"]["libssl_uprobe_object_path"],
            json!("/opt/sssa/ebpf-tls-plaintext.bpf.o")
        );
        assert_eq!(
            value["plaintext"]["instrumentation"]["reconcile_interval_ms"],
            json!(2500)
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn tls_status_reports_configured_plaintext_material_refs()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-tls-plaintext-materials")?;
        let key_log_path = temp.join("sslkeylog.log");
        let session_secret_path = temp.join("session-secrets.jsonl");
        fs::write(&key_log_path, b"client random")?;
        fs::write(&session_secret_path, b"{\"secret\":\"test\"}\n")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-keys".to_string()];
        config.tls.plaintext.decrypt_hints.session_secret_refs =
            vec!["session-secrets".to_string()];
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

        let status = tls_status(&plan, &plan.capabilities, None);

        assert_eq!(
            status.plaintext.instrumentation.capability,
            TlsPlaintextCapabilityStatusSnapshot::NotRequired
        );
        let hints = &status.plaintext.decrypt_hints;
        assert_eq!(hints.key_logs.len(), 1);
        assert_eq!(hints.key_logs[0].id, "ssl-keys");
        assert_eq!(
            hints.key_logs[0].kind,
            probe_config::TlsMaterialKind::KeyLogFile
        );
        assert_eq!(hints.key_logs[0].path, key_log_path);
        assert_eq!(hints.key_logs[0].source.mode, RuntimeMode::Available);
        assert_eq!(hints.session_secrets.len(), 1);
        assert_eq!(hints.session_secrets[0].id, "session-secrets");
        assert_eq!(hints.session_secrets[0].path, session_secret_path);
        assert_eq!(
            hints.session_secrets[0].source.check,
            TlsMaterialSourceCheck::MetadataOnly
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn tls_status_reports_missing_decrypt_hint_without_changing_health()
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

        let status = tls_status(&plan, &plan.capabilities, None);

        let material = &status.materials[0];
        assert_eq!(material.purpose, TlsMaterialPurpose::DecryptHint);
        assert_eq!(material.source.mode, RuntimeMode::Unavailable);
        assert!(
            material
                .source
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("does not exist"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }
}

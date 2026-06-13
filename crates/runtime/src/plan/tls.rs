use std::{collections::BTreeMap, path::PathBuf};

use probe_config::{AgentConfig, TlsMaterialConfig, TlsMaterialKind, TlsPlaintextProvider};
use probe_core::{CapabilityKind, CapabilityMatrix, RuntimeMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPlan {
    pub plaintext: TlsPlaintextPlan,
}

impl TlsPlan {
    pub(super) fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        Self {
            plaintext: TlsPlaintextPlan::resolve(config, capabilities),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPlaintextPlan {
    pub enabled: bool,
    pub provider: TlsPlaintextProvider,
    pub selector_configured: bool,
    pub libssl_uprobe_object_path: Option<PathBuf>,
    pub capability: TlsPlaintextCapabilityPlan,
    pub key_logs: Vec<TlsPlaintextMaterialPlan>,
    pub session_secrets: Vec<TlsPlaintextMaterialPlan>,
}

impl TlsPlaintextPlan {
    fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        let materials_by_id = tls_plaintext_materials_by_id(&config.tls.materials);
        Self {
            enabled: config.tls.plaintext.enabled,
            provider: config.tls.plaintext.provider,
            selector_configured: config.tls.plaintext.selector.is_some(),
            libssl_uprobe_object_path: config.tls.plaintext.libssl_uprobe_object_path.clone(),
            capability: TlsPlaintextCapabilityPlan::from_config(config, capabilities),
            key_logs: tls_plaintext_materials_from_refs(
                &config.tls.plaintext.key_log_refs,
                TlsMaterialKind::KeyLogFile,
                &materials_by_id,
            ),
            session_secrets: tls_plaintext_materials_from_refs(
                &config.tls.plaintext.session_secret_refs,
                TlsMaterialKind::SessionSecretFile,
                &materials_by_id,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TlsPlaintextCapabilityPlan {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
    },
}

impl TlsPlaintextCapabilityPlan {
    fn from_config(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        if !config.tls.plaintext.enabled {
            return Self::NotRequired;
        }
        match config.tls.plaintext.provider {
            TlsPlaintextProvider::LibsslUprobe => Self::Required {
                capability: CapabilityKind::LibsslUprobe,
                mode: capabilities.mode(CapabilityKind::LibsslUprobe),
            },
            TlsPlaintextProvider::Keylog => {
                unreachable!("runtime validation rejects keylog plaintext provider before planning")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsMaterialPlan {
    pub id: String,
    pub kind: TlsMaterialKind,
    pub path: PathBuf,
}

pub type TlsPlaintextMaterialPlan = TlsMaterialPlan;
pub type ExportTlsMaterialPlan = TlsMaterialPlan;

pub(super) fn export_tls_materials_by_id(
    materials: &[TlsMaterialConfig],
) -> BTreeMap<&str, ExportTlsMaterialPlan> {
    tls_materials_by_id(materials, is_export_tls_material)
}

fn tls_plaintext_materials_by_id(
    materials: &[TlsMaterialConfig],
) -> BTreeMap<&str, TlsPlaintextMaterialPlan> {
    tls_materials_by_id(materials, is_plaintext_tls_material)
}

fn tls_materials_by_id(
    materials: &[TlsMaterialConfig],
    include: impl Fn(TlsMaterialKind) -> bool,
) -> BTreeMap<&str, TlsMaterialPlan> {
    materials
        .iter()
        .filter_map(|material| {
            let id = material.id.as_deref()?;
            include(material.kind).then(|| {
                (
                    id,
                    TlsMaterialPlan {
                        id: id.to_string(),
                        kind: material.kind,
                        path: material.path.clone(),
                    },
                )
            })
        })
        .collect()
}

fn is_export_tls_material(kind: TlsMaterialKind) -> bool {
    matches!(
        kind,
        TlsMaterialKind::TrustAnchor
            | TlsMaterialKind::ClientCertificate
            | TlsMaterialKind::ClientPrivateKey
    )
}

fn is_plaintext_tls_material(kind: TlsMaterialKind) -> bool {
    matches!(
        kind,
        TlsMaterialKind::KeyLogFile | TlsMaterialKind::SessionSecretFile
    )
}

fn tls_plaintext_materials_from_refs(
    refs: &[String],
    expected_kind: TlsMaterialKind,
    materials_by_id: &BTreeMap<&str, TlsPlaintextMaterialPlan>,
) -> Vec<TlsPlaintextMaterialPlan> {
    refs.iter()
        .filter_map(|reference| materials_by_id.get(reference.as_str()))
        .filter(|material| material.kind == expected_kind)
        .cloned()
        .collect()
}

use std::{collections::BTreeMap, path::PathBuf};

use probe_config::{AgentConfig, TlsMaterialConfig, TlsMaterialKind};
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TlsMaterialStorePlan {
    #[default]
    Unrestricted,
    FilesystemRoots {
        allowed_roots: Vec<PathBuf>,
    },
}

impl TlsMaterialStorePlan {
    pub(super) fn resolve(config: &AgentConfig) -> Self {
        let allowed_roots = config.tls.material_store.filesystem.allowed_roots.clone();
        if allowed_roots.is_empty() {
            Self::Unrestricted
        } else {
            Self::FilesystemRoots { allowed_roots }
        }
    }

    pub fn allowed_roots(&self) -> &[PathBuf] {
        match self {
            Self::Unrestricted => &[],
            Self::FilesystemRoots { allowed_roots } => allowed_roots,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPlaintextPlan {
    pub instrumentation: TlsPlaintextInstrumentationPlan,
    pub decrypt_hints: TlsDecryptHintPlan,
}

impl TlsPlaintextPlan {
    fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        Self {
            instrumentation: TlsPlaintextInstrumentationPlan::resolve(config, capabilities),
            decrypt_hints: TlsDecryptHintPlan::resolve(config),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPlaintextInstrumentationPlan {
    pub enabled: bool,
    pub selector_configured: bool,
    pub libssl_uprobe_object_path: Option<PathBuf>,
    pub reconcile_interval_ms: u64,
    pub capability: TlsPlaintextCapabilityPlan,
}

impl TlsPlaintextInstrumentationPlan {
    fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        Self {
            enabled: config.tls.plaintext.instrumentation.enabled,
            selector_configured: config.tls.plaintext.instrumentation.selector.is_some(),
            libssl_uprobe_object_path: config
                .tls
                .plaintext
                .instrumentation
                .libssl_uprobe_object_path
                .clone(),
            reconcile_interval_ms: config.tls.plaintext.instrumentation.reconcile_interval_ms,
            capability: TlsPlaintextCapabilityPlan::from_config(config, capabilities),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsDecryptHintPlan {
    pub key_logs: Vec<TlsPlaintextMaterialPlan>,
    pub session_secrets: Vec<TlsPlaintextMaterialPlan>,
    pub refresh_interval_ms: u64,
}

impl TlsDecryptHintPlan {
    fn resolve(config: &AgentConfig) -> Self {
        let materials_by_id = tls_plaintext_materials_by_id(&config.tls.materials);
        Self {
            key_logs: tls_plaintext_materials_from_refs(
                &config.tls.plaintext.decrypt_hints.key_log_refs,
                TlsMaterialKind::KeyLogFile,
                &materials_by_id,
            ),
            session_secrets: tls_plaintext_materials_from_refs(
                &config.tls.plaintext.decrypt_hints.session_secret_refs,
                TlsMaterialKind::SessionSecretFile,
                &materials_by_id,
            ),
            refresh_interval_ms: config.tls.plaintext.decrypt_hints.refresh_interval_ms,
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
        if !config.tls.plaintext.instrumentation.enabled {
            return Self::NotRequired;
        }
        Self::Required {
            capability: CapabilityKind::LibsslUprobe,
            mode: capabilities.mode(CapabilityKind::LibsslUprobe),
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
pub type MitmTlsMaterialPlan = TlsMaterialPlan;

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

pub(super) fn mitm_tls_materials_by_id(
    materials: &[TlsMaterialConfig],
) -> BTreeMap<&str, MitmTlsMaterialPlan> {
    tls_materials_by_id(materials, is_mitm_tls_material)
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

fn is_mitm_tls_material(kind: TlsMaterialKind) -> bool {
    matches!(
        kind,
        TlsMaterialKind::MitmCaCertificate
            | TlsMaterialKind::MitmCaPrivateKey
            | TlsMaterialKind::MitmLeafCertificate
            | TlsMaterialKind::MitmLeafPrivateKey
            | TlsMaterialKind::MitmUpstreamTrustAnchor
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

pub(super) fn mitm_tls_material_from_ref(
    reference: &str,
    expected_kind: TlsMaterialKind,
    materials_by_id: &BTreeMap<&str, MitmTlsMaterialPlan>,
) -> Option<MitmTlsMaterialPlan> {
    materials_by_id
        .get(reference)
        .filter(|material| material.kind == expected_kind)
        .cloned()
}

pub(super) fn mitm_tls_materials_from_refs(
    refs: &[String],
    expected_kind: TlsMaterialKind,
    materials_by_id: &BTreeMap<&str, MitmTlsMaterialPlan>,
) -> Vec<MitmTlsMaterialPlan> {
    refs.iter()
        .filter_map(|reference| {
            mitm_tls_material_from_ref(reference, expected_kind, materials_by_id)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use probe_core::{CapabilityState, Selector};

    use super::*;

    #[test]
    fn tls_plaintext_plan_preserves_selector_and_capability_requirement() {
        let mut config = AgentConfig::default();
        config.tls.plaintext.instrumentation.enabled = true;
        config.tls.plaintext.instrumentation.selector = Some(Selector::default());
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into());
        config.tls.plaintext.instrumentation.reconcile_interval_ms = 2500;
        let capabilities = capability_matrix_with_libssl(RuntimeMode::Available);

        let plan = TlsPlan::resolve(&config, &capabilities);

        assert!(plan.plaintext.instrumentation.enabled);
        assert!(plan.plaintext.instrumentation.selector_configured);
        assert_eq!(
            plan.plaintext.instrumentation.libssl_uprobe_object_path,
            Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into())
        );
        assert_eq!(plan.plaintext.instrumentation.reconcile_interval_ms, 2500);
        assert_eq!(
            plan.plaintext.instrumentation.capability,
            TlsPlaintextCapabilityPlan::Required {
                capability: CapabilityKind::LibsslUprobe,
                mode: RuntimeMode::Available,
            }
        );
        assert!(plan.plaintext.decrypt_hints.key_logs.is_empty());
        assert!(plan.plaintext.decrypt_hints.session_secrets.is_empty());
    }

    #[test]
    fn tls_material_store_plan_resolves_filesystem_roots() {
        let mut config = AgentConfig::default();
        config.tls.material_store.filesystem.allowed_roots = vec!["/etc/traffic-probe/tls".into()];

        let plan = TlsMaterialStorePlan::resolve(&config);

        assert_eq!(
            plan,
            TlsMaterialStorePlan::FilesystemRoots {
                allowed_roots: vec![PathBuf::from("/etc/traffic-probe/tls")]
            }
        );
        assert_eq!(
            plan.allowed_roots(),
            &[PathBuf::from("/etc/traffic-probe/tls")]
        );
    }

    #[test]
    fn tls_material_store_plan_defaults_to_unrestricted() {
        let plan = TlsMaterialStorePlan::resolve(&AgentConfig::default());

        assert_eq!(plan, TlsMaterialStorePlan::Unrestricted);
        assert!(plan.allowed_roots().is_empty());
    }

    #[test]
    fn tls_plaintext_plan_allows_degraded_libssl_capability_for_best_effort_instrumentation() {
        let mut config = AgentConfig::default();
        config.tls.plaintext.instrumentation.enabled = true;
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into());
        let capabilities = capability_matrix_with_libssl(RuntimeMode::Degraded);

        let plan = TlsPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.plaintext.instrumentation.capability,
            TlsPlaintextCapabilityPlan::Required {
                capability: CapabilityKind::LibsslUprobe,
                mode: RuntimeMode::Degraded,
            }
        );
    }

    #[test]
    fn tls_plaintext_plan_resolves_decrypt_hint_material_refs() {
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-keys".to_string()];
        config.tls.plaintext.decrypt_hints.session_secret_refs =
            vec!["session-secrets".to_string()];
        config.tls.plaintext.decrypt_hints.refresh_interval_ms = 250;
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("ssl-keys".to_string()),
                kind: TlsMaterialKind::KeyLogFile,
                path: "/tmp/sslkeylog.log".into(),
            },
            TlsMaterialConfig {
                id: Some("session-secrets".to_string()),
                kind: TlsMaterialKind::SessionSecretFile,
                path: "/tmp/session-secrets.jsonl".into(),
            },
        ];
        let capabilities = capability_matrix_with_libssl(RuntimeMode::Unavailable);

        let plan = TlsPlan::resolve(&config, &capabilities);

        assert_eq!(
            plan.plaintext.instrumentation.capability,
            TlsPlaintextCapabilityPlan::NotRequired
        );
        assert_eq!(
            plan.plaintext.decrypt_hints.key_logs,
            vec![TlsPlaintextMaterialPlan {
                id: "ssl-keys".to_string(),
                kind: TlsMaterialKind::KeyLogFile,
                path: "/tmp/sslkeylog.log".into(),
            }]
        );
        assert_eq!(
            plan.plaintext.decrypt_hints.session_secrets,
            vec![TlsPlaintextMaterialPlan {
                id: "session-secrets".to_string(),
                kind: TlsMaterialKind::SessionSecretFile,
                path: "/tmp/session-secrets.jsonl".into(),
            }]
        );
        assert_eq!(plan.plaintext.decrypt_hints.refresh_interval_ms, 250);
    }

    fn capability_matrix_with_libssl(mode: RuntimeMode) -> CapabilityMatrix {
        CapabilityMatrix::new([
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            match mode {
                RuntimeMode::Available => CapabilityState::available(CapabilityKind::LibsslUprobe),
                RuntimeMode::Degraded => {
                    CapabilityState::degraded(CapabilityKind::LibsslUprobe, "degraded")
                }
                RuntimeMode::Unavailable => {
                    CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built")
                }
            },
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
        ])
    }
}

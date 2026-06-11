use std::{
    fs,
    path::{Path, PathBuf},
};

use probe_config::{TlsMaterialKind, TlsPlaintextProvider};
use probe_core::{CapabilityKind, RuntimeMode};
use runtime::RuntimePlan;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsStatusSnapshot {
    pub plaintext: TlsPlaintextStatusSnapshot,
    pub materials: Vec<TlsMaterialStatusSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextStatusSnapshot {
    pub enabled: bool,
    pub provider: TlsPlaintextProvider,
    pub capability: TlsPlaintextCapabilityStatusSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TlsPlaintextCapabilityStatusSnapshot {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
    },
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

pub(super) fn tls_status(plan: &RuntimePlan) -> TlsStatusSnapshot {
    TlsStatusSnapshot {
        plaintext: plaintext_status(plan),
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

fn plaintext_status(plan: &RuntimePlan) -> TlsPlaintextStatusSnapshot {
    let plaintext = &plan.config.tls.plaintext;
    let capability = if !plaintext.enabled {
        TlsPlaintextCapabilityStatusSnapshot::NotRequired
    } else {
        match plaintext.provider {
            TlsPlaintextProvider::LibsslUprobe => TlsPlaintextCapabilityStatusSnapshot::Required {
                capability: CapabilityKind::LibsslUprobe,
                mode: plan.capabilities.mode(CapabilityKind::LibsslUprobe),
            },
            TlsPlaintextProvider::Keylog => {
                unreachable!("runtime plan validation rejects keylog plaintext provider")
            }
        }
    };

    TlsPlaintextStatusSnapshot {
        enabled: plaintext.enabled,
        provider: plaintext.provider,
        capability,
    }
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

fn material_source_status(path: &Path) -> TlsMaterialSourceStatusSnapshot {
    let (mode, reason) = inspect_material_source(path);

    TlsMaterialSourceStatusSnapshot {
        check: TlsMaterialSourceCheck::MetadataOnly,
        mode,
        reason,
    }
}

fn inspect_material_source(path: &Path) -> (RuntimeMode, Option<String>) {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => (RuntimeMode::Available, None),
        Ok(metadata) if metadata.is_dir() => (
            RuntimeMode::Unavailable,
            Some("TLS material path is a directory".to_string()),
        ),
        Ok(_) => (
            RuntimeMode::Unavailable,
            Some("TLS material path is not a regular file".to_string()),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            RuntimeMode::Unavailable,
            Some("TLS material path does not exist".to_string()),
        ),
        Err(error) => (
            RuntimeMode::Unavailable,
            Some(format!("failed to inspect TLS material: {error}")),
        ),
    }
}

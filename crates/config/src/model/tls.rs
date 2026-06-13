use std::path::PathBuf;

use probe_core::Selector;
use serde::{Deserialize, Serialize};

pub const DEFAULT_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS: u64 = 1_000;
pub const MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS: u64 = 3_600_000;

fn default_tls_plaintext_reconcile_interval_ms() -> u64 {
    DEFAULT_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub plaintext: PlaintextTlsConfig,
    pub materials: Vec<TlsMaterialConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlaintextTlsConfig {
    pub enabled: bool,
    pub provider: TlsPlaintextProvider,
    pub selector: Option<Selector>,
    pub libssl_uprobe_object_path: Option<PathBuf>,
    #[serde(default = "default_tls_plaintext_reconcile_interval_ms")]
    pub reconcile_interval_ms: u64,
    pub key_log_refs: Vec<String>,
    pub session_secret_refs: Vec<String>,
}

impl Default for PlaintextTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: TlsPlaintextProvider::LibsslUprobe,
            selector: None,
            libssl_uprobe_object_path: None,
            reconcile_interval_ms: DEFAULT_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS,
            key_log_refs: Vec::new(),
            session_secret_refs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPlaintextProvider {
    LibsslUprobe,
    Keylog,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsMaterialConfig {
    pub id: Option<String>,
    pub kind: TlsMaterialKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMaterialKind {
    TrustAnchor,
    ClientCertificate,
    ClientPrivateKey,
    KeyLogFile,
    SessionSecretFile,
}

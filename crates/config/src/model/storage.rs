use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub ingress_retention_bytes: Option<u64>,
    pub export_retention_bytes: Option<u64>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/sssa-probe/spool"),
            ingress_retention_bytes: None,
            export_retention_bytes: None,
        }
    }
}

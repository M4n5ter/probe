use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::paths::default_storage_path;

pub const DEFAULT_INGRESS_RETENTION_PRUNE_BATCH_LIMIT: u64 = 1024;
pub const DEFAULT_INGRESS_RETENTION_SWEEP_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_EXPORT_RETENTION_PRUNE_BATCH_LIMIT: u64 = 1024;
pub const DEFAULT_EXPORT_RETENTION_SWEEP_INTERVAL_MS: u64 = 1_000;

fn default_ingress_retention_prune_batch_limit() -> u64 {
    DEFAULT_INGRESS_RETENTION_PRUNE_BATCH_LIMIT
}

fn default_ingress_retention_sweep_interval_ms() -> u64 {
    DEFAULT_INGRESS_RETENTION_SWEEP_INTERVAL_MS
}

fn default_export_retention_prune_batch_limit() -> u64 {
    DEFAULT_EXPORT_RETENTION_PRUNE_BATCH_LIMIT
}

fn default_export_retention_sweep_interval_ms() -> u64 {
    DEFAULT_EXPORT_RETENTION_SWEEP_INTERVAL_MS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub retention: StorageRetentionConfig,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: default_storage_path(),
            retention: StorageRetentionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageRetentionConfig {
    pub ingress: IngressJournalRetentionConfig,
    pub export: ExportQueueRetentionConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IngressJournalRetentionConfig {
    pub max_age_ms: Option<u64>,
    pub max_records: Option<u64>,
    #[serde(default = "default_ingress_retention_sweep_interval_ms")]
    pub sweep_interval_ms: u64,
    #[serde(default = "default_ingress_retention_prune_batch_limit")]
    pub prune_batch_limit: u64,
}

impl Default for IngressJournalRetentionConfig {
    fn default() -> Self {
        Self {
            max_age_ms: None,
            max_records: None,
            sweep_interval_ms: DEFAULT_INGRESS_RETENTION_SWEEP_INTERVAL_MS,
            prune_batch_limit: DEFAULT_INGRESS_RETENTION_PRUNE_BATCH_LIMIT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExportQueueRetentionConfig {
    pub max_age_ms: Option<u64>,
    pub max_records: Option<u64>,
    #[serde(default = "default_export_retention_sweep_interval_ms")]
    pub sweep_interval_ms: u64,
    #[serde(default = "default_export_retention_prune_batch_limit")]
    pub prune_batch_limit: u64,
}

impl Default for ExportQueueRetentionConfig {
    fn default() -> Self {
        Self {
            max_age_ms: None,
            max_records: None,
            sweep_interval_ms: DEFAULT_EXPORT_RETENTION_SWEEP_INTERVAL_MS,
            prune_batch_limit: DEFAULT_EXPORT_RETENTION_PRUNE_BATCH_LIMIT,
        }
    }
}

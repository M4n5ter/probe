use std::num::NonZeroU64;

use probe_config::{AgentConfig, StorageRetentionConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePlan {
    pub retention: StorageRetentionPlan,
}

impl StoragePlan {
    pub(super) fn resolve(config: &AgentConfig) -> Self {
        Self {
            retention: StorageRetentionPlan::from_config(&config.storage.retention),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRetentionPlan {
    pub ingress: IngressRetentionPlan,
    pub export: ExportRetentionPlan,
}

impl StorageRetentionPlan {
    fn from_config(config: &StorageRetentionConfig) -> Self {
        Self {
            ingress: IngressRetentionPlan::from_config(config),
            export: ExportRetentionPlan::from_config(config),
        }
    }
}

impl Default for StorageRetentionPlan {
    fn default() -> Self {
        Self::from_config(&StorageRetentionConfig::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressRetentionPlan {
    pub max_age_ms: Option<u64>,
    pub sweep_interval_ms: NonZeroU64,
    pub prune_batch_limit: NonZeroU64,
}

impl IngressRetentionPlan {
    fn from_config(config: &StorageRetentionConfig) -> Self {
        Self {
            max_age_ms: config.ingress.max_age_ms,
            sweep_interval_ms: NonZeroU64::new(config.ingress.sweep_interval_ms)
                .unwrap_or(NonZeroU64::MIN),
            prune_batch_limit: NonZeroU64::new(config.ingress.prune_batch_limit)
                .unwrap_or(NonZeroU64::MIN),
        }
    }

    pub fn enabled(&self) -> bool {
        self.max_age_ms.is_some()
    }
}

impl Default for IngressRetentionPlan {
    fn default() -> Self {
        Self::from_config(&StorageRetentionConfig::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRetentionPlan {
    pub max_age_ms: Option<u64>,
    pub sweep_interval_ms: NonZeroU64,
    pub prune_batch_limit: NonZeroU64,
}

impl ExportRetentionPlan {
    fn from_config(config: &StorageRetentionConfig) -> Self {
        Self {
            max_age_ms: config.export.max_age_ms,
            sweep_interval_ms: NonZeroU64::new(config.export.sweep_interval_ms)
                .unwrap_or(NonZeroU64::MIN),
            prune_batch_limit: NonZeroU64::new(config.export.prune_batch_limit)
                .unwrap_or(NonZeroU64::MIN),
        }
    }

    pub fn enabled(&self) -> bool {
        self.max_age_ms.is_some()
    }
}

impl Default for ExportRetentionPlan {
    fn default() -> Self {
        Self::from_config(&StorageRetentionConfig::default())
    }
}

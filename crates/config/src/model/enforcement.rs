use std::path::PathBuf;

use probe_core::{EnforcementMode, ProtectiveActionProfile, Selector};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementConfig {
    pub mode: EnforcementMode,
    pub selector: Option<Selector>,
    pub policy: EnforcementPolicyConfig,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::AuditOnly,
            selector: None,
            policy: EnforcementPolicyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementPolicyConfig {
    pub source: EnforcementPolicySourceConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum EnforcementPolicySourceConfig {
    #[default]
    None,
    File {
        path: PathBuf,
    },
    Directory {
        path: PathBuf,
    },
    Remote {
        endpoint: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementPolicyManifest {
    pub id: String,
    pub version: String,
    pub selector: Option<Selector>,
    pub protective_actions: ProtectiveActionProfile,
}

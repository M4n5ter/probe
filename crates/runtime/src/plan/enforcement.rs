use std::path::PathBuf;

use probe_config::{AgentConfig, EnforcementPolicySourceConfig};
use probe_core::{CapabilityKind, CapabilityMatrix, EnforcementMode, RuntimeMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPlan {
    pub mode: EnforcementMode,
    pub capability: EnforcementCapabilityPlan,
    pub config_selector_configured: bool,
    pub policy_source: EnforcementPolicySourcePlan,
}

impl EnforcementPlan {
    pub fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        Self {
            mode: config.enforcement.mode,
            capability: EnforcementCapabilityPlan::from_mode(config.enforcement.mode, capabilities),
            config_selector_configured: config.enforcement.selector.is_some(),
            policy_source: EnforcementPolicySourcePlan::from_config(
                &config.enforcement.policy.source,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementCapabilityPlan {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
    },
}

impl EnforcementCapabilityPlan {
    pub(super) fn requirement_for_mode(
        mode: EnforcementMode,
    ) -> Option<EnforcementCapabilityRequirement> {
        match mode {
            EnforcementMode::Disabled | EnforcementMode::AuditOnly => None,
            EnforcementMode::DryRun => Some(EnforcementCapabilityRequirement {
                capability: CapabilityKind::DryRunEnforcement,
                unavailable_reason: "dry-run enforcement provider is not available in this build/runtime",
            }),
            EnforcementMode::Enforce => Some(EnforcementCapabilityRequirement {
                capability: CapabilityKind::ConnectionEnforcement,
                unavailable_reason: "connection-level enforcement backend is not available in this build/runtime",
            }),
        }
    }

    fn from_mode(mode: EnforcementMode, capabilities: &CapabilityMatrix) -> Self {
        Self::requirement_for_mode(mode).map_or(Self::NotRequired, |requirement| {
            Self::required(
                requirement.capability,
                capabilities.mode(requirement.capability),
            )
        })
    }

    fn required(capability: CapabilityKind, mode: RuntimeMode) -> Self {
        Self::Required { capability, mode }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EnforcementCapabilityRequirement {
    pub(super) capability: CapabilityKind,
    pub(super) unavailable_reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementPolicySourcePlan {
    None,
    LocalManifest {
        source_kind: EnforcementPolicySourceKind,
        path: PathBuf,
    },
    Remote {
        endpoint: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPolicySourceKind {
    File,
    Directory,
}

impl EnforcementPolicySourcePlan {
    fn from_config(source: &EnforcementPolicySourceConfig) -> Self {
        match source {
            EnforcementPolicySourceConfig::None => Self::None,
            EnforcementPolicySourceConfig::File { path } => Self::LocalManifest {
                source_kind: EnforcementPolicySourceKind::File,
                path: path.clone(),
            },
            EnforcementPolicySourceConfig::Directory { path } => Self::LocalManifest {
                source_kind: EnforcementPolicySourceKind::Directory,
                path: path.join("manifest.toml"),
            },
            EnforcementPolicySourceConfig::Remote { endpoint } => Self::Remote {
                endpoint: endpoint.clone(),
            },
        }
    }
}

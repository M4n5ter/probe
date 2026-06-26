use std::path::PathBuf;

use probe_config::{EnforcementPolicySourceConfig, RemoteEnforcementPolicyBodyLimitBytes};
use serde::{Deserialize, Serialize};

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
        max_body_bytes: RemoteEnforcementPolicyBodyLimitBytes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPolicySourceKind {
    File,
    Directory,
}

impl EnforcementPolicySourcePlan {
    pub(super) fn from_config(source: &EnforcementPolicySourceConfig) -> Self {
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
            EnforcementPolicySourceConfig::Remote {
                endpoint,
                max_body_bytes,
            } => Self::Remote {
                endpoint: endpoint.clone(),
                max_body_bytes: RemoteEnforcementPolicyBodyLimitBytes::from_config(*max_body_bytes)
                    .expect("validated remote enforcement policy body limit must be in range"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use probe_config::DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES;

    use super::*;

    #[test]
    fn policy_source_plan_resolves_local_manifest_paths() {
        assert_eq!(
            EnforcementPolicySourcePlan::from_config(&EnforcementPolicySourceConfig::File {
                path: "/etc/traffic-probe/enforcement.toml".into(),
            }),
            EnforcementPolicySourcePlan::LocalManifest {
                source_kind: EnforcementPolicySourceKind::File,
                path: "/etc/traffic-probe/enforcement.toml".into(),
            }
        );
        assert_eq!(
            EnforcementPolicySourcePlan::from_config(&EnforcementPolicySourceConfig::Directory {
                path: "/etc/traffic-probe/enforcement.d".into(),
            }),
            EnforcementPolicySourcePlan::LocalManifest {
                source_kind: EnforcementPolicySourceKind::Directory,
                path: "/etc/traffic-probe/enforcement.d/manifest.toml".into(),
            }
        );
    }

    #[test]
    fn policy_source_plan_resolves_remote_body_limit() {
        assert_eq!(
            EnforcementPolicySourcePlan::from_config(&EnforcementPolicySourceConfig::Remote {
                endpoint: "https://control.example/enforcement".to_string(),
                max_body_bytes: None,
            }),
            EnforcementPolicySourcePlan::Remote {
                endpoint: "https://control.example/enforcement".to_string(),
                max_body_bytes: RemoteEnforcementPolicyBodyLimitBytes::from_config(None)
                    .expect("default remote body limit should be valid"),
            }
        );
        assert_eq!(
            RemoteEnforcementPolicyBodyLimitBytes::from_config(None)
                .expect("default remote body limit should be valid")
                .get(),
            DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES
        );

        assert_eq!(
            EnforcementPolicySourcePlan::from_config(&EnforcementPolicySourceConfig::Remote {
                endpoint: "https://control.example/enforcement".to_string(),
                max_body_bytes: Some(32 * 1024 * 1024),
            }),
            EnforcementPolicySourcePlan::Remote {
                endpoint: "https://control.example/enforcement".to_string(),
                max_body_bytes: RemoteEnforcementPolicyBodyLimitBytes::from_config(Some(
                    32 * 1024 * 1024,
                ))
                .expect("explicit remote body limit should be valid"),
            }
        );
    }
}

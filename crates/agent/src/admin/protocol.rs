use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{io::AsyncReadExt, net::UnixStream};

use crate::{
    configured_enforcement::{ActiveEnforcementPolicy, LoadedEnforcementPolicySourceSnapshot},
    configured_policy::ConfiguredPolicySource,
    status::MetricsSnapshot,
};

const ADMIN_REQUEST_MAX_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "command")]
pub(crate) enum AdminRequest {
    Status,
    Metrics,
    PrometheusMetrics,
    ReloadPolicies,
    ReloadEnforcementPolicy,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(super) enum AdminResponse {
    Status {
        snapshot: Box<crate::status::AgentStatusSnapshot>,
    },
    Metrics {
        metrics: Box<MetricsSnapshot>,
    },
    PrometheusMetrics {
        content_type: &'static str,
        metrics: String,
    },
    PolicyReload {
        loaded_count: u64,
        policies: Vec<ConfiguredPolicySource>,
    },
    EnforcementPolicyReload {
        source: EnforcementPolicyReloadSource,
        effective_selector_configured: bool,
        manifest_selector_configured: Option<bool>,
        protective_actions: probe_core::ProtectiveActionProfile,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub(super) enum EnforcementPolicyReloadSource {
    NotConfigured,
    Loaded {
        source: LoadedEnforcementPolicySourceSnapshot,
        manifest: EnforcementPolicyManifestSnapshot,
    },
}

#[derive(Debug, Serialize)]
pub(super) struct EnforcementPolicyManifestSnapshot {
    id: String,
    version: String,
    selector_configured: bool,
    protective_actions: probe_core::ProtectiveActionProfile,
}

pub(super) fn enforcement_policy_reload_source(
    policy: &ActiveEnforcementPolicy,
) -> EnforcementPolicyReloadSource {
    policy
        .policy_source()
        .map_or(EnforcementPolicyReloadSource::NotConfigured, |source| {
            EnforcementPolicyReloadSource::Loaded {
                source: source.snapshot(),
                manifest: EnforcementPolicyManifestSnapshot {
                    id: source.manifest.id.clone(),
                    version: source.manifest.version.clone(),
                    selector_configured: source.manifest.selector.is_some(),
                    protective_actions: source.manifest.protective_actions.clone(),
                },
            }
        })
}

pub(super) async fn read_admin_request(
    stream: &mut UnixStream,
) -> Result<AdminRequest, AdminRequestError> {
    let bytes = read_admin_request_line(stream).await?;
    let trimmed = trim_ascii_whitespace(&bytes);
    if trimmed.is_empty() {
        return Err(AdminRequestError::Empty);
    }
    serde_json::from_slice(trimmed).map_err(AdminRequestError::Json)
}

async fn read_admin_request_line(stream: &mut UnixStream) -> Result<Vec<u8>, AdminRequestError> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > ADMIN_REQUEST_MAX_BYTES {
            return Err(AdminRequestError::TooLarge {
                limit: ADMIN_REQUEST_MAX_BYTES,
            });
        }
    }
    Ok(bytes)
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

#[derive(Debug, Error)]
pub(super) enum AdminRequestError {
    #[error("failed to read admin request: {0}")]
    Io(#[from] std::io::Error),
    #[error("admin request is empty")]
    Empty,
    #[error("admin request exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("failed to parse admin request JSON: {0}")]
    Json(serde_json::Error),
}

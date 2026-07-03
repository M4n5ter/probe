use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{io::AsyncReadExt, net::UnixStream};

use crate::{
    configured_enforcement::{ActiveEnforcementPolicy, LoadedEnforcementPolicySourceSnapshot},
    configured_policy::ConfiguredPolicySource,
    status::MetricsSnapshot,
};

use super::{config_reload::ConfigReloadPlanSnapshot, debug_dump::AdminDebugDump};

const ADMIN_REQUEST_MAX_BYTES: usize = 4 * 1024;

macro_rules! admin_requests {
    (
        $(
            $variant:ident $( { $($field:ident : $field_ty:ty),+ $(,)? } )?
                => ($name:literal, $mutating:literal)
        ),+ $(,)?
    ) => {
        #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
        #[serde(tag = "command")]
        pub(crate) enum AdminRequest {
            $(
                #[serde(rename = $name)]
                $variant $( { $($field: $field_ty),+ } )?,
            )+
        }

        const ADMIN_COMMAND_SPECS: &[AdminCommandSpec] = &[
            $(
                AdminCommandSpec {
                    name: $name,
                    mutating: $mutating,
                },
            )+
        ];
    };
}

admin_requests! {
    Status => ("status", false),
    Metrics => ("metrics", false),
    PrometheusMetrics => ("prometheus_metrics", false),
    DebugDump => ("debug_dump", false),
    TailEvents {
        after_sequence: u64,
        limit: usize,
        selector: Option<probe_core::Selector>,
        event_types: Vec<probe_core::EventType>,
    } => ("tail_events", false),
    EventDetail {
        sequence: u64,
    } => ("event_detail", false),
    PlanConfigReload { path: PathBuf } => ("plan_config_reload", false),
    ReloadRuntimeActions => ("reload_runtime_actions", true),
    ReloadPolicies => ("reload_policies", true),
    ReloadEnforcementPolicy => ("reload_enforcement_policy", true),
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
    DebugDump {
        dump: Box<AdminDebugDump>,
    },
    EventTail {
        tail: Box<super::event_tail::EventTailSnapshot>,
    },
    EventDetail {
        detail: Box<super::event_tail::EventDetailSnapshot>,
    },
    EventDetailTooLarge {
        detail: Box<super::event_tail::EventDetailTooLargeSnapshot>,
    },
    ConfigReloadPlan {
        plan: Box<ConfigReloadPlanSnapshot>,
    },
    PolicyReload(PolicyReloadSuccess),
    RuntimeActionsReload {
        actions: Vec<RuntimeReloadActionResult>,
    },
    EnforcementPolicyReload(EnforcementPolicyReloadSuccess),
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize)]
pub(super) struct PolicyReloadSuccess {
    pub loaded_count: u64,
    pub policies: Vec<ConfiguredPolicySource>,
    pub active_set_updated: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct EnforcementPolicyReloadSuccess {
    pub source: EnforcementPolicyReloadSource,
    pub effective_selector_configured: bool,
    pub manifest_selector_configured: Option<bool>,
    pub protective_actions: probe_core::ProtectiveActionProfile,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "action", content = "outcome")]
pub(super) enum RuntimeReloadActionResult {
    ReloadPolicies(RuntimeReloadPolicyOutcome),
    ReloadEnforcementPolicy(RuntimeReloadEnforcementOutcome),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub(super) enum RuntimeReloadPolicyOutcome {
    Succeeded(PolicyReloadSuccess),
    Failed { message: String },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub(super) enum RuntimeReloadEnforcementOutcome {
    Succeeded(EnforcementPolicyReloadSuccess),
    Failed { message: String },
}

#[derive(Debug, Serialize)]
pub(super) struct AdminProtocolSnapshot {
    pub framing: &'static str,
    pub request_max_bytes: usize,
    pub commands: Vec<AdminCommandSnapshot>,
}

#[derive(Debug, Serialize)]
pub(super) struct AdminCommandSnapshot {
    pub name: &'static str,
    pub mutating: bool,
}

pub(super) fn admin_protocol_snapshot() -> AdminProtocolSnapshot {
    AdminProtocolSnapshot {
        framing: "json_lines",
        request_max_bytes: ADMIN_REQUEST_MAX_BYTES,
        commands: admin_command_specs()
            .iter()
            .map(|spec| AdminCommandSnapshot {
                name: spec.name,
                mutating: spec.mutating,
            })
            .collect(),
    }
}

#[derive(Debug, Clone, Copy)]
struct AdminCommandSpec {
    name: &'static str,
    mutating: bool,
}

fn admin_command_specs() -> &'static [AdminCommandSpec] {
    ADMIN_COMMAND_SPECS
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

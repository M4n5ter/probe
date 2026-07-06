use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{io::AsyncReadExt, net::UnixStream};

use crate::{
    configured_enforcement::{ActiveEnforcementPolicy, LoadedEnforcementPolicySourceSnapshot},
    configured_policy::ConfiguredPolicySource,
    runtime_reload::config_reload::{ConfigReloadApplySnapshot, ConfigReloadPlanSnapshot},
    status::MetricsSnapshot,
};

use super::debug_dump::AdminDebugDump;

const ADMIN_REQUEST_MAX_BYTES: usize = 4 * 1024;
const ADMIN_RESPONSE_MAX_BYTES: usize = 16 * 1024 * 1024;
const ADMIN_EVENT_DETAIL_RESPONSE_MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminResponseBudget {
    Default,
    LargeEventDetail,
}

impl AdminResponseBudget {
    pub(crate) fn max_bytes(self) -> usize {
        match self {
            Self::Default => ADMIN_RESPONSE_MAX_BYTES,
            Self::LargeEventDetail => ADMIN_EVENT_DETAIL_RESPONSE_MAX_BYTES,
        }
    }
}

macro_rules! admin_requests {
    (
        $(
            $variant:ident $( { $($field:ident : $field_ty:ty),+ $(,)? } )?
                => ($name:literal, $mutating:literal, $response_budget:expr)
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

        impl AdminRequest {
            pub(crate) fn command_name(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant $( { $($field: _),+ } )? => $name,
                    )+
                }
            }

            pub(crate) fn response_budget(&self) -> AdminResponseBudget {
                match self {
                    $(
                        Self::$variant $( { $($field: _),+ } )? => $response_budget,
                    )+
                }
            }
        }

        const ADMIN_COMMAND_SPECS: &[AdminCommandSpec] = &[
            $(
                AdminCommandSpec {
                    name: $name,
                    mutating: $mutating,
                    response_budget: $response_budget,
                },
            )+
        ];
    };
}

admin_requests! {
    Ping => ("ping", false, AdminResponseBudget::Default),
    Status => ("status", false, AdminResponseBudget::Default),
    TrafficStatus => ("traffic_status", false, AdminResponseBudget::Default),
    Metrics => ("metrics", false, AdminResponseBudget::Default),
    PrometheusMetrics => ("prometheus_metrics", false, AdminResponseBudget::Default),
    DebugDump => ("debug_dump", false, AdminResponseBudget::Default),
    TailEvents {
        after_sequence: u64,
        latest: bool,
        limit: usize,
        scan_limit: Option<usize>,
        selector: Option<probe_core::Selector>,
        event_types: Vec<probe_core::EventType>,
    } => ("tail_events", false, AdminResponseBudget::Default),
    EventDetail {
        sequence: u64,
    } => ("event_detail", false, AdminResponseBudget::LargeEventDetail),
    PlanConfigReload { path: PathBuf } => ("plan_config_reload", false, AdminResponseBudget::Default),
    ApplyConfigReload { path: PathBuf } => ("apply_config_reload", true, AdminResponseBudget::Default),
    ReloadRuntimeActions => ("reload_runtime_actions", true, AdminResponseBudget::Default),
    ReloadPolicies => ("reload_policies", true, AdminResponseBudget::Default),
    ReloadEnforcementPolicy => ("reload_enforcement_policy", true, AdminResponseBudget::Default),
    Shutdown => ("shutdown", true, AdminResponseBudget::Default),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(super) enum AdminResponse {
    Pong,
    Status {
        snapshot: Box<crate::status::AgentStatusSnapshot>,
    },
    TrafficStatus {
        projection: Box<crate::status::TrafficStatusProjection>,
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
    ConfigReloadApply {
        apply: Box<ConfigReloadApplySnapshot>,
    },
    PolicyReload(PolicyReloadSuccess),
    RuntimeActionsReload {
        actions: Vec<RuntimeReloadActionResult>,
    },
    EnforcementPolicyReload(EnforcementPolicyReloadSuccess),
    Shutdown {
        requested: bool,
    },
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
    pub response_max_bytes: usize,
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
                response_max_bytes: spec.response_budget.max_bytes(),
            })
            .collect(),
    }
}

#[derive(Debug, Clone, Copy)]
struct AdminCommandSpec {
    name: &'static str,
    mutating: bool,
    response_budget: AdminResponseBudget,
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

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn admin_request_command_contracts_match_wire_commands() {
        assert_command(AdminRequest::Ping, "ping", AdminResponseBudget::Default);
        assert_command(AdminRequest::Status, "status", AdminResponseBudget::Default);
        assert_command(
            AdminRequest::TrafficStatus,
            "traffic_status",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::Metrics,
            "metrics",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::PrometheusMetrics,
            "prometheus_metrics",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::DebugDump,
            "debug_dump",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::TailEvents {
                after_sequence: 0,
                latest: false,
                limit: 1,
                scan_limit: Some(1),
                selector: None,
                event_types: Vec::new(),
            },
            "tail_events",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::EventDetail { sequence: 1 },
            "event_detail",
            AdminResponseBudget::LargeEventDetail,
        );
        assert_command(
            AdminRequest::PlanConfigReload {
                path: PathBuf::from("agent.toml"),
            },
            "plan_config_reload",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::ApplyConfigReload {
                path: PathBuf::from("agent.toml"),
            },
            "apply_config_reload",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::ReloadRuntimeActions,
            "reload_runtime_actions",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::ReloadPolicies,
            "reload_policies",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::ReloadEnforcementPolicy,
            "reload_enforcement_policy",
            AdminResponseBudget::Default,
        );
        assert_command(
            AdminRequest::Shutdown,
            "shutdown",
            AdminResponseBudget::Default,
        );
    }

    fn assert_command(
        request: AdminRequest,
        expected: &'static str,
        expected_budget: AdminResponseBudget,
    ) {
        assert_eq!(request.command_name(), expected);
        assert_eq!(request.response_budget(), expected_budget);
        let value = serde_json::to_value(request).expect("serialize admin request");
        assert_eq!(value.get("command").and_then(Value::as_str), Some(expected));
    }

    #[test]
    fn tail_events_scan_limit_is_an_optional_wire_override() {
        let request = serde_json::from_value::<AdminRequest>(serde_json::json!({
            "command": "tail_events",
            "after_sequence": 0,
            "latest": false,
            "limit": 16,
            "selector": null,
            "event_types": []
        }))
        .expect("tail_events should accept the default scan policy");

        assert_eq!(
            request,
            AdminRequest::TailEvents {
                after_sequence: 0,
                latest: false,
                limit: 16,
                scan_limit: None,
                selector: None,
                event_types: Vec::new(),
            }
        );
    }
}

use std::{path::Path, time::Duration};

use probe_config::AgentConfig;
use serde_json::Value;
use thiserror::Error;

mod capture;
mod mitm;
mod mitm_data_path;

#[cfg(test)]
use crate::status::AgentStatusSnapshot;
use crate::{
    admin::{AdminClientError, AdminRequest, send_admin_json_request_with_timeout},
    artifacts::project_runtime_artifact_paths,
    runtime_composition::build_runtime_diagnostic_composition,
    runtime_generation::{
        RuntimeGenerationReloadRequestSnapshot, RuntimeGenerationReloadResultSnapshot,
        RuntimeGenerationSnapshot,
    },
    status::{
        CaptureStatusSnapshot, EnforcementStatusSnapshot, TrafficStatusProjection,
        build_traffic_status_projection,
    },
    tui::copy::{
        MITM_HTTP_PATH_LABEL, MITM_PLAINTEXT_COVERAGE, MITM_PROXY_DATA_PATH_LABEL,
        MITM_TLS_PATH_LABEL, MITM_TLS_TRUST_ACTION,
    },
};

use self::{
    capture::CaptureDiagnostics,
    mitm::{MitmDiagnostics, MitmTlsMaterialDiagnostics},
};

const STATUS_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) async fn request_traffic_runtime_diagnostics(
    socket_path: &Path,
) -> Result<TrafficRuntimeDiagnostics, RuntimeStatusClientError> {
    let response = send_admin_json_request_with_timeout(
        socket_path,
        AdminRequest::TrafficStatus,
        STATUS_TIMEOUT,
    )
    .await
    .map_err(RuntimeStatusClientError::AdminClient)?;
    parse_traffic_runtime_diagnostics_response(&response)
}

pub(crate) fn local_traffic_runtime_diagnostics(
    mut config: AgentConfig,
) -> Result<TrafficRuntimeDiagnostics, LocalRuntimeStatusError> {
    project_runtime_artifact_paths(&mut config);
    let composition = build_runtime_diagnostic_composition(config)
        .map_err(|error| LocalRuntimeStatusError::Runtime(error.into_parts().0))?;
    let plan = composition.into_plan();
    let projection = build_traffic_status_projection(&plan);
    TrafficRuntimeDiagnostics::from_status_projection(projection)
        .map_err(LocalRuntimeStatusError::Status)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficRuntimeDiagnostics {
    runtime_generation: Option<RuntimeGenerationSnapshot>,
    capture: CaptureDiagnostics,
    mitm: Option<MitmDiagnostics>,
}

impl TrafficRuntimeDiagnostics {
    #[cfg(test)]
    pub(crate) fn from_capture_snapshot(capture: CaptureStatusSnapshot) -> Self {
        Self {
            runtime_generation: None,
            capture: CaptureDiagnostics::new(capture),
            mitm: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_status_snapshot(
        snapshot: AgentStatusSnapshot,
    ) -> Result<Self, RuntimeStatusClientError> {
        let AgentStatusSnapshot {
            runtime_generation,
            capture,
            enforcement,
            tls,
            ..
        } = snapshot;
        let tls_materials = MitmTlsMaterialDiagnostics::from_tls_status_snapshot(tls);
        Ok(Self {
            runtime_generation: Some(runtime_generation),
            capture: CaptureDiagnostics::new(capture),
            mitm: MitmDiagnostics::from_enforcement(enforcement, Some(&tls_materials)),
        })
    }

    pub(crate) fn from_status_projection(
        projection: TrafficStatusProjection,
    ) -> Result<Self, RuntimeStatusClientError> {
        let TrafficStatusProjection {
            runtime_generation,
            capture,
            enforcement,
            tls,
        } = projection;
        let tls_materials = MitmTlsMaterialDiagnostics::from_tls_status_snapshot(tls);
        Ok(Self {
            runtime_generation,
            capture: CaptureDiagnostics::new(capture),
            mitm: MitmDiagnostics::from_enforcement(enforcement, Some(&tls_materials)),
        })
    }

    pub(crate) fn status_message(&self, traffic_empty: bool) -> Option<CaptureDiagnosticMessage> {
        let mitm_next_step = self.mitm_next_step();
        let generation_message = self.runtime_generation_status_message();
        if self.capture.using_mitm_plaintext_bridge() {
            return combine_diagnostic_messages(
                generation_message,
                self.mitm_bridge_status_message(traffic_empty, mitm_next_step.as_str()),
            );
        }
        let capture_message = self
            .capture
            .status_message(traffic_empty, mitm_next_step.as_str());
        let mitm_message = self.mitm_data_path_status_message(traffic_empty);
        let data_path_message = if self.capture.using_live_host()
            && matches!(capture_message, Some(CaptureDiagnosticMessage::Info(_)))
            && mitm_message.is_some()
        {
            let prefix = self
                .capture
                .live_host_status_prefix()
                .map(|prefix| format!("{prefix}; "))
                .unwrap_or_default();
            mitm_message.map(|message| message.with_prefix(prefix))
        } else {
            combine_diagnostic_messages(capture_message, mitm_message)
        };
        combine_diagnostic_messages(generation_message, data_path_message)
    }

    pub(crate) fn tail_attribution_mode(&self) -> crate::admin::EventTailAttributionMode {
        if self.capture.using_libpcap_live_host() {
            crate::admin::EventTailAttributionMode::IncludeUnknownProcess
        } else {
            crate::admin::EventTailAttributionMode::Strict
        }
    }

    fn mitm_bridge_status_message(
        &self,
        traffic_empty: bool,
        mitm_next_step: &str,
    ) -> Option<CaptureDiagnosticMessage> {
        let capture_context = self.capture.mitm_bridge_passive_context_message();
        let mitm_message = self.mitm_data_path_status_message(traffic_empty);
        combine_diagnostic_messages(capture_context, mitm_message)
            .or_else(|| self.capture.status_message(traffic_empty, mitm_next_step))
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = self.runtime_generation_detail_lines();
        lines.extend(self.capture.detail_lines());
        lines.extend(self.mitm_detail_lines());
        lines
    }

    pub(crate) fn running_status_text(&self, traffic_empty: bool) -> String {
        self.status_message(traffic_empty)
            .map(CaptureDiagnosticMessage::into_text)
            .unwrap_or_else(|| "data path ready".to_string())
    }

    pub(crate) fn local_status_text(&self) -> String {
        self.capture
            .local_status_message(self.mitm_next_step().as_str())
            .map(CaptureDiagnosticMessage::into_text)
            .unwrap_or_else(|| {
                "local config is valid; run or attach an agent to confirm live traffic".to_string()
            })
    }

    pub(crate) fn capture_overview_line(&self) -> String {
        self.capture.overview_line()
    }

    pub(crate) fn mitm_overview_line(&self) -> String {
        self.mitm.as_ref().map_or_else(
            || {
                format!(
                    "not configured; {MITM_PROXY_DATA_PATH_LABEL} can capture {MITM_PLAINTEXT_COVERAGE}"
                )
            },
            MitmDiagnostics::overview_line,
        )
    }

    fn mitm_detail_lines(&self) -> Vec<String> {
        self.mitm.as_ref().map_or_else(
            || {
                let mut lines = vec![
                    "MITM diagnostics".to_string(),
                    "strategy: disabled".to_string(),
                    format!("coverage: {MITM_PLAINTEXT_COVERAGE}"),
                ];
                lines.extend(mitm_visibility_lines());
                lines.extend([
                    format!("configuration: {}", missing_mitm_configuration_action()),
                    format!("next action: {}", missing_mitm_next_step()),
                ]);
                lines
            },
            MitmDiagnostics::detail_lines,
        )
    }

    pub(crate) fn mitm_next_step(&self) -> String {
        self.mitm
            .as_ref()
            .map_or_else(missing_mitm_next_step, MitmDiagnostics::next_step)
    }

    fn mitm_data_path_status_message(
        &self,
        traffic_empty: bool,
    ) -> Option<CaptureDiagnosticMessage> {
        if !self.capture.using_live_host() && !self.capture.using_mitm_plaintext_bridge() {
            return None;
        }
        self.mitm
            .as_ref()
            .and_then(|mitm| mitm.live_side_channel_status_message(traffic_empty))
    }

    fn runtime_generation_status_message(&self) -> Option<CaptureDiagnosticMessage> {
        let runtime_generation = self.runtime_generation.as_ref()?;
        if let Some(pending) = &runtime_generation.pending {
            return Some(CaptureDiagnosticMessage::Info(format!(
                "Runtime generation request {} is queued for {}; active generation {} ({}) remains in use",
                pending.request_id,
                candidate_config_version_label(pending.candidate_config_version.as_deref()),
                runtime_generation.active.generation,
                runtime_generation.active.config_version,
            )));
        }
        if let Some(applying) = &runtime_generation.applying {
            let request = &applying.request;
            return Some(CaptureDiagnosticMessage::Info(format!(
                "Runtime generation request {} is applying for {}; active generation {} ({}) remains in use until swap completes",
                request.request_id,
                candidate_config_version_label(request.candidate_config_version.as_deref()),
                runtime_generation.active.generation,
                runtime_generation.active.config_version,
            )));
        }
        let Some(outcome) = &runtime_generation.last_outcome else {
            return None;
        };
        match &outcome.result {
            RuntimeGenerationReloadResultSnapshot::Applied { .. } => None,
            RuntimeGenerationReloadResultSnapshot::Failed { message } => {
                Some(CaptureDiagnosticMessage::Warning(format!(
                    "Runtime generation request {} failed; active generation {} ({}) remains in use: {message}",
                    outcome.request_id,
                    runtime_generation.active.generation,
                    runtime_generation.active.config_version,
                )))
            }
        }
    }

    fn runtime_generation_detail_lines(&self) -> Vec<String> {
        let Some(snapshot) = &self.runtime_generation else {
            return Vec::new();
        };
        let mut lines = vec![
            "Runtime generation".to_string(),
            format!(
                "active: generation {} ({})",
                snapshot.active.generation, snapshot.active.config_version
            ),
            format!(
                "capture safe points: {}{}",
                snapshot.capture_control.safe_points,
                snapshot
                    .capture_control
                    .last_safe_point_unix_ns
                    .map(|timestamp| format!(", last={timestamp}"))
                    .unwrap_or_default()
            ),
        ];
        match (
            &snapshot.pending,
            &snapshot.applying,
            &snapshot.last_outcome,
        ) {
            (Some(pending), _, _) => lines.push(format!(
                "pending: {}",
                runtime_generation_request_line(pending)
            )),
            (_, Some(applying), _) => lines.push(format!(
                "applying: {}",
                runtime_generation_request_line(&applying.request)
            )),
            (_, _, Some(outcome)) => match &outcome.result {
                RuntimeGenerationReloadResultSnapshot::Applied {
                    generation,
                    config_version,
                } => lines.push(format!(
                    "last outcome: request {} applied as generation {} ({})",
                    outcome.request_id, generation, config_version
                )),
                RuntimeGenerationReloadResultSnapshot::Failed { message } => lines.push(format!(
                    "last outcome: request {} failed: {message}",
                    outcome.request_id
                )),
            },
            _ => lines.push("state: no pending generation reload".to_string()),
        }
        lines
    }
}

fn runtime_generation_request_line(request: &RuntimeGenerationReloadRequestSnapshot) -> String {
    format!(
        "request {} for {}, sections={}",
        request.request_id,
        candidate_config_version_label(request.candidate_config_version.as_deref()),
        if request.changed_sections.is_empty() {
            "<none>".to_string()
        } else {
            request.changed_sections.join(", ")
        }
    )
}

fn candidate_config_version_label(config_version: Option<&str>) -> &str {
    config_version.unwrap_or("<unknown config_version>")
}

fn combine_diagnostic_messages(
    primary: Option<CaptureDiagnosticMessage>,
    secondary: Option<CaptureDiagnosticMessage>,
) -> Option<CaptureDiagnosticMessage> {
    match (primary, secondary) {
        (None, None) => None,
        (Some(message), None) | (None, Some(message)) => Some(message),
        (Some(primary), Some(secondary)) => {
            let kind = primary.max_kind(&secondary);
            let text = format!("{}; {}", primary.into_text(), secondary.into_text());
            Some(CaptureDiagnosticMessage::from_kind(kind, text))
        }
    }
}

fn missing_mitm_next_step() -> String {
    format!(
        "configure {MITM_PROXY_DATA_PATH_LABEL} for {MITM_PLAINTEXT_COVERAGE}: {}",
        missing_mitm_configuration_action()
    )
}

pub(crate) fn missing_mitm_configuration_action() -> &'static str {
    "configure transparent MITM interception in Enforcement"
}

pub(crate) fn mitm_data_path_coverage_line() -> String {
    format!(
        "{MITM_PROXY_DATA_PATH_LABEL} covers {MITM_PLAINTEXT_COVERAGE} for scoped bidirectional MITM traffic"
    )
}

pub(crate) fn mitm_visibility_lines() -> Vec<String> {
    vec![
        mitm_path_labels_line(),
        mitm_plain_http_visibility_line(),
        mitm_tls_http_visibility_line(),
    ]
}

fn mitm_path_labels_line() -> String {
    format!(
        "path labels: {MITM_HTTP_PATH_LABEL}=plain HTTP, {MITM_TLS_PATH_LABEL}=TLS-decrypted HTTP"
    )
}

fn mitm_plain_http_visibility_line() -> String {
    format!(
        "plain HTTP: visible as {MITM_HTTP_PATH_LABEL} after scoped MITM proxy event feed is active"
    )
}

fn mitm_tls_http_visibility_line() -> String {
    format!("TLS-decrypted HTTP: visible as {MITM_TLS_PATH_LABEL} after {MITM_TLS_TRUST_ACTION}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CaptureDiagnosticMessage {
    Info(String),
    Warning(String),
    Error(String),
}

impl CaptureDiagnosticMessage {
    fn from_kind(kind: CaptureDiagnosticMessageKind, text: String) -> Self {
        match kind {
            CaptureDiagnosticMessageKind::Info => Self::Info(text),
            CaptureDiagnosticMessageKind::Warning => Self::Warning(text),
            CaptureDiagnosticMessageKind::Error => Self::Error(text),
        }
    }

    fn max_kind(&self, other: &Self) -> CaptureDiagnosticMessageKind {
        self.kind().max(other.kind())
    }

    fn kind(&self) -> CaptureDiagnosticMessageKind {
        match self {
            Self::Info(_) => CaptureDiagnosticMessageKind::Info,
            Self::Warning(_) => CaptureDiagnosticMessageKind::Warning,
            Self::Error(_) => CaptureDiagnosticMessageKind::Error,
        }
    }

    fn into_text(self) -> String {
        match self {
            Self::Info(text) | Self::Warning(text) | Self::Error(text) => text,
        }
    }

    fn with_prefix(self, prefix: String) -> Self {
        let kind = self.kind();
        Self::from_kind(kind, format!("{prefix}{}", self.into_text()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CaptureDiagnosticMessageKind {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Error)]
pub(crate) enum RuntimeStatusClientError {
    #[error("admin client error: {0}")]
    AdminClient(AdminClientError),
    #[error("admin traffic_status response is missing projection.capture")]
    MissingCapture,
    #[error("admin traffic_status failed: {0}")]
    Admin(String),
    #[error("unexpected admin response kind: {kind}")]
    UnexpectedResponse { kind: String },
    #[error("failed to parse admin traffic_status response: {0}")]
    Json(serde_json::Error),
}

#[derive(Debug, Error)]
pub(crate) enum LocalRuntimeStatusError {
    #[error("local runtime plan error: {0}")]
    Runtime(runtime::RuntimeError),
    #[error("local runtime status error: {0}")]
    Status(RuntimeStatusClientError),
}

fn parse_traffic_runtime_diagnostics_response(
    response: &Value,
) -> Result<TrafficRuntimeDiagnostics, RuntimeStatusClientError> {
    match response.get("kind").and_then(Value::as_str) {
        Some("traffic_status") => {
            let projection = response
                .get("projection")
                .ok_or(RuntimeStatusClientError::MissingCapture)?;
            let runtime_generation = projection
                .get("runtime_generation")
                .filter(|value| !value.is_null())
                .cloned()
                .map(serde_json::from_value::<RuntimeGenerationSnapshot>)
                .transpose()
                .map_err(RuntimeStatusClientError::Json)?;
            let capture = projection
                .get("capture")
                .cloned()
                .ok_or(RuntimeStatusClientError::MissingCapture)?;
            let provider_reported = json_field_present(&capture, "provider");
            let input_activity_reported = json_field_present(&capture, "input_activity");
            let capture = serde_json::from_value::<CaptureStatusSnapshot>(capture)
                .map_err(RuntimeStatusClientError::Json)?;
            let tls = projection.get("tls").cloned();
            let mitm = projection
                .get("enforcement")
                .cloned()
                .map(|enforcement| parse_mitm_diagnostics(enforcement, tls))
                .transpose()?
                .flatten();
            Ok(TrafficRuntimeDiagnostics {
                runtime_generation,
                capture: CaptureDiagnostics::from_admin_status(
                    capture,
                    provider_reported,
                    input_activity_reported,
                ),
                mitm,
            })
        }
        Some("error") => Err(RuntimeStatusClientError::Admin(
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("admin status returned an error")
                .to_string(),
        )),
        other => Err(RuntimeStatusClientError::UnexpectedResponse {
            kind: other.unwrap_or("<missing>").to_string(),
        }),
    }
}

fn json_field_present(value: &Value, field: &str) -> bool {
    value.get(field).is_some_and(|value| !value.is_null())
}

fn parse_mitm_diagnostics(
    enforcement: Value,
    tls: Option<Value>,
) -> Result<Option<MitmDiagnostics>, RuntimeStatusClientError> {
    let enforcement = serde_json::from_value::<EnforcementStatusSnapshot>(enforcement)
        .map_err(RuntimeStatusClientError::Json)?;
    let tls_materials = tls
        .map(MitmTlsMaterialDiagnostics::from_tls_status)
        .transpose()
        .map_err(RuntimeStatusClientError::Json)?;
    Ok(MitmDiagnostics::from_enforcement(
        enforcement,
        tls_materials.as_ref(),
    ))
}

#[cfg(test)]
mod tests {
    use probe_config::{
        AgentConfig, CaptureSelection, EnforcementPolicySourceConfig, TlsMaterialConfig,
        TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, Direction, EnforcementMode, ProcessSelector, Selector,
        TrafficSelector,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::{
        l7_mitm::{
            L7MitmBackendHealthSnapshot, L7MitmClientTrustMaterialMode, L7MitmClientTrustMode,
            L7MitmClientTrustSnapshot, L7MitmPlaintextBridgeMode, L7MitmPlaintextBridgeSnapshot,
            L7MitmRuntimeSnapshot,
        },
        status::{
            build_status_snapshot, collect_spool_status,
            enforcement_status_with_transparent_proxy_for_test,
        },
        tcp_health::TcpHealthMode,
        tui::copy::{
            MITM_HTTP_PATH_LABEL, MITM_PLAINTEXT_COVERAGE, MITM_TLS_PATH_LABEL,
            MITM_TLS_TRUST_ACTION,
        },
    };

    const MITM_CA_CERTIFICATE_PATH: &str = "/etc/traffic-probe/mitm-ca.pem";
    const MITM_CA_PRIVATE_KEY_PATH: &str = "/etc/traffic-probe/mitm-ca.key";
    const MITM_LEAF_CERTIFICATE_PATH: &str = "/etc/traffic-probe/mitm-leaf.pem";
    const MITM_LEAF_PRIVATE_KEY_PATH: &str = "/etc/traffic-probe/mitm-leaf.key";

    fn assert_detail_line(lines: &[String], expected: impl AsRef<str>) {
        let expected = expected.as_ref();
        assert!(
            lines.iter().any(|line| line == expected),
            "missing detail line: {expected}"
        );
    }

    #[test]
    fn traffic_diagnostics_summarize_unavailable_capture_and_missing_mitm()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": null,
                    "mode": "unavailable",
                    "reason": "no live capture provider is available in this build/runtime",
                    "candidates": [
                        {
                            "backend": "ebpf",
                            "runtime_mode": "unavailable",
                            "capability_mode": "unavailable",
                            "evidence_mode": "nominal",
                            "reason": "capture.ebpf.object_path is not configured"
                        },
                        {
                            "backend": "libpcap",
                            "runtime_mode": "unavailable",
                            "capability_mode": "unavailable",
                            "evidence_mode": "nominal",
                            "reason": "libpcap is not available"
                        }
                    ],
                    "open_failures": []
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Error(format!(
                "Capture unavailable: ebpf: capture.ebpf.object_path is not configured; libpcap: libpcap is not available; configure reliable MITM proxy data path for {MITM_PLAINTEXT_COVERAGE}: {}",
                missing_mitm_configuration_action()
            )))
        );
        let lines = diagnostics.detail_lines();
        assert!(lines.iter().any(|line| line == "strategy: disabled"));
        assert_detail_line(
            &lines,
            format!(
                "path labels: {MITM_HTTP_PATH_LABEL}=plain HTTP, {MITM_TLS_PATH_LABEL}=TLS-decrypted HTTP"
            ),
        );
        assert_detail_line(
            &lines,
            format!(
                "plain HTTP: visible as {MITM_HTTP_PATH_LABEL} after scoped MITM proxy event feed is active"
            ),
        );
        assert_detail_line(
            &lines,
            format!(
                "TLS-decrypted HTTP: visible as {MITM_TLS_PATH_LABEL} after {MITM_TLS_TRUST_ACTION}"
            ),
        );
        assert_detail_line(
            &lines,
            format!("configuration: {}", missing_mitm_configuration_action()),
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_do_not_report_ladder_when_mitm_is_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "ebpf",
                    "selected_backend": null,
                    "mode": "unavailable",
                    "reason": "eBPF capture provider is not available",
                    "candidates": [
                        {
                            "backend": "ebpf",
                            "runtime_mode": "unavailable",
                            "capability_mode": "unavailable",
                            "evidence_mode": "nominal",
                            "reason": "eBPF object is missing"
                        }
                    ],
                    "open_failures": []
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert_detail_line(&lines, "strategy: disabled");
        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with("data path priority:")),
            "MITM disabled diagnostics must not claim an active data path priority: {lines:?}"
        );
        Ok(())
    }

    #[test]
    fn local_status_snapshot_diagnostics_keep_passive_failures_and_mitm_action()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = AgentConfig::default();
        config.storage.path = temp.path().join("spool");
        let plan = RuntimePlan::build(
            config,
            &ProviderRegistry::new(
                vec![
                    CaptureProviderDescriptor::unavailable(
                        probe_config::CaptureBackend::Ebpf,
                        CaptureProviderBuilder::Ebpf,
                        "capture.ebpf.object_path is not configured",
                    ),
                    CaptureProviderDescriptor::unavailable(
                        probe_config::CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Libpcap,
                        "libpcap is not available",
                    ),
                ],
                test_platform_capabilities(),
            ),
        )?;
        let snapshot = build_status_snapshot(&plan, collect_spool_status(&plan));

        let diagnostics = TrafficRuntimeDiagnostics::from_status_snapshot(snapshot)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Error(format!(
                "Capture unavailable: ebpf: capture.ebpf.object_path is not configured; libpcap: libpcap is not available; configure reliable MITM proxy data path for {MITM_PLAINTEXT_COVERAGE}: {}",
                missing_mitm_configuration_action()
            )))
        );
        assert!(diagnostics.detail_lines().iter().any(|line| {
            line == &format!("configuration: {}", missing_mitm_configuration_action())
        }));
        Ok(())
    }

    #[test]
    fn local_runtime_diagnostics_entry_uses_runtime_status_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        let spool_path = temp.path().join("spool");
        config.storage.path = spool_path.clone();

        let diagnostics = local_traffic_runtime_diagnostics(config)?;

        let lines = diagnostics.detail_lines();
        assert!(lines.iter().any(|line| line == "selected: replay"));
        assert!(
            !lines.iter().any(
                |line| line == "Runtime generation" || line.starts_with("active: generation 0")
            ),
            "local config diagnostics must not invent live runtime generation state: {lines:?}"
        );
        assert!(lines.iter().any(|line| {
            line == &format!("configuration: {}", missing_mitm_configuration_action())
        }));
        assert!(!spool_path.exists());
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_configured_mitm_path() -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": null,
                    "mode": "unavailable",
                    "reason": "no passive provider is available",
                    "candidates": [],
                    "open_failures": []
                },
                "enforcement": configured_mitm_enforcement_status_json()?,
                "tls": mitm_tls_material_status_json("available", None, "available", None)
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert!(
            lines
                .iter()
                .any(|line| line == "strategy: inbound_tproxy_mitm")
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("backend: external readiness=127.0.0.1:15002"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("MITM proxy event feed: capture_event_feed"))
        );
        assert!(lines.iter().any(|line| {
            line == &format!(
                "path labels: {MITM_HTTP_PATH_LABEL}=plain HTTP, {MITM_TLS_PATH_LABEL}=TLS-decrypted HTTP"
            )
        }));
        assert!(lines.iter().any(|line| {
            line == &format!(
                "plain HTTP: visible as {MITM_HTTP_PATH_LABEL} without TLS client trust"
            )
        }));
        assert!(lines.iter().any(|line| {
            line == &format!(
                "TLS-decrypted HTTP: visible as {MITM_TLS_PATH_LABEL} after {MITM_TLS_TRUST_ACTION}"
            )
        }));
        assert!(
            lines
                .iter()
                .any(|line| line == &format!("coverage: {MITM_PLAINTEXT_COVERAGE}"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line == &format!("tls trust action: {MITM_TLS_TRUST_ACTION}"))
        );
        assert_detail_line(
            &lines,
            format!("MITM CA certificate: {MITM_CA_CERTIFICATE_PATH} source=available"),
        );
        assert_detail_line(
            &lines,
            format!("MITM CA private key: {MITM_CA_PRIVATE_KEY_PATH} source=available"),
        );
        let expected_next_action =
            format!("next action: MITM TLS trust needs attention: {MITM_TLS_TRUST_ACTION}");
        assert!(lines.iter().any(|line| line == &expected_next_action));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("l7 mitm backend health: healthy"))
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_live_capture_with_active_mitm_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "ebpf",
                    "selected_input_source": "live_host",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": [],
                    "auto_mitm_plaintext_bridge_candidate": {
                        "backend": "capture_event_feed",
                        "runtime_mode": "available",
                        "capability_mode": "available",
                        "evidence_mode": "nominal",
                        "reason": null,
                        "evidence_reason": null
                    }
                },
                "enforcement": configured_mitm_enforcement_status_json()?,
                "tls": mitm_tls_material_status_json("available", None, "available", None)
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Info(
                "Capture ebpf active; MITM proxy path ready for plain HTTP and TLS-decrypted HTTP after client trust; no matching events yet"
                    .to_string()
            ))
        );
        assert_eq!(diagnostics.status_message(false), None);
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_surface_pending_runtime_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
            "projection": {
                "runtime_generation": {
                    "active": { "generation": 1, "config_version": "current" },
                    "pending": {
                        "request_id": 7,
                        "candidate_path": "/tmp/agent.toml",
                        "current_config_version": "current",
                        "candidate_config_version": "candidate",
                        "changed_sections": ["capture", "observations"],
                        "requested_unix_ns": 10
                    },
                    "applying": null,
                    "last_outcome": null,
                    "capture_control": {
                        "safe_points": 3,
                        "last_safe_point_unix_ns": 20
                    }
                },
                "capture": {
                    "selection": "auto",
                    "selected_backend": "ebpf",
                    "selected_input_source": "live_host",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": []
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Info(
                "Runtime generation request 7 is queued for candidate; active generation 1 (current) remains in use; Capture ebpf active; no matching events yet"
                    .to_string()
            ))
        );
        let lines = diagnostics.detail_lines();
        assert_detail_line(&lines, "active: generation 1 (current)");
        assert_detail_line(&lines, "capture safe points: 3, last=20");
        assert_detail_line(
            &lines,
            "pending: request 7 for candidate, sections=capture, observations",
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_warn_for_failed_runtime_generation_with_active_traffic()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
            "projection": {
                "runtime_generation": {
                    "active": { "generation": 1, "config_version": "current" },
                    "pending": null,
                    "applying": null,
                    "last_outcome": {
                        "request_id": 8,
                        "completed_unix_ns": 30,
                        "result": {
                            "result": "failed",
                            "message": "candidate capture provider failed to open"
                        }
                    },
                    "capture_control": {
                        "safe_points": 4,
                        "last_safe_point_unix_ns": 40
                    }
                },
                "capture": {
                    "selection": "auto",
                    "selected_backend": "ebpf",
                    "selected_input_source": "live_host",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": []
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(false),
            Some(CaptureDiagnosticMessage::Warning(
                "Runtime generation request 8 failed; active generation 1 (current) remains in use: candidate capture provider failed to open"
                    .to_string()
            ))
        );
        let lines = diagnostics.detail_lines();
        assert_detail_line(
            &lines,
            "last outcome: request 8 failed: candidate capture provider failed to open",
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_reports_live_capture_provider_starting()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "ebpf",
                    "selected_input_source": "live_host",
                    "provider_runtime_mode": "available",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": []
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Info(
                "Capture ebpf is starting; waiting for provider".to_string()
            ))
        );
        assert_eq!(diagnostics.status_message(false), None);
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_do_not_report_provider_starting_after_input_activity()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "ebpf",
                    "selected_input_source": "live_host",
                    "provider_runtime_mode": "available",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": [],
                    "input_activity": {
                        "polls": {
                            "total": 1,
                            "events": 1,
                            "progress": 0,
                            "idle": 0,
                            "finished": 0
                        },
                        "capture_events": 1,
                        "output_loss_events": 0,
                        "lost_events": 0,
                        "providers": [],
                        "last_signal": null
                    }
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Info(
                "Capture ebpf active; no matching events yet".to_string()
            ))
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_warn_when_empty_traffic_has_capture_loss()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "ebpf",
                    "selected_input_source": "live_host",
                    "provider_runtime_mode": "available",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": [],
                    "input_activity": {
                        "polls": {
                            "total": 12,
                            "events": 9,
                            "progress": 3,
                            "idle": 0,
                            "finished": 0
                        },
                        "capture_events": 8,
                        "output_loss_events": 1,
                        "lost_events": 2245,
                        "providers": [
                            {
                                "provider": "ebpf",
                                "capture_events": 8,
                                "output_loss_events": 1,
                                "lost_events": 2245
                            }
                        ],
                        "last_signal": {
                            "kind": "output_loss",
                            "sequence": 12,
                            "observed_unix_ns": 1783060723710836934_u64,
                            "source": "ebpf_syscall",
                            "provider": "ebpf",
                            "event_wall_time_unix_ns": 1783060723000000000_i64,
                            "lost_events": 2245
                        }
                    }
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Warning(
                "Capture ebpf lost 2245 input event(s) across 1 output-loss signal(s) (ebpf lost 2245 event(s)); parsed HTTP may be incomplete, switch to Diagnostics/All or use MITM for reliable full payload visibility".to_string()
            ))
        );
        assert_eq!(diagnostics.status_message(false), None);
        let lines = diagnostics.detail_lines();
        assert_detail_line(
            &lines,
            "input activity: capture_events=8, output_loss_events=1, lost_events=2245",
        );
        assert_detail_line(
            &lines,
            "input provider ebpf: capture_events=8, output_loss_events=1, lost_events=2245",
        );
        assert_detail_line(&lines, "last input signal: output_loss");
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_warn_when_active_mitm_bridge_data_path_is_blocked()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut enforcement = configured_mitm_enforcement_status_json()?;
        enforcement["interception"]["runtime_l7_mitm"]["backend_health"]["mode"] =
            json!("unhealthy");
        enforcement["interception"]["runtime_l7_mitm"]["backend_health"]["last_failure_reason"] =
            json!("readiness probe failed");
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "ebpf",
                    "selected_input_source": "live_host",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": []
                },
                "enforcement": enforcement,
                "tls": mitm_tls_material_status_json("available", None, "available", None)
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(false),
            Some(CaptureDiagnosticMessage::Warning(
                "MITM proxy data path is blocked".to_string()
            ))
        );
        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Warning(
                "Capture ebpf active; MITM proxy data path is blocked".to_string()
            ))
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_bridge_runtime_action_before_activation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut enforcement = configured_mitm_enforcement_status_json()?;
        enforcement["interception"]["runtime_l7_mitm"]["plaintext_bridge"]["mode"] = json!("ready");
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "libpcap",
                    "selected_input_source": "live_host",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": []
                },
                "enforcement": enforcement
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let message = diagnostics.status_message(false);

        assert_eq!(
            message,
            Some(CaptureDiagnosticMessage::Warning(
                "MITM proxy path is not active yet: waiting for capture provider activation to read the MITM proxy event feed"
                    .to_string()
            ))
        );
        assert!(
            !format!("{message:?}").contains("TLS trust"),
            "bridge activation status must not reuse TLS trust next action"
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_unavailable_mitm_tls_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": mitm_bridge_capture_status_json(),
                "enforcement": configured_mitm_enforcement_status_json()?,
                "tls": mitm_tls_material_status_json(
                    "unavailable",
                    Some("permission denied"),
                    "available",
                    None,
                )
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert_detail_line(
            &lines,
            format!(
                "MITM CA certificate: {MITM_CA_CERTIFICATE_PATH} source=unavailable reason=permission denied"
            ),
        );
        assert_detail_line(
            &lines,
            format!("plain HTTP: visible as {MITM_HTTP_PATH_LABEL} without TLS client trust"),
        );
        assert_detail_line(
            &lines,
            "TLS-decrypted HTTP: blocked because MITM CA certificate source is unavailable: permission denied",
        );
        assert_detail_line(
            &lines,
            "next action: MITM TLS material needs attention: MITM CA certificate source is unavailable: permission denied",
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_unavailable_static_leaf_mitm_tls_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": mitm_bridge_capture_status_json(),
                "enforcement": configured_static_leaf_mitm_enforcement_status_json()?,
                "tls": mitm_static_leaf_tls_material_status_json(
                    "unavailable",
                    Some("leaf certificate is missing"),
                    "available",
                    None,
                )
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert_detail_line(
            &lines,
            format!(
                "MITM leaf certificate chain[0]: {MITM_LEAF_CERTIFICATE_PATH} source=unavailable reason=leaf certificate is missing"
            ),
        );
        assert_detail_line(
            &lines,
            "tls trust action: trust the configured MITM leaf certificate chain or issuing CA to see TLS-decrypted HTTP",
        );
        assert_detail_line(
            &lines,
            "TLS-decrypted HTTP: blocked because MITM leaf certificate chain[0] source is unavailable: leaf certificate is missing",
        );
        assert_detail_line(
            &lines,
            "next action: MITM TLS material needs attention: MITM leaf certificate chain[0] source is unavailable: leaf certificate is missing",
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_unavailable_ca_and_leaf_mitm_tls_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": mitm_bridge_capture_status_json(),
                "enforcement": configured_ca_and_leaf_mitm_enforcement_status_json()?,
                "tls": mitm_ca_and_leaf_tls_material_status_json(
                    "unavailable",
                    Some("leaf certificate is missing"),
                    "available",
                    None,
                )
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert_detail_line(
            &lines,
            format!("MITM CA certificate: {MITM_CA_CERTIFICATE_PATH} source=available"),
        );
        assert_detail_line(
            &lines,
            format!(
                "MITM leaf certificate chain[0]: {MITM_LEAF_CERTIFICATE_PATH} source=unavailable reason=leaf certificate is missing"
            ),
        );
        assert_detail_line(
            &lines,
            "tls trust action: install the generated MITM CA and trust the configured MITM leaf certificate chain or issuing CA to see TLS-decrypted HTTP",
        );
        assert_detail_line(
            &lines,
            "TLS-decrypted HTTP: blocked because MITM leaf certificate chain[0] source is unavailable: leaf certificate is missing",
        );
        assert_detail_line(
            &lines,
            "next action: MITM TLS material needs attention: MITM leaf certificate chain[0] source is unavailable: leaf certificate is missing",
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_allow_degraded_mitm_tls_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": mitm_bridge_capture_status_json(),
                "enforcement": configured_mitm_enforcement_status_json()?,
                "tls": mitm_tls_material_status_json(
                    "degraded",
                    Some("metadata check is partial"),
                    "available",
                    None,
                )
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert_detail_line(
            &lines,
            format!(
                "MITM CA certificate: {MITM_CA_CERTIFICATE_PATH} source=degraded reason=metadata check is partial"
            ),
        );
        assert_detail_line(
            &lines,
            format!(
                "TLS-decrypted HTTP: visible as {MITM_TLS_PATH_LABEL} after {MITM_TLS_TRUST_ACTION}"
            ),
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_unknown_mitm_tls_material_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": mitm_bridge_capture_status_json(),
                "enforcement": configured_mitm_enforcement_status_json()?
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert_detail_line(
            &lines,
            format!("MITM CA certificate: {MITM_CA_CERTIFICATE_PATH} source=unknown"),
        );
        assert_detail_line(
            &lines,
            "TLS-decrypted HTTP: unknown because MITM CA certificate source status is unknown",
        );
        assert_detail_line(
            &lines,
            "next action: MITM TLS material status is unknown: MITM CA certificate source status is unknown",
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_next_step_reports_disabled_mitm_client_trust()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut enforcement = configured_mitm_enforcement_status_json()?;
        enforcement["interception"]["mitm"]["client_trust"] = json!({ "mode": "disabled" });
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": null,
                    "mode": "unavailable",
                    "reason": "no passive provider is available",
                    "candidates": [],
                    "open_failures": []
                },
                "enforcement": enforcement
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert!(lines.iter().any(|line| {
            line == "tls trust action: configure MITM client trust before expecting TLS-decrypted HTTP"
        }));
        assert!(lines.iter().any(|line| {
            line == "TLS-decrypted HTTP: blocked until MITM client trust is configured"
        }));
        assert!(lines.iter().any(|line| {
            line == "next action: MITM TLS trust needs attention: configure MITM client trust before expecting TLS-decrypted HTTP"
        }));
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_disabled_mitm_bridge_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut enforcement = configured_mitm_enforcement_status_json()?;
        enforcement["interception"]["runtime_l7_mitm"]["plaintext_bridge"]["mode"] =
            json!("disabled_after_error");
        enforcement["interception"]["runtime_l7_mitm"]["plaintext_bridge"]["disable_reason"] =
            json!("feed writer closed");
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "capture_event_feed",
                    "selected_input_source": "mitm_plaintext_bridge",
                    "mode": "capture_event_feed",
                    "reason": null,
                    "candidates": [],
                    "open_failures": []
                },
                "enforcement": enforcement
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert!(lines.iter().any(|line| {
            line == &format!(
                "path labels: {MITM_HTTP_PATH_LABEL}=plain HTTP, {MITM_TLS_PATH_LABEL}=TLS-decrypted HTTP"
            )
        }));
        assert!(lines.iter().any(|line| {
            line == "plain HTTP: blocked because MITM proxy event feed runtime is disabled: feed writer closed"
        }));
        assert!(lines.iter().any(|line| {
            line == "TLS-decrypted HTTP: blocked because MITM proxy event feed runtime is disabled: feed writer closed"
        }));
        assert!(
            lines
                .iter()
                .any(|line| line == "l7 mitm proxy event feed runtime: disabled_after_error")
        );
        assert!(
            lines.iter().any(|line| {
                line == "next action: MITM backend is unhealthy: feed writer closed"
            })
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_warn_when_live_capture_has_disabled_mitm_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut enforcement = configured_mitm_enforcement_status_json()?;
        enforcement["interception"]["runtime_l7_mitm"]["plaintext_bridge"]["mode"] =
            json!("disabled_after_error");
        enforcement["interception"]["runtime_l7_mitm"]["plaintext_bridge"]["disable_reason"] =
            json!("feed writer closed");
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "libpcap",
                    "selected_input_source": "live_host",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": [
                        {
                            "backend": "ebpf",
                            "reason": "permission denied"
                        }
                    ]
                },
                "enforcement": enforcement
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(false),
            Some(CaptureDiagnosticMessage::Warning(
                "Capture using libpcap; passive fallback occurred (ebpf: permission denied); MITM proxy event feed disabled: feed writer closed"
                    .to_string()
            ))
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_reports_runtime_fallback() -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "libpcap",
                    "mode": "live",
                    "reason": null,
                    "candidates": [],
                    "open_failures": [
                        {
                            "backend": "ebpf",
                            "reason": "permission denied"
                        }
                    ]
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(false),
            Some(CaptureDiagnosticMessage::Warning(
                "Capture using libpcap; passive fallback occurred (ebpf: permission denied)"
                    .to_string()
            ))
        );
        assert_eq!(
            diagnostics.tail_attribution_mode(),
            crate::admin::EventTailAttributionMode::IncludeUnknownProcess
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_label_mitm_bridge_capture_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "capture_event_feed",
                    "selected_input_source": "mitm_plaintext_bridge",
                    "mode": "capture_event_feed",
                    "reason": null,
                    "candidates": [],
                    "open_failures": [
                        {
                            "backend": "ebpf",
                            "reason": "object path is not configured"
                        },
                        {
                            "backend": "libpcap",
                            "reason": "libpcap is not installed"
                        }
                    ],
                    "auto_mitm_plaintext_bridge_candidate": {
                        "backend": "capture_event_feed",
                        "runtime_mode": "available",
                        "capability_mode": "available",
                        "evidence_mode": "nominal",
                        "reason": null,
                        "evidence_reason": null
                    }
                },
                "enforcement": configured_mitm_enforcement_status_json()?
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(false),
            Some(CaptureDiagnosticMessage::Warning(format!(
                "Passive capture failed (ebpf: object path is not configured; libpcap: libpcap is not installed); using reliable MITM proxy data path for {MITM_PLAINTEXT_COVERAGE}; MITM proxy path ready for plain HTTP; TLS-decrypted HTTP status is unknown"
            )))
        );
        let lines = diagnostics.detail_lines();
        assert!(
            lines
                .iter()
                .any(|line| line == "selected: reliable MITM proxy data path")
        );
        assert!(
            lines
                .iter()
                .any(|line| line == "provider backend: capture_event_feed")
        );
        assert_detail_line(
            &lines,
            "data path priority: passive capture (ebpf -> libpcap), scoped reliable MITM proxy data path",
        );
        assert!(
            lines
                .iter()
                .any(|line| line == &format!("coverage: {MITM_PLAINTEXT_COVERAGE}"))
        );
        assert!(lines.iter().any(|line| {
            line == "auto reliable MITM proxy data path candidate: capture_event_feed: runtime=available, capability=available, evidence=nominal"
        }));
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_surface_plain_and_tls_mitm_visibility_when_bridge_replaces_passive_capture()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "capture_event_feed",
                    "selected_input_source": "mitm_plaintext_bridge",
                    "mode": "capture_event_feed",
                    "reason": null,
                    "candidates": [],
                    "open_failures": [
                        {
                            "backend": "ebpf",
                            "reason": "object path is not configured"
                        },
                        {
                            "backend": "libpcap",
                            "reason": "libpcap is not installed"
                        }
                    ],
                    "auto_mitm_plaintext_bridge_candidate": {
                        "backend": "capture_event_feed",
                        "runtime_mode": "available",
                        "capability_mode": "available",
                        "evidence_mode": "nominal",
                        "reason": null,
                        "evidence_reason": null
                    }
                },
                "tls": mitm_tls_material_status_json("available", None, "available", None),
                "enforcement": configured_mitm_enforcement_status_json()?
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Warning(format!(
                "Passive capture failed (ebpf: object path is not configured; libpcap: libpcap is not installed); using reliable MITM proxy data path for {MITM_PLAINTEXT_COVERAGE}; MITM proxy path ready for plain HTTP and TLS-decrypted HTTP after client trust; no matching events yet"
            )))
        );
        Ok(())
    }

    #[test]
    fn mitm_bridge_ready_status_uses_data_path_message_once_without_passive_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": mitm_bridge_capture_status_json(),
                "tls": mitm_tls_material_status_json("available", None, "available", None),
                "enforcement": configured_mitm_enforcement_status_json()?
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        let Some(CaptureDiagnosticMessage::Info(message)) = diagnostics.status_message(true) else {
            panic!("ready MITM bridge should report an info status");
        };
        assert!(message.starts_with(
            "MITM proxy path ready for plain HTTP and TLS-decrypted HTTP after client trust"
        ));
        assert_eq!(message.matches("no matching events yet").count(), 1);
        assert!(!message.contains("reliable MITM proxy data path active"));
        Ok(())
    }

    #[test]
    fn mitm_bridge_blocked_status_does_not_claim_active_no_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut enforcement = configured_mitm_enforcement_status_json()?;
        enforcement["interception"]["runtime_l7_mitm"]["plaintext_bridge"]["mode"] =
            json!("disabled_after_error");
        enforcement["interception"]["runtime_l7_mitm"]["plaintext_bridge"]["disable_reason"] =
            json!("feed writer closed");
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": mitm_bridge_capture_status_json(),
                "enforcement": enforcement
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        let Some(CaptureDiagnosticMessage::Warning(message)) = diagnostics.status_message(true)
        else {
            panic!("blocked MITM bridge should report a warning status");
        };
        assert_eq!(
            message,
            "MITM proxy event feed disabled: feed writer closed"
        );
        assert!(!message.contains("active"));
        assert!(!message.contains("no matching events yet"));
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_configured_passive_fallback_order_for_mitm_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "capture_event_feed",
                    "selected_input_source": "mitm_plaintext_bridge",
                    "mode": "capture_event_feed",
                    "reason": null,
                    "candidates": [
                        {
                            "backend": "libpcap",
                            "runtime_mode": "unavailable",
                            "capability_mode": "unavailable",
                            "evidence_mode": "nominal",
                            "reason": "libpcap is not available"
                        },
                        {
                            "backend": "ebpf",
                            "runtime_mode": "unavailable",
                            "capability_mode": "unavailable",
                            "evidence_mode": "nominal",
                            "reason": "eBPF unavailable"
                        },
                        {
                            "backend": "capture_event_feed",
                            "runtime_mode": "available",
                            "capability_mode": "available",
                            "evidence_mode": "nominal",
                            "reason": null,
                            "evidence_reason": null
                        }
                    ],
                    "open_failures": [],
                    "auto_mitm_plaintext_bridge_candidate": {
                        "backend": "capture_event_feed",
                        "runtime_mode": "available",
                        "capability_mode": "available",
                        "evidence_mode": "nominal",
                        "reason": null,
                        "evidence_reason": null
                    }
                },
                "enforcement": configured_mitm_enforcement_status_json()?
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;
        let lines = diagnostics.detail_lines();

        assert_detail_line(
            &lines,
            "data path priority: passive capture (libpcap -> ebpf), scoped reliable MITM proxy data path",
        );
        Ok(())
    }

    #[test]
    fn local_status_text_does_not_claim_mitm_bridge_is_running()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "capture_event_feed",
                    "selected_input_source": "mitm_plaintext_bridge",
                    "mode": "capture_event_feed",
                    "reason": null,
                    "candidates": [],
                    "open_failures": []
                }
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert!(diagnostics.running_status_text(true).contains("active"));
        let local = diagnostics.local_status_text();
        assert!(
            local.contains("local config uses"),
            "local status should describe readiness projection: {local}"
        );
        assert!(
            !local.contains("active") && !local.contains("no matching events yet"),
            "local status must not use running-agent wording: {local}"
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_warn_when_mitm_bridge_replaces_unavailable_passive_capture()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "capture_event_feed",
                    "selected_input_source": "mitm_plaintext_bridge",
                    "mode": "capture_event_feed",
                    "reason": null,
                    "candidates": [
                        {
                            "backend": "ebpf",
                            "runtime_mode": "unavailable",
                            "capability_mode": "unavailable",
                            "evidence_mode": "nominal",
                            "reason": "capture.ebpf.object_path is not configured"
                        },
                        {
                            "backend": "libpcap",
                            "runtime_mode": "unavailable",
                            "capability_mode": "unavailable",
                            "evidence_mode": "nominal",
                            "reason": "libpcap is not available"
                        },
                        {
                            "backend": "capture_event_feed",
                            "runtime_mode": "available",
                            "capability_mode": "available",
                            "evidence_mode": "nominal",
                            "reason": null,
                            "evidence_reason": null
                        }
                    ],
                    "open_failures": [],
                    "auto_mitm_plaintext_bridge_candidate": {
                        "backend": "capture_event_feed",
                        "runtime_mode": "available",
                        "capability_mode": "available",
                        "evidence_mode": "nominal",
                        "reason": null,
                        "evidence_reason": null
                    }
                },
                "enforcement": configured_mitm_enforcement_status_json()?
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Warning(format!(
                "Passive capture unavailable (ebpf: capture.ebpf.object_path is not configured; libpcap: libpcap is not available); using reliable MITM proxy data path for {MITM_PLAINTEXT_COVERAGE}; MITM proxy path ready for plain HTTP; TLS-decrypted HTTP status is unknown"
            )))
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_do_not_label_generic_feed_as_mitm()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "traffic_status",
                "projection": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": "capture_event_feed",
                    "selected_input_source": "configured_capture_event_feed",
                    "mode": "capture_event_feed",
                    "reason": null,
                    "candidates": [],
                    "open_failures": [
                        {
                            "backend": "ebpf",
                            "reason": "object path is not configured"
                        }
                    ]
                },
                "enforcement": configured_mitm_enforcement_status_json()?
            }
        });

        let diagnostics = parse_traffic_runtime_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(false),
            Some(CaptureDiagnosticMessage::Warning(
                "Capture using capture_event_feed; passive fallback occurred (ebpf: object path is not configured)"
                    .to_string()
            ))
        );
        assert!(
            diagnostics
                .detail_lines()
                .iter()
                .any(|line| line == "selected: capture_event_feed")
        );
        Ok(())
    }

    fn configured_mitm_enforcement_status_json() -> Result<Value, Box<dyn std::error::Error>> {
        configured_mitm_enforcement_status_json_with_material(MitmMaterialFixture::DynamicCa)
    }

    fn configured_static_leaf_mitm_enforcement_status_json()
    -> Result<Value, Box<dyn std::error::Error>> {
        configured_mitm_enforcement_status_json_with_material(MitmMaterialFixture::StaticLeaf)
    }

    fn configured_ca_and_leaf_mitm_enforcement_status_json()
    -> Result<Value, Box<dyn std::error::Error>> {
        configured_mitm_enforcement_status_json_with_material(MitmMaterialFixture::CaAndLeaf)
    }

    fn mitm_bridge_capture_status_json() -> Value {
        json!({
            "selection": "auto",
            "selected_backend": "capture_event_feed",
            "selected_input_source": "mitm_plaintext_bridge",
            "mode": "capture_event_feed",
            "reason": null,
            "candidates": [],
            "open_failures": []
        })
    }

    fn configured_mitm_enforcement_status_json_with_material(
        material: MitmMaterialFixture,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let bridge_path = "/home/user/.local/state/traffic-probe/mitm/feed.jsonl";
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Auto;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some("127.0.0.1:15002".to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        config.enforcement.interception.mitm.client_trust.mode =
            probe_config::TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(bridge_path.into());
        match material {
            MitmMaterialFixture::DynamicCa => {
                config.enforcement.interception.mitm.ca_certificate_ref =
                    Some("mitm-ca".to_string());
                config.enforcement.interception.mitm.ca_private_key_ref =
                    Some("mitm-ca-key".to_string());
            }
            MitmMaterialFixture::StaticLeaf => {
                config
                    .enforcement
                    .interception
                    .mitm
                    .leaf_certificate_chain_refs = vec!["mitm-leaf".to_string()];
                config.enforcement.interception.mitm.leaf_private_key_ref =
                    Some("mitm-leaf-key".to_string());
            }
            MitmMaterialFixture::CaAndLeaf => {
                config.enforcement.interception.mitm.ca_certificate_ref =
                    Some("mitm-ca".to_string());
                config.enforcement.interception.mitm.ca_private_key_ref =
                    Some("mitm-ca-key".to_string());
                config
                    .enforcement
                    .interception
                    .mitm
                    .leaf_certificate_chain_refs = vec!["mitm-leaf".to_string()];
                config.enforcement.interception.mitm.leaf_private_key_ref =
                    Some("mitm-leaf-key".to_string());
            }
        }
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: "/tmp/traffic-probe-enforcement.toml".into(),
        };
        config.tls.materials = material.tls_materials();
        let plan = RuntimePlan::build(
            config,
            &ProviderRegistry::new(
                vec![
                    CaptureProviderDescriptor::unavailable(
                        probe_config::CaptureBackend::Ebpf,
                        CaptureProviderBuilder::Unimplemented,
                        "eBPF unavailable",
                    ),
                    CaptureProviderDescriptor::unavailable(
                        probe_config::CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Unimplemented,
                        "libpcap unavailable",
                    ),
                    CaptureProviderDescriptor::available(
                        probe_config::CaptureBackend::CaptureEventFeed,
                        CaptureProviderBuilder::CaptureEventFeed,
                    ),
                ],
                vec![
                    CapabilityState::available(CapabilityKind::Http1),
                    CapabilityState::available(CapabilityKind::Sse),
                    CapabilityState::available(CapabilityKind::WebSocketHandoff),
                    CapabilityState::available(CapabilityKind::WebSocketFrame),
                    CapabilityState::available(CapabilityKind::TransparentInterception),
                    CapabilityState::available(CapabilityKind::L7Mitm),
                    CapabilityState::available(CapabilityKind::CaptureEventFeed),
                ],
            ),
        )?;
        let l7_mitm = L7MitmRuntimeSnapshot {
            backend_health: L7MitmBackendHealthSnapshot {
                mode: TcpHealthMode::Healthy,
                check_successes: 3,
                check_failures: 0,
                consecutive_failures: 0,
                last_failure_reason: None,
            },
            client_trust: L7MitmClientTrustSnapshot {
                mode: L7MitmClientTrustMode::OperatorManaged,
                material: material.client_trust_material_mode(),
                reason: Some("operator managed".to_string()),
            },
            plaintext_bridge: L7MitmPlaintextBridgeSnapshot {
                mode: L7MitmPlaintextBridgeMode::Active,
                disable_reason: None,
            },
        };
        Ok(serde_json::to_value(
            enforcement_status_with_transparent_proxy_for_test(&plan, Some(l7_mitm), None),
        )?)
    }

    fn mitm_tls_material_status_json(
        certificate_mode: &str,
        certificate_reason: Option<&str>,
        private_key_mode: &str,
        private_key_reason: Option<&str>,
    ) -> Value {
        json!({
            "materials": [
                {
                    "kind": "mitm_ca_certificate",
                    "path": MITM_CA_CERTIFICATE_PATH,
                    "purpose": "mitm",
                    "source": {
                        "check": "metadata_only",
                        "mode": certificate_mode,
                        "reason": certificate_reason
                    }
                },
                {
                    "kind": "mitm_ca_private_key",
                    "path": MITM_CA_PRIVATE_KEY_PATH,
                    "purpose": "mitm",
                    "source": {
                        "check": "metadata_only",
                        "mode": private_key_mode,
                        "reason": private_key_reason
                    }
                }
            ]
        })
    }

    fn mitm_static_leaf_tls_material_status_json(
        certificate_mode: &str,
        certificate_reason: Option<&str>,
        private_key_mode: &str,
        private_key_reason: Option<&str>,
    ) -> Value {
        json!({
            "materials": [
                {
                    "kind": "mitm_leaf_certificate",
                    "path": MITM_LEAF_CERTIFICATE_PATH,
                    "purpose": "mitm",
                    "source": {
                        "check": "metadata_only",
                        "mode": certificate_mode,
                        "reason": certificate_reason
                    }
                },
                {
                    "kind": "mitm_leaf_private_key",
                    "path": MITM_LEAF_PRIVATE_KEY_PATH,
                    "purpose": "mitm",
                    "source": {
                        "check": "metadata_only",
                        "mode": private_key_mode,
                        "reason": private_key_reason
                    }
                }
            ]
        })
    }

    fn mitm_ca_and_leaf_tls_material_status_json(
        leaf_certificate_mode: &str,
        leaf_certificate_reason: Option<&str>,
        leaf_private_key_mode: &str,
        leaf_private_key_reason: Option<&str>,
    ) -> Value {
        let mut status = mitm_tls_material_status_json("available", None, "available", None);
        let leaf_status = mitm_static_leaf_tls_material_status_json(
            leaf_certificate_mode,
            leaf_certificate_reason,
            leaf_private_key_mode,
            leaf_private_key_reason,
        );
        status["materials"]
            .as_array_mut()
            .expect("materials should be an array")
            .extend(
                leaf_status["materials"]
                    .as_array()
                    .expect("leaf materials should be an array")
                    .iter()
                    .cloned(),
            );
        status
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::available(CapabilityKind::CaptureEventFeed),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not configured"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not configured"),
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not configured"),
            CapabilityState::unavailable(
                CapabilityKind::TransparentProcessClassifier,
                "not configured",
            ),
            CapabilityState::unavailable(
                CapabilityKind::TransparentFlowClassifier,
                "not configured",
            ),
            CapabilityState::unavailable(CapabilityKind::L7Mitm, "not configured"),
        ]
    }

    #[derive(Debug, Clone, Copy)]
    enum MitmMaterialFixture {
        DynamicCa,
        StaticLeaf,
        CaAndLeaf,
    }

    impl MitmMaterialFixture {
        fn tls_materials(self) -> Vec<TlsMaterialConfig> {
            match self {
                Self::DynamicCa => vec![
                    TlsMaterialConfig {
                        id: Some("mitm-ca".to_string()),
                        kind: TlsMaterialKind::MitmCaCertificate,
                        path: MITM_CA_CERTIFICATE_PATH.into(),
                    },
                    TlsMaterialConfig {
                        id: Some("mitm-ca-key".to_string()),
                        kind: TlsMaterialKind::MitmCaPrivateKey,
                        path: MITM_CA_PRIVATE_KEY_PATH.into(),
                    },
                ],
                Self::StaticLeaf => vec![
                    TlsMaterialConfig {
                        id: Some("mitm-leaf".to_string()),
                        kind: TlsMaterialKind::MitmLeafCertificate,
                        path: MITM_LEAF_CERTIFICATE_PATH.into(),
                    },
                    TlsMaterialConfig {
                        id: Some("mitm-leaf-key".to_string()),
                        kind: TlsMaterialKind::MitmLeafPrivateKey,
                        path: MITM_LEAF_PRIVATE_KEY_PATH.into(),
                    },
                ],
                Self::CaAndLeaf => {
                    let mut materials = Self::DynamicCa.tls_materials();
                    materials.extend(Self::StaticLeaf.tls_materials());
                    materials
                }
            }
        }

        fn client_trust_material_mode(self) -> L7MitmClientTrustMaterialMode {
            match self {
                Self::DynamicCa => L7MitmClientTrustMaterialMode::CaCertificateAuthority,
                Self::StaticLeaf => L7MitmClientTrustMaterialMode::LeafCertificateChain,
                Self::CaAndLeaf => L7MitmClientTrustMaterialMode::CaAndLeafCertificateChain,
            }
        }
    }
}

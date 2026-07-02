use std::{path::Path, time::Duration};

use serde_json::Value;
use thiserror::Error;

use probe_config::TransparentInterceptionStrategyConfig;
use probe_core::{CapabilityKind, RuntimeMode};
use runtime::{
    RequiredCapabilityPlan, TransparentInterceptionMitmBackendPlan,
    TransparentInterceptionMitmBackendReadinessProbePlan,
    TransparentInterceptionMitmClientTrustPlan, TransparentInterceptionMitmPlaintextBridgePlan,
};

use crate::{
    admin::{AdminClientError, AdminRequest, send_admin_json_request_with_timeout},
    l7_mitm::{L7MitmPlaintextBridgeMode, L7MitmRuntimeSnapshot},
    status::{CaptureStatusSnapshot, EnforcementStatusMode, EnforcementStatusSnapshot},
    tcp_health::{TcpHealthMode, TcpHealthSnapshot},
    transparent_interception::{TransparentProxyRuntimeMode, TransparentProxyRuntimeSnapshot},
};

use super::wire::capture_selection_name;

const STATUS_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) async fn request_traffic_runtime_diagnostics(
    socket_path: &Path,
) -> Result<TrafficRuntimeDiagnostics, RuntimeStatusClientError> {
    let response =
        send_admin_json_request_with_timeout(socket_path, AdminRequest::Status, STATUS_TIMEOUT)
            .await
            .map_err(RuntimeStatusClientError::AdminClient)?;
    parse_traffic_runtime_diagnostics_response(&response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficRuntimeDiagnostics {
    capture: CaptureStatusSnapshot,
    mitm: Option<MitmDiagnostics>,
}

impl TrafficRuntimeDiagnostics {
    #[cfg(test)]
    pub(crate) fn from_capture_snapshot(capture: CaptureStatusSnapshot) -> Self {
        Self {
            capture,
            mitm: None,
        }
    }

    pub(crate) fn status_message(&self, traffic_empty: bool) -> Option<CaptureDiagnosticMessage> {
        if self.capture_unavailable() {
            return Some(CaptureDiagnosticMessage::Error(format!(
                "Capture unavailable: {}; {}",
                self.failure_summary(),
                self.mitm_next_step()
            )));
        }
        if let Some(failure) = self.capture.open_failures.first() {
            return Some(CaptureDiagnosticMessage::Warning(format!(
                "Capture using {}; {} failed: {}",
                self.selected_backend_label(),
                capture_backend_name(failure.backend),
                failure.reason
            )));
        }
        traffic_empty.then(|| {
            CaptureDiagnosticMessage::Info(format!(
                "Capture {} active; no matching events yet",
                self.selected_backend_label()
            ))
        })
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            "Capture diagnostics".to_string(),
            format!(
                "selection: {}",
                capture_selection_name(self.capture.selection)
            ),
            format!("selected: {}", self.selected_backend_label()),
            format!("mode: {}", capture_plan_mode_name(self.capture.mode)),
        ];
        if let Some(reason) = &self.capture.reason {
            lines.push(format!("reason: {reason}"));
        }
        if !self.capture.candidates.is_empty() {
            lines.push("provider candidates:".to_string());
            lines.extend(self.capture.candidates.iter().map(|candidate| {
                let mut details = vec![
                    format!("runtime={}", runtime_mode_name(candidate.runtime_mode)),
                    format!(
                        "capability={}",
                        runtime_mode_name(candidate.capability_mode)
                    ),
                    format!("evidence={}", evidence_mode_name(candidate.evidence_mode)),
                ];
                if let Some(reason) = &candidate.reason {
                    details.push(format!("reason={reason}"));
                }
                if let Some(reason) = &candidate.evidence_reason {
                    details.push(format!("evidence_reason={reason}"));
                }
                format!(
                    "{}: {}",
                    capture_backend_name(candidate.backend),
                    details.join(", ")
                )
            }));
        }
        if !self.capture.open_failures.is_empty() {
            lines.push("runtime open failures:".to_string());
            lines.extend(self.capture.open_failures.iter().map(|failure| {
                format!(
                    "{}: {}",
                    capture_backend_name(failure.backend),
                    failure.reason
                )
            }));
        }
        lines.extend(self.mitm_detail_lines());
        lines
    }

    fn mitm_detail_lines(&self) -> Vec<String> {
        self.mitm.as_ref().map_or_else(
            || {
                vec![
                    "MITM diagnostics".to_string(),
                    "strategy: disabled".to_string(),
                    "next action: configure transparent MITM when passive capture is unavailable or when full HTTP/TLS content visibility is needed".to_string(),
                ]
            },
            MitmDiagnostics::detail_lines,
        )
    }

    fn capture_unavailable(&self) -> bool {
        self.capture.selected_backend.is_none()
            || self.capture.mode == runtime::CapturePlanMode::Unavailable
    }

    fn selected_backend_label(&self) -> &'static str {
        self.capture
            .selected_backend
            .map(capture_backend_name)
            .unwrap_or("none")
    }

    fn failure_summary(&self) -> String {
        let mut reasons = self
            .capture
            .candidates
            .iter()
            .filter_map(|candidate| {
                candidate
                    .reason
                    .as_ref()
                    .or(candidate.evidence_reason.as_ref())
                    .map(|reason| format!("{}: {reason}", capture_backend_name(candidate.backend)))
            })
            .collect::<Vec<_>>();
        reasons.extend(self.capture.open_failures.iter().map(|failure| {
            format!(
                "{}: {}",
                capture_backend_name(failure.backend),
                failure.reason
            )
        }));
        if reasons.is_empty() {
            self.capture
                .reason
                .clone()
                .unwrap_or_else(|| "no live provider is available".to_string())
        } else {
            reasons.join("; ")
        }
    }

    fn mitm_next_step(&self) -> String {
        self.mitm.as_ref().map_or_else(
            || "MITM path is not configured".to_string(),
            MitmDiagnostics::next_step,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CaptureDiagnosticMessage {
    Info(String),
    Warning(String),
    Error(String),
}

#[derive(Debug, Error)]
pub(crate) enum RuntimeStatusClientError {
    #[error("admin client error: {0}")]
    AdminClient(AdminClientError),
    #[error("admin status response is missing snapshot.capture")]
    MissingCapture,
    #[error("admin status failed: {0}")]
    Admin(String),
    #[error("unexpected admin response kind: {kind}")]
    UnexpectedResponse { kind: String },
    #[error("failed to parse admin status response: {0}")]
    Json(serde_json::Error),
}

fn parse_traffic_runtime_diagnostics_response(
    response: &Value,
) -> Result<TrafficRuntimeDiagnostics, RuntimeStatusClientError> {
    match response.get("kind").and_then(Value::as_str) {
        Some("status") => {
            let snapshot = response
                .get("snapshot")
                .ok_or(RuntimeStatusClientError::MissingCapture)?;
            let capture = snapshot
                .get("capture")
                .cloned()
                .ok_or(RuntimeStatusClientError::MissingCapture)?;
            let capture = serde_json::from_value::<CaptureStatusSnapshot>(capture)
                .map_err(RuntimeStatusClientError::Json)?;
            let mitm = snapshot
                .get("enforcement")
                .cloned()
                .map(parse_mitm_diagnostics)
                .transpose()?
                .flatten();
            Ok(TrafficRuntimeDiagnostics { capture, mitm })
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

fn parse_mitm_diagnostics(
    enforcement: Value,
) -> Result<Option<MitmDiagnostics>, RuntimeStatusClientError> {
    let enforcement = serde_json::from_value::<EnforcementStatusSnapshot>(enforcement)
        .map_err(RuntimeStatusClientError::Json)?;
    Ok(MitmDiagnostics::from_enforcement(enforcement))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MitmDiagnostics {
    enforcement_status: EnforcementStatusMode,
    strategy: TransparentInterceptionStrategyConfig,
    selector_configured: bool,
    backend: TransparentInterceptionMitmBackendPlan,
    client_trust: TransparentInterceptionMitmClientTrustPlan,
    plaintext_bridge: TransparentInterceptionMitmPlaintextBridgePlan,
    capabilities: Vec<RequiredCapabilityPlan>,
    runtime_l7_mitm: Option<L7MitmRuntimeSnapshot>,
    runtime_proxy: Option<TransparentProxyRuntimeSnapshot>,
}

impl MitmDiagnostics {
    fn from_enforcement(enforcement: EnforcementStatusSnapshot) -> Option<Self> {
        let interception = enforcement.interception;
        let mitm = interception.mitm;
        let diagnostics = Self {
            enforcement_status: enforcement.status,
            strategy: interception.strategy,
            selector_configured: interception.selector_configured,
            backend: mitm.backend,
            client_trust: mitm.client_trust,
            plaintext_bridge: mitm.plaintext_bridge,
            capabilities: interception.capabilities,
            runtime_l7_mitm: interception.runtime_l7_mitm,
            runtime_proxy: interception.runtime_proxy,
        };
        diagnostics.is_relevant().then_some(diagnostics)
    }

    fn is_relevant(&self) -> bool {
        self.strategy.is_mitm()
            || !matches!(
                self.backend,
                TransparentInterceptionMitmBackendPlan::Disabled
            )
            || !matches!(
                self.plaintext_bridge,
                TransparentInterceptionMitmPlaintextBridgePlan::Disabled
            )
            || self.runtime_l7_mitm.is_some()
    }

    fn next_step(&self) -> String {
        if !self.selector_configured {
            return "MITM path is configured but has no scoped interception selector".to_string();
        }
        if let Some(capability) = self.first_unavailable_capability() {
            return format!(
                "MITM path is blocked by {}: {}",
                capability_kind_name(capability.capability),
                capability
                    .reason
                    .as_deref()
                    .unwrap_or("required capability is unavailable")
            );
        }
        if self
            .runtime_l7_mitm
            .as_ref()
            .is_some_and(l7_mitm_runtime_is_unhealthy)
        {
            return self
                .runtime_l7_mitm
                .as_ref()
                .and_then(l7_mitm_runtime_unhealthy_reason)
                .map(|reason| format!("MITM backend is unhealthy: {reason}"))
                .unwrap_or_else(|| "MITM backend is unhealthy".to_string());
        }
        if matches!(
            self.plaintext_bridge,
            TransparentInterceptionMitmPlaintextBridgePlan::Disabled
        ) {
            return "MITM path needs a plaintext bridge to feed captured HTTP/TLS plaintext into traffic events".to_string();
        }
        "MITM path is configured; inspect backend health, client trust, and plaintext bridge status"
            .to_string()
    }

    fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            "MITM diagnostics".to_string(),
            format!("strategy: {}", interception_strategy_name(self.strategy)),
            format!(
                "enforcement: {}",
                enforcement_status_name(self.enforcement_status)
            ),
            format!(
                "selector: {}",
                if self.selector_configured {
                    "configured"
                } else {
                    "missing"
                }
            ),
            format!(
                "backend: {}{}",
                mitm_backend_name(&self.backend),
                mitm_backend_readiness_target(&self.backend)
                    .map(|target| format!(" readiness={target}"))
                    .unwrap_or_default()
            ),
            format!(
                "client trust: {}",
                mitm_client_trust_name(&self.client_trust)
            ),
            self.plaintext_bridge_line(),
        ];
        if !self.capabilities.is_empty() {
            lines.push("required capabilities:".to_string());
            lines.extend(
                self.capabilities
                    .iter()
                    .map(required_capability_detail_line),
            );
        }
        if let Some(runtime) = &self.runtime_l7_mitm {
            lines.extend(l7_mitm_runtime_detail_lines(runtime));
        }
        if let Some(runtime) = &self.runtime_proxy {
            lines.extend(transparent_proxy_runtime_detail_lines(runtime));
        }
        lines.push(format!("next action: {}", self.next_step()));
        lines
    }

    fn plaintext_bridge_line(&self) -> String {
        let mut line = format!(
            "plaintext bridge: {}",
            mitm_plaintext_bridge_name(&self.plaintext_bridge)
        );
        if let Some(path) = mitm_plaintext_bridge_path(&self.plaintext_bridge) {
            line.push_str(&format!(" path={path}"));
        }
        if let Some(follow) = mitm_plaintext_bridge_follow(&self.plaintext_bridge) {
            line.push_str(&format!(" follow={follow}"));
        }
        line
    }

    fn first_unavailable_capability(&self) -> Option<&RequiredCapabilityPlan> {
        self.capabilities
            .iter()
            .find(|capability| capability.mode == RuntimeMode::Unavailable)
    }
}

fn required_capability_detail_line(capability: &RequiredCapabilityPlan) -> String {
    let mut line = format!(
        "{}: {}",
        capability_kind_name(capability.capability),
        runtime_mode_name(capability.mode)
    );
    if let Some(reason) = &capability.reason {
        line.push_str(&format!(" reason={reason}"));
    }
    line
}

fn l7_mitm_runtime_is_unhealthy(runtime: &L7MitmRuntimeSnapshot) -> bool {
    runtime.backend_health.mode == TcpHealthMode::Unhealthy
        || runtime.plaintext_bridge.mode == L7MitmPlaintextBridgeMode::DisabledAfterError
}

fn l7_mitm_runtime_unhealthy_reason(runtime: &L7MitmRuntimeSnapshot) -> Option<&str> {
    runtime
        .backend_health
        .last_failure_reason
        .as_deref()
        .or(runtime.plaintext_bridge.disable_reason.as_deref())
}

fn l7_mitm_runtime_detail_lines(runtime: &L7MitmRuntimeSnapshot) -> Vec<String> {
    let mut lines = vec![
        format!(
            "l7 mitm backend health: {} successes={} failures={} consecutive_failures={}",
            tcp_health_mode_name(runtime.backend_health.mode),
            runtime.backend_health.check_successes,
            runtime.backend_health.check_failures,
            runtime.backend_health.consecutive_failures
        ),
        format!(
            "l7 mitm client trust runtime: {} material={}",
            runtime.client_trust.mode.wire_name(),
            runtime.client_trust.material.wire_name()
        ),
        format!(
            "l7 mitm plaintext bridge runtime: {}",
            runtime.plaintext_bridge.mode.wire_name()
        ),
    ];
    if let Some(reason) = &runtime.backend_health.last_failure_reason {
        lines.push(format!("l7 mitm backend failure: {reason}"));
    }
    if let Some(reason) = &runtime.plaintext_bridge.disable_reason {
        lines.push(format!("l7 mitm bridge disabled: {reason}"));
    }
    lines
}

fn transparent_proxy_runtime_detail_lines(
    runtime: &TransparentProxyRuntimeSnapshot,
) -> Vec<String> {
    let mut lines = vec![format!(
        "transparent proxy runtime: {} active_relays={} accepted={} rejected={} relay_failures={} listener_failures={}",
        transparent_proxy_runtime_mode_name(runtime.mode),
        runtime.active_relays,
        runtime.accepted_relays,
        runtime.rejected_relays,
        runtime.relay_failures,
        runtime.listener_failures
    )];
    lines.push(tcp_health_detail_line(
        "transparent proxy health",
        &runtime.health_probe,
    ));
    if let Some(reason) = &runtime.health_probe.last_failure_reason {
        lines.push(format!("transparent proxy failure: {reason}"));
    }
    lines
}

fn tcp_health_detail_line(label: &str, health: &TcpHealthSnapshot) -> String {
    format!(
        "{label}: {} successes={} failures={} consecutive_failures={}",
        tcp_health_mode_name(health.mode),
        health.check_successes,
        health.check_failures,
        health.consecutive_failures
    )
}

fn interception_strategy_name(strategy: TransparentInterceptionStrategyConfig) -> &'static str {
    match strategy {
        TransparentInterceptionStrategyConfig::None => "none",
        TransparentInterceptionStrategyConfig::InboundTproxy => "inbound_tproxy",
        TransparentInterceptionStrategyConfig::OutboundTransparentProxy => {
            "outbound_transparent_proxy"
        }
        TransparentInterceptionStrategyConfig::InboundTproxyMitm => "inbound_tproxy_mitm",
        TransparentInterceptionStrategyConfig::OutboundTransparentMitm => {
            "outbound_transparent_mitm"
        }
    }
}

fn enforcement_status_name(status: EnforcementStatusMode) -> &'static str {
    match status {
        EnforcementStatusMode::Disabled => "disabled",
        EnforcementStatusMode::AuditOnly => "audit_only",
        EnforcementStatusMode::DryRun => "dry_run",
        EnforcementStatusMode::Enforce => "enforce",
    }
}

fn mitm_backend_name(backend: &TransparentInterceptionMitmBackendPlan) -> &'static str {
    match backend {
        TransparentInterceptionMitmBackendPlan::Disabled => "disabled",
        TransparentInterceptionMitmBackendPlan::External { .. } => "external",
        TransparentInterceptionMitmBackendPlan::ManagedProcess { .. } => "managed_process",
        TransparentInterceptionMitmBackendPlan::ProductProxy { .. } => "product_proxy",
    }
}

fn mitm_backend_readiness_target(
    backend: &TransparentInterceptionMitmBackendPlan,
) -> Option<String> {
    match backend {
        TransparentInterceptionMitmBackendPlan::Disabled => None,
        TransparentInterceptionMitmBackendPlan::External { readiness_probe }
        | TransparentInterceptionMitmBackendPlan::ManagedProcess {
            readiness_probe, ..
        }
        | TransparentInterceptionMitmBackendPlan::ProductProxy {
            readiness_probe, ..
        } => Some(mitm_readiness_probe_target(readiness_probe)),
    }
}

fn mitm_readiness_probe_target(
    readiness_probe: &TransparentInterceptionMitmBackendReadinessProbePlan,
) -> String {
    match readiness_probe {
        TransparentInterceptionMitmBackendReadinessProbePlan::TcpConnect { target, .. } => {
            target.to_string()
        }
    }
}

fn mitm_client_trust_name(
    client_trust: &TransparentInterceptionMitmClientTrustPlan,
) -> &'static str {
    match client_trust {
        TransparentInterceptionMitmClientTrustPlan::Disabled => "disabled",
        TransparentInterceptionMitmClientTrustPlan::OperatorManaged => "operator_managed",
    }
}

fn mitm_plaintext_bridge_name(
    bridge: &TransparentInterceptionMitmPlaintextBridgePlan,
) -> &'static str {
    match bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => "disabled",
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { .. } => {
            "capture_event_feed"
        }
    }
}

fn mitm_plaintext_bridge_path(
    bridge: &TransparentInterceptionMitmPlaintextBridgePlan,
) -> Option<String> {
    match bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => None,
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { path, .. } => {
            Some(path.display().to_string())
        }
    }
}

fn mitm_plaintext_bridge_follow(
    bridge: &TransparentInterceptionMitmPlaintextBridgePlan,
) -> Option<bool> {
    match bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => None,
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { follow, .. } => {
            Some(*follow)
        }
    }
}

fn capability_kind_name(kind: CapabilityKind) -> &'static str {
    kind.wire_name()
}

fn tcp_health_mode_name(mode: TcpHealthMode) -> &'static str {
    mode.wire_name()
}

fn transparent_proxy_runtime_mode_name(mode: TransparentProxyRuntimeMode) -> &'static str {
    mode.wire_name()
}

fn capture_backend_name(backend: probe_config::CaptureBackend) -> &'static str {
    match backend {
        probe_config::CaptureBackend::Ebpf => "ebpf",
        probe_config::CaptureBackend::Libpcap => "libpcap",
        probe_config::CaptureBackend::PlaintextFeed => "plaintext_feed",
        probe_config::CaptureBackend::CaptureEventFeed => "capture_event_feed",
        probe_config::CaptureBackend::Replay => "replay",
    }
}

fn capture_plan_mode_name(mode: runtime::CapturePlanMode) -> &'static str {
    match mode {
        runtime::CapturePlanMode::Live => "live",
        runtime::CapturePlanMode::PlaintextFeed => "plaintext_feed",
        runtime::CapturePlanMode::CaptureEventFeed => "capture_event_feed",
        runtime::CapturePlanMode::Replay => "replay",
        runtime::CapturePlanMode::Unavailable => "unavailable",
    }
}

fn runtime_mode_name(mode: probe_core::RuntimeMode) -> &'static str {
    match mode {
        probe_core::RuntimeMode::Available => "available",
        probe_core::RuntimeMode::Degraded => "degraded",
        probe_core::RuntimeMode::Unavailable => "unavailable",
    }
}

fn evidence_mode_name(mode: runtime::CaptureEvidenceMode) -> &'static str {
    match mode {
        runtime::CaptureEvidenceMode::Nominal => "nominal",
        runtime::CaptureEvidenceMode::BestEffort => "best_effort",
    }
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
            L7MitmClientTrustSnapshot, L7MitmPlaintextBridgeSnapshot,
        },
        status::enforcement_status_with_transparent_proxy_for_test,
    };

    #[test]
    fn traffic_diagnostics_summarize_unavailable_capture_and_missing_mitm()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "status",
            "snapshot": {
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
            Some(CaptureDiagnosticMessage::Error(
                "Capture unavailable: ebpf: capture.ebpf.object_path is not configured; libpcap: libpcap is not available; MITM path is not configured"
                    .to_string()
            ))
        );
        assert!(
            diagnostics
                .detail_lines()
                .iter()
                .any(|line| line == "strategy: disabled")
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_report_configured_mitm_path() -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "status",
            "snapshot": {
                "capture": {
                    "selection": "auto",
                    "selected_backend": null,
                    "mode": "unavailable",
                    "reason": "no passive provider is available",
                    "candidates": [],
                    "open_failures": []
                },
                "enforcement": configured_mitm_enforcement_status_json()?
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
                .any(|line| line.contains("plaintext bridge: capture_event_feed"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("l7 mitm backend health: healthy"))
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_reports_runtime_fallback() -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "status",
            "snapshot": {
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
                "Capture using libpcap; ebpf failed: permission denied".to_string()
            ))
        );
        Ok(())
    }

    fn configured_mitm_enforcement_status_json() -> Result<Value, Box<dyn std::error::Error>> {
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
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
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
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
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
                material: L7MitmClientTrustMaterialMode::CaCertificateAuthority,
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
}

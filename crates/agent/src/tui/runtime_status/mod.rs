use std::{path::Path, time::Duration};

use serde_json::Value;
use thiserror::Error;

mod capture;
mod mitm;

use crate::{
    admin::{AdminClientError, AdminRequest, send_admin_json_request_with_timeout},
    status::{CaptureStatusSnapshot, EnforcementStatusSnapshot},
    tui::{
        controls::ControlId,
        copy::{MITM_PLAINTEXT_COVERAGE, MITM_QUICK_SETUP_APPLY},
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
    let response =
        send_admin_json_request_with_timeout(socket_path, AdminRequest::Status, STATUS_TIMEOUT)
            .await
            .map_err(RuntimeStatusClientError::AdminClient)?;
    parse_traffic_runtime_diagnostics_response(&response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficRuntimeDiagnostics {
    capture: CaptureDiagnostics,
    mitm: Option<MitmDiagnostics>,
}

impl TrafficRuntimeDiagnostics {
    #[cfg(test)]
    pub(crate) fn from_capture_snapshot(capture: CaptureStatusSnapshot) -> Self {
        Self {
            capture: CaptureDiagnostics::new(capture),
            mitm: None,
        }
    }

    pub(crate) fn status_message(&self, traffic_empty: bool) -> Option<CaptureDiagnosticMessage> {
        let mitm_next_step = self.mitm_next_step();
        self.capture
            .status_message(traffic_empty, mitm_next_step.as_str())
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = self.capture.detail_lines();
        lines.extend(self.mitm_detail_lines());
        lines
    }

    fn mitm_detail_lines(&self) -> Vec<String> {
        self.mitm.as_ref().map_or_else(
            || {
                vec![
                    "MITM diagnostics".to_string(),
                    "strategy: disabled".to_string(),
                    format!("coverage: {MITM_PLAINTEXT_COVERAGE}"),
                    format!("quick setup: {}", missing_mitm_quick_setup_action()),
                    format!("apply: {MITM_QUICK_SETUP_APPLY}"),
                    format!("next action: {}", missing_mitm_next_step()),
                ]
            },
            MitmDiagnostics::detail_lines,
        )
    }

    fn mitm_next_step(&self) -> String {
        self.mitm
            .as_ref()
            .map_or_else(missing_mitm_next_step, MitmDiagnostics::next_step)
    }
}

fn missing_mitm_next_step() -> String {
    format!(
        "configure MITM fallback for {MITM_PLAINTEXT_COVERAGE}: {}",
        missing_mitm_quick_setup_action()
    )
}

pub(crate) fn missing_mitm_quick_setup_action() -> String {
    format!(
        "select a process in Traffic, then use {} for outbound clients or {} for server listeners",
        ControlId::ConfigureOutboundMitm.traffic_action_label(),
        ControlId::ConfigureInboundMitm.traffic_action_label()
    )
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
            let tls = snapshot.get("tls").cloned();
            let mitm = snapshot
                .get("enforcement")
                .cloned()
                .map(|enforcement| parse_mitm_diagnostics(enforcement, tls))
                .transpose()?
                .flatten();
            Ok(TrafficRuntimeDiagnostics {
                capture: CaptureDiagnostics::new(capture),
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
        status::enforcement_status_with_transparent_proxy_for_test,
        tcp_health::TcpHealthMode,
        tui::{
            controls::ControlId,
            copy::{
                MITM_HTTP_PATH_LABEL, MITM_PLAINTEXT_COVERAGE, MITM_QUICK_SETUP_APPLY,
                MITM_TLS_PATH_LABEL, MITM_TLS_TRUST_ACTION,
            },
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
            Some(CaptureDiagnosticMessage::Error(format!(
                "Capture unavailable: ebpf: capture.ebpf.object_path is not configured; libpcap: libpcap is not available; configure MITM fallback for {MITM_PLAINTEXT_COVERAGE}: {}",
                missing_mitm_quick_setup_action()
            )))
        );
        let lines = diagnostics.detail_lines();
        assert!(lines.iter().any(|line| line == "strategy: disabled"));
        assert!(lines.iter().any(|line| {
            line.contains(ControlId::ConfigureOutboundMitm.traffic_action_label())
                && line.contains(ControlId::ConfigureInboundMitm.traffic_action_label())
        }));
        assert!(
            lines
                .iter()
                .any(|line| line == &format!("quick setup: {}", missing_mitm_quick_setup_action()))
        );
        assert!(
            lines
                .iter()
                .any(|line| line == &format!("apply: {MITM_QUICK_SETUP_APPLY}"))
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
                .any(|line| line.contains("plaintext bridge: capture_event_feed"))
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
    fn traffic_diagnostics_report_unavailable_mitm_tls_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "status",
            "snapshot": {
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
            "kind": "status",
            "snapshot": {
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
            "kind": "status",
            "snapshot": {
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
            "kind": "status",
            "snapshot": {
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
            "kind": "status",
            "snapshot": {
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
            "kind": "status",
            "snapshot": {
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
            line == "plain HTTP: blocked because MITM plaintext bridge runtime is disabled: feed writer closed"
        }));
        assert!(lines.iter().any(|line| {
            line == "TLS-decrypted HTTP: blocked because MITM plaintext bridge runtime is disabled: feed writer closed"
        }));
        assert!(
            lines
                .iter()
                .any(|line| line == "l7 mitm plaintext bridge runtime: disabled_after_error")
        );
        assert!(
            lines.iter().any(|line| {
                line == "next action: MITM backend is unhealthy: feed writer closed"
            })
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
                "Capture using libpcap; passive fallback occurred (ebpf: permission denied)"
                    .to_string()
            ))
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_label_mitm_bridge_capture_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "status",
            "snapshot": {
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
                "Passive capture failed (ebpf: object path is not configured; libpcap: libpcap is not installed); using MITM plaintext bridge for {MITM_PLAINTEXT_COVERAGE}"
            )))
        );
        assert!(
            diagnostics
                .detail_lines()
                .iter()
                .any(|line| line == "selected: MITM plaintext bridge")
        );
        assert!(
            diagnostics
                .detail_lines()
                .iter()
                .any(|line| line == &format!("coverage: {MITM_PLAINTEXT_COVERAGE}"))
        );
        assert!(diagnostics.detail_lines().iter().any(|line| {
            line == "auto MITM plaintext bridge fallback: capture_event_feed: runtime=available, capability=available, evidence=nominal"
        }));
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_warn_when_mitm_bridge_replaces_unavailable_passive_capture()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "status",
            "snapshot": {
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
                "Passive capture unavailable (ebpf: capture.ebpf.object_path is not configured; libpcap: libpcap is not available); using MITM plaintext bridge for {MITM_PLAINTEXT_COVERAGE}"
            )))
        );
        Ok(())
    }

    #[test]
    fn traffic_diagnostics_do_not_label_generic_feed_as_mitm()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "kind": "status",
            "snapshot": {
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

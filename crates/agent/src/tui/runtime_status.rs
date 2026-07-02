use std::{path::Path, time::Duration};

use serde_json::Value;
use thiserror::Error;

use crate::{
    admin::{AdminClientError, AdminRequest, send_admin_json_request_with_timeout},
    status::CaptureStatusSnapshot,
};

use super::wire::capture_selection_name;

const STATUS_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) async fn request_capture_diagnostics(
    socket_path: &Path,
) -> Result<CaptureDiagnostics, RuntimeStatusClientError> {
    let response =
        send_admin_json_request_with_timeout(socket_path, AdminRequest::Status, STATUS_TIMEOUT)
            .await
            .map_err(RuntimeStatusClientError::AdminClient)?;
    parse_capture_diagnostics_response(&response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureDiagnostics {
    capture: CaptureStatusSnapshot,
}

impl CaptureDiagnostics {
    #[cfg(test)]
    pub(crate) fn from_capture_snapshot(capture: CaptureStatusSnapshot) -> Self {
        Self { capture }
    }

    pub(crate) fn status_message(&self, traffic_empty: bool) -> Option<CaptureDiagnosticMessage> {
        if self.capture_unavailable() {
            return Some(CaptureDiagnosticMessage::Error(format!(
                "Capture unavailable: {}",
                self.failure_summary()
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
        lines.push(
            "MITM path: configure transparent interception when passive capture is unavailable or when full HTTP/TLS content visibility is needed"
                .to_string(),
        );
        lines
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

fn parse_capture_diagnostics_response(
    response: &Value,
) -> Result<CaptureDiagnostics, RuntimeStatusClientError> {
    match response.get("kind").and_then(Value::as_str) {
        Some("status") => {
            let capture = response
                .get("snapshot")
                .and_then(|snapshot| snapshot.get("capture"))
                .cloned()
                .ok_or(RuntimeStatusClientError::MissingCapture)?;
            let capture = serde_json::from_value::<CaptureStatusSnapshot>(capture)
                .map_err(RuntimeStatusClientError::Json)?;
            Ok(CaptureDiagnostics { capture })
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
    use serde_json::json;

    use super::*;

    #[test]
    fn capture_diagnostics_summarize_unavailable_candidates()
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

        let diagnostics = parse_capture_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(true),
            Some(CaptureDiagnosticMessage::Error(
                "Capture unavailable: ebpf: capture.ebpf.object_path is not configured; libpcap: libpcap is not available"
                    .to_string()
            ))
        );
        assert!(
            diagnostics
                .detail_lines()
                .iter()
                .any(|line| line.contains("MITM path"))
        );
        Ok(())
    }

    #[test]
    fn capture_diagnostics_reports_runtime_fallback() -> Result<(), Box<dyn std::error::Error>> {
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

        let diagnostics = parse_capture_diagnostics_response(&response)?;

        assert_eq!(
            diagnostics.status_message(false),
            Some(CaptureDiagnosticMessage::Warning(
                "Capture using libpcap; ebpf failed: permission denied".to_string()
            ))
        );
        Ok(())
    }
}

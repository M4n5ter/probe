use crate::tui::{
    copy::{MITM_PLAINTEXT_COVERAGE, MITM_PROXY_DATA_PATH_LABEL},
    runtime_status::{
        TrafficRuntimeDiagnostics, local_tui_ebpf_expected_contract_line,
        missing_mitm_configuration_action, mitm_visibility_lines,
    },
    text::terminal_safe_inline_text,
};

mod failure;

use failure::DataPathFailureHint;
pub(crate) use failure::{DataPathFailureKind, classify_runtime_detach_message};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataPathOverviewLineKind {
    Source,
    Status,
    NextAction,
    Capture,
    Mitm,
    Reason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataPathOverviewLine {
    pub(crate) kind: DataPathOverviewLineKind,
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

impl DataPathOverviewLine {
    fn new(kind: DataPathOverviewLineKind, label: &'static str, value: impl Into<String>) -> Self {
        Self {
            kind,
            label,
            value: terminal_safe_inline_text(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataPathCompactSummary {
    pub(crate) status: String,
    pub(crate) capture: String,
    pub(crate) mitm: String,
    pub(crate) next: String,
}

impl DataPathCompactSummary {
    fn new(
        status: impl Into<String>,
        capture: impl Into<String>,
        mitm: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self {
            status: terminal_safe_inline_text(status),
            capture: terminal_safe_inline_text(capture),
            mitm: terminal_safe_inline_text(mitm),
            next: terminal_safe_inline_text(next),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DataPathDiagnosticsView {
    RunningAgent {
        diagnostics: TrafficRuntimeDiagnostics,
    },
    AttachedRuntimeDiagnosticsUnavailable {
        reason: String,
    },
    LocalConfig {
        diagnostics: TrafficRuntimeDiagnostics,
        reason: Option<String>,
    },
    Unavailable {
        reason: String,
        failure: Option<DataPathFailureKind>,
    },
}

impl DataPathDiagnosticsView {
    pub(crate) fn from_running_agent(diagnostics: TrafficRuntimeDiagnostics) -> Self {
        Self::RunningAgent { diagnostics }
    }

    pub(crate) fn attached_runtime_diagnostics_unavailable(reason: impl Into<String>) -> Self {
        Self::AttachedRuntimeDiagnosticsUnavailable {
            reason: reason.into(),
        }
    }

    pub(crate) fn from_local_config(diagnostics: TrafficRuntimeDiagnostics) -> Self {
        Self::LocalConfig {
            diagnostics,
            reason: None,
        }
    }

    pub(crate) fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
            failure: None,
        }
    }

    pub(crate) fn unavailable_with_kind(
        failure: DataPathFailureKind,
        reason: impl Into<String>,
    ) -> Self {
        Self::Unavailable {
            reason: reason.into(),
            failure: Some(failure),
        }
    }

    pub(crate) fn overview_lines(&self, traffic_empty: bool) -> Vec<DataPathOverviewLine> {
        let summary = self.compact_summary(traffic_empty);
        let mut lines = vec![DataPathOverviewLine::new(
            DataPathOverviewLineKind::Source,
            "Data path source",
            self.source_label(),
        )];
        lines.extend([
            DataPathOverviewLine::new(
                DataPathOverviewLineKind::Status,
                "Data path",
                summary.status,
            ),
            DataPathOverviewLine::new(DataPathOverviewLineKind::NextAction, "Next", summary.next),
            DataPathOverviewLine::new(
                DataPathOverviewLineKind::Capture,
                "Capture",
                summary.capture,
            ),
            DataPathOverviewLine::new(DataPathOverviewLineKind::Mitm, "MITM", summary.mitm),
        ]);

        if let Some(reason) = self.reason() {
            lines.push(DataPathOverviewLine::new(
                DataPathOverviewLineKind::Reason,
                "Reason",
                reason,
            ));
        }
        lines
    }

    pub(crate) fn compact_summary(&self, traffic_empty: bool) -> DataPathCompactSummary {
        match self {
            Self::RunningAgent { diagnostics } => DataPathCompactSummary::new(
                diagnostics.running_status_text(traffic_empty),
                diagnostics.capture_overview_line(),
                diagnostics.mitm_overview_line(),
                diagnostics.mitm_next_step(),
            ),
            Self::AttachedRuntimeDiagnosticsUnavailable { .. } => DataPathCompactSummary::new(
                "runtime diagnostics unavailable",
                "live status not available",
                format!(
                    "live status not available; {MITM_PROXY_DATA_PATH_LABEL} can capture {MITM_PLAINTEXT_COVERAGE}"
                ),
                "check admin socket or open Data Path",
            ),
            Self::LocalConfig { diagnostics, .. } => DataPathCompactSummary::new(
                diagnostics.local_status_text(),
                diagnostics.capture_overview_line(),
                diagnostics.mitm_overview_line(),
                diagnostics.mitm_next_step(),
            ),
            Self::Unavailable { .. } => DataPathCompactSummary::new(
                self.failure_hint()
                    .map_or("cannot evaluate capture or MITM readiness", |hint| {
                        hint.summary
                    }),
                self.failure_hint()
                    .map_or("not evaluated", |hint| hint.capture),
                format!(
                    "not evaluated; {MITM_PROXY_DATA_PATH_LABEL} can capture {MITM_PLAINTEXT_COVERAGE}"
                ),
                self.failure_hint()
                    .map_or("fix runtime config; use Data Path", |hint| hint.next),
            ),
        }
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("Data path source: {}", self.source_label())];
        match self {
            Self::RunningAgent { diagnostics } => {
                lines.push("state: live runtime diagnostics from the attached agent".to_string());
                lines.extend(diagnostics.detail_lines());
            }
            Self::AttachedRuntimeDiagnosticsUnavailable { .. } => {
                lines.push(
                    "state: TUI has an active admin socket attachment, but runtime diagnostics could not be read"
                        .to_string(),
                );
                lines.push(
                    "traffic: see the Traffic status line for the latest tail-events result"
                        .to_string(),
                );
                lines.push("capture: live status not available".to_string());
                lines.push(local_tui_ebpf_expected_contract_line());
                lines.push(format!(
                    "MITM: live status not available; {MITM_PROXY_DATA_PATH_LABEL} can capture {MITM_PLAINTEXT_COVERAGE}"
                ));
            }
            Self::LocalConfig { diagnostics, .. } => {
                lines.push(
                    "state: local config readiness projection, not live traffic activity"
                        .to_string(),
                );
                lines.extend(diagnostics.detail_lines());
            }
            Self::Unavailable { .. } => {
                lines.push("state: diagnostics unavailable".to_string());
                if let Some(hint) = self.failure_hint() {
                    lines.push(format!("failure: {}", hint.summary));
                    lines.push(format!("action: {}", hint.next));
                }
                lines.push("capture: not evaluated".to_string());
                lines.push(local_tui_ebpf_expected_contract_line());
                lines.push(format!(
                    "MITM: not evaluated; {MITM_PROXY_DATA_PATH_LABEL} can capture {MITM_PLAINTEXT_COVERAGE}"
                ));
                lines.extend(mitm_visibility_lines());
                lines.push(format!(
                    "configuration: {}",
                    missing_mitm_configuration_action()
                ));
            }
        }
        if let Some(reason) = self.reason() {
            lines.push(format!("reason: {reason}"));
        }
        lines.into_iter().map(terminal_safe_inline_text).collect()
    }

    fn source_label(&self) -> &'static str {
        match self {
            Self::RunningAgent { .. } => "running agent",
            Self::AttachedRuntimeDiagnosticsUnavailable { .. } => "attached runtime",
            Self::LocalConfig { .. } => "local config",
            Self::Unavailable { .. } => "unavailable",
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::RunningAgent { .. } => None,
            Self::AttachedRuntimeDiagnosticsUnavailable { reason } => Some(reason),
            Self::LocalConfig { reason, .. } => reason.as_deref(),
            Self::Unavailable { reason, .. } => Some(reason),
        }
    }

    fn failure_hint(&self) -> Option<DataPathFailureHint> {
        match self {
            Self::Unavailable {
                failure: Some(failure),
                ..
            } => Some(failure.hint()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_compact_summary_keeps_all_traffic_header_fields_explicit() {
        let summary = DataPathDiagnosticsView::unavailable("startup failed").compact_summary(true);

        assert_eq!(summary.status, "cannot evaluate capture or MITM readiness");
        assert_eq!(summary.capture, "not evaluated");
        assert!(summary.mitm.contains(
            "reliable MITM proxy data path can capture plain HTTP and TLS-decrypted HTTP"
        ));
        assert!(summary.next.contains("fix runtime config"));
    }

    #[test]
    fn unavailable_compact_summary_explains_kernel_capture_permissions() {
        let summary = DataPathDiagnosticsView::unavailable_with_kind(
            DataPathFailureKind::CapturePrivilegesMissing,
            "capture startup failed",
        )
        .compact_summary(true);

        assert_eq!(summary.status, "kernel capture privileges are missing");
        assert_eq!(
            summary.capture,
            "live capture needs root or Linux capabilities"
        );
        assert!(summary.next.contains("CAP_BPF"));
        assert!(summary.next.contains("CAP_NET_RAW"));
    }

    #[test]
    fn attached_runtime_diagnostics_unavailable_keeps_neutral_tail_copy() {
        let view = DataPathDiagnosticsView::attached_runtime_diagnostics_unavailable(
            "admin traffic_status response exceeds 16777216 bytes",
        );

        let summary = view.compact_summary(true);
        assert_eq!(summary.status, "runtime diagnostics unavailable");
        assert_eq!(summary.capture, "live status not available");
        assert!(summary.mitm.contains("live status not available"));

        let lines = view.detail_lines();
        assert!(lines.contains(&"Data path source: attached runtime".to_string()));
        assert!(lines.iter().any(|line| {
            line == "state: TUI has an active admin socket attachment, but runtime diagnostics could not be read"
        }));
        assert!(lines.iter().any(|line| {
            line == "traffic: see the Traffic status line for the latest tail-events result"
        }));
        assert!(lines.iter().any(|line| line
            == &format!(
                "local TUI eBPF expected contract: ABI revision {}, process payload sample window {} KiB",
                ::capture::EBPF_ABI_REVISION,
                ::capture::EBPF_PAYLOAD_SAMPLE_BYTES / 1024
            )));
        assert!(lines.iter().any(|line| {
            line == "reason: admin traffic_status response exceeds 16777216 bytes"
        }));
    }

    #[test]
    fn unavailable_reason_text_does_not_create_failure_hint_without_kind() {
        let summary = DataPathDiagnosticsView::unavailable("TLS material permission denied")
            .compact_summary(true);

        assert_eq!(summary.status, "cannot evaluate capture or MITM readiness");
        assert_eq!(summary.capture, "not evaluated");
        assert_eq!(summary.next, "fix runtime config; use Data Path");

        let lines =
            DataPathDiagnosticsView::unavailable("TLS material permission denied").detail_lines();
        assert!(lines.iter().any(|line| line
            == &format!(
                "local TUI eBPF expected contract: ABI revision {}, process payload sample window {} KiB",
                ::capture::EBPF_ABI_REVISION,
                ::capture::EBPF_PAYLOAD_SAMPLE_BYTES / 1024
            )));
    }

    #[test]
    fn overview_lines_are_derived_from_the_compact_summary_projection() {
        let lines = DataPathDiagnosticsView::unavailable("startup failed").overview_lines(true);

        assert!(
            lines
                .iter()
                .any(|line| line.kind == DataPathOverviewLineKind::Capture
                    && line.value == "not evaluated")
        );
        assert!(
            lines
                .iter()
                .any(|line| line.kind == DataPathOverviewLineKind::NextAction
                    && line.value == "fix runtime config; use Data Path")
        );
    }

    #[test]
    fn diagnostic_reason_lines_are_terminal_safe() {
        let view = DataPathDiagnosticsView::unavailable("startup\nfailed\x1b[31m");

        let overview = view.overview_lines(true);
        let detail = view.detail_lines();

        assert!(
            overview
                .iter()
                .filter(|line| line.kind == DataPathOverviewLineKind::Reason)
                .all(|line| !line.value.chars().any(char::is_control))
        );
        assert!(
            detail
                .iter()
                .all(|line| !line.chars().any(char::is_control))
        );
    }

    #[test]
    fn unavailable_details_still_explain_mitm_plain_and_tls_visibility() {
        let lines = DataPathDiagnosticsView::unavailable("startup failed").detail_lines();

        for expected in mitm_visibility_lines() {
            assert!(lines.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn unavailable_details_include_permission_action_when_capture_lacks_privileges() {
        let lines = DataPathDiagnosticsView::unavailable_with_kind(
            DataPathFailureKind::CapturePrivilegesMissing,
            "capture startup failed",
        )
        .detail_lines();

        assert!(
            lines
                .iter()
                .any(|line| line == "failure: kernel capture privileges are missing")
        );
        assert!(lines.iter().any(|line| line.contains("CAP_NET_ADMIN")));
    }
}

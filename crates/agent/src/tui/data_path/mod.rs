use crate::tui::{
    copy::{MITM_PLAINTEXT_COVERAGE, MITM_PROXY_DATA_PATH_LABEL},
    runtime_status::{
        TrafficRuntimeDiagnostics, missing_mitm_configuration_action, mitm_visibility_lines,
    },
    text::terminal_safe_inline_text,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataPathDiagnosticsSource {
    RunningAgent,
    LocalConfig,
    Unavailable,
}

impl DataPathDiagnosticsSource {
    fn label(self) -> &'static str {
        match self {
            Self::RunningAgent => "running agent",
            Self::LocalConfig => "local config",
            Self::Unavailable => "unavailable",
        }
    }
}

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
pub(crate) struct DataPathDiagnosticsView {
    source: DataPathDiagnosticsSource,
    diagnostics: Option<TrafficRuntimeDiagnostics>,
    reason: Option<String>,
}

impl DataPathDiagnosticsView {
    pub(crate) fn from_running_agent(diagnostics: TrafficRuntimeDiagnostics) -> Self {
        Self {
            source: DataPathDiagnosticsSource::RunningAgent,
            diagnostics: Some(diagnostics),
            reason: None,
        }
    }

    pub(crate) fn from_local_config(diagnostics: TrafficRuntimeDiagnostics) -> Self {
        Self {
            source: DataPathDiagnosticsSource::LocalConfig,
            diagnostics: Some(diagnostics),
            reason: None,
        }
    }

    pub(crate) fn from_local_config_with_reason(
        diagnostics: TrafficRuntimeDiagnostics,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            source: DataPathDiagnosticsSource::LocalConfig,
            diagnostics: Some(diagnostics),
            reason: Some(reason.into()),
        }
    }

    pub(crate) fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            source: DataPathDiagnosticsSource::Unavailable,
            diagnostics: None,
            reason: Some(reason.into()),
        }
    }

    pub(crate) fn overview_lines(&self, traffic_empty: bool) -> Vec<DataPathOverviewLine> {
        let summary = self.compact_summary(traffic_empty);
        let mut lines = vec![DataPathOverviewLine::new(
            DataPathOverviewLineKind::Source,
            "Data path source",
            self.source.label(),
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

        if let Some(reason) = &self.reason {
            lines.push(DataPathOverviewLine::new(
                DataPathOverviewLineKind::Reason,
                "Reason",
                reason.clone(),
            ));
        }
        lines
    }

    pub(crate) fn compact_summary(&self, traffic_empty: bool) -> DataPathCompactSummary {
        match (&self.source, &self.diagnostics) {
            (DataPathDiagnosticsSource::RunningAgent, Some(diagnostics)) => {
                DataPathCompactSummary::new(
                    diagnostics.running_status_text(traffic_empty),
                    diagnostics.capture_overview_line(),
                    diagnostics.mitm_overview_line(),
                    diagnostics.mitm_next_step(),
                )
            }
            (DataPathDiagnosticsSource::LocalConfig, Some(diagnostics)) => {
                DataPathCompactSummary::new(
                    diagnostics.local_status_text(),
                    diagnostics.capture_overview_line(),
                    diagnostics.mitm_overview_line(),
                    diagnostics.mitm_next_step(),
                )
            }
            _ => DataPathCompactSummary::new(
                "cannot evaluate capture or MITM readiness",
                "not evaluated",
                format!(
                    "not evaluated; {MITM_PROXY_DATA_PATH_LABEL} can capture {MITM_PLAINTEXT_COVERAGE}"
                ),
                "fix runtime config; use Data Path",
            ),
        }
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("Data path source: {}", self.source.label())];
        match (&self.source, &self.diagnostics) {
            (DataPathDiagnosticsSource::RunningAgent, Some(diagnostics)) => {
                lines.push("state: live runtime diagnostics from the attached agent".to_string());
                lines.extend(diagnostics.detail_lines());
            }
            (DataPathDiagnosticsSource::LocalConfig, Some(diagnostics)) => {
                lines.push(
                    "state: local config readiness projection, not live traffic activity"
                        .to_string(),
                );
                lines.extend(diagnostics.detail_lines());
            }
            _ => {
                lines.push("state: diagnostics unavailable".to_string());
                lines.push("capture: not evaluated".to_string());
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
        if let Some(reason) = &self.reason {
            lines.push(format!("reason: {reason}"));
        }
        lines.into_iter().map(terminal_safe_inline_text).collect()
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
}

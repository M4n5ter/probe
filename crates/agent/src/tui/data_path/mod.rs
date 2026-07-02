use crate::tui::{
    copy::{MITM_PLAINTEXT_COVERAGE, MITM_PROXY_FALLBACK_LABEL},
    runtime_status::{TrafficRuntimeDiagnostics, missing_mitm_quick_setup_action},
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
            value: value.into(),
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
        let mut lines = vec![DataPathOverviewLine::new(
            DataPathOverviewLineKind::Source,
            "Data path source",
            self.source.label(),
        )];

        match (&self.source, &self.diagnostics) {
            (DataPathDiagnosticsSource::RunningAgent, Some(diagnostics)) => {
                lines.extend(running_overview_lines(diagnostics, traffic_empty));
            }
            (DataPathDiagnosticsSource::LocalConfig, Some(diagnostics)) => {
                lines.extend(local_overview_lines(diagnostics));
            }
            _ => {
                lines.extend(unavailable_overview_lines());
            }
        }

        if let Some(reason) = &self.reason {
            lines.push(DataPathOverviewLine::new(
                DataPathOverviewLineKind::Reason,
                "Reason",
                reason.clone(),
            ));
        }
        lines
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
                    "MITM: not evaluated; {MITM_PROXY_FALLBACK_LABEL} can capture {MITM_PLAINTEXT_COVERAGE}"
                ));
                lines.push(format!("MITM setup: {}", missing_mitm_quick_setup_action()));
            }
        }
        if let Some(reason) = &self.reason {
            lines.push(format!("reason: {reason}"));
        }
        lines
    }
}

fn running_overview_lines(
    diagnostics: &TrafficRuntimeDiagnostics,
    traffic_empty: bool,
) -> Vec<DataPathOverviewLine> {
    vec![
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::Status,
            "Data path",
            diagnostics.running_status_text(traffic_empty),
        ),
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::NextAction,
            "Next",
            diagnostics.mitm_next_step(),
        ),
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::Capture,
            "Capture",
            diagnostics.capture_overview_line(),
        ),
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::Mitm,
            "MITM",
            diagnostics.mitm_overview_line(),
        ),
    ]
}

fn local_overview_lines(diagnostics: &TrafficRuntimeDiagnostics) -> Vec<DataPathOverviewLine> {
    vec![
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::Status,
            "Data path",
            diagnostics.local_status_text(),
        ),
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::NextAction,
            "Next",
            diagnostics.mitm_next_step(),
        ),
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::Capture,
            "Capture",
            diagnostics.capture_overview_line(),
        ),
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::Mitm,
            "MITM",
            diagnostics.mitm_overview_line(),
        ),
    ]
}

fn unavailable_overview_lines() -> Vec<DataPathOverviewLine> {
    vec![
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::Status,
            "Data path",
            "cannot evaluate capture or MITM readiness",
        ),
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::NextAction,
            "Next",
            "open Traffic and use Data Path after fixing runtime config validation",
        ),
        DataPathOverviewLine::new(
            DataPathOverviewLineKind::Mitm,
            "MITM",
            format!(
                "not evaluated; {MITM_PROXY_FALLBACK_LABEL} can capture {MITM_PLAINTEXT_COVERAGE}"
            ),
        ),
    ]
}

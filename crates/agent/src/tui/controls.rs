use probe_config::AgentConfig;

use super::{
    app::TuiTab,
    copy::{
        INBOUND_MITM_PROXY_FALLBACK_SETUP_LABEL, MITM_IN_ACTION_LABEL, MITM_OUT_ACTION_LABEL,
        MITM_PLAINTEXT_COVERAGE, MITM_PROXY_FALLBACK_LABEL,
        OUTBOUND_MITM_PROXY_FALLBACK_SETUP_LABEL,
    },
    fields::{FieldId, field_value, fields_for_tab},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlId {
    ReloadRuntimeActions,
    OpenTrafficDiagnostics,
    ConfigureOutboundMitm,
    ConfigureInboundMitm,
    SearchProcesses,
    ClearProcessSearch,
}

impl ControlId {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ReloadRuntimeActions => "Reload runtime actions",
            Self::OpenTrafficDiagnostics => "Show data path",
            Self::ConfigureOutboundMitm => OUTBOUND_MITM_PROXY_FALLBACK_SETUP_LABEL,
            Self::ConfigureInboundMitm => INBOUND_MITM_PROXY_FALLBACK_SETUP_LABEL,
            Self::SearchProcesses => "Search",
            Self::ClearProcessSearch => "Clear",
        }
    }

    pub(crate) fn action_hint(self) -> &'static str {
        match self {
            Self::ReloadRuntimeActions => "run action",
            Self::OpenTrafficDiagnostics => "open diagnostics",
            Self::ConfigureOutboundMitm | Self::ConfigureInboundMitm => "apply selected process",
            Self::SearchProcesses => "search",
            Self::ClearProcessSearch => "clear",
        }
    }

    pub(crate) fn traffic_action_label(self) -> &'static str {
        match self {
            Self::OpenTrafficDiagnostics => "Data Path",
            Self::ConfigureOutboundMitm => MITM_OUT_ACTION_LABEL,
            Self::ConfigureInboundMitm => MITM_IN_ACTION_LABEL,
            _ => self.label(),
        }
    }

    pub(crate) fn value(self, _config: &AgentConfig) -> String {
        match self {
            Self::ReloadRuntimeActions => "uses active TUI runtime".to_string(),
            Self::OpenTrafficDiagnostics => "capture and MITM runtime diagnostics".to_string(),
            Self::ConfigureOutboundMitm => {
                format!("process-scoped {MITM_PROXY_FALLBACK_LABEL} for {MITM_PLAINTEXT_COVERAGE}")
            }
            Self::ConfigureInboundMitm => {
                format!(
                    "process-scoped server {MITM_PROXY_FALLBACK_LABEL} for {MITM_PLAINTEXT_COVERAGE}"
                )
            }
            Self::SearchProcesses | Self::ClearProcessSearch => String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FocusTarget {
    Field(FieldId),
    Control(ControlId),
}

impl FocusTarget {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Field(field) => field.label(),
            Self::Control(control) => control.label(),
        }
    }

    pub(crate) fn action_hint(self) -> &'static str {
        match self {
            Self::Field(field) => field.action_hint(),
            Self::Control(control) => control.action_hint(),
        }
    }

    pub(crate) fn value(self, config: &AgentConfig, selected_process_name: Option<&str>) -> String {
        match self {
            Self::Field(field) => field_value(config, field, selected_process_name),
            Self::Control(control) => control.value(config),
        }
    }
}

pub(crate) fn focus_targets_for_tab(tab: TuiTab, config: &AgentConfig) -> Vec<FocusTarget> {
    fields_for_tab(tab, config)
        .into_iter()
        .map(FocusTarget::Field)
        .chain(controls_for_tab(tab).into_iter().map(FocusTarget::Control))
        .collect()
}

fn controls_for_tab(tab: TuiTab) -> Vec<ControlId> {
    match tab {
        TuiTab::Runtime => vec![ControlId::ReloadRuntimeActions],
        TuiTab::Enforcement => vec![
            ControlId::ConfigureOutboundMitm,
            ControlId::ConfigureInboundMitm,
        ],
        _ => Vec::new(),
    }
}

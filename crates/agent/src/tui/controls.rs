use probe_config::AgentConfig;

use super::{
    app::TuiTab,
    fields::{FieldId, field_value, fields_for_tab},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlId {
    ReloadRuntimeActions,
    OpenTrafficDiagnostics,
    TrafficViewMode,
    TrafficEventFilter,
    TrafficTailFollow,
    ObserveAuto,
    ObserveEbpf,
    ObserveLibpcap,
    SearchProcesses,
    ClearProcessSearch,
}

impl ControlId {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ReloadRuntimeActions => "Reload runtime actions",
            Self::OpenTrafficDiagnostics => "Show data path",
            Self::TrafficViewMode => "Toggle traffic view",
            Self::TrafficEventFilter => "Cycle traffic event filter",
            Self::TrafficTailFollow => "Follow latest traffic events",
            Self::ObserveAuto => "Observe selected process with auto data path",
            Self::ObserveEbpf => "Observe selected process with eBPF",
            Self::ObserveLibpcap => "Observe selected process with libpcap",
            Self::SearchProcesses => "Search",
            Self::ClearProcessSearch => "Clear",
        }
    }

    pub(crate) fn action_hint(self) -> &'static str {
        match self {
            Self::ReloadRuntimeActions => "run action",
            Self::OpenTrafficDiagnostics => "open diagnostics",
            Self::TrafficViewMode => "toggle view",
            Self::TrafficEventFilter => "cycle filter",
            Self::TrafficTailFollow => "jump to live",
            Self::ObserveAuto | Self::ObserveEbpf | Self::ObserveLibpcap => "observe process",
            Self::SearchProcesses => "search",
            Self::ClearProcessSearch => "clear",
        }
    }

    pub(crate) fn traffic_action_label(self) -> &'static str {
        match self {
            Self::OpenTrafficDiagnostics => "Data Path",
            Self::TrafficViewMode => "View",
            Self::TrafficEventFilter => "Events",
            Self::TrafficTailFollow => "Live",
            Self::ObserveAuto => "Auto",
            Self::ObserveEbpf => "eBPF",
            Self::ObserveLibpcap => "libpcap",
            _ => self.label(),
        }
    }

    pub(crate) fn value(self, _config: &AgentConfig) -> String {
        match self {
            Self::ReloadRuntimeActions => "uses active TUI runtime".to_string(),
            Self::OpenTrafficDiagnostics => "capture and MITM runtime diagnostics".to_string(),
            Self::TrafficViewMode => {
                "HTTP exchanges, WebSocket sessions, or raw traffic events".to_string()
            }
            Self::TrafficEventFilter => {
                "parsed protocol, security, diagnostics, or all events".to_string()
            }
            Self::TrafficTailFollow => {
                "jump to the newest traffic event and resume live follow".to_string()
            }
            Self::ObserveAuto => {
                "selected process, inbound and outbound, auto data path".to_string()
            }
            Self::ObserveEbpf => "selected process, inbound and outbound, eBPF".to_string(),
            Self::ObserveLibpcap => "selected process, inbound and outbound, libpcap".to_string(),
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
            ControlId::ObserveAuto,
            ControlId::ObserveEbpf,
            ControlId::ObserveLibpcap,
        ],
        _ => Vec::new(),
    }
}

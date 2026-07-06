use probe_config::AgentConfig;

use super::{
    app::TuiTab,
    fields::{FieldId, field_value, fields_for_tab},
    traffic::{TrafficEventFilter, TrafficViewMode},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlId {
    ReloadRuntimeActions,
    OpenTrafficDiagnostics,
    TrafficView(TrafficViewMode),
    TrafficFilter(TrafficEventFilter),
    TrafficTailFollow,
    ObserveAuto,
    ObserveEbpf,
    ObserveLibpcap,
    SearchProcesses,
    ClearProcessSearch,
    SearchTraffic,
    ClearTrafficSearch,
}

pub(crate) const TRAFFIC_VIEW_CONTROLS: [ControlId; 3] = [
    ControlId::TrafficView(TrafficViewMode::Http),
    ControlId::TrafficView(TrafficViewMode::WebSocket),
    ControlId::TrafficView(TrafficViewMode::Events),
];

pub(crate) const TRAFFIC_FILTER_CONTROLS: [ControlId; 6] = [
    ControlId::TrafficFilter(TrafficEventFilter::Application),
    ControlId::TrafficFilter(TrafficEventFilter::Http),
    ControlId::TrafficFilter(TrafficEventFilter::WebSocket),
    ControlId::TrafficFilter(TrafficEventFilter::Security),
    ControlId::TrafficFilter(TrafficEventFilter::Diagnostics),
    ControlId::TrafficFilter(TrafficEventFilter::All),
];

pub(crate) const TRAFFIC_OBSERVE_CONTROLS: [ControlId; 3] = [
    ControlId::ObserveAuto,
    ControlId::ObserveEbpf,
    ControlId::ObserveLibpcap,
];

impl ControlId {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ReloadRuntimeActions => "Reload runtime actions",
            Self::OpenTrafficDiagnostics => "Show data path",
            Self::TrafficView(mode) => mode.control_label(),
            Self::TrafficFilter(filter) => filter.control_label(),
            Self::TrafficTailFollow => "Follow latest traffic events",
            Self::ObserveAuto => "Observe selected process with auto data path",
            Self::ObserveEbpf => "Observe selected process with eBPF",
            Self::ObserveLibpcap => "Observe selected process with libpcap",
            Self::SearchProcesses => "Search",
            Self::ClearProcessSearch => "Clear",
            Self::SearchTraffic => "Search traffic",
            Self::ClearTrafficSearch => "Clear traffic search",
        }
    }

    pub(crate) fn action_hint(self) -> &'static str {
        match self {
            Self::ReloadRuntimeActions => "run action",
            Self::OpenTrafficDiagnostics => "open diagnostics",
            Self::TrafficView(_) => "select view",
            Self::TrafficFilter(_) => "select filter",
            Self::TrafficTailFollow => "jump to live",
            Self::ObserveAuto | Self::ObserveEbpf | Self::ObserveLibpcap => "observe process",
            Self::SearchProcesses => "search",
            Self::ClearProcessSearch => "clear",
            Self::SearchTraffic => "search traffic",
            Self::ClearTrafficSearch => "clear traffic search",
        }
    }

    pub(crate) fn traffic_action_label(self) -> &'static str {
        match self {
            Self::OpenTrafficDiagnostics => "Data Path",
            Self::TrafficView(mode) => mode.short_label(),
            Self::TrafficFilter(filter) => filter.short_label(),
            Self::TrafficTailFollow => "Live",
            Self::ObserveAuto => "Auto",
            Self::ObserveEbpf => "eBPF",
            Self::ObserveLibpcap => "libpcap",
            Self::SearchTraffic => "Search",
            Self::ClearTrafficSearch => "Clear",
            _ => self.label(),
        }
    }

    pub(crate) fn value(self, _config: &AgentConfig) -> String {
        match self {
            Self::ReloadRuntimeActions => "uses active TUI runtime".to_string(),
            Self::OpenTrafficDiagnostics => "capture and MITM runtime diagnostics".to_string(),
            Self::TrafficView(mode) => mode.description().to_string(),
            Self::TrafficFilter(filter) => filter.description().to_string(),
            Self::TrafficTailFollow => {
                "jump to the newest traffic event and resume live follow".to_string()
            }
            Self::ObserveAuto => {
                "selected process, inbound and outbound, auto data path".to_string()
            }
            Self::ObserveEbpf => "selected process, inbound and outbound, eBPF".to_string(),
            Self::ObserveLibpcap => "selected process, inbound and outbound, libpcap".to_string(),
            Self::SearchTraffic => "filter the current traffic table by visible text".to_string(),
            Self::ClearTrafficSearch => "clear the current traffic table search".to_string(),
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

pub(crate) fn traffic_digit_control(digit: char) -> Option<ControlId> {
    let value = digit.to_digit(10)? as usize;
    match value {
        1..=3 => TRAFFIC_VIEW_CONTROLS.get(value - 1).copied(),
        4..=9 => TRAFFIC_FILTER_CONTROLS.get(value - 4).copied(),
        _ => None,
    }
}

fn controls_for_tab(tab: TuiTab) -> Vec<ControlId> {
    match tab {
        TuiTab::Runtime => vec![ControlId::ReloadRuntimeActions],
        TuiTab::Enforcement => TRAFFIC_OBSERVE_CONTROLS.to_vec(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_digit_controls_follow_canonical_action_order() {
        for (index, control) in TRAFFIC_VIEW_CONTROLS.into_iter().enumerate() {
            let digit = char::from_digit((index + 1) as u32, 10).expect("valid digit");
            assert_eq!(traffic_digit_control(digit), Some(control));
        }
        for (index, control) in TRAFFIC_FILTER_CONTROLS.into_iter().enumerate() {
            let digit = char::from_digit((index + 4) as u32, 10).expect("valid digit");
            assert_eq!(traffic_digit_control(digit), Some(control));
        }
        assert_eq!(traffic_digit_control('0'), None);
    }
}

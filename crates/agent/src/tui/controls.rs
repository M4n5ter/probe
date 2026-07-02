use probe_config::AgentConfig;

use super::{
    app::TuiTab,
    fields::{FieldId, field_value, fields_for_tab},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlId {
    EnableAdmin,
    ReloadRuntimeActions,
}

impl ControlId {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::EnableAdmin => "Enable admin",
            Self::ReloadRuntimeActions => "Reload runtime actions",
        }
    }

    pub(crate) fn action_hint(self) -> &'static str {
        match self {
            Self::EnableAdmin => "enable",
            Self::ReloadRuntimeActions => "run action",
        }
    }

    pub(crate) fn value(self, config: &AgentConfig) -> String {
        match self {
            Self::EnableAdmin => "disabled; save config before starting agent".to_string(),
            Self::ReloadRuntimeActions => {
                if config.admin.enabled {
                    "available through online admin".to_string()
                } else {
                    "requires admin socket".to_string()
                }
            }
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
        .chain(
            controls_for_tab(tab, config)
                .into_iter()
                .map(FocusTarget::Control),
        )
        .collect()
}

fn controls_for_tab(tab: TuiTab, config: &AgentConfig) -> Vec<ControlId> {
    match tab {
        TuiTab::Traffic if !config.admin.enabled => vec![ControlId::EnableAdmin],
        TuiTab::Runtime => vec![ControlId::ReloadRuntimeActions],
        _ => Vec::new(),
    }
}

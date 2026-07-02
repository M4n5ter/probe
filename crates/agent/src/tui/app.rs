use std::path::{Path, PathBuf};

use probe_config::AgentConfig;

use super::controls::{ControlId, FocusTarget, focus_targets_for_tab};
use super::fields::{
    FieldApplyOutcome, FieldId, apply_field, apply_text_field, editable_text_value,
};
use super::hit::HitTarget;
use super::process_view::ProcessViewState;
use super::processes::{ProcessCatalog, selector_for_exe_path};
use super::runtime_attachment::RuntimeAttachment;
use super::runtime_status::request_capture_diagnostics;
use super::traffic::TrafficState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TuiTab {
    Overview,
    Traffic,
    Capture,
    Processes,
    Runtime,
    Export,
    Storage,
    Enforcement,
    Tls,
}

impl TuiTab {
    pub(crate) const ALL: [Self; 9] = [
        Self::Overview,
        Self::Traffic,
        Self::Capture,
        Self::Processes,
        Self::Runtime,
        Self::Export,
        Self::Storage,
        Self::Enforcement,
        Self::Tls,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Traffic => "Traffic",
            Self::Capture => "Capture",
            Self::Processes => "Processes",
            Self::Runtime => "Runtime",
            Self::Export => "Export",
            Self::Storage => "Storage",
            Self::Enforcement => "Enforcement",
            Self::Tls => "TLS",
        }
    }

    pub(crate) fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|tab| *tab == self)
            .unwrap_or_default()
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    fn previous(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TuiAction {
    NextTab,
    PreviousTab,
    MoveUp,
    MoveDown,
    PreviousValue,
    NextValue,
    TextInput(char),
    TextBackspace,
    TextSubmit,
    TextCancel,
    StartProcessSearch,
    ToggleProcessMonitor,
    Hover {
        target: Option<HitTarget>,
        column: u16,
        row: u16,
    },
    Click(HitTarget),
    Save,
    Reload,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TuiEffect {
    SaveConfig,
    ReloadConfig,
    ReloadRuntimeActions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusKind {
    Info,
    Saved,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusMessage {
    pub(crate) kind: StatusKind,
    pub(crate) text: String,
}

impl StatusMessage {
    pub(crate) fn info(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Info,
            text: text.into(),
        }
    }

    pub(crate) fn saved(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Saved,
            text: text.into(),
        }
    }

    pub(crate) fn warning(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Warning,
            text: text.into(),
        }
    }

    pub(crate) fn error(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Error,
            text: text.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TextEditSession {
    target: TextEditTarget,
    label: String,
    buffer: String,
    replace_on_input: bool,
}

impl TextEditSession {
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn buffer(&self) -> &str {
        &self.buffer
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextEditTarget {
    Field(FieldId),
    ProcessSearch,
}

#[derive(Debug, Clone)]
pub(crate) struct TuiApp {
    config_path: PathBuf,
    config: AgentConfig,
    active_tab: TuiTab,
    selected_field_index: usize,
    process_view: ProcessViewState,
    traffic: TrafficState,
    traffic_visible_rows: usize,
    traffic_detail_open: bool,
    traffic_detail_scroll: usize,
    runtime_attachment: RuntimeAttachment,
    dirty: bool,
    should_quit: bool,
    status: StatusMessage,
    processes: ProcessCatalog,
    text_edit: Option<TextEditSession>,
    hovered_target: Option<HitTarget>,
    hovered_process_argv: Option<ProcessArgvHover>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessArgvHover {
    pub(crate) index: usize,
    pub(crate) column: u16,
    pub(crate) row: u16,
}

impl TuiApp {
    pub(crate) fn new(
        config_path: PathBuf,
        config: AgentConfig,
        processes: ProcessCatalog,
    ) -> Self {
        let status = initial_status(&processes);
        Self {
            config_path,
            config,
            active_tab: TuiTab::Overview,
            selected_field_index: 0,
            process_view: ProcessViewState::default(),
            traffic: TrafficState::default(),
            traffic_visible_rows: 12,
            traffic_detail_open: false,
            traffic_detail_scroll: 0,
            runtime_attachment: RuntimeAttachment::default(),
            dirty: false,
            should_quit: false,
            status,
            processes,
            text_edit: None,
            hovered_target: None,
            hovered_process_argv: None,
        }
    }

    pub(crate) fn config_path(&self) -> &PathBuf {
        &self.config_path
    }

    pub(crate) fn config(&self) -> &AgentConfig {
        &self.config
    }

    pub(crate) fn active_tab(&self) -> TuiTab {
        self.active_tab
    }

    pub(crate) fn selected_focus_target(&self) -> Option<FocusTarget> {
        self.focus_targets_for_active_tab()
            .get(self.selected_field_index)
            .copied()
    }

    pub(crate) fn selected_process_index(&self) -> Option<usize> {
        self.process_view.selected_index()
    }

    pub(crate) fn process_scroll(&self) -> usize {
        self.process_view.scroll()
    }

    pub(crate) fn process_filter(&self) -> &str {
        self.process_view.filter()
    }

    pub(crate) fn filtered_process_indices(&self) -> Vec<usize> {
        self.process_view.filtered_indices(&self.processes)
    }

    pub(crate) fn set_process_viewport_rows(&mut self, rows: usize) {
        self.process_view.set_viewport_rows(rows, &self.processes);
    }

    pub(crate) fn set_traffic_viewport_rows(&mut self, rows: usize) {
        self.traffic_visible_rows = rows.max(1);
    }

    pub(crate) fn processes(&self) -> &ProcessCatalog {
        &self.processes
    }

    pub(crate) fn traffic(&self) -> &TrafficState {
        &self.traffic
    }

    pub(crate) fn traffic_detail_open(&self) -> bool {
        self.traffic_detail_open
    }

    pub(crate) fn traffic_detail_scroll(&self) -> usize {
        self.traffic_detail_scroll
    }

    pub(crate) fn traffic_filter_label(&self) -> String {
        let monitored = self.process_view.monitored_process_count(&self.processes);
        if monitored > 0 {
            return format!("{monitored} watched processes");
        }
        self.selected_process_name()
            .map(|name| format!("focused process: {name}"))
            .unwrap_or_else(|| "no process selected".to_string())
    }

    pub(crate) fn process_is_monitored(&self, index: usize) -> bool {
        self.processes
            .entries()
            .get(index)
            .and_then(|process| process.selector_key())
            .as_deref()
            .is_some_and(|key| self.process_view.monitors_process(Some(key)))
    }

    pub(crate) fn hovered_process_argv(&self) -> Option<ProcessArgvHover> {
        self.hovered_process_argv
    }

    pub(crate) fn is_hovered(&self, target: HitTarget) -> bool {
        self.hovered_target == Some(target)
    }

    pub(crate) fn status(&self) -> &StatusMessage {
        &self.status
    }

    pub(crate) fn dirty(&self) -> bool {
        self.dirty
    }

    pub(crate) fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub(crate) fn text_edit(&self) -> Option<&TextEditSession> {
        self.text_edit.as_ref()
    }

    pub(crate) fn runtime_agent_status(&self) -> String {
        self.runtime_attachment.status_text()
    }

    pub(crate) fn active_admin_socket_path(&self) -> Option<&Path> {
        self.runtime_attachment.active_socket_path()
    }

    pub(crate) fn is_editing_text(&self) -> bool {
        self.text_edit.is_some()
    }

    pub(crate) fn attach_agent(&mut self, attachment: RuntimeAttachment) {
        let status = attachment.status_text();
        self.runtime_attachment = attachment;
        self.status = StatusMessage::info(status);
    }

    pub(crate) fn detach_agent(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.runtime_attachment = RuntimeAttachment::lost(message.clone());
        self.status = StatusMessage::error(message);
    }

    pub(crate) fn handle_action(&mut self, action: TuiAction) -> Option<TuiEffect> {
        if self.text_edit.is_some() {
            return self.handle_text_edit_action(action);
        }
        if self.traffic_detail_open {
            return self.handle_traffic_detail_action(action);
        }
        match action {
            TuiAction::NextTab => self.select_tab(self.active_tab.next()),
            TuiAction::PreviousTab => self.select_tab(self.active_tab.previous()),
            TuiAction::MoveUp => self.move_selection(-1),
            TuiAction::MoveDown => self.move_selection(1),
            TuiAction::NextValue => return self.adjust_selected(1),
            TuiAction::PreviousValue => return self.adjust_selected(-1),
            TuiAction::TextInput(_)
            | TuiAction::TextBackspace
            | TuiAction::TextSubmit
            | TuiAction::TextCancel => {}
            TuiAction::StartProcessSearch => self.begin_process_search(),
            TuiAction::ToggleProcessMonitor => self.toggle_selected_process_monitor(),
            TuiAction::Hover {
                target,
                column,
                row,
            } => self.handle_hover(target, column, row),
            TuiAction::Click(target) => return self.handle_click(target),
            TuiAction::Save => {
                return Some(TuiEffect::SaveConfig);
            }
            TuiAction::Reload => {
                return Some(TuiEffect::ReloadConfig);
            }
            TuiAction::Quit => self.should_quit = true,
        }
        None
    }

    pub(crate) fn mark_saved(&mut self) {
        self.dirty = false;
        self.status = StatusMessage::saved("Saved config");
    }

    pub(crate) fn mark_info(&mut self, message: impl Into<String>) {
        self.status = StatusMessage::info(message);
    }

    pub(crate) fn mark_warning(&mut self, message: impl Into<String>) {
        self.status = StatusMessage::warning(message);
    }

    pub(crate) fn mark_error(&mut self, message: impl Into<String>) {
        self.status = StatusMessage::error(message);
    }

    pub(crate) fn mark_save_failed(&mut self, message: impl Into<String>) {
        self.mark_error(message);
    }

    pub(crate) fn replace_config(&mut self, config: AgentConfig, processes: ProcessCatalog) {
        self.config = config;
        self.processes = processes;
        self.traffic = TrafficState::default();
        self.traffic_detail_open = false;
        self.traffic_detail_scroll = 0;
        self.text_edit = None;
        self.hovered_target = None;
        self.hovered_process_argv = None;
        self.dirty = false;
        self.process_view.reconcile_monitors(&self.processes);
        self.status = StatusMessage::info("Reloaded config and process list");
        self.clamp_selection();
    }

    pub(crate) fn focus_targets_for_active_tab(&self) -> Vec<FocusTarget> {
        focus_targets_for_tab(self.active_tab, &self.config)
    }

    pub(crate) fn focus_target_value(&self, target: FocusTarget) -> String {
        target.value(&self.config, self.selected_process_name())
    }

    pub(crate) fn selected_process_name(&self) -> Option<&str> {
        self.processes
            .entries()
            .get(self.process_view.selected_index()?)
            .map(|process| process.name.as_str())
    }

    fn handle_click(&mut self, target: HitTarget) -> Option<TuiEffect> {
        match target {
            HitTarget::Tab(tab) => self.select_tab(tab),
            HitTarget::Field(field) => {
                self.select_field(field);
                return self.adjust_selected(1);
            }
            HitTarget::Control(control) => {
                self.select_control(control);
                return self.activate_control(control, 1);
            }
            HitTarget::TextEditSubmit | HitTarget::TextEditCancel => {}
            HitTarget::Process(index) | HitTarget::ProcessArgv(index) => self.select_process(index),
            HitTarget::ProcessMonitor(index) => self.toggle_process_monitor(index),
            HitTarget::TrafficProcess(index) => self.watch_process_from_traffic(index),
            HitTarget::TrafficRow(index) => self.select_traffic_row(index),
            HitTarget::TrafficDetailPanel | HitTarget::TextEditPanel => {}
            HitTarget::TrafficDetailClose => self.close_traffic_detail(),
            HitTarget::Save => {
                return Some(TuiEffect::SaveConfig);
            }
            HitTarget::Reload => {
                return Some(TuiEffect::ReloadConfig);
            }
            HitTarget::Quit => self.should_quit = true,
        }
        None
    }

    fn handle_hover(&mut self, target: Option<HitTarget>, column: u16, row: u16) {
        self.hovered_target = target;
        self.hovered_process_argv = match target {
            Some(HitTarget::ProcessArgv(index)) => Some(ProcessArgvHover { index, column, row }),
            _ => None,
        };
    }

    fn select_tab(&mut self, tab: TuiTab) {
        self.active_tab = tab;
        self.selected_field_index = 0;
        self.clamp_selection();
    }

    fn select_field(&mut self, field: FieldId) {
        if let Some(index) = self
            .focus_targets_for_active_tab()
            .iter()
            .position(|candidate| *candidate == FocusTarget::Field(field))
        {
            self.selected_field_index = index;
        }
    }

    fn select_control(&mut self, control: ControlId) {
        if let Some(index) = self
            .focus_targets_for_active_tab()
            .iter()
            .position(|candidate| *candidate == FocusTarget::Control(control))
        {
            self.selected_field_index = index;
        }
    }

    fn select_process(&mut self, index: usize) {
        self.process_view.select(index, &self.processes);
        self.active_tab = TuiTab::Processes;
    }

    fn toggle_process_monitor(&mut self, index: usize) {
        if self.process_view.toggle_monitor(index, &self.processes) {
            self.traffic = TrafficState::default();
            self.traffic_detail_open = false;
            self.traffic_detail_scroll = 0;
            self.status = StatusMessage::info(self.traffic_filter_label());
        } else {
            self.status = StatusMessage::warning(
                "Selected process has no readable executable path; traffic filter was not changed",
            );
        }
    }

    fn toggle_selected_process_monitor(&mut self) {
        let Some(index) = self.process_view.selected_index() else {
            self.status = StatusMessage::warning("No selected process");
            return;
        };
        self.toggle_process_monitor(index);
    }

    fn watch_process_from_traffic(&mut self, index: usize) {
        if self.process_view.set_single_monitor(index, &self.processes) {
            self.traffic = TrafficState::default();
            self.traffic_detail_open = false;
            self.traffic_detail_scroll = 0;
            self.active_tab = TuiTab::Traffic;
            self.status = StatusMessage::info(self.traffic_filter_label());
        } else {
            self.status = StatusMessage::warning(
                "Selected process has no readable executable path; traffic filter was not changed",
            );
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.active_tab == TuiTab::Processes {
            self.move_process(delta);
            return;
        }
        if self.active_tab == TuiTab::Traffic && self.focus_targets_for_active_tab().is_empty() {
            self.move_traffic(delta);
            return;
        }
        let targets = self.focus_targets_for_active_tab();
        if targets.is_empty() {
            return;
        }
        self.selected_field_index = offset_index(self.selected_field_index, targets.len(), delta);
    }

    fn move_process(&mut self, delta: isize) {
        self.process_view.move_selection(delta, &self.processes);
    }

    pub(crate) async fn refresh_traffic(&mut self) {
        let Some(socket_path) = self
            .runtime_attachment
            .active_socket_path()
            .map(PathBuf::from)
        else {
            self.traffic.mark_admin_unavailable(format!(
                "No active agent admin socket is attached; {}",
                self.runtime_agent_status()
            ));
            self.status = StatusMessage::warning(self.traffic.status().text.clone());
            return;
        };
        let selector = match self.traffic_filter_selector() {
            Some(selector) => selector,
            None if self.processes.entries().is_empty() => {
                let message = "No readable process is selected; traffic filter was not changed";
                self.traffic.mark_filter_unavailable(message);
                self.status = StatusMessage::warning(message);
                return;
            }
            None => {
                let message = "Selected process has no readable executable path; traffic filter was not changed";
                self.traffic.mark_filter_unavailable(message);
                self.status = StatusMessage::warning(message);
                return;
            }
        };
        self.traffic.refresh(&socket_path, selector).await;
        if let Ok(diagnostics) = request_capture_diagnostics(&socket_path).await {
            self.traffic.set_capture_diagnostics(diagnostics);
        }
        match self.traffic.status().kind {
            super::traffic::TrafficStatusKind::Error
            | super::traffic::TrafficStatusKind::Warning => {
                self.status = StatusMessage::warning(self.traffic.status().text.clone());
            }
            super::traffic::TrafficStatusKind::Idle | super::traffic::TrafficStatusKind::Active => {
                self.status = StatusMessage::info(self.traffic.status().text.clone());
            }
        }
    }

    fn move_traffic(&mut self, delta: isize) {
        self.traffic
            .move_selection(delta, self.traffic_visible_rows);
    }

    fn select_traffic_row(&mut self, index: usize) {
        self.active_tab = TuiTab::Traffic;
        self.traffic.select_row(index, self.traffic_visible_rows);
        self.open_traffic_detail();
    }

    fn adjust_selected(&mut self, direction: isize) -> Option<TuiEffect> {
        if direction > 0 && self.active_tab == TuiTab::Traffic {
            self.open_traffic_detail();
            return None;
        }
        if direction > 0 && self.active_tab == TuiTab::Processes {
            self.toggle_selected_process_monitor();
            return None;
        }
        let field = match self.selected_focus_target()? {
            FocusTarget::Field(field) => field,
            FocusTarget::Control(control) => return self.activate_control(control, direction),
        };
        if editable_text_value(&self.config, field).is_some() {
            self.begin_text_edit(field);
            return None;
        }
        let selected_process_selector = self.selected_process_selector();
        match apply_field(
            &mut self.config,
            field,
            direction,
            selected_process_selector,
        ) {
            FieldApplyOutcome::Changed(message) => {
                self.mark_dirty(message);
                self.clamp_selection();
            }
            FieldApplyOutcome::MissingProcessSelector => {
                self.status = self.process_selector_warning();
            }
            FieldApplyOutcome::Unchanged => {}
        }
        None
    }

    fn activate_control(&mut self, control: ControlId, direction: isize) -> Option<TuiEffect> {
        if direction <= 0 {
            return None;
        }
        match control {
            ControlId::ReloadRuntimeActions => Some(TuiEffect::ReloadRuntimeActions),
            ControlId::SearchProcesses => {
                self.begin_process_search();
                None
            }
            ControlId::ClearProcessSearch => {
                self.clear_process_search();
                None
            }
        }
    }

    fn begin_text_edit(&mut self, field: FieldId) {
        let Some(value) = editable_text_value(&self.config, field) else {
            return;
        };
        let label = field.label().to_string();
        self.clear_hover();
        self.text_edit = Some(TextEditSession {
            target: TextEditTarget::Field(field),
            label: label.clone(),
            buffer: value,
            replace_on_input: true,
        });
        self.status = StatusMessage::info(format!("Editing {label}"));
    }

    fn begin_process_search(&mut self) {
        self.select_tab(TuiTab::Processes);
        self.clear_hover();
        self.text_edit = Some(TextEditSession {
            target: TextEditTarget::ProcessSearch,
            label: "Process search".to_string(),
            buffer: self.process_view.filter().to_string(),
            replace_on_input: self.process_view.filter().is_empty(),
        });
        self.status = StatusMessage::info("Editing process search");
    }

    fn clear_process_search(&mut self) {
        if self.process_view.clear_filter(&self.processes) {
            self.status = StatusMessage::info("Process search cleared");
        }
    }

    fn handle_text_edit_action(&mut self, action: TuiAction) -> Option<TuiEffect> {
        match action {
            TuiAction::TextInput(character) => {
                if let Some(edit) = &mut self.text_edit {
                    if edit.replace_on_input {
                        edit.buffer.clear();
                        edit.replace_on_input = false;
                    }
                    edit.buffer.push(character);
                }
            }
            TuiAction::TextBackspace => {
                if let Some(edit) = &mut self.text_edit {
                    if edit.replace_on_input {
                        edit.buffer.clear();
                        edit.replace_on_input = false;
                    } else {
                        edit.buffer.pop();
                    }
                }
            }
            TuiAction::TextSubmit | TuiAction::Click(HitTarget::TextEditSubmit) => {
                self.submit_text_edit();
            }
            TuiAction::TextCancel | TuiAction::Click(HitTarget::TextEditCancel) => {
                self.text_edit = None;
                self.clear_hover();
                self.status = StatusMessage::info("Edit canceled");
            }
            TuiAction::Hover {
                target,
                column,
                row,
            } => self.handle_hover(target, column, row),
            _ => {}
        }
        None
    }

    fn submit_text_edit(&mut self) {
        let Some(edit) = self.text_edit.take() else {
            return;
        };
        self.clear_hover();
        match edit.target {
            TextEditTarget::Field(field) => {
                match apply_text_field(&mut self.config, field, edit.buffer) {
                    FieldApplyOutcome::Changed(message) => {
                        self.mark_dirty(message);
                        self.clamp_selection();
                    }
                    FieldApplyOutcome::MissingProcessSelector => {
                        self.status = self.process_selector_warning();
                    }
                    FieldApplyOutcome::Unchanged => {}
                }
            }
            TextEditTarget::ProcessSearch => self.apply_process_search(edit.buffer),
        }
    }

    fn apply_process_search(&mut self, query: String) {
        self.process_view.set_filter(query, &self.processes);
        if self.process_view.filter().is_empty() {
            self.status = StatusMessage::info("Process search cleared");
        } else {
            let count = self.filtered_process_indices().len();
            self.status = StatusMessage::info(format!("Process search matched {count} entries"));
        }
    }

    fn selected_process_selector(&self) -> Option<probe_core::Selector> {
        self.processes
            .entries()
            .get(self.process_view.selected_index()?)
            .and_then(|process| process.selector())
    }

    fn traffic_filter_selector(&self) -> Option<probe_core::Selector> {
        let selectors = self
            .process_view
            .monitored_exe_paths()
            .iter()
            .cloned()
            .map(selector_for_exe_path)
            .collect::<Vec<_>>();
        match selectors.len() {
            0 => self.selected_process_selector(),
            1 => selectors.into_iter().next(),
            _ => Some(probe_core::Selector::Any { selectors }),
        }
    }

    fn open_traffic_detail(&mut self) {
        if self.traffic.selected_row().is_some() {
            self.clear_hover();
            self.traffic_detail_open = true;
            self.traffic_detail_scroll = 0;
        }
    }

    fn close_traffic_detail(&mut self) {
        self.traffic_detail_open = false;
        self.traffic_detail_scroll = 0;
        self.status = StatusMessage::info("Traffic detail closed");
    }

    fn handle_traffic_detail_action(&mut self, action: TuiAction) -> Option<TuiEffect> {
        match action {
            TuiAction::MoveUp => {
                self.traffic_detail_scroll = self.traffic_detail_scroll.saturating_sub(1);
            }
            TuiAction::MoveDown => {
                self.traffic_detail_scroll = self.traffic_detail_scroll.saturating_add(1);
            }
            TuiAction::TextCancel
            | TuiAction::Quit
            | TuiAction::Click(HitTarget::TrafficDetailClose) => self.close_traffic_detail(),
            TuiAction::Hover {
                target,
                column,
                row,
            } => self.handle_hover(target, column, row),
            TuiAction::Click(HitTarget::TrafficRow(index)) => {
                self.traffic.select_row(index, self.traffic_visible_rows);
                self.traffic_detail_scroll = 0;
            }
            _ => {}
        }
        None
    }

    fn clear_hover(&mut self) {
        self.hovered_target = None;
        self.hovered_process_argv = None;
    }

    fn process_selector_warning(&self) -> StatusMessage {
        let message = self
            .process_view
            .selected_index()
            .and_then(|index| self.processes.entries().get(index))
            .map(|process| {
                format!(
                    "Selected process {} has no readable executable path; selector was not changed",
                    process.name
                )
            })
            .unwrap_or_else(|| "No selected process".to_string());
        StatusMessage::warning(message)
    }

    pub(crate) fn mark_dirty(&mut self, message: impl Into<String>) {
        self.dirty = true;
        self.status = StatusMessage::info(message);
    }

    fn clamp_selection(&mut self) {
        let targets = self.focus_targets_for_active_tab();
        if self.selected_field_index >= targets.len() {
            self.selected_field_index = targets.len().saturating_sub(1);
        }
        self.process_view.clamp(&self.processes);
    }
}

fn initial_status(processes: &ProcessCatalog) -> StatusMessage {
    match (processes.is_empty(), processes.diagnostic_summary()) {
        (true, Some(diagnostic)) => StatusMessage::warning(diagnostic),
        (true, None) => StatusMessage::warning("No process entries were readable under /proc"),
        (false, Some(diagnostic)) => StatusMessage::warning(diagnostic),
        (false, None) => StatusMessage::info("Ready"),
    }
}

fn offset_index(index: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    let raw = index as isize + delta;
    raw.clamp(0, len.saturating_sub(1) as isize) as usize
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use probe_config::{
        AgentConfig, CaptureSelection, ExporterConfig, ExporterTransportConfig,
        default_export_file_path,
    };

    use super::{
        super::{
            controls::{ControlId, FocusTarget},
            processes::{ProcessCatalog, ProcessEntry},
            runtime_attachment::RuntimeAttachment,
        },
        *,
    };

    #[test]
    fn keyboard_and_mouse_actions_share_the_same_field_path() {
        let mut keyboard_app = test_app();
        keyboard_app.select_tab(TuiTab::Capture);
        keyboard_app.handle_action(TuiAction::NextValue);

        let mut mouse_app = test_app();
        mouse_app.select_tab(TuiTab::Capture);
        mouse_app.handle_action(TuiAction::Click(HitTarget::Field(
            FieldId::CaptureSelection,
        )));

        assert_eq!(
            keyboard_app.config.capture.selection,
            mouse_app.config.capture.selection
        );
        assert!(keyboard_app.dirty());
        assert!(mouse_app.dirty());
    }

    #[test]
    fn selecting_process_can_scope_capture_without_manual_selector_toml() {
        let mut app = test_app();
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Processes)));
        app.handle_action(TuiAction::Click(HitTarget::Process(0)));
        app.select_tab(TuiTab::Capture);
        app.handle_action(TuiAction::MoveDown);
        app.handle_action(TuiAction::NextValue);

        let Some(selector) = app.config.capture.deep_observe_selector else {
            panic!("capture selector should be configured from selected process");
        };
        let probe_core::Selector::Match { term } = selector else {
            panic!("process selector should be a match selector");
        };
        assert_eq!(term.process.exe_path_globs, ["/usr/bin/curl".to_string()]);
    }

    #[test]
    fn process_scope_fails_closed_when_executable_path_is_unreadable() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::from_entries([ProcessEntry {
                pid: 42,
                name: "python".to_string(),
                exe_path: None,
                argv: vec!["python".to_string()],
            }]),
        );
        app.select_tab(TuiTab::Capture);
        app.handle_action(TuiAction::MoveDown);

        app.handle_action(TuiAction::NextValue);

        assert!(app.config.capture.deep_observe_selector.is_none());
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(!app.dirty());
    }

    #[test]
    fn process_navigation_keeps_context_above_selected_row() {
        let mut app = multi_process_app();
        app.select_tab(TuiTab::Processes);
        app.set_process_viewport_rows(3);

        app.handle_action(TuiAction::MoveDown);
        app.handle_action(TuiAction::MoveDown);
        app.handle_action(TuiAction::MoveDown);

        assert_eq!(app.selected_process_index(), Some(3));
        assert_eq!(app.process_scroll(), 1);
    }

    #[test]
    fn process_search_filters_selection_and_can_be_cleared_by_control() {
        let mut app = multi_process_app();

        app.handle_action(TuiAction::StartProcessSearch);
        input_text(&mut app, "nginx");
        app.handle_action(TuiAction::TextSubmit);

        assert_eq!(app.process_filter(), "nginx");
        assert_eq!(app.filtered_process_indices(), vec![1]);
        assert_eq!(app.selected_process_index(), Some(1));

        app.handle_action(TuiAction::Click(HitTarget::Control(
            ControlId::ClearProcessSearch,
        )));

        assert!(app.process_filter().is_empty());
        assert_eq!(app.filtered_process_indices().len(), 5);
    }

    #[test]
    fn process_search_with_no_matches_clears_selected_process() {
        let mut app = multi_process_app();

        app.handle_action(TuiAction::StartProcessSearch);
        input_text(&mut app, "does-not-exist");
        app.handle_action(TuiAction::TextSubmit);

        assert!(app.filtered_process_indices().is_empty());
        assert_eq!(app.selected_process_index(), None);
        assert!(app.selected_process_selector().is_none());
    }

    #[test]
    fn process_watch_set_builds_multi_process_traffic_selector() {
        let mut app = multi_process_app();

        app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(0)));
        app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(1)));

        assert!(app.process_is_monitored(0));
        assert!(app.process_is_monitored(1));
        assert_eq!(app.traffic_filter_label(), "2 watched processes");
        let Some(probe_core::Selector::Any { selectors }) = app.traffic_filter_selector() else {
            panic!("multiple watched processes should use any selector");
        };
        assert_eq!(selectors.len(), 2);
    }

    #[test]
    fn config_reload_prunes_watched_processes_that_are_no_longer_visible() {
        let mut app = multi_process_app();
        app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(0)));
        app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(1)));

        app.replace_config(
            app.config().clone(),
            ProcessCatalog::from_entries([process(9, "python", "/usr/bin/python3")]),
        );

        assert!(!app.process_is_monitored(0));
        assert_eq!(app.traffic_filter_label(), "focused process: python");
        let Some(probe_core::Selector::Match { term }) = app.traffic_filter_selector() else {
            panic!("traffic selector should fall back to the focused process");
        };
        assert_eq!(
            term.process.exe_path_globs,
            ["/usr/bin/python3".to_string()]
        );
    }

    #[test]
    fn process_argv_hover_tracks_mouse_position_and_target() {
        let mut app = test_app();

        app.handle_action(TuiAction::Hover {
            target: Some(HitTarget::ProcessArgv(0)),
            column: 40,
            row: 9,
        });

        assert_eq!(
            app.hovered_process_argv(),
            Some(ProcessArgvHover {
                index: 0,
                column: 40,
                row: 9
            })
        );
        assert!(app.is_hovered(HitTarget::ProcessArgv(0)));

        app.handle_action(TuiAction::Hover {
            target: None,
            column: 0,
            row: 0,
        });

        assert_eq!(app.hovered_process_argv(), None);
    }

    #[test]
    fn opening_text_edit_clears_stale_process_argv_hover() {
        let mut app = test_app();
        app.handle_action(TuiAction::Hover {
            target: Some(HitTarget::ProcessArgv(0)),
            column: 40,
            row: 9,
        });

        app.handle_action(TuiAction::StartProcessSearch);
        app.handle_action(TuiAction::Hover {
            target: Some(HitTarget::TextEditSubmit),
            column: 7,
            row: 14,
        });

        assert_eq!(app.hovered_process_argv(), None);
        assert!(app.is_hovered(HitTarget::TextEditSubmit));
    }

    #[tokio::test]
    async fn traffic_view_fails_closed_when_no_process_selector_is_available() {
        let config = AgentConfig::default();
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            config,
            ProcessCatalog::default(),
        );
        app.attach_agent(RuntimeAttachment::existing(PathBuf::from(
            "/tmp/missing-admin.sock",
        )));
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Traffic)));

        app.refresh_traffic().await;

        assert!(app.traffic().rows().is_empty());
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(
            app.status()
                .text
                .contains("No readable process is selected")
        );
    }

    #[test]
    fn capture_backend_cycles_through_live_and_feed_backends() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        assert_eq!(
            app.focus_target_value(FocusTarget::Field(FieldId::CaptureSelection)),
            "auto"
        );
        app.select_tab(TuiTab::Capture);

        app.handle_action(TuiAction::NextValue);

        assert_eq!(app.config.capture.selection, CaptureSelection::Ebpf);
        app.handle_action(TuiAction::PreviousValue);
        assert_eq!(app.config.capture.selection, CaptureSelection::Auto);
    }

    #[test]
    fn storage_retention_fields_share_keyboard_and_mouse_action_path() {
        let mut keyboard_app = test_app();
        keyboard_app.select_tab(TuiTab::Storage);
        keyboard_app.handle_action(TuiAction::NextValue);

        let mut mouse_app = test_app();
        mouse_app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Storage)));
        mouse_app.handle_action(TuiAction::Click(HitTarget::Field(
            FieldId::IngressRetentionMaxRecords,
        )));

        assert_eq!(
            keyboard_app.config.storage.retention.ingress.max_records,
            Some(10_000)
        );
        assert_eq!(
            keyboard_app.config.storage.retention.ingress.max_records,
            mouse_app.config.storage.retention.ingress.max_records
        );
        assert!(keyboard_app.dirty());
        assert!(mouse_app.dirty());
    }

    #[test]
    fn runtime_reload_action_shares_keyboard_and_mouse_action_path() {
        let mut keyboard_app = test_app();
        keyboard_app.select_tab(TuiTab::Runtime);
        keyboard_app.handle_action(TuiAction::MoveDown);
        keyboard_app.handle_action(TuiAction::MoveDown);
        keyboard_app.handle_action(TuiAction::MoveDown);
        let keyboard_effect = keyboard_app.handle_action(TuiAction::NextValue);
        let left_effect = keyboard_app.handle_action(TuiAction::PreviousValue);

        let mut mouse_app = test_app();
        mouse_app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Runtime)));
        let mouse_effect = mouse_app.handle_action(TuiAction::Click(HitTarget::Control(
            ControlId::ReloadRuntimeActions,
        )));

        assert_eq!(keyboard_effect, Some(TuiEffect::ReloadRuntimeActions));
        assert_eq!(mouse_effect, Some(TuiEffect::ReloadRuntimeActions));
        assert_eq!(left_effect, None);
        assert!(!keyboard_app.dirty());
        assert!(!mouse_app.dirty());
    }

    #[test]
    fn exporter_target_text_edit_shares_keyboard_and_mouse_action_path() {
        let mut keyboard_app = export_app(ExporterTransportConfig::File {
            path: PathBuf::new(),
        });
        keyboard_app.select_tab(TuiTab::Export);
        keyboard_app.select_field(FieldId::ExporterFilePath(0));
        keyboard_app.handle_action(TuiAction::NextValue);
        input_text(&mut keyboard_app, "/tmp/probe-keyboard.jsonl");
        keyboard_app.handle_action(TuiAction::TextSubmit);

        let mut mouse_app = export_app(ExporterTransportConfig::File {
            path: PathBuf::new(),
        });
        mouse_app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Export)));
        mouse_app.handle_action(TuiAction::Click(HitTarget::Field(
            FieldId::ExporterFilePath(0),
        )));
        input_text(&mut mouse_app, "/tmp/probe-keyboard.jsonl");
        mouse_app.handle_action(TuiAction::Click(HitTarget::TextEditSubmit));

        let ExporterTransportConfig::File { path } = &keyboard_app.config.exporters[0].transport
        else {
            panic!("keyboard edit should keep file transport");
        };
        assert_eq!(path, &PathBuf::from("/tmp/probe-keyboard.jsonl"));
        assert_eq!(
            keyboard_app.config.exporters[0].transport,
            mouse_app.config.exporters[0].transport
        );
        assert!(keyboard_app.dirty());
        assert!(mouse_app.dirty());
    }

    #[test]
    fn text_edit_replaces_existing_value_on_first_input() {
        let mut app = export_app(ExporterTransportConfig::Webhook {
            endpoint: "http://127.0.0.1:8080/old".to_string(),
            headers: Default::default(),
            tls: Default::default(),
        });
        app.select_tab(TuiTab::Export);
        app.select_field(FieldId::ExporterWebhookEndpoint(0));
        app.handle_action(TuiAction::NextValue);

        input_text(&mut app, "http://127.0.0.1:8080/new");
        app.handle_action(TuiAction::TextSubmit);

        let ExporterTransportConfig::Webhook { endpoint, .. } = &app.config.exporters[0].transport
        else {
            panic!("text edit should keep webhook transport");
        };
        assert_eq!(endpoint, "http://127.0.0.1:8080/new");
    }

    #[test]
    fn export_tab_can_add_default_exporter_without_manual_toml() {
        let mut app = test_app();
        app.select_tab(TuiTab::Export);
        app.handle_action(TuiAction::Click(HitTarget::Field(
            FieldId::AddDefaultExporter,
        )));

        assert_eq!(app.config.exporters.len(), 1);
        let ExporterTransportConfig::File { path } = &app.config.exporters[0].transport else {
            panic!("default exporter should use file transport");
        };
        assert_eq!(path, &default_export_file_path());
        assert!(app.dirty());
    }

    fn test_app() -> TuiApp {
        TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::from_entries([ProcessEntry {
                pid: 42,
                name: "curl".to_string(),
                exe_path: Some(PathBuf::from("/usr/bin/curl")),
                argv: vec!["curl".to_string()],
            }]),
        )
    }

    fn multi_process_app() -> TuiApp {
        TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::from_entries([
                process(1, "curl", "/usr/bin/curl"),
                process(2, "nginx", "/usr/sbin/nginx"),
                process(3, "postgres", "/usr/bin/postgres"),
                process(4, "redis", "/usr/bin/redis-server"),
                process(5, "python", "/usr/bin/python3"),
            ]),
        )
    }

    fn process(pid: u32, name: &str, exe_path: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            name: name.to_string(),
            exe_path: Some(PathBuf::from(exe_path)),
            argv: vec![name.to_string()],
        }
    }

    fn export_app(transport: ExporterTransportConfig) -> TuiApp {
        let mut config = AgentConfig::default();
        config.exporters.push(ExporterConfig {
            transport,
            ..ExporterConfig::default()
        });
        TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            config,
            ProcessCatalog::default(),
        )
    }

    fn input_text(app: &mut TuiApp, text: &str) {
        for character in text.chars() {
            app.handle_action(TuiAction::TextInput(character));
        }
    }
}

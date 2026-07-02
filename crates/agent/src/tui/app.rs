use std::path::PathBuf;

use probe_config::AgentConfig;

use super::fields::{FieldApplyOutcome, FieldId, apply_field, field_value, fields_for_tab};
use super::hit::HitTarget;
use super::processes::ProcessCatalog;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TuiTab {
    Overview,
    Capture,
    Processes,
    Export,
    Enforcement,
    Tls,
}

impl TuiTab {
    pub(crate) const ALL: [Self; 6] = [
        Self::Overview,
        Self::Capture,
        Self::Processes,
        Self::Export,
        Self::Enforcement,
        Self::Tls,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Capture => "Capture",
            Self::Processes => "Processes",
            Self::Export => "Export",
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
    Click(HitTarget),
    Save,
    Reload,
    Quit,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActionOutcome {
    pub(crate) save_requested: bool,
    pub(crate) reload_requested: bool,
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

#[derive(Debug, Clone)]
pub(crate) struct TuiApp {
    config_path: PathBuf,
    config: AgentConfig,
    active_tab: TuiTab,
    selected_field_index: usize,
    selected_process_index: usize,
    process_scroll: usize,
    dirty: bool,
    should_quit: bool,
    status: StatusMessage,
    processes: ProcessCatalog,
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
            selected_process_index: 0,
            process_scroll: 0,
            dirty: false,
            should_quit: false,
            status,
            processes,
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

    pub(crate) fn selected_field(&self) -> Option<FieldId> {
        self.fields_for_active_tab()
            .get(self.selected_field_index)
            .copied()
    }

    pub(crate) fn selected_process_index(&self) -> usize {
        self.selected_process_index
    }

    pub(crate) fn process_scroll(&self) -> usize {
        self.process_scroll
    }

    pub(crate) fn processes(&self) -> &ProcessCatalog {
        &self.processes
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

    pub(crate) fn handle_action(&mut self, action: TuiAction) -> ActionOutcome {
        match action {
            TuiAction::NextTab => self.select_tab(self.active_tab.next()),
            TuiAction::PreviousTab => self.select_tab(self.active_tab.previous()),
            TuiAction::MoveUp => self.move_selection(-1),
            TuiAction::MoveDown => self.move_selection(1),
            TuiAction::NextValue => self.adjust_selected(1),
            TuiAction::PreviousValue => self.adjust_selected(-1),
            TuiAction::Click(target) => return self.handle_click(target),
            TuiAction::Save => {
                return ActionOutcome {
                    save_requested: true,
                    reload_requested: false,
                };
            }
            TuiAction::Reload => {
                return ActionOutcome {
                    save_requested: false,
                    reload_requested: true,
                };
            }
            TuiAction::Quit => self.should_quit = true,
        }
        ActionOutcome::default()
    }

    pub(crate) fn mark_saved(&mut self) {
        self.dirty = false;
        self.status = StatusMessage::saved("Saved config");
    }

    pub(crate) fn mark_save_failed(&mut self, message: impl Into<String>) {
        self.status = StatusMessage::error(message);
    }

    pub(crate) fn replace_config(&mut self, config: AgentConfig, processes: ProcessCatalog) {
        self.config = config;
        self.processes = processes;
        self.dirty = false;
        self.status = StatusMessage::info("Reloaded config and process list");
        self.clamp_selection();
    }

    pub(crate) fn fields_for_active_tab(&self) -> Vec<FieldId> {
        fields_for_tab(self.active_tab, &self.config)
    }

    pub(crate) fn field_value(&self, field: FieldId) -> String {
        field_value(&self.config, field, self.selected_process_name())
    }

    pub(crate) fn selected_process_name(&self) -> Option<&str> {
        self.processes
            .entries()
            .get(self.selected_process_index)
            .map(|process| process.name.as_str())
    }

    fn handle_click(&mut self, target: HitTarget) -> ActionOutcome {
        match target {
            HitTarget::Tab(tab) => self.select_tab(tab),
            HitTarget::Field(field) => {
                self.select_field(field);
                self.adjust_selected(1);
            }
            HitTarget::Process(index) => self.select_process(index),
            HitTarget::Save => {
                return ActionOutcome {
                    save_requested: true,
                    reload_requested: false,
                };
            }
            HitTarget::Reload => {
                return ActionOutcome {
                    save_requested: false,
                    reload_requested: true,
                };
            }
            HitTarget::Quit => self.should_quit = true,
        }
        ActionOutcome::default()
    }

    fn select_tab(&mut self, tab: TuiTab) {
        self.active_tab = tab;
        self.selected_field_index = 0;
        self.clamp_selection();
    }

    fn select_field(&mut self, field: FieldId) {
        if let Some(index) = self
            .fields_for_active_tab()
            .iter()
            .position(|candidate| *candidate == field)
        {
            self.selected_field_index = index;
        }
    }

    fn select_process(&mut self, index: usize) {
        if index < self.processes.entries().len() {
            self.selected_process_index = index;
            self.active_tab = TuiTab::Processes;
            self.keep_process_visible(1);
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.active_tab == TuiTab::Processes {
            self.move_process(delta);
            return;
        }
        let fields = self.fields_for_active_tab();
        if fields.is_empty() {
            return;
        }
        self.selected_field_index = offset_index(self.selected_field_index, fields.len(), delta);
    }

    fn move_process(&mut self, delta: isize) {
        let len = self.processes.entries().len();
        if len == 0 {
            return;
        }
        self.selected_process_index = offset_index(self.selected_process_index, len, delta);
        self.keep_process_visible(1);
    }

    fn adjust_selected(&mut self, direction: isize) {
        let Some(field) = self.selected_field() else {
            return;
        };
        let selected_process_selector = self.selected_process_selector();
        match apply_field(
            &mut self.config,
            field,
            direction,
            selected_process_selector,
        ) {
            FieldApplyOutcome::Changed(message) => self.mark_dirty(message),
            FieldApplyOutcome::MissingProcessSelector => {
                self.status = self.process_selector_warning();
            }
            FieldApplyOutcome::Unchanged => {}
        }
    }

    fn selected_process_selector(&self) -> Option<probe_core::Selector> {
        self.processes
            .entries()
            .get(self.selected_process_index)
            .and_then(|process| process.selector())
    }

    fn process_selector_warning(&self) -> StatusMessage {
        let message = self
            .processes
            .entries()
            .get(self.selected_process_index)
            .map(|process| {
                format!(
                    "Selected process {} has no readable executable path; selector was not changed",
                    process.name
                )
            })
            .unwrap_or_else(|| "No selected process".to_string());
        StatusMessage::warning(message)
    }

    fn keep_process_visible(&mut self, visible_rows: usize) {
        if self.selected_process_index < self.process_scroll {
            self.process_scroll = self.selected_process_index;
        }
        if visible_rows > 0 {
            let end = self.process_scroll.saturating_add(visible_rows);
            if self.selected_process_index >= end {
                self.process_scroll = self
                    .selected_process_index
                    .saturating_sub(visible_rows.saturating_sub(1));
            }
        }
    }

    fn mark_dirty(&mut self, message: impl Into<String>) {
        self.dirty = true;
        self.status = StatusMessage::info(message);
    }

    fn clamp_selection(&mut self) {
        let fields = self.fields_for_active_tab();
        if self.selected_field_index >= fields.len() {
            self.selected_field_index = fields.len().saturating_sub(1);
        }
        let process_count = self.processes.entries().len();
        if self.selected_process_index >= process_count {
            self.selected_process_index = process_count.saturating_sub(1);
        }
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

    use probe_config::{AgentConfig, CaptureSelection};

    use super::{
        super::processes::{ProcessCatalog, ProcessEntry},
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
                argv_count: 1,
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
    fn capture_backend_cycles_through_live_and_feed_backends() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        assert_eq!(app.field_value(FieldId::CaptureSelection), "auto");
        app.select_tab(TuiTab::Capture);

        app.handle_action(TuiAction::NextValue);

        assert_eq!(app.config.capture.selection, CaptureSelection::Ebpf);
        app.handle_action(TuiAction::PreviousValue);
        assert_eq!(app.config.capture.selection, CaptureSelection::Auto);
    }

    fn test_app() -> TuiApp {
        TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::from_entries([ProcessEntry {
                pid: 42,
                name: "curl".to_string(),
                exe_path: Some(PathBuf::from("/usr/bin/curl")),
                argv_count: 1,
            }]),
        )
    }
}

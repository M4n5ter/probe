use std::path::PathBuf;

use probe_config::AgentConfig;

use super::fields::{
    FieldApplyOutcome, FieldId, apply_field, apply_text_field, editable_text_value, field_value,
    fields_for_tab,
};
use super::hit::HitTarget;
use super::processes::ProcessCatalog;
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
    field: FieldId,
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

#[derive(Debug, Clone)]
pub(crate) struct TuiApp {
    config_path: PathBuf,
    config: AgentConfig,
    active_tab: TuiTab,
    selected_field_index: usize,
    selected_process_index: usize,
    process_scroll: usize,
    traffic: TrafficState,
    dirty: bool,
    should_quit: bool,
    status: StatusMessage,
    processes: ProcessCatalog,
    text_edit: Option<TextEditSession>,
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
            traffic: TrafficState::default(),
            dirty: false,
            should_quit: false,
            status,
            processes,
            text_edit: None,
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

    pub(crate) fn traffic(&self) -> &TrafficState {
        &self.traffic
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

    pub(crate) fn is_editing_text(&self) -> bool {
        self.text_edit.is_some()
    }

    pub(crate) fn handle_action(&mut self, action: TuiAction) -> Option<TuiEffect> {
        if self.text_edit.is_some() {
            return self.handle_text_edit_action(action);
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
        self.text_edit = None;
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

    fn handle_click(&mut self, target: HitTarget) -> Option<TuiEffect> {
        match target {
            HitTarget::Tab(tab) => self.select_tab(tab),
            HitTarget::Field(field) => {
                self.select_field(field);
                return self.adjust_selected(1);
            }
            HitTarget::TextEditSubmit | HitTarget::TextEditCancel => {}
            HitTarget::Process(index) => self.select_process(index),
            HitTarget::TrafficRow(index) => self.select_traffic_row(index),
            HitTarget::Save => {
                return Some(TuiEffect::SaveConfig);
            }
            HitTarget::Reload => {
                return Some(TuiEffect::ReloadConfig);
            }
            HitTarget::ReloadRuntimeActions => return Some(TuiEffect::ReloadRuntimeActions),
            HitTarget::Quit => self.should_quit = true,
        }
        None
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
        if self.active_tab == TuiTab::Traffic {
            self.move_traffic(delta);
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

    pub(crate) async fn refresh_traffic(&mut self) {
        if !self.config.admin.enabled {
            self.traffic.mark_admin_disabled();
            self.status = StatusMessage::warning("Enable admin to view live traffic in the TUI");
            return;
        }
        let selector = match self.selected_process_selector() {
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
        self.traffic
            .refresh(&self.config.admin.socket_path, selector)
            .await;
        match self.traffic.status().kind {
            super::traffic::TrafficStatusKind::Error => {
                self.status = StatusMessage::warning(self.traffic.status().text.clone());
            }
            super::traffic::TrafficStatusKind::Idle | super::traffic::TrafficStatusKind::Active => {
                self.status = StatusMessage::info(self.traffic.status().text.clone());
            }
        }
    }

    fn move_traffic(&mut self, delta: isize) {
        self.traffic.move_selection(delta, 1);
    }

    fn select_traffic_row(&mut self, index: usize) {
        self.active_tab = TuiTab::Traffic;
        self.traffic.select_row(index, 1);
    }

    fn adjust_selected(&mut self, direction: isize) -> Option<TuiEffect> {
        if self.active_tab == TuiTab::Runtime {
            return (direction > 0).then_some(TuiEffect::ReloadRuntimeActions);
        }
        let field = self.selected_field()?;
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

    fn begin_text_edit(&mut self, field: FieldId) {
        let Some(value) = editable_text_value(&self.config, field) else {
            return;
        };
        let label = field.label().to_string();
        self.text_edit = Some(TextEditSession {
            field,
            label: label.clone(),
            buffer: value,
            replace_on_input: true,
        });
        self.status = StatusMessage::info(format!("Editing {label}"));
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
                self.status = StatusMessage::info("Edit canceled");
            }
            _ => {}
        }
        None
    }

    fn submit_text_edit(&mut self) {
        let Some(edit) = self.text_edit.take() else {
            return;
        };
        match apply_text_field(&mut self.config, edit.field, edit.buffer) {
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

    use probe_config::{
        AgentConfig, CaptureSelection, ExporterConfig, ExporterTransportConfig,
        default_export_file_path,
    };

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

    #[tokio::test]
    async fn traffic_view_fails_closed_when_no_process_selector_is_available() {
        let mut config = AgentConfig::default();
        config.admin.enabled = true;
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            config,
            ProcessCatalog::default(),
        );
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
        assert_eq!(app.field_value(FieldId::CaptureSelection), "auto");
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
        let keyboard_effect = keyboard_app.handle_action(TuiAction::NextValue);
        let left_effect = keyboard_app.handle_action(TuiAction::PreviousValue);

        let mut mouse_app = test_app();
        mouse_app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Runtime)));
        let mouse_effect =
            mouse_app.handle_action(TuiAction::Click(HitTarget::ReloadRuntimeActions));

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
                argv_count: 1,
            }]),
        )
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

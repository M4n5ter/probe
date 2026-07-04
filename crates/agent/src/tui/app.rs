use std::path::{Path, PathBuf};

use probe_config::AgentConfig;

use super::controls::{ControlId, FocusTarget, focus_targets_for_tab};
use super::data_path::{DataPathCompactSummary, DataPathDiagnosticsView, DataPathOverviewLine};
use super::fields::{
    FieldApplyOutcome, FieldId, apply_field, apply_text_field, editable_text_value,
};
use super::hit::{HitTarget, ScrollTarget};
use super::observation_setup::{
    ProcessObservationMode, process_observation_exe_paths, remove_process_observation,
    replace_process_observations_with, upsert_process_observation,
};
use super::process_view::ProcessViewState;
use super::processes::{ProcessCatalog, ProcessEntry, selector_for_exe_path};
use super::runtime_attachment::RuntimeAttachment;
use super::runtime_status::{
    TrafficRuntimeDiagnostics, local_traffic_runtime_diagnostics,
    request_traffic_runtime_diagnostics,
};
use super::text::terminal_safe_inline_text;
use super::traffic::{
    TrafficDetailLoadRequest, TrafficDetailLoadResult, TrafficRefreshRequest, TrafficRefreshResult,
    TrafficState, load_traffic_refresh, traffic_selector_key,
};

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

    fn keeps_process_search_in_place(self) -> bool {
        matches!(self, Self::Processes | Self::Traffic)
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
    OpenTrafficDiagnostics,
    CycleTrafficViewMode,
    CycleTrafficEventFilter,
    FollowTrafficTail,
    ObserveAuto,
    ObserveEbpf,
    ObserveLibpcap,
    Scroll {
        delta: isize,
        target: Option<ScrollTarget>,
    },
    DragScrollbar {
        target: ScrollTarget,
        offset: usize,
        height: usize,
    },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TuiEffect {
    SaveConfig { saved_status: StatusMessage },
    ReloadConfig,
    ReloadRuntimeActions,
    LoadTrafficDetail { sequence: u64 },
}

#[derive(Debug)]
struct TrafficRefreshIdentity {
    runtime_epoch: u64,
    socket_path: PathBuf,
    selector_key: String,
}

#[derive(Debug)]
pub(crate) struct TrafficRefreshLoadRequest {
    identity: TrafficRefreshIdentity,
    traffic: TrafficRefreshRequest,
}

#[derive(Debug)]
pub(crate) struct TrafficRefreshLoadResult {
    identity: TrafficRefreshIdentity,
    diagnostics: Result<TrafficRuntimeDiagnostics, String>,
    traffic: TrafficRefreshResult,
}

pub(crate) async fn load_traffic_refresh_with_diagnostics(
    request: TrafficRefreshLoadRequest,
) -> TrafficRefreshLoadResult {
    let identity = request.identity;
    let diagnostics_socket_path = identity.socket_path.clone();
    let diagnostics = request_traffic_runtime_diagnostics(&diagnostics_socket_path);
    let traffic = load_traffic_refresh(request.traffic);
    let (diagnostics, traffic) = tokio::join!(diagnostics, traffic);
    TrafficRefreshLoadResult {
        identity,
        diagnostics: diagnostics.map_err(|error| error.to_string()),
        traffic,
    }
}

impl TuiEffect {
    fn save_config() -> Self {
        Self::SaveConfig {
            saved_status: StatusMessage::saved("Saved config"),
        }
    }

    fn save_config_with_status(saved_status: StatusMessage) -> Self {
        Self::SaveConfig { saved_status }
    }
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
            text: terminal_safe_inline_text(text),
        }
    }

    pub(crate) fn saved(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Saved,
            text: terminal_safe_inline_text(text),
        }
    }

    pub(crate) fn warning(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Warning,
            text: terminal_safe_inline_text(text),
        }
    }

    pub(crate) fn error(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Error,
            text: terminal_safe_inline_text(text),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrafficPopup {
    RowDetail,
    Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrafficPopupState {
    kind: TrafficPopup,
    scroll: usize,
}

impl TrafficPopupState {
    fn new(kind: TrafficPopup) -> Self {
        Self { kind, scroll: 0 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficPopupView {
    pub(crate) title: &'static str,
    pub(crate) lines: Vec<String>,
    pub(crate) scroll: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct TuiApp {
    config_path: PathBuf,
    config: AgentConfig,
    active_tab: TuiTab,
    selected_field_index: usize,
    process_view: ProcessViewState,
    traffic: TrafficState,
    traffic_detail_request_id: u64,
    traffic_visible_rows: usize,
    traffic_popup: Option<TrafficPopupState>,
    traffic_popup_content_rows: usize,
    traffic_popup_viewport_rows: usize,
    runtime_attachment: RuntimeAttachment,
    runtime_epoch: u64,
    data_path_diagnostics: DataPathDiagnosticsView,
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
        let mut app = Self {
            config_path,
            config,
            active_tab: TuiTab::Overview,
            selected_field_index: 0,
            process_view: ProcessViewState::default(),
            traffic: TrafficState::default(),
            traffic_detail_request_id: 0,
            traffic_visible_rows: 12,
            traffic_popup: None,
            traffic_popup_content_rows: 0,
            traffic_popup_viewport_rows: 1,
            runtime_attachment: RuntimeAttachment::default(),
            runtime_epoch: 0,
            data_path_diagnostics: DataPathDiagnosticsView::unavailable(
                "local config diagnostics have not been evaluated yet",
            ),
            dirty: false,
            should_quit: false,
            status,
            processes,
            text_edit: None,
            hovered_target: None,
            hovered_process_argv: None,
        };
        app.sync_process_monitors_from_config();
        app.refresh_local_runtime_diagnostics();
        app
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
        self.traffic.set_viewport_rows(self.traffic_visible_rows);
    }

    pub(crate) fn processes(&self) -> &ProcessCatalog {
        &self.processes
    }

    pub(crate) fn traffic(&self) -> &TrafficState {
        &self.traffic
    }

    pub(crate) fn traffic_popup_open(&self) -> bool {
        self.traffic_popup.is_some()
    }

    pub(crate) fn set_traffic_popup_layout(
        &mut self,
        content_rows: usize,
        viewport_rows: usize,
    ) -> Option<usize> {
        self.traffic_popup_content_rows = content_rows;
        self.traffic_popup_viewport_rows = viewport_rows.max(1);
        let max_scroll = self.traffic_popup_max_scroll();
        if let Some(popup) = &mut self.traffic_popup {
            popup.scroll = popup.scroll.min(max_scroll);
            return Some(popup.scroll);
        }
        None
    }

    pub(crate) fn traffic_popup_view(&self) -> Option<TrafficPopupView> {
        let state = self.traffic_popup?;
        Some(TrafficPopupView {
            title: traffic_popup_title_for(state.kind),
            lines: self.traffic_popup_lines(state.kind),
            scroll: state.scroll,
        })
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

    pub(crate) fn overview_data_path_lines(&self) -> Vec<DataPathOverviewLine> {
        self.data_path_diagnostics
            .overview_lines(self.traffic.rows().is_empty())
    }

    pub(crate) fn traffic_data_path_summary(&self) -> DataPathCompactSummary {
        self.data_path_diagnostics
            .compact_summary(self.traffic.rows().is_empty())
    }

    pub(crate) fn traffic_preview_title(&self) -> &'static str {
        if self.traffic.rows().is_empty() {
            "Traffic Readiness"
        } else {
            "Selected Traffic"
        }
    }

    pub(crate) fn traffic_preview_lines(&self, max_lines: usize) -> Vec<String> {
        if !self.traffic.rows().is_empty() {
            return self.traffic.detail_preview_lines(max_lines);
        }
        let mut lines = self.data_path_diagnostics.detail_lines();
        lines.push("Actions: select a process, then choose Auto, eBPF, or libpcap to observe inbound and outbound traffic".to_string());
        fit_lines(lines, max_lines.max(1))
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
        self.bump_runtime_epoch();
        self.invalidate_traffic_detail_requests();
        self.refresh_local_runtime_diagnostics();
        self.status = StatusMessage::info(status);
    }

    pub(crate) fn detach_agent(&mut self, message: impl Into<String>) {
        let status = StatusMessage::error(message);
        self.runtime_attachment = RuntimeAttachment::lost(status.text.clone());
        self.bump_runtime_epoch();
        self.invalidate_traffic_detail_requests();
        self.status = status;
        self.refresh_local_runtime_diagnostics();
    }

    pub(crate) fn handle_action(&mut self, action: TuiAction) -> Option<TuiEffect> {
        if self.text_edit.is_some() {
            return self.handle_text_edit_action(action);
        }
        if self.traffic_popup.is_some() {
            return self.handle_traffic_popup_action(action);
        }
        match action {
            TuiAction::NextTab => self.select_tab(self.active_tab.next()),
            TuiAction::PreviousTab => self.select_tab(self.active_tab.previous()),
            TuiAction::MoveUp => self.move_selection(-1),
            TuiAction::MoveDown => self.move_selection(1),
            TuiAction::Scroll { delta, target } => self.scroll_target(delta, target),
            TuiAction::DragScrollbar {
                target,
                offset,
                height,
            } => self.drag_scrollbar(target, offset, height),
            TuiAction::NextValue => return self.adjust_selected(1),
            TuiAction::PreviousValue => return self.adjust_selected(-1),
            TuiAction::TextInput(_)
            | TuiAction::TextBackspace
            | TuiAction::TextSubmit
            | TuiAction::TextCancel => {}
            TuiAction::StartProcessSearch => self.begin_process_search(),
            TuiAction::ToggleProcessMonitor => return self.toggle_selected_process_monitor(),
            TuiAction::OpenTrafficDiagnostics => self.open_traffic_diagnostics(),
            TuiAction::CycleTrafficViewMode => self.cycle_traffic_view_mode(),
            TuiAction::CycleTrafficEventFilter => self.cycle_traffic_event_filter(),
            TuiAction::FollowTrafficTail => self.follow_traffic_tail(),
            TuiAction::ObserveAuto => {
                return self.apply_process_observation(ProcessObservationMode::Auto);
            }
            TuiAction::ObserveEbpf => {
                return self.apply_process_observation(ProcessObservationMode::Ebpf);
            }
            TuiAction::ObserveLibpcap => {
                return self.apply_process_observation(ProcessObservationMode::Libpcap);
            }
            TuiAction::Hover {
                target,
                column,
                row,
            } => self.handle_hover(target, column, row),
            TuiAction::Click(target) => return self.handle_click(target),
            TuiAction::Save => {
                return Some(TuiEffect::save_config());
            }
            TuiAction::Reload => {
                return Some(TuiEffect::ReloadConfig);
            }
            TuiAction::Quit => self.should_quit = true,
        }
        None
    }

    pub(crate) fn mark_saved(&mut self, saved_status: StatusMessage) {
        self.dirty = false;
        self.status = saved_status;
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
        self.refresh_local_runtime_diagnostics();
        self.clear_traffic_popup();
        self.text_edit = None;
        self.hovered_target = None;
        self.hovered_process_argv = None;
        self.dirty = false;
        self.sync_process_monitors_from_config();
        self.status = StatusMessage::info("Reloaded config and process list");
        self.clamp_selection();
    }

    pub(crate) fn replace_process_catalog(&mut self, processes: ProcessCatalog) {
        self.processes = processes;
        self.hovered_process_argv = None;
        self.sync_process_monitors_from_config();
        self.clamp_selection();
    }

    pub(crate) fn focus_targets_for_active_tab(&self) -> Vec<FocusTarget> {
        focus_targets_for_tab(self.active_tab, &self.config)
    }

    pub(crate) fn focus_target_value(&self, target: FocusTarget) -> String {
        target.value(&self.config, self.selected_process_name())
    }

    pub(crate) fn selected_process_name(&self) -> Option<&str> {
        self.selected_process().map(|process| process.name.as_str())
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
            HitTarget::ProcessMonitor(index) => return self.toggle_process_monitor(index),
            HitTarget::TrafficProcess(index) => return self.watch_process_from_traffic(index),
            HitTarget::TrafficRow(index) => return self.select_traffic_row(index),
            HitTarget::TrafficPopupPanel | HitTarget::TextEditPanel => {}
            HitTarget::TrafficPopupClose => self.close_traffic_popup(),
            HitTarget::Save => {
                return Some(TuiEffect::save_config());
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

    fn toggle_process_monitor(&mut self, index: usize) -> Option<TuiEffect> {
        match self.process_view.toggle_monitor(index, &self.processes) {
            Some(true) => self.observe_process_at_index(
                index,
                ProcessObservationMode::Auto,
                MonitorMode::Keep,
            ),
            Some(false) => self.remove_process_observation_at_index(index),
            None => {
                self.status = StatusMessage::warning(
                    "Selected process has no readable executable path; observation was not changed",
                );
                None
            }
        }
    }

    fn toggle_selected_process_monitor(&mut self) -> Option<TuiEffect> {
        let Some(index) = self.process_view.selected_index() else {
            self.status = StatusMessage::warning("No selected process");
            return None;
        };
        self.toggle_process_monitor(index)
    }

    fn watch_process_from_traffic(&mut self, index: usize) -> Option<TuiEffect> {
        self.active_tab = TuiTab::Traffic;
        self.observe_process_at_index(index, ProcessObservationMode::Auto, MonitorMode::Single)
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

    fn scroll_target(&mut self, delta: isize, target: Option<ScrollTarget>) {
        if target_scrolls_processes(self.active_tab, target) {
            self.move_process(delta);
        } else if target_scrolls_traffic_events(self.active_tab, target) {
            self.scroll_traffic(delta);
        } else {
            self.move_selection(delta);
        }
    }

    fn drag_scrollbar(&mut self, target: ScrollTarget, offset: usize, height: usize) {
        if target_scrolls_traffic_events(self.active_tab, Some(target)) {
            self.traffic
                .drag_scrollbar(offset, height, self.traffic_visible_rows);
        }
    }

    fn move_process(&mut self, delta: isize) {
        self.process_view.move_selection(delta, &self.processes);
    }

    pub(crate) fn begin_traffic_refresh(&mut self) -> Option<TrafficRefreshLoadRequest> {
        let Some(socket_path) = self
            .runtime_attachment
            .active_socket_path()
            .map(PathBuf::from)
        else {
            let message = format!(
                "No active agent admin socket is attached; {}",
                self.runtime_agent_status()
            );
            self.refresh_local_runtime_diagnostics();
            self.traffic.mark_admin_unavailable(message);
            self.status = StatusMessage::warning(self.traffic.status().text.clone());
            return None;
        };
        let selector = match self.traffic_filter_selector() {
            Some(selector) => selector,
            None if self.processes.entries().is_empty() => {
                let message = "No readable process is selected; traffic filter was not changed";
                self.traffic.mark_filter_unavailable(message);
                self.status = StatusMessage::warning(message);
                return None;
            }
            None => {
                let message = "Selected process has no readable executable path; traffic filter was not changed";
                self.traffic.mark_filter_unavailable(message);
                self.status = StatusMessage::warning(message);
                return None;
            }
        };
        let traffic = self.traffic.begin_refresh(socket_path.clone(), selector);
        Some(TrafficRefreshLoadRequest {
            identity: TrafficRefreshIdentity {
                runtime_epoch: self.runtime_epoch,
                socket_path,
                selector_key: traffic.selector_key().to_string(),
            },
            traffic,
        })
    }

    pub(crate) fn apply_traffic_refresh_result(&mut self, result: TrafficRefreshLoadResult) {
        if !self.is_current_traffic_refresh_result(&result) {
            return;
        }
        match &result.diagnostics {
            Ok(diagnostics) => {
                self.data_path_diagnostics =
                    DataPathDiagnosticsView::from_running_agent(diagnostics.clone());
            }
            Err(error) => {
                let message = format!("running agent status unavailable: {error}");
                self.refresh_local_runtime_diagnostics_with_reason(message);
            }
        }
        let traffic_applied = self.traffic.apply_refresh_result(result.traffic);
        if !traffic_applied {
            return;
        }
        let diagnostics_error = match result.diagnostics {
            Ok(diagnostics) => {
                let message = diagnostics.status_message(self.traffic.rows().is_empty());
                self.traffic.apply_runtime_diagnostic_message(message);
                None
            }
            Err(error) => {
                let message = format!("running agent status unavailable: {error}");
                Some(message)
            }
        };
        let diagnostics_failed = diagnostics_error.is_some();
        let traffic_status_text = diagnostics_error.map_or_else(
            || self.traffic.status().text.clone(),
            |error| format!("{}; {error}", self.traffic.status().text),
        );
        match self.traffic.status().kind {
            super::traffic::TrafficStatusKind::Error
            | super::traffic::TrafficStatusKind::Warning => {
                self.status = StatusMessage::warning(traffic_status_text);
            }
            super::traffic::TrafficStatusKind::Idle | super::traffic::TrafficStatusKind::Active
                if diagnostics_failed =>
            {
                self.status = StatusMessage::warning(traffic_status_text);
            }
            super::traffic::TrafficStatusKind::Idle | super::traffic::TrafficStatusKind::Active => {
                self.status = StatusMessage::info(traffic_status_text);
            }
        }
    }

    fn is_current_traffic_refresh_result(&self, result: &TrafficRefreshLoadResult) -> bool {
        self.is_current_traffic_refresh_identity(&result.identity)
    }

    fn is_current_traffic_refresh_identity(&self, identity: &TrafficRefreshIdentity) -> bool {
        self.runtime_epoch == identity.runtime_epoch
            && self.runtime_attachment.active_socket_path() == Some(identity.socket_path.as_path())
            && self
                .traffic_filter_selector()
                .is_some_and(|selector| traffic_selector_key(&selector) == identity.selector_key)
    }

    fn bump_runtime_epoch(&mut self) {
        self.runtime_epoch = self
            .runtime_epoch
            .checked_add(1)
            .expect("runtime epoch overflow");
    }

    pub(crate) fn begin_traffic_detail_load(
        &mut self,
        sequence: u64,
    ) -> Option<TrafficDetailLoadRequest> {
        let Some(socket_path) = self
            .runtime_attachment
            .active_socket_path()
            .map(PathBuf::from)
        else {
            let message = format!(
                "Cannot load full event detail {sequence}: {}",
                self.runtime_agent_status()
            );
            self.traffic.mark_detail_failed(sequence, message.clone());
            self.status = StatusMessage::warning(message);
            return None;
        };
        let request_id = self.next_traffic_detail_request_id();
        self.traffic.mark_detail_loading(sequence, request_id);
        self.status = StatusMessage::info(self.traffic.status().text.clone());
        Some(TrafficDetailLoadRequest {
            socket_path,
            sequence,
            request_id,
        })
    }

    pub(crate) fn apply_traffic_detail_result(&mut self, result: TrafficDetailLoadResult) {
        if !self.traffic.apply_detail_load_result(result) {
            return;
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

    fn next_traffic_detail_request_id(&mut self) -> u64 {
        self.traffic_detail_request_id = self.traffic_detail_request_id.wrapping_add(1);
        self.traffic_detail_request_id
    }

    fn invalidate_traffic_detail_requests(&mut self) {
        self.traffic_detail_request_id = self.traffic_detail_request_id.wrapping_add(1);
        self.traffic.clear_detail_state();
    }

    fn move_traffic(&mut self, delta: isize) {
        self.traffic
            .move_selection(delta, self.traffic_visible_rows);
    }

    fn scroll_traffic(&mut self, delta: isize) {
        self.traffic
            .scroll_viewport(delta.saturating_mul(3), self.traffic_visible_rows);
    }

    fn select_traffic_row(&mut self, index: usize) -> Option<TuiEffect> {
        self.active_tab = TuiTab::Traffic;
        self.traffic.select_row(index, self.traffic_visible_rows);
        self.open_traffic_detail()
    }

    fn adjust_selected(&mut self, direction: isize) -> Option<TuiEffect> {
        if direction > 0 && self.active_tab == TuiTab::Traffic {
            return self.open_traffic_detail();
        }
        if direction > 0 && self.active_tab == TuiTab::Processes {
            return self.toggle_selected_process_monitor();
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
            ControlId::OpenTrafficDiagnostics => {
                self.open_traffic_diagnostics();
                None
            }
            ControlId::TrafficViewMode => {
                self.cycle_traffic_view_mode();
                None
            }
            ControlId::TrafficEventFilter => {
                self.cycle_traffic_event_filter();
                None
            }
            ControlId::TrafficTailFollow => {
                self.follow_traffic_tail();
                None
            }
            ControlId::ObserveAuto => self.apply_process_observation(ProcessObservationMode::Auto),
            ControlId::ObserveEbpf => self.apply_process_observation(ProcessObservationMode::Ebpf),
            ControlId::ObserveLibpcap => {
                self.apply_process_observation(ProcessObservationMode::Libpcap)
            }
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

    fn apply_process_observation(&mut self, mode: ProcessObservationMode) -> Option<TuiEffect> {
        let Some(index) = self.process_view.selected_index() else {
            self.status = StatusMessage::warning("No selected process");
            return None;
        };
        self.observe_process_at_index(index, mode, MonitorMode::Single)
    }

    fn observe_process_at_index(
        &mut self,
        index: usize,
        mode: ProcessObservationMode,
        monitor_mode: MonitorMode,
    ) -> Option<TuiEffect> {
        let Some(process) = self.processes.entries().get(index) else {
            self.status = StatusMessage::warning("No selected process");
            return None;
        };
        let Some(selector) = process.selector() else {
            self.status = StatusMessage::warning(
                "Selected process has no readable executable path; observation was not changed",
            );
            return None;
        };
        let Some(exe_path) = process.selector_key() else {
            self.status = StatusMessage::warning(
                "Selected process has no readable executable path; observation was not changed",
            );
            return None;
        };
        let process_name = process.name.clone();
        match monitor_mode {
            MonitorMode::Keep => {
                upsert_process_observation(&mut self.config, &exe_path, selector, mode);
                self.process_view.select(index, &self.processes);
            }
            MonitorMode::Single => {
                replace_process_observations_with(&mut self.config, &exe_path, selector, mode);
                self.process_view.set_single_monitor(index, &self.processes);
            }
        }
        self.traffic = TrafficState::default();
        self.clear_traffic_popup();
        self.dirty = true;
        self.refresh_local_runtime_diagnostics();
        self.clamp_selection();

        let saved_status = process_observation_status(mode, &process_name);
        self.status = saved_status.clone();
        Some(TuiEffect::save_config_with_status(saved_status))
    }

    fn remove_process_observation_at_index(&mut self, index: usize) -> Option<TuiEffect> {
        let Some(process) = self.processes.entries().get(index) else {
            self.status = StatusMessage::warning("No selected process");
            return None;
        };
        let Some(exe_path) = process.selector_key() else {
            self.status = StatusMessage::warning(
                "Selected process has no readable executable path; observation was not changed",
            );
            return None;
        };
        let process_name = process.name.clone();
        self.process_view.select(index, &self.processes);
        if !remove_process_observation(&mut self.config, &exe_path) {
            self.traffic = TrafficState::default();
            self.clear_traffic_popup();
            self.status = StatusMessage::info(self.traffic_filter_label());
            return None;
        }

        self.traffic = TrafficState::default();
        self.clear_traffic_popup();
        self.dirty = true;
        self.refresh_local_runtime_diagnostics();
        self.clamp_selection();

        let saved_status = process_observation_removed_status(&process_name);
        self.status = saved_status.clone();
        Some(TuiEffect::save_config_with_status(saved_status))
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
        if !self.active_tab.keeps_process_search_in_place() {
            self.select_tab(TuiTab::Processes);
        }
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
        self.selected_process().and_then(ProcessEntry::selector)
    }

    fn selected_process(&self) -> Option<&ProcessEntry> {
        self.processes
            .entries()
            .get(self.process_view.selected_index()?)
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

    fn open_traffic_detail(&mut self) -> Option<TuiEffect> {
        if self.traffic.active_row_count() > 0 {
            self.open_traffic_popup(TrafficPopup::RowDetail);
        }
        self.traffic
            .selected_detail_fetch_sequence()
            .map(|sequence| TuiEffect::LoadTrafficDetail { sequence })
    }

    fn open_traffic_diagnostics(&mut self) {
        self.open_traffic_popup(TrafficPopup::Diagnostics);
    }

    fn cycle_traffic_event_filter(&mut self) {
        self.traffic.cycle_event_filter();
        self.status = StatusMessage::info(self.traffic.status().text.clone());
    }

    fn cycle_traffic_view_mode(&mut self) {
        self.traffic.cycle_view_mode();
        self.status = StatusMessage::info(self.traffic.status().text.clone());
    }

    fn follow_traffic_tail(&mut self) {
        self.traffic.jump_to_tail(self.traffic_visible_rows);
        self.status = StatusMessage::info(self.traffic.status().text.clone());
    }

    fn open_traffic_popup(&mut self, kind: TrafficPopup) {
        self.clear_hover();
        self.traffic_popup_content_rows = 0;
        self.traffic_popup_viewport_rows = 1;
        self.traffic_popup = Some(TrafficPopupState::new(kind));
    }

    fn close_traffic_popup(&mut self) {
        let status = match self.traffic_popup.map(|popup| popup.kind) {
            Some(TrafficPopup::Diagnostics) => "Data path diagnostics closed",
            _ => "Traffic detail closed",
        };
        self.clear_traffic_popup();
        self.status = StatusMessage::info(status);
    }

    fn clear_traffic_popup(&mut self) {
        self.traffic_popup = None;
        self.traffic_popup_content_rows = 0;
        self.traffic_popup_viewport_rows = 1;
    }

    fn handle_traffic_popup_action(&mut self, action: TuiAction) -> Option<TuiEffect> {
        match action {
            TuiAction::MoveUp => {
                self.scroll_open_traffic_popup(-1);
            }
            TuiAction::MoveDown => {
                self.scroll_open_traffic_popup(1);
            }
            TuiAction::Scroll { delta, .. } => {
                self.scroll_open_traffic_popup(delta);
            }
            TuiAction::DragScrollbar {
                target: ScrollTarget::TrafficPopup,
                offset,
                height,
            } => self.drag_open_traffic_popup(offset, height),
            TuiAction::TextCancel
            | TuiAction::Quit
            | TuiAction::Click(HitTarget::TrafficPopupClose) => self.close_traffic_popup(),
            TuiAction::Hover {
                target,
                column,
                row,
            } => self.handle_hover(target, column, row),
            TuiAction::Click(HitTarget::TrafficRow(index)) => {
                self.traffic.select_row(index, self.traffic_visible_rows);
                return self.open_traffic_detail();
            }
            _ => {}
        }
        None
    }

    fn scroll_open_traffic_popup(&mut self, delta: isize) {
        if self.traffic_popup.is_none() {
            return;
        }
        let max_scroll = self.traffic_popup_max_scroll();
        if let Some(popup) = &mut self.traffic_popup {
            popup.scroll = apply_scroll_delta(popup.scroll, delta).min(max_scroll);
        }
    }

    fn drag_open_traffic_popup(&mut self, offset: usize, height: usize) {
        if self.traffic_popup.is_none() {
            return;
        }
        self.traffic_popup_viewport_rows = height.max(1);
        let max_scroll = self.traffic_popup_max_scroll();
        let track = height.saturating_sub(1).max(1);
        let scroll = offset.min(track).saturating_mul(max_scroll) / track;
        if let Some(popup) = &mut self.traffic_popup {
            popup.scroll = scroll;
        }
    }

    fn traffic_popup_lines(&self, kind: TrafficPopup) -> Vec<String> {
        match kind {
            TrafficPopup::RowDetail => self
                .traffic
                .selected_detail_lines()
                .unwrap_or_else(|| vec!["No selected traffic row".to_string()]),
            TrafficPopup::Diagnostics => self.data_path_diagnostics.detail_lines(),
        }
    }

    fn traffic_popup_max_scroll(&self) -> usize {
        self.traffic_popup_content_rows
            .saturating_sub(self.traffic_popup_viewport_rows.max(1))
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
        self.refresh_local_runtime_diagnostics();
        self.status = StatusMessage::info(message);
    }

    fn refresh_local_runtime_diagnostics(&mut self) {
        match local_traffic_runtime_diagnostics(self.config.clone()) {
            Ok(diagnostics) => {
                self.data_path_diagnostics =
                    DataPathDiagnosticsView::from_local_config(diagnostics);
            }
            Err(error) => {
                self.data_path_diagnostics =
                    DataPathDiagnosticsView::unavailable(error.to_string());
            }
        }
    }

    fn refresh_local_runtime_diagnostics_with_reason(&mut self, reason: String) {
        match local_traffic_runtime_diagnostics(self.config.clone()) {
            Ok(diagnostics) => {
                self.data_path_diagnostics =
                    DataPathDiagnosticsView::from_local_config_with_reason(diagnostics, reason);
            }
            Err(error) => {
                self.data_path_diagnostics = DataPathDiagnosticsView::unavailable(format!(
                    "{reason}; local config diagnostics unavailable: {error}"
                ));
            }
        }
    }

    fn sync_process_monitors_from_config(&mut self) {
        let exe_paths = process_observation_exe_paths(&self.config);
        self.process_view
            .replace_monitors(exe_paths, &self.processes);
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

fn process_observation_status(mode: ProcessObservationMode, process_name: &str) -> StatusMessage {
    StatusMessage::saved(format!(
        "Observing {process_name} inbound and outbound with {} data path",
        mode.label()
    ))
}

fn process_observation_removed_status(process_name: &str) -> StatusMessage {
    StatusMessage::saved(format!("Stopped observing {process_name}"))
}

fn traffic_popup_title_for(kind: TrafficPopup) -> &'static str {
    match kind {
        TrafficPopup::RowDetail => "Traffic Detail",
        TrafficPopup::Diagnostics => "Data Path Diagnostics",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitorMode {
    Keep,
    Single,
}

fn fit_lines(mut lines: Vec<String>, max_lines: usize) -> Vec<String> {
    if lines.len() <= max_lines {
        return lines;
    }
    lines.truncate(max_lines);
    if let Some(last) = lines.last_mut() {
        *last = "... open Data Path for full diagnostics".to_string();
    }
    lines
}

fn offset_index(index: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    let raw = index as isize + delta;
    raw.clamp(0, len.saturating_sub(1) as isize) as usize
}

fn apply_scroll_delta(position: usize, delta: isize) -> usize {
    if delta < 0 {
        position.saturating_sub(delta.unsigned_abs())
    } else {
        position.saturating_add(delta as usize)
    }
}

fn target_scrolls_processes(active_tab: TuiTab, target: Option<ScrollTarget>) -> bool {
    match active_tab {
        TuiTab::Processes => target == Some(ScrollTarget::ProcessList),
        TuiTab::Traffic => target == Some(ScrollTarget::TrafficProcessList),
        _ => false,
    }
}

fn target_scrolls_traffic_events(active_tab: TuiTab, target: Option<ScrollTarget>) -> bool {
    active_tab == TuiTab::Traffic && target == Some(ScrollTarget::TrafficEvents)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use probe_config::{
        AgentConfig, CaptureSelection, ExporterConfig, ExporterTransportConfig,
        ObservationDataPathMode, ProcessObservationConfig, default_export_file_path,
    };

    use super::{
        super::{
            controls::{ControlId, FocusTarget},
            copy::MITM_PLAINTEXT_COVERAGE,
            processes::{ProcessCatalog, ProcessEntry, selector_for_exe_path},
            runtime_attachment::RuntimeAttachment,
            text::INLINE_TEXT_MAX_CHARS,
        },
        *,
    };

    #[test]
    fn detach_agent_stores_terminal_safe_runtime_status() {
        let mut app = test_app();
        let raw = format!(
            "TUI managed agent exited\nstderr: {}\n{}",
            "failed",
            "x".repeat(INLINE_TEXT_MAX_CHARS * 2)
        );

        app.detach_agent(raw);

        assert_eq!(app.status().kind, StatusKind::Error);
        assert_eq!(app.runtime_agent_status(), app.status().text);
        assert!(!app.runtime_agent_status().chars().any(char::is_control));
        assert!(app.runtime_agent_status().chars().count() <= INLINE_TEXT_MAX_CHARS);
    }

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
                uid: 1000,
                gid: 1000,
                cgroup_path: None,
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
    fn traffic_process_search_keeps_the_user_on_traffic() {
        let mut app = multi_process_app();
        app.select_tab(TuiTab::Traffic);

        app.handle_action(TuiAction::Click(HitTarget::Control(
            ControlId::SearchProcesses,
        )));
        input_text(&mut app, "nginx");
        app.handle_action(TuiAction::Click(HitTarget::TextEditSubmit));

        assert_eq!(app.active_tab(), TuiTab::Traffic);
        assert_eq!(app.process_filter(), "nginx");
        assert_eq!(app.filtered_process_indices(), vec![1]);
        assert_eq!(app.selected_process_index(), Some(1));
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
    fn enforcement_observe_libpcap_control_writes_selected_process_observation() {
        let mut app = multi_process_app();
        app.select_tab(TuiTab::Processes);
        app.handle_action(TuiAction::Click(HitTarget::Process(1)));

        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Enforcement)));
        let effect = app.handle_action(TuiAction::Click(HitTarget::Control(
            ControlId::ObserveLibpcap,
        )));

        let saved_status = expect_save_status(effect);
        assert_eq!(saved_status.kind, StatusKind::Saved);
        assert!(app.dirty());
        assert_eq!(app.config.capture.selection, CaptureSelection::Auto);
        assert!(app.config.capture.deep_observe_selector.is_none());
        assert_eq!(app.config.observations.len(), 1);
        assert_eq!(app.config.observations[0].id, "exe:/usr/sbin/nginx");
        assert_eq!(
            app.config.observations[0].data_path,
            probe_config::ObservationDataPathMode::Libpcap
        );
        assert_eq!(
            app.config.observations[0].directions,
            [
                probe_core::Direction::Inbound,
                probe_core::Direction::Outbound
            ]
        );
    }

    #[test]
    fn traffic_observe_auto_writes_bidirectional_process_profile() {
        let mut app = multi_process_app();
        app.select_tab(TuiTab::Traffic);
        app.handle_action(TuiAction::Click(HitTarget::TrafficProcess(1)));
        let effect = app.handle_action(TuiAction::ObserveAuto);

        let saved_status = expect_save_status(effect);
        assert_eq!(saved_status.kind, StatusKind::Saved);
        assert!(app.dirty());
        assert_eq!(app.config.capture.selection, CaptureSelection::Auto);
        assert!(app.config.capture.deep_observe_selector.is_none());
        assert_eq!(app.traffic_filter_label(), "1 watched processes");
        assert_eq!(app.config.observations.len(), 1);
        assert_eq!(
            app.config.observations[0].data_path,
            probe_config::ObservationDataPathMode::Auto
        );
        assert_eq!(
            app.config.observations[0].directions,
            [
                probe_core::Direction::Inbound,
                probe_core::Direction::Outbound
            ]
        );
    }

    #[test]
    fn traffic_process_click_writes_auto_observation() {
        let mut app = multi_process_app();
        app.select_tab(TuiTab::Traffic);

        let effect = app.handle_action(TuiAction::Click(HitTarget::TrafficProcess(1)));

        let saved_status = expect_save_status(effect);
        assert_eq!(saved_status.kind, StatusKind::Saved);
        assert!(app.dirty());
        assert_eq!(app.active_tab(), TuiTab::Traffic);
        assert!(app.process_is_monitored(1));
        assert_eq!(app.traffic_filter_label(), "1 watched processes");
        assert_eq!(app.config.observations.len(), 1);
        assert_eq!(app.config.observations[0].id, "exe:/usr/sbin/nginx");
        assert_eq!(
            app.config.observations[0].data_path,
            ObservationDataPathMode::Auto
        );
        assert_eq!(
            app.config.observations[0].directions,
            [
                probe_core::Direction::Inbound,
                probe_core::Direction::Outbound
            ]
        );
    }

    #[test]
    fn overview_data_path_summary_updates_after_process_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = AgentConfig::default();
        config.storage.path = temp.path().join("spool");
        let mut app = multi_process_app_with_config(config);
        let initial = overview_value(&app, "MITM");
        assert!(
            initial.contains("not configured"),
            "unexpected initial MITM summary: {initial}"
        );

        app.select_tab(TuiTab::Traffic);
        app.handle_action(TuiAction::Click(HitTarget::TrafficProcess(1)));
        let effect = app.handle_action(TuiAction::ObserveAuto);

        let saved_status = expect_save_status(effect);
        assert_eq!(saved_status.kind, StatusKind::Saved);
        let updated = overview_value(&app, "Capture");
        assert!(updated.contains("mode=live") || updated.contains("unavailable"));
        assert!(
            !overview_value(&app, "Data path source").contains("running agent"),
            "overview must not report running agent diagnostics before admin refresh"
        );
        Ok(())
    }

    #[test]
    fn traffic_data_path_popup_uses_diagnostic_copy_without_row_prompt() {
        let mut app = test_app();
        app.select_tab(TuiTab::Traffic);

        app.handle_action(TuiAction::OpenTrafficDiagnostics);

        let popup = app
            .traffic_popup_view()
            .expect("data path popup should be open");
        assert_eq!(popup.title, "Data Path Diagnostics");
        assert!(
            popup
                .lines
                .iter()
                .any(|line| line == "Data path source: local config")
        );
        assert!(popup.lines.iter().any(|line| line == "Capture diagnostics"));
        assert!(
            popup
                .lines
                .iter()
                .any(|line| line.contains(MITM_PLAINTEXT_COVERAGE))
        );
        assert!(
            !popup
                .lines
                .iter()
                .any(|line| line.contains("Select a traffic row"))
        );
    }

    #[test]
    fn traffic_popup_scrollbar_drag_uses_rendered_content_height() {
        let mut app = test_app();
        app.open_traffic_diagnostics();
        app.set_traffic_popup_layout(50, 5);

        app.handle_action(TuiAction::DragScrollbar {
            target: ScrollTarget::TrafficPopup,
            offset: 4,
            height: 5,
        });

        let popup = app
            .traffic_popup_view()
            .expect("traffic popup should remain open");
        assert_eq!(popup.scroll, 45);
    }

    #[test]
    fn traffic_popup_wheel_scroll_clamps_to_visible_window() {
        let mut app = test_app();
        app.open_traffic_diagnostics();
        app.set_traffic_popup_layout(50, 5);

        app.handle_action(TuiAction::Scroll {
            delta: 999,
            target: Some(ScrollTarget::TrafficPopup),
        });

        let popup = app
            .traffic_popup_view()
            .expect("traffic popup should remain open");
        assert_eq!(popup.scroll, 45);
    }

    #[test]
    fn traffic_popup_scroll_keeps_large_offsets_as_usize() {
        let mut app = test_app();
        app.open_traffic_diagnostics();
        app.set_traffic_popup_layout(70_000, 5);

        app.handle_action(TuiAction::Scroll {
            delta: 69_995,
            target: Some(ScrollTarget::TrafficPopup),
        });

        let popup = app
            .traffic_popup_view()
            .expect("traffic popup should remain open");
        assert_eq!(popup.scroll, 69_995);
    }

    #[test]
    fn process_observation_fails_closed_without_executable_path() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::from_entries([ProcessEntry {
                pid: 42,
                name: "root-daemon".to_string(),
                exe_path: None,
                argv: vec!["root-daemon".to_string()],
                uid: 0,
                gid: 0,
                cgroup_path: Some("/".to_string()),
            }]),
        );
        app.select_tab(TuiTab::Traffic);
        let effect = app.handle_action(TuiAction::ObserveAuto);

        assert_eq!(effect, None);
        assert!(!app.dirty());
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(app.status().text.contains("no readable executable path"));
    }

    #[test]
    fn process_watch_set_builds_multi_process_traffic_selector() {
        let mut app = multi_process_app();

        let first_effect = app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(0)));
        let second_effect = app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(1)));

        assert_eq!(expect_save_status(first_effect).kind, StatusKind::Saved);
        assert_eq!(expect_save_status(second_effect).kind, StatusKind::Saved);
        assert!(app.process_is_monitored(0));
        assert!(app.process_is_monitored(1));
        assert_eq!(app.config.observations.len(), 2);
        assert_eq!(app.traffic_filter_label(), "2 watched processes");
        let Some(probe_core::Selector::Any { selectors }) = app.traffic_filter_selector() else {
            panic!("multiple watched processes should use any selector");
        };
        assert_eq!(selectors.len(), 2);
    }

    #[test]
    fn process_watch_toggle_removes_process_observation() {
        let mut app = multi_process_app();

        let observe_effect = app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(1)));
        let remove_effect = app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(1)));

        assert_eq!(expect_save_status(observe_effect).kind, StatusKind::Saved);
        assert_eq!(expect_save_status(remove_effect).kind, StatusKind::Saved);
        assert!(!app.process_is_monitored(1));
        assert!(app.config.observations.is_empty());
        assert_eq!(app.traffic_filter_label(), "focused process: nginx");
    }

    #[test]
    fn traffic_single_watch_replaces_other_process_observations() {
        let mut app = multi_process_app();
        app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(0)));
        app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(1)));

        let effect = app.handle_action(TuiAction::Click(HitTarget::TrafficProcess(1)));

        assert_eq!(expect_save_status(effect).kind, StatusKind::Saved);
        assert!(!app.process_is_monitored(0));
        assert!(app.process_is_monitored(1));
        assert_eq!(app.config.observations.len(), 1);
        assert_eq!(app.config.observations[0].id, "exe:/usr/sbin/nginx");
        assert_eq!(
            app.config.observations[0].selector,
            selector_for_exe_path("/usr/sbin/nginx".to_string())
        );
    }

    #[test]
    fn traffic_single_watch_deduplicates_existing_process_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(named_process_observation("backend-a", "/usr/sbin/nginx"));
        config
            .observations
            .push(named_process_observation("backend-b", "/usr/sbin/nginx"));
        config
            .observations
            .push(named_process_observation("curl", "/usr/bin/curl"));
        let mut app = multi_process_app_with_config(config);

        let effect = app.handle_action(TuiAction::Click(HitTarget::TrafficProcess(1)));

        assert_eq!(expect_save_status(effect).kind, StatusKind::Saved);
        assert!(app.process_is_monitored(1));
        assert_eq!(app.config.observations.len(), 1);
        assert_eq!(app.config.observations[0].id, "backend-a");
        assert_eq!(
            app.config.observations[0].selector,
            selector_for_exe_path("/usr/sbin/nginx".to_string())
        );
    }

    #[test]
    fn app_initializes_process_monitors_from_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(process_observation("/usr/sbin/nginx"));

        let app = multi_process_app_with_config(config);

        assert!(!app.process_is_monitored(0));
        assert!(app.process_is_monitored(1));
        assert_eq!(app.traffic_filter_label(), "1 watched processes");
    }

    #[test]
    fn app_initializes_process_monitors_from_named_process_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(named_process_observation("backend", "/usr/sbin/nginx"));

        let app = multi_process_app_with_config(config);

        assert!(!app.process_is_monitored(0));
        assert!(app.process_is_monitored(1));
        assert_eq!(app.traffic_filter_label(), "1 watched processes");
    }

    #[test]
    fn process_watch_toggle_removes_named_process_observation() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(named_process_observation("backend", "/usr/sbin/nginx"));
        let mut app = multi_process_app_with_config(config);

        let effect = app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(1)));

        assert_eq!(expect_save_status(effect).kind, StatusKind::Saved);
        assert!(!app.process_is_monitored(1));
        assert!(app.config.observations.is_empty());
    }

    #[test]
    fn config_reload_prunes_watched_processes_that_are_no_longer_visible() {
        let mut app = multi_process_app();
        let first_effect = app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(0)));
        let second_effect = app.handle_action(TuiAction::Click(HitTarget::ProcessMonitor(1)));
        assert_eq!(expect_save_status(first_effect).kind, StatusKind::Saved);
        assert_eq!(expect_save_status(second_effect).kind, StatusKind::Saved);

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

    #[test]
    fn traffic_view_fails_closed_when_no_process_selector_is_available() {
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

        let request = app.begin_traffic_refresh();

        assert!(request.is_none());
        assert!(app.traffic().rows().is_empty());
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(
            app.status()
                .text
                .contains("No readable process is selected")
        );
    }

    #[test]
    fn lost_agent_attachment_does_not_expose_stale_admin_socket() {
        let mut app = test_app();
        app.attach_agent(RuntimeAttachment::managed(
            PathBuf::from("/tmp/stale-admin.sock"),
            Some(42),
            PathBuf::from("/tmp/stale-agent.log"),
        ));

        app.detach_agent("TUI managed agent unavailable");

        assert!(app.active_admin_socket_path().is_none());
        assert_eq!(app.runtime_agent_status(), "TUI managed agent unavailable");
        assert_eq!(app.status().kind, StatusKind::Error);
    }

    #[test]
    fn pending_traffic_refresh_is_stale_after_focused_process_changes() {
        let mut app = multi_process_app();
        app.attach_agent(RuntimeAttachment::existing(PathBuf::from(
            "/tmp/admin.sock",
        )));

        let request = app
            .begin_traffic_refresh()
            .expect("selected process should produce a traffic selector");
        assert!(app.is_current_traffic_refresh_identity(&request.identity));

        app.handle_action(TuiAction::Click(HitTarget::Process(1)));

        assert!(!app.is_current_traffic_refresh_identity(&request.identity));
    }

    #[test]
    fn pending_traffic_refresh_is_stale_after_same_socket_runtime_reattach() {
        let socket_path = PathBuf::from("/tmp/admin.sock");
        let mut app = test_app();
        app.attach_agent(RuntimeAttachment::existing(socket_path.clone()));

        let request = app
            .begin_traffic_refresh()
            .expect("selected process should produce a traffic selector");
        assert!(app.is_current_traffic_refresh_identity(&request.identity));

        app.attach_agent(RuntimeAttachment::existing(socket_path));

        assert!(!app.is_current_traffic_refresh_identity(&request.identity));
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

    #[test]
    fn traffic_refresh_without_admin_socket_keeps_local_data_path_diagnostics() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.storage.path = temp.path().join("spool");
        let mut app = TuiApp::new(
            temp.path().join("agent.toml"),
            config,
            ProcessCatalog::default(),
        );

        let request = app.begin_traffic_refresh();

        assert!(request.is_none());
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(app.status().text.contains("No active agent admin socket"));
        assert!(app.status().text.contains("No agent runtime attached"));
        app.open_traffic_diagnostics();
        let popup = app
            .traffic_popup_view()
            .expect("data path popup should be open");
        assert!(popup.lines.iter().any(|line| line == "selected: replay"));
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
                uid: 1000,
                gid: 1000,
                cgroup_path: Some("user.slice/user-1000.slice/app.slice/curl.scope".to_string()),
            }]),
        )
    }

    fn multi_process_app() -> TuiApp {
        multi_process_app_with_config(AgentConfig::default())
    }

    fn multi_process_app_with_config(config: AgentConfig) -> TuiApp {
        TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            config,
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
            uid: 1000,
            gid: 1000,
            cgroup_path: Some(format!("system.slice/{name}.service")),
        }
    }

    fn process_observation(exe_path: &str) -> ProcessObservationConfig {
        named_process_observation(&format!("exe:{exe_path}"), exe_path)
    }

    fn named_process_observation(id: &str, exe_path: &str) -> ProcessObservationConfig {
        ProcessObservationConfig {
            id: id.to_string(),
            selector: selector_for_exe_path(exe_path.to_string()),
            data_path: ObservationDataPathMode::Auto,
            directions: vec![
                probe_core::Direction::Inbound,
                probe_core::Direction::Outbound,
            ],
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

    fn expect_save_status(effect: Option<TuiEffect>) -> StatusMessage {
        let Some(TuiEffect::SaveConfig {
            saved_status: status,
        }) = effect
        else {
            panic!("expected save effect with status");
        };
        status
    }

    fn overview_value(app: &TuiApp, label: &str) -> String {
        app.overview_data_path_lines()
            .into_iter()
            .find_map(|line| (line.label == label).then_some(line.value))
            .unwrap_or_else(|| panic!("overview should include {label}"))
    }
}

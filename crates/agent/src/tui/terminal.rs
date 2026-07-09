use std::{
    io::{self, Stdout},
    path::PathBuf,
    time::{Duration, Instant},
};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use probe_config::{AgentConfig, default_config_path};

use crate::process_catalog::ProcessCatalog;

use super::{
    agent::TuiAgentSupervisor,
    app::{
        StatusMessage, TrafficRefreshLoadResult, TuiAction, TuiApp, TuiEffect, TuiTab,
        load_traffic_refresh_with_diagnostics,
    },
    config_edit::{TuiError, load_config, load_or_create_config},
    config_save_task::{ConfigSaveCompletion, ConfigSaveState, SavedConfigRuntimeReconcile},
    controls::{ControlId, traffic_digit_control},
    hit::HitMap,
    process_catalog_task::{
        STARTUP_BACKGROUND_STATUS, apply_process_catalog_load_result,
        cancel_pending_process_catalog, spawn_process_catalog_load, take_finished_process_catalog,
    },
    render::draw,
    runtime_reconcile::{
        PendingRuntimeReconcile, QueuedRuntimeReconcile, apply_runtime_reconcile_result,
        cancel_pending_runtime_reconcile, mark_saved_runtime_success, reload_runtime_actions,
        spawn_agent_management_runtime_reconcile, spawn_saved_runtime_reconcile,
        spawn_startup_runtime_reconcile, take_finished_runtime_reconcile,
        wait_for_runtime_reconcile,
    },
    traffic_detail_task::TrafficDetailTaskPool,
};

const TRAFFIC_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuiOptions {
    pub(crate) config: Option<PathBuf>,
    pub(crate) tab: TuiTab,
}

pub(crate) async fn run_tui(options: TuiOptions) -> Result<(), TuiError> {
    let config_path = resolve_config_path(options.config);
    let mut loaded = load_or_create_config(&config_path)?;
    let mut app = TuiApp::new(
        config_path,
        loaded.config.clone(),
        ProcessCatalog::default(),
    );
    app.select_tab(options.tab);
    let mut supervisor = None;
    let mut pending_process_catalog = Some(spawn_process_catalog_load());
    let startup_runtime_reconcile = spawn_startup_runtime_reconcile(
        app.config().clone(),
        StatusMessage::info(STARTUP_BACKGROUND_STATUS),
    );
    apply_pending_runtime_wait_status(&mut app, &startup_runtime_reconcile);
    let mut pending_runtime_reconcile = Some(startup_runtime_reconcile);
    let mut queued_runtime_reconcile: Option<QueuedRuntimeReconcile> = None;
    let result = async {
        let mut terminal = TerminalSession::enter()?;
        let mut last_traffic_refresh = Instant::now()
            .checked_sub(TRAFFIC_REFRESH_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_agent_poll = Instant::now();
        let mut config_saves = ConfigSaveState::default();
        let mut traffic_detail_tasks = TrafficDetailTaskPool::default();
        let mut pending_traffic_refresh: Option<PendingTrafficRefresh> = None;

        loop {
            if let Some(completion) = config_saves.take_finished().await {
                apply_config_save_and_queue_runtime(
                    &mut loaded.source,
                    &mut supervisor,
                    &mut config_saves,
                    &mut pending_runtime_reconcile,
                    &mut queued_runtime_reconcile,
                    &mut app,
                    completion,
                );
            }
            if let Some(result) = take_finished_process_catalog(&mut pending_process_catalog).await
            {
                apply_process_catalog_load_result(&mut app, result);
            }
            if let Some(result) =
                take_finished_runtime_reconcile(&mut pending_runtime_reconcile).await
            {
                apply_runtime_reconcile_result(&mut supervisor, &mut app, result);
                if let Some(queued) = queued_runtime_reconcile.take() {
                    pending_runtime_reconcile = Some(spawn_queued_runtime_reconcile(
                        &mut supervisor,
                        &mut app,
                        queued,
                    ));
                }
            }
            for result in traffic_detail_tasks.drain_finished().await {
                app.apply_traffic_detail_result(result);
            }
            traffic_detail_tasks.fill(&mut app, None);
            if let Some(result) = take_finished_traffic_refresh(&mut pending_traffic_refresh).await
            {
                match result {
                    Ok(result) => app.apply_traffic_refresh_result(result),
                    Err(error) => app.mark_warning(format!("Traffic refresh task failed: {error}")),
                }
            }
            if last_agent_poll.elapsed() >= TRAFFIC_REFRESH_INTERVAL {
                let agent_exit = match supervisor.as_mut() {
                    Some(running) => match running.poll_exit().await {
                        Ok(Some(message)) => Some(message),
                        Ok(None) => None,
                        Err(error) => {
                            app.mark_error(error.to_string());
                            None
                        }
                    },
                    None => None,
                };
                if let Some(message) = agent_exit {
                    if let Some(supervisor) = supervisor.take() {
                        stop_supervisor_after_tui(supervisor, "after managed agent exit").await;
                    }
                    app.detach_agent(message);
                }
                last_agent_poll = Instant::now();
            }
            if app.active_tab() == TuiTab::Traffic
                && last_traffic_refresh.elapsed() >= TRAFFIC_REFRESH_INTERVAL
                && pending_traffic_refresh.is_none()
            {
                if let Some(message) =
                    traffic_refresh_waiting_for_runtime(&supervisor, &pending_runtime_reconcile)
                {
                    app.mark_traffic_refresh_waiting_for_runtime(message);
                } else if let Some(request) = app.begin_traffic_refresh() {
                    pending_traffic_refresh = Some(PendingTrafficRefresh {
                        task: tokio::spawn(load_traffic_refresh_with_diagnostics(request)),
                    });
                }
                last_traffic_refresh = Instant::now();
            }
            let hit_map = terminal.draw(&mut app)?;
            if app.should_quit() {
                finish_before_quit(
                    &mut terminal,
                    &mut loaded.source,
                    &mut supervisor,
                    &mut config_saves,
                    &mut pending_runtime_reconcile,
                    &mut queued_runtime_reconcile,
                    &mut app,
                )
                .await?;
                break;
            }
            if !event::poll(Duration::from_millis(250))? {
                continue;
            }
            let Some(action) = event_to_action(
                &hit_map,
                event::read()?,
                app.is_editing_text(),
                app.active_tab(),
            ) else {
                continue;
            };
            if let Some(effect) = app.handle_action(action) {
                match effect {
                    TuiEffect::SaveConfig { saved_status } => {
                        let should_reconcile_runtime = app.dirty() || supervisor.as_ref().is_none();
                        config_saves.start_or_queue(
                            &loaded.source,
                            &mut app,
                            saved_status,
                            should_reconcile_runtime,
                        );
                    }
                    TuiEffect::ReloadConfig => {
                        if config_saves.reject_reload(&mut app) {
                            continue;
                        }
                        match load_config(app.config_path()) {
                            Ok(next) => {
                                loaded = next;
                                app.replace_config(
                                    loaded.config.clone(),
                                    ProcessCatalog::default(),
                                );
                                app.mark_info(
                                    "Reloaded config; refreshing process list in background",
                                );
                                pending_process_catalog = Some(spawn_process_catalog_load());
                                queue_runtime_reconcile(
                                    &mut supervisor,
                                    &mut pending_runtime_reconcile,
                                    &mut queued_runtime_reconcile,
                                    &mut app,
                                    StatusMessage::info("Reloaded config"),
                                );
                            }
                            Err(error) => app.mark_save_failed(error.to_string()),
                        }
                    }
                    TuiEffect::ManageAgent => queue_agent_management(
                        &mut supervisor,
                        &mut pending_runtime_reconcile,
                        &mut app,
                    ),
                    TuiEffect::ReloadRuntimeActions => reload_runtime_actions(&mut app).await,
                    TuiEffect::LoadTrafficDetail { sequence } => {
                        traffic_detail_tasks.fill(&mut app, Some(sequence));
                    }
                }
            }
        }
        traffic_detail_tasks.abort_all();
        if let Some(pending) = pending_traffic_refresh {
            pending.task.abort();
        }
        cancel_pending_runtime_reconcile(pending_runtime_reconcile).await;
        cancel_pending_process_catalog(pending_process_catalog).await;

        Ok(())
    }
    .await;
    if let Some(supervisor) = supervisor {
        stop_supervisor_after_tui(supervisor, "during TUI shutdown").await;
    }
    result
}

struct PendingTrafficRefresh {
    task: tokio::task::JoinHandle<TrafficRefreshLoadResult>,
}

async fn stop_supervisor_after_tui(supervisor: TuiAgentSupervisor, action: &'static str) {
    if let Err(error) = supervisor.stop().await {
        eprintln!("failed to stop TUI agent {action}: {error}");
    }
}

fn traffic_refresh_waiting_for_runtime(
    supervisor: &Option<TuiAgentSupervisor>,
    pending_runtime_reconcile: &Option<PendingRuntimeReconcile>,
) -> Option<StatusMessage> {
    if supervisor.is_none() {
        pending_runtime_reconcile
            .as_ref()
            .and_then(PendingRuntimeReconcile::traffic_wait_status)
            .cloned()
    } else {
        None
    }
}

fn apply_config_save_and_queue_runtime(
    loaded_source: &mut String,
    supervisor: &mut Option<TuiAgentSupervisor>,
    config_saves: &mut ConfigSaveState,
    pending_runtime_reconcile: &mut Option<PendingRuntimeReconcile>,
    queued_runtime_reconcile: &mut Option<QueuedRuntimeReconcile>,
    app: &mut TuiApp,
    completion: ConfigSaveCompletion,
) {
    if let Some(reconcile) = config_saves.apply_completion(loaded_source, app, completion) {
        queue_saved_runtime_reconcile(
            supervisor,
            pending_runtime_reconcile,
            queued_runtime_reconcile,
            app,
            reconcile,
        );
    }
}

async fn finish_before_quit(
    terminal: &mut TerminalSession,
    loaded_source: &mut String,
    supervisor: &mut Option<TuiAgentSupervisor>,
    config_saves: &mut ConfigSaveState,
    pending_runtime_reconcile: &mut Option<PendingRuntimeReconcile>,
    queued_runtime_reconcile: &mut Option<QueuedRuntimeReconcile>,
    app: &mut TuiApp,
) -> Result<(), TuiError> {
    while config_saves.has_work() {
        app.mark_info("Waiting for config save to finish before quit");
        let _ = terminal.draw(app)?;
        if let Some(completion) = config_saves.wait_for_pending().await {
            apply_config_save_and_queue_runtime(
                loaded_source,
                supervisor,
                config_saves,
                pending_runtime_reconcile,
                queued_runtime_reconcile,
                app,
                completion,
            );
        }
    }
    if runtime_reconcile_needs_finish_before_quit(
        pending_runtime_reconcile,
        queued_runtime_reconcile,
    ) {
        app.mark_info("Waiting for runtime task to finish before quit");
        let _ = terminal.draw(app)?;
        drain_runtime_reconcile_before_quit(
            supervisor,
            app,
            pending_runtime_reconcile,
            queued_runtime_reconcile,
        )
        .await;
    }
    Ok(())
}

fn runtime_reconcile_needs_finish_before_quit(
    pending_runtime_reconcile: &Option<PendingRuntimeReconcile>,
    queued_runtime_reconcile: &Option<QueuedRuntimeReconcile>,
) -> bool {
    queued_runtime_reconcile.is_some()
        || pending_runtime_reconcile
            .as_ref()
            .is_some_and(PendingRuntimeReconcile::must_finish_before_quit)
}

async fn drain_runtime_reconcile_before_quit(
    supervisor: &mut Option<TuiAgentSupervisor>,
    app: &mut TuiApp,
    pending_runtime_reconcile: &mut Option<PendingRuntimeReconcile>,
    queued_runtime_reconcile: &mut Option<QueuedRuntimeReconcile>,
) {
    loop {
        if pending_runtime_reconcile.is_none() {
            let Some(queued) = queued_runtime_reconcile.take() else {
                break;
            };
            *pending_runtime_reconcile =
                Some(spawn_queued_runtime_reconcile(supervisor, app, queued));
        }
        let Some(result) = wait_for_runtime_reconcile(pending_runtime_reconcile).await else {
            break;
        };
        apply_runtime_reconcile_result(supervisor, app, result);
        if let Some(queued) = queued_runtime_reconcile.take() {
            *pending_runtime_reconcile =
                Some(spawn_queued_runtime_reconcile(supervisor, app, queued));
        }
    }
}

fn queue_runtime_reconcile(
    supervisor: &mut Option<TuiAgentSupervisor>,
    pending_runtime_reconcile: &mut Option<PendingRuntimeReconcile>,
    queued_runtime_reconcile: &mut Option<QueuedRuntimeReconcile>,
    app: &mut TuiApp,
    status: StatusMessage,
) {
    queue_runtime_reconcile_for_config(
        supervisor,
        pending_runtime_reconcile,
        queued_runtime_reconcile,
        app,
        app.config().clone(),
        app.config_path().clone(),
        status,
    );
}

fn queue_agent_management(
    supervisor: &mut Option<TuiAgentSupervisor>,
    pending_runtime_reconcile: &mut Option<PendingRuntimeReconcile>,
    app: &mut TuiApp,
) {
    if app.dirty() {
        app.mark_warning("Save or reload config before managing the agent");
        return;
    }
    if pending_runtime_reconcile.is_some() {
        app.mark_info("Agent startup or runtime apply is already in progress");
        return;
    }
    let pending = spawn_agent_management_runtime_reconcile(
        supervisor,
        app.config().clone(),
        StatusMessage::info("Manage agent"),
        StatusMessage::info(STARTUP_BACKGROUND_STATUS),
    );
    apply_pending_runtime_wait_status(app, &pending);
    *pending_runtime_reconcile = Some(pending);
}

fn queue_saved_runtime_reconcile(
    supervisor: &mut Option<TuiAgentSupervisor>,
    pending_runtime_reconcile: &mut Option<PendingRuntimeReconcile>,
    queued_runtime_reconcile: &mut Option<QueuedRuntimeReconcile>,
    app: &mut TuiApp,
    reconcile: SavedConfigRuntimeReconcile,
) {
    queue_runtime_reconcile_for_config(
        supervisor,
        pending_runtime_reconcile,
        queued_runtime_reconcile,
        app,
        reconcile.config,
        reconcile.config_path,
        reconcile.status,
    );
}

fn queue_runtime_reconcile_for_config(
    supervisor: &mut Option<TuiAgentSupervisor>,
    pending_runtime_reconcile: &mut Option<PendingRuntimeReconcile>,
    queued_runtime_reconcile: &mut Option<QueuedRuntimeReconcile>,
    app: &mut TuiApp,
    config: AgentConfig,
    config_path: PathBuf,
    status: StatusMessage,
) {
    let queued = runtime_reconcile_request(config, config_path, status.clone());
    if pending_runtime_reconcile.is_some() {
        *queued_runtime_reconcile = Some(queued);
        mark_saved_runtime_success(
            app,
            &status,
            "runtime apply queued behind the active agent task",
        );
        return;
    }
    let pending = spawn_queued_runtime_reconcile(supervisor, app, queued);
    let waits_for_runtime = pending.traffic_wait_status().is_some();
    *pending_runtime_reconcile = Some(pending);
    if !waits_for_runtime {
        mark_saved_runtime_success(app, &status, "applying runtime changes in background");
    }
}

fn runtime_reconcile_request(
    config: AgentConfig,
    config_path: PathBuf,
    status: StatusMessage,
) -> QueuedRuntimeReconcile {
    QueuedRuntimeReconcile {
        config,
        config_path,
        saved_status: status,
    }
}

fn spawn_queued_runtime_reconcile(
    supervisor: &mut Option<TuiAgentSupervisor>,
    app: &mut TuiApp,
    queued: QueuedRuntimeReconcile,
) -> PendingRuntimeReconcile {
    let active_socket_path = app.active_admin_socket_path().map(PathBuf::from);
    let pending = spawn_saved_runtime_reconcile(supervisor, queued, active_socket_path);
    apply_pending_runtime_wait_status(app, &pending);
    pending
}

fn apply_pending_runtime_wait_status(app: &mut TuiApp, pending: &PendingRuntimeReconcile) {
    let Some(status) = pending.traffic_wait_status().cloned() else {
        return;
    };
    app.mark_runtime_starting_with_status(status);
}

async fn take_finished_traffic_refresh(
    pending: &mut Option<PendingTrafficRefresh>,
) -> Option<Result<TrafficRefreshLoadResult, tokio::task::JoinError>> {
    if !pending
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return None;
    }
    let pending = pending.take().expect("pending refresh task was checked");
    Some(pending.task.await)
}

fn resolve_config_path(config: Option<PathBuf>) -> PathBuf {
    config.unwrap_or_else(default_config_path)
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    fn enter() -> Result<Self, TuiError> {
        let raw_mode = RawModeGuard::enter()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let screen = ScreenGuard::active();
        execute!(stdout, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;
        raw_mode.disarm();
        screen.disarm();
        Ok(Self { terminal })
    }

    fn draw(&mut self, app: &mut TuiApp) -> Result<HitMap, TuiError> {
        let mut hit_map = HitMap::default();
        self.terminal.draw(|frame| {
            hit_map = draw(frame, app);
        })?;
        Ok(hit_map)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = self.terminal.show_cursor();
    }
}

struct RawModeGuard {
    active: bool,
}

impl RawModeGuard {
    fn enter() -> Result<Self, TuiError> {
        enable_raw_mode()?;
        Ok(Self { active: true })
    }

    fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = disable_raw_mode();
        }
    }
}

struct ScreenGuard {
    active: bool,
}

impl ScreenGuard {
    fn active() -> Self {
        Self { active: true }
    }

    fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for ScreenGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
        }
    }
}

fn event_to_action(
    hit_map: &HitMap,
    event: Event,
    editing_text: bool,
    active_tab: TuiTab,
) -> Option<TuiAction> {
    match event {
        Event::Key(key) => key_to_action(key, editing_text, active_tab),
        Event::Mouse(mouse) => mouse_to_action(hit_map, mouse),
        Event::Resize(_, _) => None,
        Event::FocusGained | Event::FocusLost | Event::Paste(_) => None,
    }
}

fn key_to_action(key: KeyEvent, editing_text: bool, active_tab: TuiTab) -> Option<TuiAction> {
    if key.kind != KeyEventKind::Press {
        return None;
    }
    if editing_text {
        return text_key_to_action(key);
    }
    match (key.code, key.modifiers) {
        (KeyCode::Char('s'), KeyModifiers::CONTROL) => Some(TuiAction::Save),
        (KeyCode::Char('r'), KeyModifiers::CONTROL) => Some(TuiAction::Reload),
        (KeyCode::Char('a'), KeyModifiers::CONTROL) => Some(TuiAction::ManageAgent),
        (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => Some(TuiAction::Quit),
        (KeyCode::Char('/'), _) if active_tab == TuiTab::Traffic => {
            Some(TuiAction::StartTrafficSearch)
        }
        (KeyCode::Char('f'), KeyModifiers::CONTROL) if active_tab == TuiTab::Traffic => {
            Some(TuiAction::StartTrafficSearch)
        }
        (KeyCode::Char('/'), _) => Some(TuiAction::StartProcessSearch),
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => Some(TuiAction::StartProcessSearch),
        (KeyCode::Char('w'), _) => Some(TuiAction::ToggleProcessMonitor),
        (KeyCode::Char('d'), _) if active_tab == TuiTab::Traffic => {
            Some(TuiAction::OpenTrafficDiagnostics)
        }
        (KeyCode::Char('v'), _) if active_tab == TuiTab::Traffic => {
            Some(TuiAction::CycleTrafficViewMode)
        }
        (KeyCode::Char('h'), _) if active_tab == TuiTab::Traffic => {
            Some(TuiAction::CycleTrafficEventFilter)
        }
        (KeyCode::Char(digit), _) if active_tab == TuiTab::Traffic && digit.is_ascii_digit() => {
            traffic_digit_action(digit)
        }
        (KeyCode::Char('t'), _) if active_tab == TuiTab::Traffic => {
            Some(TuiAction::FollowTrafficLive)
        }
        (KeyCode::Char('a'), _) if active_tab == TuiTab::Traffic => Some(TuiAction::ObserveAuto),
        (KeyCode::Char('e'), _) if active_tab == TuiTab::Traffic => Some(TuiAction::ObserveEbpf),
        (KeyCode::Char('l'), _) if active_tab == TuiTab::Traffic => Some(TuiAction::ObserveLibpcap),
        (KeyCode::Tab, _) => Some(TuiAction::NextTab),
        (KeyCode::BackTab, _) => Some(TuiAction::PreviousTab),
        (KeyCode::Up, _) => Some(TuiAction::MoveUp),
        (KeyCode::Down, _) => Some(TuiAction::MoveDown),
        (KeyCode::Left, _) => Some(TuiAction::PreviousValue),
        (KeyCode::Right, _) | (KeyCode::Enter, _) | (KeyCode::Char(' '), _) => {
            Some(TuiAction::NextValue)
        }
        _ => None,
    }
}

fn traffic_digit_action(digit: char) -> Option<TuiAction> {
    match traffic_digit_control(digit)? {
        ControlId::TrafficView(view_mode) => Some(TuiAction::SetTrafficViewMode(view_mode)),
        ControlId::TrafficFilter(event_filter) => {
            Some(TuiAction::SetTrafficEventFilter(event_filter))
        }
        _ => None,
    }
}

fn text_key_to_action(key: KeyEvent) -> Option<TuiAction> {
    match key.code {
        KeyCode::Enter => Some(TuiAction::TextSubmit),
        KeyCode::Esc => Some(TuiAction::TextCancel),
        KeyCode::Backspace => Some(TuiAction::TextBackspace),
        KeyCode::Char(character)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Some(TuiAction::TextInput(character))
        }
        _ => None,
    }
}

fn mouse_to_action(hit_map: &HitMap, mouse: MouseEvent) -> Option<TuiAction> {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(hit) = hit_map.scrollbar_hit(mouse.column, mouse.row) {
                return Some(TuiAction::DragScrollbar {
                    target: hit.target,
                    offset: hit.offset,
                    height: hit.height,
                });
            }
            hit_map.hit(mouse.column, mouse.row).map(TuiAction::Click)
        }
        MouseEventKind::Drag(MouseButton::Left) => hit_map
            .scrollbar_hit(mouse.column, mouse.row)
            .map(|hit| TuiAction::DragScrollbar {
                target: hit.target,
                offset: hit.offset,
                height: hit.height,
            }),
        MouseEventKind::Moved => Some(TuiAction::Hover {
            target: hit_map.hit(mouse.column, mouse.row),
            column: mouse.column,
            row: mouse.row,
        }),
        MouseEventKind::ScrollUp => Some(TuiAction::Scroll {
            delta: -1,
            target: hit_map.scroll_target(mouse.column, mouse.row),
        }),
        MouseEventKind::ScrollDown => Some(TuiAction::Scroll {
            delta: 1,
            target: hit_map.scroll_target(mouse.column, mouse.row),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use probe_config::AgentConfig;
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};

    use super::{
        super::{
            app::{StatusKind, StatusMessage, TuiAction, TuiApp, TuiTab},
            hit::{HitArea, HitMap, HitTarget, ScrollTarget},
            render::draw,
            runtime_reconcile::{
                completed_blocking_saved_runtime_reconcile_for_test,
                completed_runtime_reconcile_for_test, completed_startup_runtime_reconcile_for_test,
            },
            traffic::{TrafficEventFilter, TrafficStatusKind, TrafficViewMode},
        },
        *,
    };
    use crate::process_catalog::{ProcessCatalog, ProcessEntry};

    #[test]
    fn key_events_translate_to_tui_actions() {
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                false,
                TuiTab::Overview
            ),
            Some(TuiAction::Save)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
                false,
                TuiTab::Traffic
            ),
            Some(TuiAction::ManageAgent)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
                false,
                TuiTab::Overview
            ),
            Some(TuiAction::NextTab)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                false,
                TuiTab::Overview
            ),
            Some(TuiAction::NextValue)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
                false,
                TuiTab::Overview
            ),
            Some(TuiAction::StartProcessSearch)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
                false,
                TuiTab::Traffic
            ),
            Some(TuiAction::StartTrafficSearch)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
                false,
                TuiTab::Traffic
            ),
            Some(TuiAction::ObserveAuto)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE),
                false,
                TuiTab::Traffic
            ),
            Some(TuiAction::ObserveEbpf)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE),
                false,
                TuiTab::Traffic
            ),
            Some(TuiAction::ObserveLibpcap)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
                false,
                TuiTab::Traffic
            ),
            Some(TuiAction::OpenTrafficDiagnostics)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
                false,
                TuiTab::Traffic
            ),
            Some(TuiAction::FollowTrafficLive)
        );
        for (digit, action) in [
            ('1', TuiAction::SetTrafficViewMode(TrafficViewMode::Http)),
            (
                '2',
                TuiAction::SetTrafficViewMode(TrafficViewMode::WebSocket),
            ),
            ('3', TuiAction::SetTrafficViewMode(TrafficViewMode::Events)),
            (
                '4',
                TuiAction::SetTrafficEventFilter(TrafficEventFilter::Application),
            ),
            (
                '5',
                TuiAction::SetTrafficEventFilter(TrafficEventFilter::Http),
            ),
            (
                '6',
                TuiAction::SetTrafficEventFilter(TrafficEventFilter::WebSocket),
            ),
            (
                '7',
                TuiAction::SetTrafficEventFilter(TrafficEventFilter::Security),
            ),
            (
                '8',
                TuiAction::SetTrafficEventFilter(TrafficEventFilter::Diagnostics),
            ),
            (
                '9',
                TuiAction::SetTrafficEventFilter(TrafficEventFilter::All),
            ),
        ] {
            assert_eq!(
                key_to_action(
                    KeyEvent::new(KeyCode::Char(digit), KeyModifiers::NONE),
                    false,
                    TuiTab::Traffic
                ),
                Some(action)
            );
        }
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE),
                false,
                TuiTab::Overview
            ),
            None
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
                false,
                TuiTab::Traffic
            ),
            None
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
                false,
                TuiTab::Overview
            ),
            None
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
                false,
                TuiTab::Overview
            ),
            None
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL),
                false,
                TuiTab::Overview
            ),
            Some(TuiAction::StartProcessSearch)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL),
                false,
                TuiTab::Traffic
            ),
            Some(TuiAction::StartTrafficSearch)
        );
    }

    #[test]
    fn text_editing_keys_feed_text_instead_of_global_shortcuts() {
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                true,
                TuiTab::Overview
            ),
            Some(TuiAction::TextInput('q'))
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                true,
                TuiTab::Overview
            ),
            None
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
                true,
                TuiTab::Overview
            ),
            Some(TuiAction::TextBackspace)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                true,
                TuiTab::Overview
            ),
            Some(TuiAction::TextCancel)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                true,
                TuiTab::Overview
            ),
            Some(TuiAction::TextSubmit)
        );
    }

    #[test]
    fn mouse_click_uses_rendered_hit_map() {
        let hit_map = HitMap::new(vec![HitArea::new(
            Rect::new(2, 3, 10, 1),
            HitTarget::Tab(TuiTab::Processes),
        )]);

        let action = mouse_to_action(
            &hit_map,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 4,
                row: 3,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            action,
            Some(TuiAction::Click(HitTarget::Tab(TuiTab::Processes)))
        );
    }

    #[test]
    fn mouse_wheel_keeps_the_pointer_target() {
        let hit_map = HitMap::default();

        assert_eq!(
            mouse_to_action(
                &hit_map,
                MouseEvent {
                    kind: MouseEventKind::ScrollUp,
                    column: 0,
                    row: 0,
                    modifiers: KeyModifiers::NONE,
                },
            ),
            Some(TuiAction::Scroll {
                delta: -1,
                target: None
            })
        );
        assert_eq!(
            mouse_to_action(
                &hit_map,
                MouseEvent {
                    kind: MouseEventKind::ScrollDown,
                    column: 0,
                    row: 0,
                    modifiers: KeyModifiers::NONE,
                },
            ),
            Some(TuiAction::Scroll {
                delta: 1,
                target: None
            })
        );
    }

    #[test]
    fn mouse_wheel_targets_the_hovered_panel() {
        let hit_map = HitMap::new(vec![HitArea::scroll(
            Rect::new(2, 3, 10, 1),
            ScrollTarget::TrafficEvents,
        )]);

        let action = mouse_to_action(
            &hit_map,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 4,
                row: 3,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            action,
            Some(TuiAction::Scroll {
                delta: 1,
                target: Some(ScrollTarget::TrafficEvents)
            })
        );
    }

    #[test]
    fn mouse_drag_on_scrollbar_targets_scrollbar_position() {
        let hit_map = HitMap::new(vec![HitArea::scrollbar(
            Rect::new(20, 4, 1, 10),
            ScrollTarget::TrafficEvents,
        )]);

        let action = mouse_to_action(
            &hit_map,
            MouseEvent {
                kind: MouseEventKind::Drag(MouseButton::Left),
                column: 20,
                row: 9,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            action,
            Some(TuiAction::DragScrollbar {
                target: ScrollTarget::TrafficEvents,
                offset: 5,
                height: 10,
            })
        );
    }

    #[test]
    fn traffic_watch_button_scroll_does_not_move_process_picker()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut app = traffic_test_app();
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Traffic)));
        let mut terminal = Terminal::new(TestBackend::new(120, 30))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;

        let watch_button = first_hit_coordinate(&hit_map, HitTarget::ProcessMonitor(0), 120, 30)
            .expect("traffic watch action should be clickable");
        assert_eq!(hit_map.scroll_target(watch_button.0, watch_button.1), None);
        let action = mouse_to_action(
            &hit_map,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: watch_button.0,
                row: watch_button.1,
                modifiers: KeyModifiers::NONE,
            },
        )
        .expect("watch button scroll should produce an action");
        app.handle_action(action);
        assert_eq!(app.selected_process_index(), Some(0));

        let picker = first_scroll_coordinate(&hit_map, ScrollTarget::TrafficProcessList, 120, 30)
            .expect("traffic process picker should be scrollable");
        let action = mouse_to_action(
            &hit_map,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: picker.0,
                row: picker.1,
                modifiers: KeyModifiers::NONE,
            },
        )
        .expect("picker scroll should produce an action");
        app.handle_action(action);

        assert_eq!(app.selected_process_index(), Some(1));
        Ok(())
    }

    #[test]
    fn tui_config_path_defaults_to_probe_home_config_file() {
        let explicit = PathBuf::from("/tmp/explicit-agent.toml");

        assert_eq!(resolve_config_path(Some(explicit.clone())), explicit);
        assert_eq!(resolve_config_path(None), default_config_path());
    }

    #[tokio::test]
    async fn quit_drain_consumes_pending_runtime_reconcile() {
        let mut supervisor = None;
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let mut pending_runtime_reconcile = Some(completed_runtime_reconcile_for_test(
            "runtime task finished",
        ));
        let mut queued_runtime_reconcile = None;

        drain_runtime_reconcile_before_quit(
            &mut supervisor,
            &mut app,
            &mut pending_runtime_reconcile,
            &mut queued_runtime_reconcile,
        )
        .await;

        assert!(pending_runtime_reconcile.is_none());
        assert!(queued_runtime_reconcile.is_none());
        assert!(app.status().text.contains("runtime task finished"));
    }

    #[tokio::test]
    async fn startup_runtime_reconcile_does_not_block_quit_without_saved_runtime_work() {
        let pending_runtime_reconcile = Some(completed_startup_runtime_reconcile_for_test(
            "startup still running",
        ));
        let queued_runtime_reconcile = None;

        assert!(!runtime_reconcile_needs_finish_before_quit(
            &pending_runtime_reconcile,
            &queued_runtime_reconcile
        ));
    }

    #[tokio::test]
    async fn traffic_refresh_waits_for_runtime_reconcile_before_reporting_admin_unavailable() {
        let startup_runtime_reconcile = Some(completed_startup_runtime_reconcile_for_test(
            STARTUP_BACKGROUND_STATUS,
        ));
        let saved_runtime_reconcile_with_active_socket =
            Some(completed_runtime_reconcile_for_test(
                "saved runtime apply still running with active socket",
            ));
        let saved_runtime_reconcile_without_active_socket =
            Some(completed_blocking_saved_runtime_reconcile_for_test(
                "saved runtime apply still attaching",
            ));
        let no_pending_runtime = None;

        assert_eq!(
            traffic_refresh_waiting_for_runtime(&None, &startup_runtime_reconcile),
            Some(StatusMessage::info(STARTUP_BACKGROUND_STATUS))
        );
        assert_eq!(
            traffic_refresh_waiting_for_runtime(&None, &saved_runtime_reconcile_with_active_socket),
            None
        );
        assert_eq!(
            traffic_refresh_waiting_for_runtime(
                &None,
                &saved_runtime_reconcile_without_active_socket
            ),
            Some(StatusMessage::saved("Saved config"))
        );
        assert_eq!(
            traffic_refresh_waiting_for_runtime(&None, &no_pending_runtime),
            None
        );
    }

    #[tokio::test]
    async fn saved_runtime_apply_without_active_socket_marks_runtime_starting() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let mut supervisor = None;
        let mut pending_runtime_reconcile = None;
        let mut queued_runtime_reconcile = None;

        queue_runtime_reconcile_for_config(
            &mut supervisor,
            &mut pending_runtime_reconcile,
            &mut queued_runtime_reconcile,
            &mut app,
            AgentConfig::default(),
            PathBuf::from("/tmp/agent.toml"),
            StatusMessage::warning("Saved observation for backend"),
        );

        assert!(pending_runtime_reconcile.is_some());
        assert!(queued_runtime_reconcile.is_none());
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(app.status().text.contains("Saved observation for backend"));
        assert!(
            app.status()
                .text
                .contains("starting or attaching TUI agent")
        );
        assert!(app.runtime_agent_status().contains("Starting or attaching"));
        cancel_pending_runtime_reconcile(pending_runtime_reconcile.take()).await;
    }

    #[tokio::test]
    async fn queued_saved_runtime_spawn_applies_wait_state_without_active_socket() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let mut supervisor = None;
        let queued = runtime_reconcile_request(
            AgentConfig::default(),
            PathBuf::from("/tmp/agent.toml"),
            StatusMessage::error("Config save failed; applying last saved config snapshot"),
        );

        let pending = spawn_queued_runtime_reconcile(&mut supervisor, &mut app, queued);

        assert!(pending.traffic_wait_status().is_some());
        assert_eq!(app.status().kind, StatusKind::Error);
        assert!(app.status().text.contains("Config save failed"));
        assert!(
            app.status()
                .text
                .contains("starting or attaching TUI agent")
        );
        assert!(app.runtime_agent_status().contains("Starting or attaching"));
        cancel_pending_runtime_reconcile(Some(pending)).await;
    }

    #[tokio::test]
    async fn startup_runtime_reconcile_wait_updates_traffic_panel_status() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let pending_runtime_reconcile = Some(completed_startup_runtime_reconcile_for_test(
            STARTUP_BACKGROUND_STATUS,
        ));
        app.mark_runtime_starting_with_status(StatusMessage::info(STARTUP_BACKGROUND_STATUS));

        let message = traffic_refresh_waiting_for_runtime(&None, &pending_runtime_reconcile)
            .expect("startup reconcile should pause traffic refresh");
        app.mark_traffic_refresh_waiting_for_runtime(message);

        assert_eq!(app.status().kind, super::super::app::StatusKind::Info);
        assert_eq!(app.status().text, STARTUP_BACKGROUND_STATUS);
        assert_eq!(app.traffic().status().kind, TrafficStatusKind::Idle);
        assert_eq!(app.traffic().status().text, STARTUP_BACKGROUND_STATUS);
    }

    #[test]
    fn agent_management_refuses_dirty_config() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let mut supervisor = None;
        let mut pending_runtime_reconcile = None;

        app.mark_dirty("Changed capture backend");
        queue_agent_management(&mut supervisor, &mut pending_runtime_reconcile, &mut app);

        assert!(pending_runtime_reconcile.is_none());
        assert!(app.status().text.contains("Save or reload config"));
    }

    fn first_hit_coordinate(
        hit_map: &HitMap,
        target: HitTarget,
        width: u16,
        height: u16,
    ) -> Option<(u16, u16)> {
        (0..height).find_map(|row| {
            (0..width)
                .find(|column| hit_map.hit(*column, row) == Some(target))
                .map(|column| (column, row))
        })
    }

    fn first_scroll_coordinate(
        hit_map: &HitMap,
        target: ScrollTarget,
        width: u16,
        height: u16,
    ) -> Option<(u16, u16)> {
        (0..height).find_map(|row| {
            (0..width)
                .find(|column| hit_map.scroll_target(*column, row) == Some(target))
                .map(|column| (column, row))
        })
    }

    fn traffic_test_app() -> TuiApp {
        TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::from_entries([
                process(42, "curl", "/usr/bin/curl"),
                process(43, "nginx", "/usr/sbin/nginx"),
            ]),
        )
    }

    fn process(pid: u32, name: &str, exe_path: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            process_key: format!("process-key-{pid}"),
            name: name.to_string(),
            exe_path: Some(PathBuf::from(exe_path)),
            argv: vec![name.to_string()],
            uid: 1000,
            gid: 1000,
            cgroup_path: Some(format!("system.slice/{name}.service")),
        }
    }
}

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

use probe_config::default_config_path;

use super::{
    agent::TuiAgentSupervisor,
    app::{TuiAction, TuiApp, TuiEffect, TuiTab},
    config_edit::{TuiError, load_config, load_or_create_config, save_config},
    hit::HitMap,
    processes::ProcessCatalog,
    render::draw,
    runtime_actions::request_runtime_actions_reload,
    traffic::{TrafficDetailLoadResult, load_traffic_detail},
};

const TRAFFIC_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuiOptions {
    pub(crate) config: Option<PathBuf>,
}

pub(crate) async fn run_tui(options: TuiOptions) -> Result<(), TuiError> {
    let config_path = resolve_config_path(options.config);
    let mut loaded = load_or_create_config(&config_path)?;
    let mut app = TuiApp::new(
        config_path,
        loaded.config.clone(),
        ProcessCatalog::from_proc(),
    );
    let mut supervisor = match TuiAgentSupervisor::attach_or_spawn(app.config()).await {
        Ok(supervisor) => {
            app.attach_agent(supervisor.attachment(app.config()));
            Some(supervisor)
        }
        Err(error) => {
            app.mark_error(format!("TUI agent unavailable: {error}"));
            None
        }
    };
    let result = async {
        let mut terminal = TerminalSession::enter()?;
        let mut last_traffic_refresh = Instant::now()
            .checked_sub(TRAFFIC_REFRESH_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_agent_poll = Instant::now();
        let mut pending_traffic_detail: Option<PendingTrafficDetail> = None;

        loop {
            if let Some(result) = take_finished_traffic_detail(&mut pending_traffic_detail).await {
                app.apply_traffic_detail_result(result);
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
                        supervisor.stop().await;
                    }
                    app.detach_agent(message);
                }
                last_agent_poll = Instant::now();
            }
            if app.active_tab() == TuiTab::Traffic
                && last_traffic_refresh.elapsed() >= TRAFFIC_REFRESH_INTERVAL
            {
                app.refresh_traffic().await;
                last_traffic_refresh = Instant::now();
            }
            let hit_map = terminal.draw(&mut app)?;
            if app.should_quit() {
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
                        match save_config(app.config_path(), &loaded.source, app.config()) {
                            Ok(source) => {
                                loaded.source = source;
                                app.mark_saved(saved_status.clone());
                                if should_reconcile_runtime {
                                    reconcile_saved_runtime(
                                        &mut supervisor,
                                        &mut app,
                                        &saved_status,
                                    )
                                    .await;
                                }
                            }
                            Err(error) => app.mark_save_failed(error.to_string()),
                        }
                    }
                    TuiEffect::ReloadConfig => match load_config(app.config_path()) {
                        Ok(next) => {
                            loaded = next;
                            app.replace_config(loaded.config.clone(), ProcessCatalog::from_proc());
                        }
                        Err(error) => app.mark_save_failed(error.to_string()),
                    },
                    TuiEffect::ReloadRuntimeActions => reload_runtime_actions(&mut app).await,
                    TuiEffect::LoadTrafficDetail { sequence } => {
                        if let Some(request) = app.begin_traffic_detail_load(sequence) {
                            if let Some(pending) = pending_traffic_detail.take() {
                                pending.task.abort();
                            }
                            pending_traffic_detail = Some(PendingTrafficDetail {
                                sequence: request.sequence,
                                request_id: request.request_id,
                                task: tokio::spawn(load_traffic_detail(request)),
                            });
                        }
                    }
                }
            }
        }
        if let Some(pending) = pending_traffic_detail {
            pending.task.abort();
        }

        Ok(())
    }
    .await;
    if let Some(supervisor) = supervisor {
        supervisor.stop().await;
    }
    result
}

struct PendingTrafficDetail {
    sequence: u64,
    request_id: u64,
    task: tokio::task::JoinHandle<TrafficDetailLoadResult>,
}

async fn take_finished_traffic_detail(
    pending: &mut Option<PendingTrafficDetail>,
) -> Option<TrafficDetailLoadResult> {
    if !pending
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return None;
    }
    let pending = pending.take().expect("pending detail task was checked");
    match pending.task.await {
        Ok(result) => Some(result),
        Err(error) => Some(TrafficDetailLoadResult::failed(
            pending.sequence,
            pending.request_id,
            format!("traffic detail task failed: {error}"),
        )),
    }
}

async fn reconcile_saved_runtime(
    supervisor: &mut Option<TuiAgentSupervisor>,
    app: &mut TuiApp,
    saved_status: &super::app::StatusMessage,
) {
    let config = app.config().clone();
    match supervisor.take() {
        Some(running) if running.is_managed() => match running.restart(&config).await {
            Ok(next) => {
                app.attach_agent(next.attachment(&config));
                mark_saved_runtime_success(
                    app,
                    saved_status,
                    format!(
                        "restarted TUI managed agent; {}",
                        app.runtime_agent_status()
                    ),
                );
                *supervisor = Some(next);
            }
            Err(error) => {
                detach_saved_runtime_error(
                    app,
                    saved_status,
                    format!("failed to restart TUI managed agent: {error}"),
                );
            }
        },
        Some(running) => {
            mark_saved_runtime_warning(
                app,
                saved_status,
                "restart the attached agent to apply capture and MITM runtime resources",
            );
            *supervisor = Some(running);
        }
        None => match TuiAgentSupervisor::attach_or_spawn(&config).await {
            Ok(next) => {
                app.attach_agent(next.attachment(&config));
                mark_saved_runtime_success(
                    app,
                    saved_status,
                    format!("attached TUI agent; {}", app.runtime_agent_status()),
                );
                *supervisor = Some(next);
            }
            Err(error) => {
                mark_saved_runtime_error(
                    app,
                    saved_status,
                    format!("TUI agent is still unavailable: {error}"),
                );
            }
        },
    }
}

fn mark_saved_runtime_success(
    app: &mut TuiApp,
    saved_status: &super::app::StatusMessage,
    suffix: impl AsRef<str>,
) {
    let text = saved_runtime_status_text(saved_status, suffix);
    match saved_status.kind {
        super::app::StatusKind::Warning => app.mark_warning(text),
        super::app::StatusKind::Error => app.mark_error(text),
        _ => app.mark_info(text),
    }
}

fn mark_saved_runtime_warning(
    app: &mut TuiApp,
    saved_status: &super::app::StatusMessage,
    suffix: impl AsRef<str>,
) {
    app.mark_warning(saved_runtime_status_text(saved_status, suffix));
}

fn mark_saved_runtime_error(
    app: &mut TuiApp,
    saved_status: &super::app::StatusMessage,
    suffix: impl AsRef<str>,
) {
    app.mark_error(saved_runtime_status_text(saved_status, suffix));
}

fn detach_saved_runtime_error(
    app: &mut TuiApp,
    saved_status: &super::app::StatusMessage,
    suffix: impl AsRef<str>,
) {
    app.detach_agent(saved_runtime_status_text(saved_status, suffix));
}

fn saved_runtime_status_text(
    saved_status: &super::app::StatusMessage,
    suffix: impl AsRef<str>,
) -> String {
    format!("{}; {}", saved_status.text, suffix.as_ref())
}

async fn reload_runtime_actions(app: &mut TuiApp) {
    let Some(socket_path) = app.active_admin_socket_path().map(PathBuf::from) else {
        app.mark_warning("No active agent admin socket is attached to this TUI session");
        return;
    };
    match request_runtime_actions_reload(&socket_path).await {
        Ok(summary) if summary.has_failures() => app.mark_warning(summary.status_text()),
        Ok(summary) => app.mark_info(summary.status_text()),
        Err(error) => app.mark_error(error.to_string()),
    }
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
        (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => Some(TuiAction::Quit),
        (KeyCode::Char('/'), _) => Some(TuiAction::StartProcessSearch),
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => Some(TuiAction::StartProcessSearch),
        (KeyCode::Char('w'), _) => Some(TuiAction::ToggleProcessMonitor),
        (KeyCode::Char('d'), _) if active_tab == TuiTab::Traffic => {
            Some(TuiAction::OpenTrafficDiagnostics)
        }
        (KeyCode::Char('h'), _) if active_tab == TuiTab::Traffic => {
            Some(TuiAction::CycleTrafficEventFilter)
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
            hit_map.hit(mouse.column, mouse.row).map(TuiAction::Click)
        }
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
            processes::{ProcessCatalog, ProcessEntry},
            render::draw,
        },
        *,
    };

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

    #[test]
    fn saved_runtime_success_preserves_warning_severity() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let status = StatusMessage::warning(
            "Outbound reliable MITM proxy data path configured, but MITM proxy executable is missing",
        );

        mark_saved_runtime_success(&mut app, &status, "restarted TUI managed agent");

        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(
            app.status()
                .text
                .contains("MITM proxy executable is missing")
        );
        assert!(app.status().text.contains("restarted TUI managed agent"));
    }

    #[test]
    fn saved_runtime_error_preserves_operation_context() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let status = StatusMessage::saved(
            "Saved bidirectional MITM observation for curl; runtime bidirectional MITM expansion is pending",
        );

        mark_saved_runtime_error(
            &mut app,
            &status,
            "TUI agent is still unavailable: startup failed",
        );

        assert_eq!(app.status().kind, StatusKind::Error);
        assert!(app.status().text.contains("bidirectional MITM observation"));
        assert!(app.status().text.contains("MITM expansion is pending"));
        assert!(app.status().text.contains("startup failed"));
    }

    #[test]
    fn saved_runtime_detach_error_preserves_operation_context() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let status = StatusMessage::saved(
            "Saved bidirectional MITM observation for curl; runtime bidirectional MITM expansion is pending",
        );

        detach_saved_runtime_error(
            &mut app,
            &status,
            "failed to restart TUI managed agent: restart failed",
        );

        assert_eq!(app.status().kind, StatusKind::Error);
        assert!(app.status().text.contains("bidirectional MITM observation"));
        assert!(app.status().text.contains("MITM expansion is pending"));
        assert!(
            app.runtime_agent_status()
                .contains("bidirectional MITM observation")
        );
        assert!(
            app.runtime_agent_status()
                .contains("MITM expansion is pending")
        );
        assert!(app.status().text.contains("restart failed"));
    }

    #[tokio::test]
    async fn finished_traffic_detail_task_is_reaped_without_blocking() {
        let mut pending = Some(PendingTrafficDetail {
            sequence: 7,
            request_id: 11,
            task: tokio::spawn(async { TrafficDetailLoadResult::failed(7, 11, "detail failed") }),
        });
        for _ in 0..10 {
            if pending
                .as_ref()
                .is_some_and(|pending| pending.task.is_finished())
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        let result = take_finished_traffic_detail(&mut pending)
            .await
            .expect("finished task should be reaped");

        assert_eq!(result.sequence, 7);
        assert!(pending.is_none());
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
            name: name.to_string(),
            exe_path: Some(PathBuf::from(exe_path)),
            argv: vec![name.to_string()],
            uid: 1000,
            gid: 1000,
            cgroup_path: Some(format!("system.slice/{name}.service")),
        }
    }
}

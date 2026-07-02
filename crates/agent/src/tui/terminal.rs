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

        loop {
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
            let Some(action) = event_to_action(&hit_map, event::read()?, app.is_editing_text())
            else {
                continue;
            };
            if let Some(effect) = app.handle_action(action) {
                match effect {
                    TuiEffect::SaveConfig => {
                        match save_config(app.config_path(), &loaded.source, app.config()) {
                            Ok(source) => {
                                loaded.source = source;
                                app.mark_saved();
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
                }
            }
        }

        Ok(())
    }
    .await;
    if let Some(supervisor) = supervisor {
        supervisor.stop().await;
    }
    result
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

fn event_to_action(hit_map: &HitMap, event: Event, editing_text: bool) -> Option<TuiAction> {
    match event {
        Event::Key(key) => key_to_action(key, editing_text),
        Event::Mouse(mouse) => mouse_to_action(hit_map, mouse),
        Event::Resize(_, _) => None,
        Event::FocusGained | Event::FocusLost | Event::Paste(_) => None,
    }
}

fn key_to_action(key: KeyEvent, editing_text: bool) -> Option<TuiAction> {
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
        MouseEventKind::ScrollUp => Some(TuiAction::MoveUp),
        MouseEventKind::ScrollDown => Some(TuiAction::MoveDown),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use ratatui::layout::Rect;

    use super::{
        super::{
            app::TuiTab,
            hit::{HitArea, HitMap, HitTarget},
        },
        *,
    };

    #[test]
    fn key_events_translate_to_tui_actions() {
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                false
            ),
            Some(TuiAction::Save)
        );
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE), false),
            Some(TuiAction::NextTab)
        );
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), false),
            Some(TuiAction::NextValue)
        );
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE), false),
            Some(TuiAction::StartProcessSearch)
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL),
                false
            ),
            Some(TuiAction::StartProcessSearch)
        );
    }

    #[test]
    fn text_editing_keys_feed_text_instead_of_global_shortcuts() {
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE), true),
            Some(TuiAction::TextInput('q'))
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                true
            ),
            None
        );
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE), true),
            Some(TuiAction::TextBackspace)
        );
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), true),
            Some(TuiAction::TextCancel)
        );
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), true),
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
    fn mouse_wheel_has_keyboard_equivalent_selection_actions() {
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
            Some(TuiAction::MoveUp)
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
            Some(TuiAction::MoveDown)
        );
    }

    #[test]
    fn tui_config_path_defaults_to_probe_home_config_file() {
        let explicit = PathBuf::from("/tmp/explicit-agent.toml");

        assert_eq!(resolve_config_path(Some(explicit.clone())), explicit);
        assert_eq!(resolve_config_path(None), default_config_path());
    }
}

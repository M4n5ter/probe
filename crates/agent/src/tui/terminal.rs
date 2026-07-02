use std::{
    io::{self, Stdout},
    path::PathBuf,
    time::Duration,
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

use super::{
    app::{TuiAction, TuiApp},
    config_edit::{TuiError, load_config, save_config},
    hit::HitMap,
    processes::ProcessCatalog,
    render::draw,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuiOptions {
    pub(crate) config: PathBuf,
}

pub(crate) fn run_tui(options: TuiOptions) -> Result<(), TuiError> {
    let mut loaded = load_config(&options.config)?;
    let mut app = TuiApp::new(
        options.config.clone(),
        loaded.config,
        ProcessCatalog::from_proc(),
    );
    let mut terminal = TerminalSession::enter()?;

    loop {
        let hit_map = terminal.draw(&app)?;
        if app.should_quit() {
            break;
        }
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Some(action) = event_to_action(&hit_map, event::read()?) else {
            continue;
        };
        let outcome = app.handle_action(action);
        if outcome.save_requested {
            match save_config(app.config_path(), &loaded.source, app.config()) {
                Ok(source) => {
                    loaded.source = source;
                    app.mark_saved();
                }
                Err(error) => app.mark_save_failed(error.to_string()),
            }
        }
        if outcome.reload_requested {
            match load_config(app.config_path()) {
                Ok(next) => {
                    loaded = next;
                    app.replace_config(loaded.config.clone(), ProcessCatalog::from_proc());
                }
                Err(error) => app.mark_save_failed(error.to_string()),
            }
        }
    }

    Ok(())
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

    fn draw(&mut self, app: &TuiApp) -> Result<HitMap, TuiError> {
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

fn event_to_action(hit_map: &HitMap, event: Event) -> Option<TuiAction> {
    match event {
        Event::Key(key) => key_to_action(key),
        Event::Mouse(mouse) => mouse_to_action(hit_map, mouse),
        Event::Resize(_, _) => None,
        Event::FocusGained | Event::FocusLost | Event::Paste(_) => None,
    }
}

fn key_to_action(key: KeyEvent) -> Option<TuiAction> {
    if key.kind != KeyEventKind::Press {
        return None;
    }
    match (key.code, key.modifiers) {
        (KeyCode::Char('s'), KeyModifiers::CONTROL) => Some(TuiAction::Save),
        (KeyCode::Char('r'), KeyModifiers::CONTROL) => Some(TuiAction::Reload),
        (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => Some(TuiAction::Quit),
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

fn mouse_to_action(hit_map: &HitMap, mouse: MouseEvent) -> Option<TuiAction> {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            hit_map.hit(mouse.column, mouse.row).map(TuiAction::Click)
        }
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
            key_to_action(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)),
            Some(TuiAction::Save)
        );
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Some(TuiAction::NextTab)
        );
        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Some(TuiAction::NextValue)
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
}

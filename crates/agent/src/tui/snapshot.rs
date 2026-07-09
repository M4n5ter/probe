use std::{convert::Infallible, path::PathBuf};

use probe_config::default_config_path;
use ratatui::{
    Terminal,
    backend::TestBackend,
    buffer::{Buffer, CellWidth},
};

use crate::process_catalog::ProcessCatalog;

use super::{
    agent::TuiAgentSupervisor,
    app::{TuiAction, TuiApp, TuiTab, load_traffic_refresh_with_diagnostics},
    config_edit::{TuiError, load_or_create_config},
    hit::ScrollTarget,
    render::draw,
    traffic::load_traffic_detail,
};

const MIN_SNAPSHOT_WIDTH: u16 = 40;
const MIN_SNAPSHOT_HEIGHT: u16 = 12;
const MAX_SNAPSHOT_WIDTH: u16 = 300;
const MAX_SNAPSHOT_HEIGHT: u16 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuiSnapshotOptions {
    pub(crate) config: Option<PathBuf>,
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) tab: TuiTab,
    pub(crate) open_detail: bool,
    pub(crate) detail_scroll: usize,
}

#[derive(Debug)]
pub(crate) struct TuiSnapshotRender {
    pub(crate) output: String,
    pub(crate) cleanup_error: Option<TuiError>,
}

pub(crate) async fn render_tui_snapshot(
    options: TuiSnapshotOptions,
) -> Result<TuiSnapshotRender, TuiError> {
    let (width, height) = options.size();
    let config_path = resolve_config_path(options.config);
    let loaded = load_or_create_config(&config_path)?;
    let processes = ProcessCatalog::from_proc();
    let mut app = TuiApp::new(config_path, loaded.config, processes);
    app.select_tab(options.tab);

    let mut supervisor = match TuiAgentSupervisor::attach_or_spawn(app.config()).await {
        Ok(supervisor) => {
            app.attach_agent(supervisor.attachment(app.config()));
            Some(supervisor)
        }
        Err(error) => {
            let log_path = error.managed_agent_log_path().map(PathBuf::from);
            app.detach_agent_with_log(error.to_string(), log_path);
            None
        }
    };

    if app.active_tab() == TuiTab::Traffic
        && let Some(request) = app.begin_traffic_refresh()
    {
        let result = load_traffic_refresh_with_diagnostics(request).await;
        app.apply_traffic_refresh_result(result);
    }
    if options.open_detail {
        open_selected_traffic_detail(&mut app).await;
    }

    let output = if options.detail_scroll > 0 {
        let _ = render_snapshot_text(&mut app, width, height);
        scroll_open_detail(&mut app, options.detail_scroll);
        render_snapshot_text(&mut app, width, height)
    } else {
        render_snapshot_text(&mut app, width, height)
    };
    let cleanup_error = match supervisor.take() {
        Some(supervisor) => supervisor.stop().await.err(),
        None => None,
    };

    Ok(TuiSnapshotRender {
        output,
        cleanup_error,
    })
}

impl TuiSnapshotOptions {
    fn size(&self) -> (u16, u16) {
        (
            self.width.clamp(MIN_SNAPSHOT_WIDTH, MAX_SNAPSHOT_WIDTH),
            self.height.clamp(MIN_SNAPSHOT_HEIGHT, MAX_SNAPSHOT_HEIGHT),
        )
    }
}

fn resolve_config_path(config: Option<PathBuf>) -> PathBuf {
    config.unwrap_or_else(default_config_path)
}

async fn open_selected_traffic_detail(app: &mut TuiApp) {
    if app.active_tab() != TuiTab::Traffic {
        return;
    }
    if let Some(request) = app.begin_open_selected_traffic_detail_load() {
        let result = load_traffic_detail(request).await;
        app.apply_traffic_detail_result(result);
    }
    while let Some(request) = app.begin_next_open_traffic_detail_load() {
        let result = load_traffic_detail(request).await;
        app.apply_traffic_detail_result(result);
    }
}

fn scroll_open_detail(app: &mut TuiApp, lines: usize) {
    let delta = isize::try_from(lines).unwrap_or(isize::MAX);
    app.handle_action(TuiAction::Scroll {
        delta,
        target: Some(ScrollTarget::TrafficPopup),
    });
}

fn render_snapshot_text(app: &mut TuiApp, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = infallible(Terminal::new(backend));
    infallible(terminal.draw(|frame| {
        let _ = draw(frame, app);
    }));
    buffer_to_text(terminal.backend().buffer())
}

fn infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => match error {},
    }
}

fn buffer_to_text(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut output = String::new();
    for y in 0..area.height {
        let mut line = String::new();
        let mut skip = 0u16;
        for x in 0..area.width {
            let cell = &buffer[(x, y)];
            if skip == 0 {
                line.push_str(cell.symbol());
            }
            skip = cell.cell_width().max(skip).saturating_sub(1);
        }
        output.push_str(line.trim_end_matches(' '));
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use probe_config::AgentConfig;

    use super::*;

    #[test]
    fn snapshot_text_uses_real_tui_renderer_without_escape_sequences() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/probe.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        app.select_tab(TuiTab::Traffic);

        let output = render_snapshot_text(&mut app, 100, 24);

        assert!(output.contains("Probe TUI"));
        assert!(output.contains("Traffic"));
        assert!(output.contains("Traffic Readiness"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn snapshot_options_apply_minimum_render_size() {
        let options = TuiSnapshotOptions {
            config: None,
            width: 1,
            height: 1,
            tab: TuiTab::Traffic,
            open_detail: false,
            detail_scroll: 0,
        };

        assert_eq!(options.size(), (MIN_SNAPSHOT_WIDTH, MIN_SNAPSHOT_HEIGHT));
    }

    #[test]
    fn snapshot_options_apply_maximum_render_size() {
        let options = TuiSnapshotOptions {
            config: None,
            width: u16::MAX,
            height: u16::MAX,
            tab: TuiTab::Traffic,
            open_detail: false,
            detail_scroll: 0,
        };

        assert_eq!(options.size(), (MAX_SNAPSHOT_WIDTH, MAX_SNAPSHOT_HEIGHT));
    }
}

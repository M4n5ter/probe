use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, HighlightSpacing, Paragraph, Row, Table, TableState},
};

use crate::tui::{
    app::TuiApp,
    controls::ControlId,
    hit::{HitArea, HitTarget, ScrollTarget},
};

const PROCESS_VISIBLE_DETAIL_WIDTH: usize = 96;

pub(super) fn render_processes(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    render_process_picker(frame, area, app, hits, ProcessPickerMode::Processes);
}

pub(super) fn render_traffic_process_picker(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    render_process_picker(frame, area, app, hits, ProcessPickerMode::Traffic);
}

#[derive(Clone, Copy)]
enum ProcessPickerMode {
    Processes,
    Traffic,
}

fn render_process_picker(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
    mode: ProcessPickerMode,
) {
    let [search_area, table_area] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(4)]).areas(area);
    hits.push(HitArea::scroll(area, mode.scroll_target()));
    let visible_rows = table_area.height.saturating_sub(3) as usize;
    app.set_process_viewport_rows(visible_rows);

    let filtered_indices = app.filtered_process_indices();
    let start = app
        .process_scroll()
        .min(filtered_indices.len().saturating_sub(visible_rows));
    let end = start
        .saturating_add(visible_rows)
        .min(filtered_indices.len());
    let rows = filtered_indices[start..end]
        .iter()
        .map(|absolute_index| mode.row(app, *absolute_index))
        .collect::<Vec<_>>();

    register_process_row_hits(table_area, hits, mode, &filtered_indices[start..end]);
    render_process_search(frame, search_area, app, hits, filtered_indices.len());

    let selected_visible = app.selected_process_index().and_then(|selected| {
        filtered_indices[start..end]
            .iter()
            .position(|index| *index == selected)
    });
    let mut state = TableState::new().with_selected(selected_visible);
    frame.render_stateful_widget(
        Table::new(rows, mode.widths())
            .header(mode.header())
            .highlight_spacing(HighlightSpacing::Always)
            .row_highlight_style(mode.selected_style())
            .block(Block::bordered().title("Processes")),
        table_area,
        &mut state,
    );
    super::render_vertical_scrollbar(
        frame,
        table_area,
        filtered_indices.len(),
        app.process_scroll(),
        visible_rows,
    );
}

fn register_process_row_hits(
    table_area: Rect,
    hits: &mut Vec<HitArea>,
    mode: ProcessPickerMode,
    visible_indices: &[usize],
) {
    let row_start = super::table_data_row_start(table_area);
    for (visible_index, absolute_index) in visible_indices.iter().copied().enumerate() {
        hits.push(HitArea::new(
            Rect::new(
                table_area.x + 1,
                row_start + visible_index as u16,
                table_area.width.saturating_sub(2),
                1,
            ),
            mode.row_target(absolute_index),
        ));
        hits.push(HitArea::new(
            Rect::new(table_area.x + 3, row_start + visible_index as u16, 3, 1),
            HitTarget::ProcessMonitor(absolute_index),
        ));
        if mode.has_argv_hover() {
            hits.push(HitArea::new(
                Rect::new(
                    table_area.x.saturating_add(table_area.width / 2),
                    row_start + visible_index as u16,
                    table_area.width / 2,
                    1,
                ),
                HitTarget::ProcessArgv(absolute_index),
            ));
        }
    }
}

fn render_process_search(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiApp,
    hits: &mut Vec<HitArea>,
    match_count: usize,
) {
    let search = Rect::new(area.x, area.y, 10, 1);
    super::render_button(
        frame,
        hits,
        search,
        "Search",
        HitTarget::Control(ControlId::SearchProcesses),
        app.is_hovered(HitTarget::Control(ControlId::SearchProcesses)),
    );
    let clear = Rect::new(area.x.saturating_add(11), area.y, 8, 1);
    if !app.process_filter().is_empty() {
        super::render_button(
            frame,
            hits,
            clear,
            "Clear",
            HitTarget::Control(ControlId::ClearProcessSearch),
            app.is_hovered(HitTarget::Control(ControlId::ClearProcessSearch)),
        );
    }
    let text_x = if app.process_filter().is_empty() {
        area.x.saturating_add(11)
    } else {
        area.x.saturating_add(20)
    };
    let text_area = Rect::new(
        text_x,
        area.y,
        area.width.saturating_sub(text_x.saturating_sub(area.x)),
        area.height,
    );
    let filter = if app.process_filter().is_empty() {
        "<none>".to_string()
    } else {
        app.process_filter().to_string()
    };
    let line = Line::from(vec![
        Span::styled("filter ", Style::default().fg(Color::Gray)),
        Span::raw(filter),
        Span::raw("   "),
        Span::styled("matches ", Style::default().fg(Color::Gray)),
        Span::raw(format!("{match_count}/{}", app.processes().entries().len())),
    ]);
    frame.render_widget(Paragraph::new(line), text_area);
}

impl ProcessPickerMode {
    fn scroll_target(self) -> ScrollTarget {
        match self {
            Self::Processes => ScrollTarget::ProcessList,
            Self::Traffic => ScrollTarget::TrafficProcessList,
        }
    }

    fn row_target(self, index: usize) -> HitTarget {
        match self {
            Self::Processes => HitTarget::Process(index),
            Self::Traffic => HitTarget::TrafficProcess(index),
        }
    }

    fn has_argv_hover(self) -> bool {
        matches!(self, Self::Processes)
    }

    fn row(self, app: &TuiApp, absolute_index: usize) -> Row<'static> {
        let process = &app.processes().entries()[absolute_index];
        let marker = if Some(absolute_index) == app.selected_process_index() {
            ">"
        } else {
            " "
        };
        let watched = if app.process_is_monitored(absolute_index) {
            "[x]"
        } else {
            "[ ]"
        };
        let row = match self {
            Self::Processes => {
                let exe = process
                    .exe_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "-".to_string());
                Row::new([
                    Cell::from(marker),
                    Cell::from(watched),
                    Cell::from(process.pid.to_string()),
                    Cell::from(process.name.clone()),
                    Cell::from(process.observation_scope_label()),
                    Cell::from(super::truncate(&exe, 48)),
                    Cell::from(process.argv_summary(PROCESS_VISIBLE_DETAIL_WIDTH)),
                ])
            }
            Self::Traffic => Row::new([
                Cell::from(marker),
                Cell::from(watched),
                Cell::from(process.pid.to_string()),
                Cell::from(process.name.clone()),
            ]),
        };
        if self.row_hovered(app, absolute_index) {
            row.style(Style::default().fg(Color::Black).bg(Color::Gray))
        } else {
            row
        }
    }

    fn row_hovered(self, app: &TuiApp, index: usize) -> bool {
        match self {
            Self::Processes => {
                app.is_hovered(HitTarget::Process(index))
                    || app.is_hovered(HitTarget::ProcessArgv(index))
                    || app.is_hovered(HitTarget::ProcessMonitor(index))
            }
            Self::Traffic => {
                app.is_hovered(HitTarget::TrafficProcess(index))
                    || app.is_hovered(HitTarget::ProcessMonitor(index))
            }
        }
    }

    fn widths(self) -> Vec<Constraint> {
        match self {
            Self::Processes => vec![
                Constraint::Length(2),
                Constraint::Length(4),
                Constraint::Length(7),
                Constraint::Length(20),
                Constraint::Length(8),
                Constraint::Length(42),
                Constraint::Min(24),
            ],
            Self::Traffic => vec![
                Constraint::Length(2),
                Constraint::Length(4),
                Constraint::Length(7),
                Constraint::Min(10),
            ],
        }
    }

    fn header(self) -> Row<'static> {
        let row = match self {
            Self::Processes => {
                Row::new(["", "Watch", "PID", "Name", "Observe", "Executable", "Argv"])
            }
            Self::Traffic => Row::new(["", "Use", "PID", "Process"]),
        };
        row.style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    }

    fn selected_style(self) -> Style {
        Style::default().fg(Color::Black).bg(Color::LightGreen)
    }
}

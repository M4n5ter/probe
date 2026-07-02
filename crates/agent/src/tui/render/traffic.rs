use ratatui::{
    Frame,
    layout::{Constraint, Layout, Offset, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Cell, Clear, HighlightSpacing, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Shadow, Table, TableState, Wrap,
    },
};

use crate::tui::{
    app::{ProcessArgvHover, TuiApp},
    hit::{HitArea, HitTarget},
    traffic::TrafficStatusKind,
};

const TRAFFIC_SUMMARY_WIDTH: usize = 96;

pub(super) fn render_traffic(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let [status_area, workspace] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(4)]).areas(area);
    let (process_area, right_area) = if workspace.width >= 100 {
        let [process_area, right_area] =
            Layout::horizontal([Constraint::Length(38), Constraint::Min(52)]).areas(workspace);
        (process_area, right_area)
    } else {
        let [process_area, right_area] =
            Layout::vertical([Constraint::Length(10), Constraint::Min(8)]).areas(workspace);
        (process_area, right_area)
    };
    let detail_height = if right_area.height >= 18 { 8 } else { 5 };
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Min(6), Constraint::Length(detail_height)]).areas(right_area);

    render_traffic_status(frame, status_area, app);
    render_traffic_process_picker(frame, process_area, app, hits);
    render_traffic_events(frame, table_area, app, hits);
    render_traffic_detail_preview(frame, detail_area, app);
}

pub(super) fn render_traffic_detail_popup(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let available_width = area.width.saturating_sub(4).max(1);
    let width = available_width.min(112).max(available_width.min(56));
    let available_height = area.height.saturating_sub(4).max(1);
    let height = available_height.min(28).max(available_height.min(14));
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let modal = Rect::new(x, y, width, height);
    hits.push(HitArea::new(area, HitTarget::TrafficDetailPanel));
    frame.render_widget(Clear, modal);

    let block = Block::bordered()
        .title("Traffic Detail")
        .shadow(Shadow::dark_shade().offset(Offset::new(2, 1)));
    let inner = block.inner(modal);
    let lines = app
        .traffic()
        .selected_row()
        .map(|row| detail_lines_for_popup(row.detail_lines()))
        .unwrap_or_else(|| vec![Line::from("No selected event")]);
    let scroll = app
        .traffic_detail_scroll()
        .min(lines.len().saturating_sub(1));
    frame.render_widget(
        Paragraph::new(lines.clone())
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll as u16, 0)),
        modal,
    );
    render_vertical_scrollbar(frame, modal, lines.len(), scroll, inner.height as usize);

    let close = Rect::new(
        modal.x.saturating_add(modal.width.saturating_sub(10)),
        modal.y,
        8,
        1,
    );
    super::render_button(
        frame,
        hits,
        close,
        "Close",
        HitTarget::TrafficDetailClose,
        app.is_hovered(HitTarget::TrafficDetailClose),
    );
}

pub(super) fn render_process_argv_hover(
    frame: &mut Frame<'_>,
    screen: Rect,
    app: &TuiApp,
    hover: ProcessArgvHover,
) {
    let Some(process) = app.processes().entries().get(hover.index) else {
        return;
    };
    let mut raw_lines = vec![
        format!("{} ({})", process.name, process.pid),
        "argv".to_string(),
    ];
    raw_lines.extend(process.argv_detail_lines());
    let content_width = raw_lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(24)
        .saturating_add(4) as u16;
    let width = content_width
        .min(screen.width.saturating_sub(2).max(1))
        .max(screen.width.min(36));
    let height = (raw_lines.len() as u16)
        .saturating_add(2)
        .min(screen.height.saturating_sub(2).max(1))
        .max(screen.height.min(6));
    let mut x = hover.column.saturating_add(2);
    if x.saturating_add(width) > screen.x.saturating_add(screen.width) {
        x = screen
            .x
            .saturating_add(screen.width.saturating_sub(width).saturating_sub(1));
    }
    let mut y = hover.row.saturating_add(1);
    if y.saturating_add(height) > screen.y.saturating_add(screen.height) {
        y = hover
            .row
            .saturating_sub(height.saturating_add(1))
            .max(screen.y.saturating_add(1));
    }
    let popup = Rect::new(x, y, width, height);
    frame.render_widget(Clear, popup);
    let lines = raw_lines.into_iter().map(Line::from).collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::bordered()
                    .title("Process argv")
                    .shadow(Shadow::dark_shade().offset(Offset::new(1, 1))),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn render_traffic_status(frame: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let traffic = app.traffic();
    let status = Line::from(vec![
        Span::styled(
            traffic.status().text.clone(),
            Style::default().fg(traffic_status_color(traffic.status().kind)),
        ),
        Span::raw("   "),
        Span::styled("filter ", Style::default().fg(Color::Gray)),
        Span::raw(app.traffic_filter_label()),
        Span::raw("   "),
        Span::styled("tail ", Style::default().fg(Color::Gray)),
        Span::raw(traffic.rows().len().to_string()),
        Span::raw("   "),
        Span::styled("last export ", Style::default().fg(Color::Gray)),
        Span::raw(traffic.last_export_sequence().to_string()),
    ]);
    frame.render_widget(Paragraph::new(status), area);
}

fn render_traffic_process_picker(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let visible_rows = area.height.saturating_sub(3) as usize;
    app.set_process_viewport_rows(visible_rows);
    let entries = app.processes().entries();
    let filtered_indices = app.filtered_process_indices();
    let start = app
        .process_scroll()
        .min(filtered_indices.len().saturating_sub(visible_rows));
    let end = start
        .saturating_add(visible_rows)
        .min(filtered_indices.len());
    let rows = filtered_indices[start..end]
        .iter()
        .map(|absolute_index| {
            let absolute_index = *absolute_index;
            let process = &entries[absolute_index];
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
            let hovered = app.is_hovered(HitTarget::TrafficProcess(absolute_index))
                || app.is_hovered(HitTarget::ProcessMonitor(absolute_index));
            let row = Row::new([
                Cell::from(marker),
                Cell::from(watched),
                Cell::from(process.pid.to_string()),
                Cell::from(process.name.clone()),
            ]);
            if hovered {
                row.style(Style::default().fg(Color::Black).bg(Color::Gray))
            } else {
                row
            }
        })
        .collect::<Vec<_>>();

    let row_start = super::table_data_row_start(area);
    for visible_index in 0..end.saturating_sub(start) {
        let absolute_index = filtered_indices[start + visible_index];
        hits.push(HitArea::new(
            Rect::new(
                area.x + 1,
                row_start + visible_index as u16,
                area.width.saturating_sub(2),
                1,
            ),
            HitTarget::TrafficProcess(absolute_index),
        ));
        hits.push(HitArea::new(
            Rect::new(area.x + 3, row_start + visible_index as u16, 3, 1),
            HitTarget::ProcessMonitor(absolute_index),
        ));
    }

    let selected_visible = app.selected_process_index().and_then(|selected| {
        filtered_indices[start..end]
            .iter()
            .position(|index| *index == selected)
    });
    let mut state = TableState::new().with_selected(selected_visible);
    frame.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Length(4),
                Constraint::Length(7),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(["", "Use", "PID", "Process"]).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .highlight_spacing(HighlightSpacing::Always)
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::LightGreen))
        .block(Block::bordered().title("Processes")),
        area,
        &mut state,
    );
    render_vertical_scrollbar(
        frame,
        area,
        filtered_indices.len(),
        app.process_scroll(),
        visible_rows,
    );
}

fn render_traffic_events(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let visible_rows = area.height.saturating_sub(3) as usize;
    app.set_traffic_viewport_rows(visible_rows);
    let traffic = app.traffic();
    let start = traffic
        .scroll()
        .min(traffic.rows().len().saturating_sub(visible_rows));
    let end = start.saturating_add(visible_rows).min(traffic.rows().len());
    let rows = traffic.rows()[start..end]
        .iter()
        .enumerate()
        .map(|(visible_index, event)| {
            let absolute_index = start + visible_index;
            let marker = if absolute_index == traffic.selected_index() {
                ">"
            } else {
                " "
            };
            let row = Row::new([
                Cell::from(marker),
                Cell::from(event.sequence.to_string()),
                Cell::from(event.process.clone()),
                Cell::from(event.event_type.clone()),
                Cell::from(event.direction.clone()),
                Cell::from(event.endpoint.clone()),
                Cell::from(super::truncate(&event.summary, TRAFFIC_SUMMARY_WIDTH)),
            ]);
            if app.is_hovered(HitTarget::TrafficRow(absolute_index)) {
                row.style(Style::default().fg(Color::Black).bg(Color::Gray))
            } else {
                row
            }
        })
        .collect::<Vec<_>>();

    let row_start = super::table_data_row_start(area);
    for visible_index in 0..end.saturating_sub(start) {
        hits.push(HitArea::new(
            Rect::new(
                area.x + 1,
                row_start + visible_index as u16,
                area.width.saturating_sub(2),
                1,
            ),
            HitTarget::TrafficRow(start + visible_index),
        ));
    }

    let mut state = TableState::new().with_selected(
        (!traffic.rows().is_empty()).then_some(traffic.selected_index().saturating_sub(start)),
    );
    frame.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Length(8),
                Constraint::Length(22),
                Constraint::Length(24),
                Constraint::Length(5),
                Constraint::Length(24),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(["", "Seq", "Process", "Event", "Dir", "Remote", "Summary"]).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .highlight_spacing(HighlightSpacing::Always)
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::LightBlue))
        .block(Block::bordered().title("Traffic")),
        area,
        &mut state,
    );
    render_vertical_scrollbar(
        frame,
        area,
        traffic.rows().len(),
        traffic.scroll(),
        visible_rows,
    );
}

fn render_traffic_detail_preview(frame: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let lines = app
        .traffic()
        .selected_row()
        .map(|row| {
            preview_lines_for_render(
                row.preview_lines(area.height.saturating_sub(2).max(1) as usize),
            )
        })
        .unwrap_or_else(|| vec![Line::from("Select a traffic row to inspect details")]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Selected Event"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn preview_lines_for_render(lines: Vec<String>) -> Vec<Line<'static>> {
    lines.into_iter().map(Line::from).collect()
}

fn detail_lines_for_popup(details: Vec<String>) -> Vec<Line<'static>> {
    details
        .iter()
        .flat_map(|line| [Line::from(line.clone()), Line::from("")])
        .collect()
}

fn render_vertical_scrollbar(
    frame: &mut Frame<'_>,
    area: Rect,
    content_len: usize,
    position: usize,
    viewport_len: usize,
) {
    if content_len <= viewport_len || area.height < 3 {
        return;
    }
    let mut state = ScrollbarState::new(content_len)
        .position(position)
        .viewport_content_length(viewport_len);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(Style::default().fg(Color::Cyan))
            .track_style(Style::default().fg(Color::DarkGray)),
        area,
        &mut state,
    );
}

fn traffic_status_color(kind: TrafficStatusKind) -> Color {
    match kind {
        TrafficStatusKind::Idle => Color::Gray,
        TrafficStatusKind::Active => Color::Green,
        TrafficStatusKind::Error => Color::Yellow,
    }
}

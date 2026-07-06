use ratatui::{
    Frame,
    layout::{Constraint, Layout, Offset, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Cell, Clear, HighlightSpacing, Paragraph, Row, Shadow, Table, TableState, Wrap,
    },
};
use unicode_width::UnicodeWidthChar;

use crate::tui::{
    app::{ProcessArgvHover, TuiApp},
    controls::{
        ControlId, TRAFFIC_FILTER_CONTROLS, TRAFFIC_OBSERVE_CONTROLS, TRAFFIC_VIEW_CONTROLS,
    },
    hit::{HitArea, HitTarget, ScrollTarget},
    traffic::TrafficStatusKind,
};

const TRAFFIC_SUMMARY_WIDTH: usize = 96;
const HTTP_SEQUENCE_WIDTH: usize = 7;
const HTTP_PROCESS_WIDTH: usize = 12;
const HTTP_METHOD_WIDTH: usize = 7;
const HTTP_TARGET_WIDTH: usize = 18;
const HTTP_STATUS_WIDTH: usize = 16;
const HTTP_BODY_WIDTH: usize = 15;
const HTTP_REMOTE_WIDTH: usize = 16;
const DATA_PATH_STATUS_WIDTH: usize = 38;
const DATA_PATH_CAPTURE_WIDTH: usize = 38;
const DATA_PATH_NEXT_WIDTH: usize = 44;
const DATA_PATH_MITM_WIDTH: usize = 38;

pub(super) fn render_traffic(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let [status_area, workspace] =
        Layout::vertical([Constraint::Length(5), Constraint::Min(4)]).areas(area);
    let (process_area, right_area) = if workspace.width >= 100 {
        let [process_area, right_area] =
            Layout::horizontal([Constraint::Length(38), Constraint::Min(52)])
                .spacing(1)
                .areas(workspace);
        (process_area, right_area)
    } else {
        let [process_area, right_area] =
            Layout::vertical([Constraint::Length(10), Constraint::Min(8)]).areas(workspace);
        (process_area, right_area)
    };
    let detail_height = if right_area.height >= 18 { 8 } else { 5 };
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Min(6), Constraint::Length(detail_height)]).areas(right_area);

    render_traffic_status(frame, status_area, app, hits);
    super::process_picker::render_traffic_process_picker(frame, process_area, app, hits);
    if app.traffic().rows().is_empty() {
        render_traffic_readiness(frame, right_area, app, hits);
        return;
    }
    render_traffic_events(frame, table_area, app, hits);
    render_traffic_detail_preview(frame, detail_area, app);
}

pub(super) fn render_traffic_popup(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let available_width = area.width.saturating_sub(4).max(1);
    let width = available_width.min(112).max(available_width.min(56));
    let available_height = area.height.saturating_sub(4).max(1);
    let height = available_height.min(28).max(available_height.min(14));
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let modal = Rect::new(x, y, width, height);
    hits.push(HitArea::new(area, HitTarget::TrafficPopupPanel));
    frame.render_widget(Clear, modal);

    let Some(popup) = app.traffic_popup_view() else {
        return;
    };
    let block = Block::bordered()
        .title(popup.title)
        .shadow(Shadow::dark_shade().offset(Offset::new(2, 1)));
    let inner = block.inner(modal);
    let content_rows = popup_visual_row_count(&popup.lines, inner.width as usize);
    let scroll = app
        .set_traffic_popup_layout(content_rows, inner.height as usize)
        .unwrap_or(popup.scroll);
    let visible_lines = popup_visible_lines_for_render(
        &popup.lines,
        inner.width as usize,
        scroll,
        inner.height as usize,
    );
    hits.push(HitArea::scroll(inner, ScrollTarget::TrafficPopup));
    frame.render_widget(Paragraph::new(visible_lines).block(block), modal);
    super::render_vertical_scrollbar(frame, inner, content_rows, scroll, inner.height as usize);
    if content_rows > inner.height as usize && inner.width > 0 && inner.height > 0 {
        let hit_width = modal.width.min(3);
        hits.push(HitArea::scrollbar(
            Rect::new(
                modal
                    .x
                    .saturating_add(modal.width.saturating_sub(hit_width)),
                inner.y,
                hit_width,
                inner.height,
            ),
            ScrollTarget::TrafficPopup,
        ));
    }

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
        HitTarget::TrafficPopupClose,
        app.is_hovered(HitTarget::TrafficPopupClose),
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

fn render_traffic_status(frame: &mut Frame<'_>, area: Rect, app: &TuiApp, hits: &mut Vec<HitArea>) {
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
        Span::styled("view ", Style::default().fg(Color::Gray)),
        Span::raw(app.traffic().view_mode_label()),
        Span::raw("   "),
        Span::styled("events ", Style::default().fg(Color::Gray)),
        Span::raw(traffic.event_filter_label()),
        Span::raw("   "),
        Span::styled("search ", Style::default().fg(Color::Gray)),
        Span::raw(traffic.search_label()),
        Span::raw(format!(
            " {}/{}",
            traffic.visible_match_count(),
            traffic.active_unfiltered_count()
        )),
        Span::raw("   "),
        Span::styled("tail ", Style::default().fg(Color::Gray)),
        Span::raw(format!(
            "{} {}",
            traffic.tail_mode_label(),
            traffic.rows().len()
        )),
        Span::raw("   "),
        Span::styled("last export ", Style::default().fg(Color::Gray)),
        Span::raw(traffic.last_export_sequence().to_string()),
    ]);
    let status_area = Rect::new(area.x, area.y, area.width, 1);
    frame.render_widget(Paragraph::new(status), status_area);
    render_traffic_action_bar(frame, area, app, hits);
    render_traffic_data_path_summary(frame, area, app);
}

fn render_traffic_action_bar(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let Some(mut cursor) = ActionBarCursor::new(area) else {
        return;
    };
    cursor.render_button(
        frame,
        hits,
        ControlId::OpenTrafficDiagnostics.traffic_action_label(),
        HitTarget::Control(ControlId::OpenTrafficDiagnostics),
        app.is_hovered(HitTarget::Control(ControlId::OpenTrafficDiagnostics)),
        false,
    );
    for control in TRAFFIC_VIEW_CONTROLS {
        let ControlId::TrafficView(mode) = control else {
            continue;
        };
        let target = HitTarget::Control(control);
        cursor.render_button(
            frame,
            hits,
            control.traffic_action_label(),
            target,
            app.is_hovered(target),
            app.traffic().active_view_mode_is(mode),
        );
    }
    for control in TRAFFIC_FILTER_CONTROLS {
        let ControlId::TrafficFilter(filter) = control else {
            continue;
        };
        let target = HitTarget::Control(control);
        cursor.render_button(
            frame,
            hits,
            control.traffic_action_label(),
            target,
            app.is_hovered(target),
            app.traffic().event_filter_is(filter),
        );
    }
    cursor.render_button(
        frame,
        hits,
        ControlId::SearchTraffic.traffic_action_label(),
        HitTarget::Control(ControlId::SearchTraffic),
        app.is_hovered(HitTarget::Control(ControlId::SearchTraffic)),
        !app.traffic().search_query().is_empty(),
    );
    if !app.traffic().search_query().is_empty() {
        cursor.render_button(
            frame,
            hits,
            ControlId::ClearTrafficSearch.traffic_action_label(),
            HitTarget::Control(ControlId::ClearTrafficSearch),
            app.is_hovered(HitTarget::Control(ControlId::ClearTrafficSearch)),
            false,
        );
    }
    let tail_label = format!("Tail {}", app.traffic().tail_mode_label());
    cursor.render_button(
        frame,
        hits,
        &tail_label,
        HitTarget::Control(ControlId::TrafficTailFollow),
        app.is_hovered(HitTarget::Control(ControlId::TrafficTailFollow)),
        false,
    );
    if let Some(index) = app
        .selected_process_index()
        .filter(|index| app.processes().entries().get(*index).is_some())
    {
        let target = HitTarget::ProcessMonitor(index);
        let label = if app.process_is_monitored(index) {
            "Unwatch"
        } else {
            "Watch"
        };
        cursor.render_button(
            frame,
            hits,
            label,
            target,
            app.is_hovered(target),
            app.process_is_monitored(index),
        );
    }
    for control in TRAFFIC_OBSERVE_CONTROLS {
        cursor.render_button(
            frame,
            hits,
            control.traffic_action_label(),
            HitTarget::Control(control),
            app.is_hovered(HitTarget::Control(control)),
            false,
        );
    }
}

struct ActionBarCursor {
    left: u16,
    right: u16,
    x: u16,
    y: u16,
    last_y: u16,
}

impl ActionBarCursor {
    fn new(area: Rect) -> Option<Self> {
        if area.width == 0 || area.height < 4 {
            return None;
        }
        let first_y = area.y.saturating_add(1);
        let last_y = area.y.saturating_add(area.height.saturating_sub(3));
        Some(Self {
            left: area.x,
            right: area.x.saturating_add(area.width),
            x: area.x,
            y: first_y,
            last_y,
        })
    }

    fn render_button(
        &mut self,
        frame: &mut Frame<'_>,
        hits: &mut Vec<HitArea>,
        label: impl Into<String>,
        target: HitTarget,
        hovered: bool,
        active: bool,
    ) -> bool {
        let label = label.into();
        let width = label.len() as u16 + 2;
        if width > self.right.saturating_sub(self.left) {
            return false;
        }
        if width > self.right.saturating_sub(self.x) && !self.wrap() {
            return false;
        }
        let area = Rect::new(self.x, self.y, width, 1);
        super::render_button_with_state(frame, hits, area, &label, target, hovered, active);
        self.x = self.x.saturating_add(width.saturating_add(1));
        true
    }

    fn wrap(&mut self) -> bool {
        if self.y >= self.last_y {
            return false;
        }
        self.x = self.left;
        self.y = self.y.saturating_add(1);
        true
    }
}

fn render_traffic_data_path_summary(frame: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    if area.height < 3 {
        return;
    }
    let [first_line, second_line] = traffic_data_path_summary(app);
    frame.render_widget(
        Paragraph::new(first_line),
        Rect::new(
            area.x,
            area.y + area.height.saturating_sub(2),
            area.width,
            1,
        ),
    );
    frame.render_widget(
        Paragraph::new(second_line),
        Rect::new(
            area.x,
            area.y + area.height.saturating_sub(1),
            area.width,
            1,
        ),
    );
}

fn traffic_data_path_summary(app: &TuiApp) -> [Line<'static>; 2] {
    let summary = app.traffic_data_path_summary();
    [
        Line::from(vec![
            Span::styled("data path ", Style::default().fg(Color::Gray)),
            Span::raw(truncate_to_width(&summary.status, DATA_PATH_STATUS_WIDTH)),
            Span::raw("   "),
            Span::styled("capture ", Style::default().fg(Color::Gray)),
            Span::raw(truncate_to_width(&summary.capture, DATA_PATH_CAPTURE_WIDTH)),
        ]),
        Line::from(vec![
            Span::styled("next ", Style::default().fg(Color::Gray)),
            Span::raw(truncate_to_width(&summary.next, DATA_PATH_NEXT_WIDTH)),
            Span::raw("   "),
            Span::styled("MITM ", Style::default().fg(Color::Gray)),
            Span::raw(truncate_to_width(&summary.mitm, DATA_PATH_MITM_WIDTH)),
        ]),
    ]
}

fn truncate_to_width(value: &str, max_width: usize) -> String {
    if value.chars().count() <= max_width {
        return value.to_string();
    }
    if max_width <= 3 {
        return ".".repeat(max_width);
    }
    super::truncate(value, max_width - 3)
}

fn render_traffic_events(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    if app.traffic().showing_http_exchanges() {
        render_http_exchanges(frame, area, app, hits);
        return;
    }
    if app.traffic().showing_websocket_sessions() {
        render_websocket_sessions(frame, area, app, hits);
        return;
    }
    render_traffic_event_rows(frame, area, app, hits);
}

fn render_traffic_readiness(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiApp,
    hits: &mut Vec<HitArea>,
) {
    hits.push(HitArea::scroll(area, ScrollTarget::TrafficEvents));
    let lines = preview_lines_for_render(
        app.traffic_preview_lines(area.height.saturating_sub(2).max(1) as usize),
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Traffic Readiness"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_http_exchanges(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let visible_rows = area.height.saturating_sub(3) as usize;
    app.set_traffic_viewport_rows(visible_rows);
    let traffic = app.traffic();
    let exchanges = traffic.visible_http_exchanges();
    render_traffic_table(
        frame,
        area,
        hits,
        TrafficTableSpec {
            title: "HTTP Exchanges",
            headers: vec![
                "",
                "Seq",
                "Process",
                "Method",
                "Target",
                "Status",
                "Req Body",
                "Resp Body",
                "Dir",
                "Remote",
                "Summary",
            ],
            constraints: vec![
                Constraint::Length(2),
                Constraint::Length(HTTP_SEQUENCE_WIDTH as u16),
                Constraint::Length(HTTP_PROCESS_WIDTH as u16),
                Constraint::Length(HTTP_METHOD_WIDTH as u16),
                Constraint::Length(HTTP_TARGET_WIDTH as u16),
                Constraint::Length(HTTP_STATUS_WIDTH as u16),
                Constraint::Length(HTTP_BODY_WIDTH as u16),
                Constraint::Length(HTTP_BODY_WIDTH as u16),
                Constraint::Length(3),
                Constraint::Length(HTTP_REMOTE_WIDTH as u16),
                Constraint::Min(12),
            ],
            total_len: exchanges.len(),
            scroll: traffic.http_scroll(),
            selected_index: traffic.selected_http_exchange_index(),
            visible_rows,
        },
        |absolute_index| app.is_hovered(HitTarget::TrafficRow(absolute_index)),
        |absolute_index, marker| {
            let exchange = exchanges
                .get(absolute_index)
                .expect("rendered HTTP exchange index is visible");
            Row::new([
                Cell::from(marker),
                Cell::from(truncate_to_width(
                    &exchange.sequence.to_string(),
                    HTTP_SEQUENCE_WIDTH,
                )),
                Cell::from(truncate_to_width(&exchange.process, HTTP_PROCESS_WIDTH)),
                Cell::from(truncate_to_width(&exchange.method, HTTP_METHOD_WIDTH)),
                Cell::from(truncate_to_width(&exchange.target, HTTP_TARGET_WIDTH)),
                Cell::from(truncate_to_width(&exchange.status, HTTP_STATUS_WIDTH)),
                Cell::from(truncate_to_width(&exchange.request_body, HTTP_BODY_WIDTH)),
                Cell::from(truncate_to_width(&exchange.response_body, HTTP_BODY_WIDTH)),
                Cell::from(truncate_to_width(&exchange.direction, 3)),
                Cell::from(truncate_to_width(&exchange.endpoint, HTTP_REMOTE_WIDTH)),
                Cell::from(super::truncate(&exchange.summary, TRAFFIC_SUMMARY_WIDTH)),
            ])
        },
    );
}

fn render_websocket_sessions(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let visible_rows = area.height.saturating_sub(3) as usize;
    app.set_traffic_viewport_rows(visible_rows);
    let traffic = app.traffic();
    let sessions = traffic.visible_websocket_sessions();
    render_traffic_table(
        frame,
        area,
        hits,
        TrafficTableSpec {
            title: "WebSocket Sessions",
            headers: vec![
                "", "Seq", "Process", "Target", "Dir", "Remote", "Frames", "Messages", "Payload",
                "Summary",
            ],
            constraints: vec![
                Constraint::Length(2),
                Constraint::Length(8),
                Constraint::Length(20),
                Constraint::Length(30),
                Constraint::Length(5),
                Constraint::Length(22),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Min(20),
            ],
            total_len: sessions.len(),
            scroll: traffic.websocket_scroll(),
            selected_index: traffic.selected_websocket_session_index(),
            visible_rows,
        },
        |absolute_index| app.is_hovered(HitTarget::TrafficRow(absolute_index)),
        |absolute_index, marker| {
            let session = sessions
                .get(absolute_index)
                .expect("rendered WebSocket session index is visible");
            Row::new([
                Cell::from(marker),
                Cell::from(session.sequence.to_string()),
                Cell::from(session.process.clone()),
                Cell::from(super::truncate(&session.target, 36)),
                Cell::from(session.direction.clone()),
                Cell::from(session.endpoint.clone()),
                Cell::from(session.frames.to_string()),
                Cell::from(session.messages.to_string()),
                Cell::from(format!("{} B", session.payload_bytes)),
                Cell::from(super::truncate(&session.summary, TRAFFIC_SUMMARY_WIDTH)),
            ])
        },
    );
}

fn render_traffic_event_rows(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    hits: &mut Vec<HitArea>,
) {
    let visible_rows = area.height.saturating_sub(3) as usize;
    app.set_traffic_viewport_rows(visible_rows);
    let traffic = app.traffic();
    let events = traffic.visible_rows();
    render_traffic_table(
        frame,
        area,
        hits,
        TrafficTableSpec {
            title: "Traffic Events",
            headers: vec![
                "", "Seq", "Process", "Path", "Event", "Dir", "Remote", "Summary",
            ],
            constraints: vec![
                Constraint::Length(2),
                Constraint::Length(8),
                Constraint::Length(20),
                Constraint::Length(12),
                Constraint::Length(22),
                Constraint::Length(5),
                Constraint::Length(22),
                Constraint::Min(20),
            ],
            total_len: events.len(),
            scroll: traffic.scroll(),
            selected_index: traffic.selected_index(),
            visible_rows,
        },
        |absolute_index| app.is_hovered(HitTarget::TrafficRow(absolute_index)),
        |absolute_index, marker| {
            let event = events
                .get(absolute_index)
                .expect("rendered traffic event index is visible");
            Row::new([
                Cell::from(marker),
                Cell::from(event.sequence.to_string()),
                Cell::from(event.process.clone()),
                Cell::from(event.capture_path),
                Cell::from(event.event_type.clone()),
                Cell::from(event.direction.clone()),
                Cell::from(event.endpoint.clone()),
                Cell::from(super::truncate(&event.summary, TRAFFIC_SUMMARY_WIDTH)),
            ])
        },
    );
}

struct TrafficTableSpec {
    title: &'static str,
    headers: Vec<&'static str>,
    constraints: Vec<Constraint>,
    total_len: usize,
    scroll: usize,
    selected_index: usize,
    visible_rows: usize,
}

fn render_traffic_table<'a>(
    frame: &mut Frame<'_>,
    area: Rect,
    hits: &mut Vec<HitArea>,
    spec: TrafficTableSpec,
    mut is_hovered: impl FnMut(usize) -> bool,
    mut row_at: impl FnMut(usize, &'static str) -> Row<'a>,
) {
    hits.push(HitArea::scroll(area, ScrollTarget::TrafficEvents));
    let start = spec
        .scroll
        .min(spec.total_len.saturating_sub(spec.visible_rows));
    let end = start.saturating_add(spec.visible_rows).min(spec.total_len);
    let rows = (start..end)
        .map(|absolute_index| {
            let marker = if absolute_index == spec.selected_index {
                ">"
            } else {
                " "
            };
            let row = row_at(absolute_index, marker);
            if is_hovered(absolute_index) {
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

    let mut state = TableState::new()
        .with_selected((spec.total_len > 0).then_some(spec.selected_index.saturating_sub(start)));
    frame.render_stateful_widget(
        Table::new(rows, spec.constraints)
            .header(
                Row::new(spec.headers).style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .highlight_spacing(HighlightSpacing::Always)
            .row_highlight_style(Style::default().fg(Color::Black).bg(Color::LightBlue))
            .block(Block::bordered().title(spec.title)),
        area,
        &mut state,
    );
    let scroll_track = super::table_scroll_track(area);
    super::render_vertical_scrollbar(
        frame,
        scroll_track,
        spec.total_len,
        spec.scroll,
        spec.visible_rows,
    );
    let scroll_hit = super::table_scrollbar_hit_rect(area);
    if spec.total_len > spec.visible_rows && scroll_hit.width > 0 && scroll_hit.height > 0 {
        hits.push(HitArea::scrollbar(scroll_hit, ScrollTarget::TrafficEvents));
    }
}

fn render_traffic_detail_preview(frame: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let lines = preview_lines_for_render(
        app.traffic_preview_lines(area.height.saturating_sub(2).max(1) as usize),
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(app.traffic_preview_title()))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn preview_lines_for_render(lines: Vec<String>) -> Vec<Line<'static>> {
    lines.into_iter().map(Line::from).collect()
}

fn popup_visual_row_count(details: &[String], width: usize) -> usize {
    scan_popup_visual_rows(details, width, |_, _| true)
}

fn popup_visible_lines_for_render(
    details: &[String],
    width: usize,
    scroll: usize,
    viewport_rows: usize,
) -> Vec<Line<'static>> {
    let width = width.max(1);
    let viewport_rows = viewport_rows.max(1);
    let mut visible = Vec::with_capacity(viewport_rows);
    let end = scroll.saturating_add(viewport_rows);
    scan_popup_visual_rows(details, width, |row_index, row| {
        if row_index >= scroll && row_index < end {
            visible.push(row.to_string());
        }
        row_index.saturating_add(1) < end
    });
    visible.into_iter().map(Line::from).collect()
}

fn scan_popup_visual_rows(
    details: &[String],
    width: usize,
    mut visitor: impl FnMut(usize, &str) -> bool,
) -> usize {
    let width = width.max(1);
    let mut row_index = 0usize;
    for line in details {
        if line.is_empty() {
            if !emit_scanned_popup_row(&mut row_index, "", &mut visitor) {
                return row_index;
            }
            continue;
        }

        let mut row_start = 0usize;
        let mut row_width = 0usize;
        let mut row_has_content = false;
        for (byte_index, character) in line.char_indices() {
            let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
            if row_has_content && row_width.saturating_add(character_width) > width {
                if !emit_scanned_popup_row(
                    &mut row_index,
                    &line[row_start..byte_index],
                    &mut visitor,
                ) {
                    return row_index;
                }
                row_start = byte_index;
                row_width = 0;
            }

            row_has_content = true;
            row_width = row_width.saturating_add(character_width);
            let character_end = byte_index.saturating_add(character.len_utf8());
            if row_width >= width && character_width > 0 {
                if !emit_scanned_popup_row(
                    &mut row_index,
                    &line[row_start..character_end],
                    &mut visitor,
                ) {
                    return row_index;
                }
                row_start = character_end;
                row_width = 0;
                row_has_content = false;
            }
        }

        if row_has_content
            && !emit_scanned_popup_row(&mut row_index, &line[row_start..], &mut visitor)
        {
            return row_index;
        }
    }
    row_index
}

fn emit_scanned_popup_row(
    row_index: &mut usize,
    row: &str,
    visitor: &mut impl FnMut(usize, &str) -> bool,
) -> bool {
    let should_continue = visitor(*row_index, row);
    *row_index = (*row_index).saturating_add(1);
    should_continue
}

fn traffic_status_color(kind: TrafficStatusKind) -> Color {
    match kind {
        TrafficStatusKind::Idle => Color::Gray,
        TrafficStatusKind::Active => Color::Green,
        TrafficStatusKind::Warning => Color::Yellow,
        TrafficStatusKind::Error => Color::Yellow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_to_width_counts_ellipsis_inside_the_width_budget() {
        let value = truncate_to_width("abcdefghijklmnopqrstuvwxyz", 10);

        assert_eq!(value, "abcdefg...");
        assert_eq!(value.chars().count(), 10);
    }

    #[test]
    fn http_body_column_width_fits_supported_payload_states() {
        for label in [
            "0B none",
            "5B loaded",
            "100B not loaded",
            "10B partial",
            "100B incomplete",
        ] {
            assert!(
                label.chars().count() <= HTTP_BODY_WIDTH,
                "{label} should fit in the HTTP body column"
            );
        }
    }

    #[test]
    fn http_status_column_width_fits_common_statuses() {
        for status in [
            "200 OK",
            "201 Created",
            "204 No Content",
            "304 Not Modified",
            "400 Bad Request",
            "404 Not Found",
        ] {
            assert!(
                status.chars().count() <= HTTP_STATUS_WIDTH,
                "{status} should fit in the HTTP status column"
            );
        }
    }

    #[test]
    fn popup_visual_row_count_counts_wrapped_visual_lines() {
        let lines = vec![format!("Payload: {}", "body ".repeat(20))];

        assert!(popup_visual_row_count(&lines, 20) > 1);
    }

    #[test]
    fn popup_visible_lines_support_large_usize_scroll_offsets() {
        let lines = vec!["x".repeat(70_000)];

        let visible = popup_visible_lines_for_render(&lines, 1, 69_998, 5);

        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].to_string(), "x");
    }
}

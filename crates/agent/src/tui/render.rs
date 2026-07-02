use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
};

use super::{
    app::{StatusKind, TextEditSession, TuiApp, TuiTab},
    controls::{ControlId, FocusTarget},
    hit::{HitArea, HitMap, HitTarget},
    traffic::TrafficStatusKind,
};

const PROCESS_VISIBLE_DETAIL_WIDTH: usize = 96;
const TRAFFIC_SUMMARY_WIDTH: usize = 96;

pub(crate) fn draw(frame: &mut Frame<'_>, app: &mut TuiApp) -> HitMap {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(2),
    ])
    .areas(area);

    let mut hits = Vec::new();
    render_header(frame, header, app, &mut hits);
    render_tabs(frame, tabs, app, &mut hits);
    match app.active_tab() {
        TuiTab::Overview => render_overview(frame, body, app),
        TuiTab::Traffic => render_traffic(frame, body, app, &mut hits),
        TuiTab::Processes => render_processes(frame, body, app, &mut hits),
        _ => render_fields(frame, body, app, &mut hits),
    }
    render_footer(frame, footer, app);
    if let Some(edit) = app.text_edit() {
        render_text_edit(frame, area, edit, &mut hits);
    }
    HitMap::new(hits)
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &TuiApp, hits: &mut Vec<HitArea>) {
    let title = format!(
        "Probe TUI  {}{}",
        app.config_path().display(),
        if app.dirty() { "  modified" } else { "" }
    );
    frame.render_widget(
        Paragraph::new(title)
            .block(Block::bordered().border_style(Style::default().fg(Color::Gray))),
        area,
    );
    let button_y = area.y + 1;
    render_button(
        frame,
        hits,
        Rect::new(
            area.x.saturating_add(area.width.saturating_sub(28)),
            button_y,
            7,
            1,
        ),
        "Save",
        HitTarget::Save,
    );
    render_button(
        frame,
        hits,
        Rect::new(
            area.x.saturating_add(area.width.saturating_sub(19)),
            button_y,
            9,
            1,
        ),
        "Reload",
        HitTarget::Reload,
    );
    render_button(
        frame,
        hits,
        Rect::new(
            area.x.saturating_add(area.width.saturating_sub(8)),
            button_y,
            6,
            1,
        ),
        "Quit",
        HitTarget::Quit,
    );
}

fn render_tabs(frame: &mut Frame<'_>, area: Rect, app: &TuiApp, hits: &mut Vec<HitArea>) {
    let mut spans = Vec::new();
    let mut x = area.x + 1;
    let hit_height = area.height.saturating_sub(1).max(1);
    for tab in TuiTab::ALL {
        let selected = tab == app.active_tab();
        let label = format!(" {} ", tab.label());
        let style = if selected {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        let width = label.len() as u16;
        hits.push(HitArea::new(
            Rect::new(x, area.y, width, hit_height),
            HitTarget::Tab(tab),
        ));
        x = x.saturating_add(width + 1);
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::BOTTOM)),
        area,
    );
}

fn render_overview(frame: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let config = app.config();
    let lines = vec![
        Line::from(vec![
            Span::styled("Agent: ", Style::default().fg(Color::Gray)),
            Span::raw(config.agent_id.clone()),
        ]),
        Line::from(vec![
            Span::styled("Capture: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{:?}", config.capture.selection)),
        ]),
        Line::from(vec![
            Span::styled("Exporters: ", Style::default().fg(Color::Gray)),
            Span::raw(config.exporters.len().to_string()),
        ]),
        Line::from(vec![
            Span::styled("Policies: ", Style::default().fg(Color::Gray)),
            Span::raw(config.policies.len().to_string()),
        ]),
        Line::from(vec![
            Span::styled("Processes readable: ", Style::default().fg(Color::Gray)),
            Span::raw(app.processes().entries().len().to_string()),
        ]),
        Line::from(vec![
            Span::styled("Runtime: ", Style::default().fg(Color::Gray)),
            Span::raw(app.runtime_agent_status()),
        ]),
        Line::from(vec![
            Span::styled(
                "Status: ",
                Style::default().fg(status_color(app.status().kind)),
            ),
            Span::raw(app.status().text.clone()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Overview"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_fields(frame: &mut Frame<'_>, area: Rect, app: &TuiApp, hits: &mut Vec<HitArea>) {
    let targets = app.focus_targets_for_active_tab();
    let selected = app.selected_focus_target();
    let rows = targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let marker = if Some(*target) == selected { ">" } else { " " };
            let row = Row::new([
                Cell::from(marker),
                Cell::from(target.label()),
                Cell::from(app.focus_target_value(*target)),
                action_cell(target.action_hint()),
            ]);
            if Some(*target) == selected {
                row.style(Style::default().fg(Color::Black).bg(Color::LightCyan))
            } else if index % 2 == 0 {
                row.style(Style::default().fg(Color::White))
            } else {
                row.style(Style::default().fg(Color::Gray))
            }
        })
        .collect::<Vec<_>>();

    let row_start = table_data_row_start(area);
    for (index, target) in targets.iter().enumerate() {
        hits.push(HitArea::new(
            Rect::new(
                area.x + 1,
                row_start + index as u16,
                area.width.saturating_sub(2),
                1,
            ),
            hit_target_for_focus(*target),
        ));
    }

    let widths = [
        Constraint::Length(2),
        Constraint::Length(28),
        Constraint::Percentage(45),
        Constraint::Percentage(35),
    ];
    frame.render_widget(
        Table::new(rows, widths)
            .header(
                Row::new(["", "Setting", "Value", "Action"]).style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(Block::bordered().title(app.active_tab().label())),
        area,
    );
}

fn hit_target_for_focus(target: FocusTarget) -> HitTarget {
    match target {
        FocusTarget::Field(field) => HitTarget::Field(field),
        FocusTarget::Control(control) => HitTarget::Control(control),
    }
}

fn render_processes(frame: &mut Frame<'_>, area: Rect, app: &mut TuiApp, hits: &mut Vec<HitArea>) {
    let [search_area, table_area] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(4)]).areas(area);
    let visible_rows = table_area.height.saturating_sub(3) as usize;
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
            let detail = truncate(&process.detail(), PROCESS_VISIBLE_DETAIL_WIDTH);
            let row = Row::new([
                Cell::from(marker),
                Cell::from(process.pid.to_string()),
                Cell::from(process.name.clone()),
                Cell::from(process.selector_status()),
                Cell::from(detail),
            ]);
            if Some(absolute_index) == app.selected_process_index() {
                row.style(Style::default().fg(Color::Black).bg(Color::LightGreen))
            } else {
                row
            }
        })
        .collect::<Vec<_>>();

    let row_start = table_data_row_start(table_area);
    for visible_index in 0..end.saturating_sub(start) {
        let absolute_index = filtered_indices[start + visible_index];
        hits.push(HitArea::new(
            Rect::new(
                table_area.x + 1,
                row_start + visible_index as u16,
                table_area.width.saturating_sub(2),
                1,
            ),
            HitTarget::Process(absolute_index),
        ));
    }

    render_process_search(frame, search_area, app, hits, filtered_indices.len());
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Length(8),
                Constraint::Length(24),
                Constraint::Length(16),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(["", "PID", "Name", "Selector", "Executable | Redacted argv"]).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(Block::bordered().title("Processes")),
        table_area,
    );
}

fn render_process_search(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &TuiApp,
    hits: &mut Vec<HitArea>,
    match_count: usize,
) {
    let search = Rect::new(area.x, area.y, 10, 1);
    render_button(
        frame,
        hits,
        search,
        "Search",
        HitTarget::Control(ControlId::SearchProcesses),
    );
    let clear = Rect::new(area.x.saturating_add(11), area.y, 8, 1);
    if !app.process_filter().is_empty() {
        render_button(
            frame,
            hits,
            clear,
            "Clear",
            HitTarget::Control(ControlId::ClearProcessSearch),
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

fn render_traffic(frame: &mut Frame<'_>, area: Rect, app: &mut TuiApp, hits: &mut Vec<HitArea>) {
    let [status_area, table_area] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(4)]).areas(area);
    let visible_rows = table_area.height.saturating_sub(3) as usize;
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
                Cell::from(truncate(&event.summary, TRAFFIC_SUMMARY_WIDTH)),
            ]);
            if absolute_index == traffic.selected_index() {
                row.style(Style::default().fg(Color::Black).bg(Color::LightBlue))
            } else {
                row
            }
        })
        .collect::<Vec<_>>();

    let row_start = table_data_row_start(table_area);
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

    let title = format!(
        "Traffic  tail={} last_export={}",
        traffic.rows().len(),
        traffic.last_export_sequence()
    );
    let status = Line::from(vec![
        Span::styled(
            traffic.status().text.clone(),
            Style::default().fg(traffic_status_color(traffic.status().kind)),
        ),
        Span::raw("   "),
        Span::styled("filter", Style::default().fg(Color::Gray)),
        Span::raw(": selected process executable path when readable"),
    ]);
    frame.render_widget(Paragraph::new(status), status_area);
    frame.render_widget(
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
        .block(Block::bordered().title(title)),
        table_area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let status_style = Style::default().fg(status_color(app.status().kind));
    let text = Line::from(vec![
        Span::styled(app.status().text.clone(), status_style),
        Span::raw("   "),
        Span::styled("Tab/Shift-Tab", Style::default().fg(Color::Gray)),
        Span::raw(" tabs  "),
        Span::styled("Up/Down", Style::default().fg(Color::Gray)),
        Span::raw(" select  "),
        Span::styled("Enter/Space/Click", Style::default().fg(Color::Gray)),
        Span::raw(" edit  "),
        Span::styled("Ctrl-S", Style::default().fg(Color::Gray)),
        Span::raw(" save  "),
        Span::styled("q", Style::default().fg(Color::Gray)),
        Span::raw(" quit"),
    ]);
    frame.render_widget(Paragraph::new(text), area);
}

fn render_text_edit(
    frame: &mut Frame<'_>,
    area: Rect,
    edit: &TextEditSession,
    hits: &mut Vec<HitArea>,
) {
    let available_width = area.width.saturating_sub(2).max(1);
    let width = available_width.min(92).max(available_width.min(40));
    let available_height = area.height.saturating_sub(2).max(1);
    let height = available_height.min(8).max(available_height.min(6));
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let modal = Rect::new(x, y, width, height);
    frame.render_widget(Clear, modal);

    let input_width = width.saturating_sub(6) as usize;
    let lines = vec![
        Line::from(vec![
            Span::styled("Field: ", Style::default().fg(Color::Gray)),
            Span::raw(edit.label().to_string()),
        ]),
        Line::from(vec![
            Span::styled("Value: ", Style::default().fg(Color::Gray)),
            Span::raw(truncate(edit.buffer(), input_width)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Edit"))
            .wrap(Wrap { trim: false }),
        modal,
    );

    let button_y = modal.y + modal.height.saturating_sub(2);
    let apply = Rect::new(modal.x + 2, button_y, 9, 1);
    let cancel = Rect::new(modal.x + 13, button_y, 10, 1);
    render_button(frame, hits, apply, "Apply", HitTarget::TextEditSubmit);
    render_button(frame, hits, cancel, "Cancel", HitTarget::TextEditCancel);
}

fn render_button(
    frame: &mut Frame<'_>,
    hits: &mut Vec<HitArea>,
    area: Rect,
    label: &'static str,
    target: HitTarget,
) {
    hits.push(HitArea::new(area, target));
    frame.render_widget(
        Paragraph::new(format!("[{label}]")).style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        area,
    );
}

fn action_cell(label: &'static str) -> Cell<'static> {
    Cell::from(format!("[{label}]")).style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::LightYellow)
            .add_modifier(Modifier::BOLD),
    )
}

fn table_data_row_start(area: Rect) -> u16 {
    area.y.saturating_add(2)
}

fn traffic_status_color(kind: TrafficStatusKind) -> Color {
    match kind {
        TrafficStatusKind::Idle => Color::Gray,
        TrafficStatusKind::Active => Color::Green,
        TrafficStatusKind::Error => Color::Yellow,
    }
}

fn status_color(kind: StatusKind) -> Color {
    match kind {
        StatusKind::Info => Color::Cyan,
        StatusKind::Saved => Color::Green,
        StatusKind::Warning => Color::Yellow,
        StatusKind::Error => Color::LightRed,
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use probe_config::{AgentConfig, ExporterConfig, ExporterTransportConfig};
    use ratatui::{Terminal, backend::TestBackend};

    use super::{
        super::{
            app::{TuiAction, TuiApp},
            controls::ControlId,
            fields::FieldId,
            processes::{ProcessCatalog, ProcessEntry},
        },
        *,
    };

    #[test]
    fn render_overview_exposes_config_and_status() -> Result<(), Box<dyn std::error::Error>> {
        let mut app = test_app();
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;

        terminal.draw(|frame| {
            let _ = draw(frame, &mut app);
        })?;

        let output = terminal.backend().to_string();
        assert!(output.contains("Probe TUI"));
        assert!(output.contains("Overview"));
        assert!(output.contains("Processes readable"));
        Ok(())
    }

    #[test]
    fn render_registers_mouse_hit_targets_for_tabs_and_process_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut app = test_app();
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Processes)));
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;

        assert_eq!(hit_map.hit(23, 4), Some(HitTarget::Tab(TuiTab::Capture)));
        assert_eq!(hit_map.hit(2, 10), Some(HitTarget::Process(0)));
        assert_eq!(
            hit_map.hit(2, 6),
            Some(HitTarget::Control(ControlId::SearchProcesses))
        );
        Ok(())
    }

    #[test]
    fn render_text_edit_modal_registers_apply_and_cancel_hits()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.exporters.push(ExporterConfig {
            transport: ExporterTransportConfig::File {
                path: PathBuf::from("/tmp/events.jsonl"),
            },
            ..ExporterConfig::default()
        });
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            config,
            ProcessCatalog::default(),
        );
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Export)));
        app.handle_action(TuiAction::Click(HitTarget::Field(
            FieldId::ExporterFilePath(0),
        )));
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;

        let output = terminal.backend().to_string();
        assert!(output.contains("Edit"));
        assert!(output.contains("Field: File path"));
        assert!(output.contains("Value: /tmp/events.jsonl"));
        assert_eq!(hit_map.hit(7, 14), Some(HitTarget::TextEditSubmit));
        assert_eq!(hit_map.hit(18, 14), Some(HitTarget::TextEditCancel));
        Ok(())
    }

    #[test]
    fn render_runtime_registers_reload_action_hit() -> Result<(), Box<dyn std::error::Error>> {
        let mut app = test_app();
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Runtime)));
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;

        let output = terminal.backend().to_string();
        assert!(output.contains("Runtime"));
        assert!(output.contains("Admin socket"));
        assert!(output.contains("Reload runtime actions"));
        assert_eq!(
            hit_map.hit(2, 11),
            Some(HitTarget::Control(ControlId::ReloadRuntimeActions))
        );
        Ok(())
    }

    #[test]
    fn render_traffic_without_attached_agent_has_no_config_toggle()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut app = test_app();
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Traffic)));
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;

        terminal.draw(|frame| {
            let _ = draw(frame, &mut app);
        })?;

        let output = terminal.backend().to_string();
        assert!(!output.contains("[Enable admin]"));
        Ok(())
    }

    #[test]
    fn truncate_preserves_short_text_and_marks_long_text() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 3), "abc...");
    }

    fn test_app() -> TuiApp {
        TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::from_entries([ProcessEntry {
                pid: 42,
                name: "curl".to_string(),
                exe_path: Some(PathBuf::from("/usr/bin/curl")),
                argv_count: 2,
            }]),
        )
    }
}

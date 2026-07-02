use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
};

use super::{
    app::{StatusKind, TuiApp, TuiTab},
    hit::{HitArea, HitMap, HitTarget},
};

const PROCESS_VISIBLE_DETAIL_WIDTH: usize = 96;

pub(crate) fn draw(frame: &mut Frame<'_>, app: &TuiApp) -> HitMap {
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
        TuiTab::Processes => render_processes(frame, body, app, &mut hits),
        _ => render_fields(frame, body, app, &mut hits),
    }
    render_footer(frame, footer, app);
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
            Rect::new(x, area.y + 1, width, 1),
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
    let fields = app.fields_for_active_tab();
    let selected = app.selected_field();
    let rows = fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let marker = if Some(*field) == selected { ">" } else { " " };
            let row = Row::new([
                Cell::from(marker),
                Cell::from(field.label()),
                Cell::from(app.field_value(*field)),
                Cell::from(field.action_hint()),
            ]);
            if Some(*field) == selected {
                row.style(Style::default().fg(Color::Black).bg(Color::LightCyan))
            } else if index % 2 == 0 {
                row.style(Style::default().fg(Color::White))
            } else {
                row.style(Style::default().fg(Color::Gray))
            }
        })
        .collect::<Vec<_>>();

    let row_start = area.y + 3;
    for (index, field) in fields.iter().enumerate() {
        hits.push(HitArea::new(
            Rect::new(
                area.x + 1,
                row_start + index as u16,
                area.width.saturating_sub(2),
                1,
            ),
            HitTarget::Field(*field),
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

fn render_processes(frame: &mut Frame<'_>, area: Rect, app: &TuiApp, hits: &mut Vec<HitArea>) {
    let entries = app.processes().entries();
    let visible_rows = area.height.saturating_sub(3) as usize;
    let start = app
        .process_scroll()
        .min(entries.len().saturating_sub(visible_rows));
    let end = start.saturating_add(visible_rows).min(entries.len());
    let rows = entries[start..end]
        .iter()
        .enumerate()
        .map(|(visible_index, process)| {
            let absolute_index = start + visible_index;
            let marker = if absolute_index == app.selected_process_index() {
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
            if absolute_index == app.selected_process_index() {
                row.style(Style::default().fg(Color::Black).bg(Color::LightGreen))
            } else {
                row
            }
        })
        .collect::<Vec<_>>();

    let row_start = area.y + 3;
    for visible_index in 0..end.saturating_sub(start) {
        hits.push(HitArea::new(
            Rect::new(
                area.x + 1,
                row_start + visible_index as u16,
                area.width.saturating_sub(2),
                1,
            ),
            HitTarget::Process(start + visible_index),
        ));
    }

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
        area,
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

    use probe_config::AgentConfig;
    use ratatui::{Terminal, backend::TestBackend};

    use super::{
        super::{
            app::{TuiAction, TuiApp},
            processes::{ProcessCatalog, ProcessEntry},
        },
        *,
    };

    #[test]
    fn render_overview_exposes_config_and_status() -> Result<(), Box<dyn std::error::Error>> {
        let app = test_app();
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;

        terminal.draw(|frame| {
            let _ = draw(frame, &app);
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
            hit_map = draw(frame, &app);
        })?;

        assert_eq!(hit_map.hit(13, 4), Some(HitTarget::Tab(TuiTab::Capture)));
        assert_eq!(hit_map.hit(2, 9), Some(HitTarget::Process(0)));
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

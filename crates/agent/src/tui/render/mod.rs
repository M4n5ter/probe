use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, Wrap,
    },
};

mod process_picker;
mod traffic;

use super::{
    app::{StatusKind, TextEditSession, TuiApp, TuiTab},
    controls::FocusTarget,
    hit::{HitArea, HitMap, HitTarget},
};

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
        TuiTab::Traffic => traffic::render_traffic(frame, body, app, &mut hits),
        TuiTab::Processes => process_picker::render_processes(frame, body, app, &mut hits),
        _ => render_fields(frame, body, app, &mut hits),
    }
    render_footer(frame, footer, app);
    if let Some(edit) = app.text_edit() {
        render_text_edit(
            frame,
            area,
            edit,
            app.is_hovered(HitTarget::TextEditSubmit),
            app.is_hovered(HitTarget::TextEditCancel),
            &mut hits,
        );
    }
    if app.traffic_popup_open() {
        traffic::render_traffic_popup(frame, area, app, &mut hits);
    }
    if let Some(hover) = app.hovered_process_argv() {
        traffic::render_process_argv_hover(frame, area, app, hover);
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
        app.is_hovered(HitTarget::Save),
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
        app.is_hovered(HitTarget::Reload),
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
        app.is_hovered(HitTarget::Quit),
    );
}

fn render_tabs(frame: &mut Frame<'_>, area: Rect, app: &TuiApp, hits: &mut Vec<HitArea>) {
    let mut spans = Vec::new();
    let mut x = area.x + 1;
    let hit_height = area.height.saturating_sub(1).max(1);
    for tab in TuiTab::ALL {
        let selected = tab == app.active_tab();
        let hovered = app.is_hovered(HitTarget::Tab(tab));
        let label = format!(" {} ", tab.label());
        let style = if selected {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if hovered {
            Style::default().fg(Color::Black).bg(Color::Gray)
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
    let mut lines = vec![
        overview_line("Agent", config.agent_id.clone(), Color::Gray),
        overview_line("Runtime", app.runtime_agent_status(), Color::Gray),
        overview_line(
            "Config",
            format!(
                "capture={:?}, exporters={}, policies={}, processes={}",
                config.capture.selection,
                config.exporters.len(),
                config.policies.len(),
                app.processes().entries().len()
            ),
            Color::Gray,
        ),
        Line::from(""),
    ];
    lines.extend(
        app.overview_data_path_lines()
            .into_iter()
            .map(|line| overview_line(line.label, line.value, Color::Cyan)),
    );
    lines.extend([
        Line::from(""),
        overview_line(
            "Status",
            app.status().text.clone(),
            status_color(app.status().kind),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Overview"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn overview_line(label: &str, value: impl Into<String>, label_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(label_color)),
        Span::raw(value.into()),
    ])
}

fn render_fields(frame: &mut Frame<'_>, area: Rect, app: &TuiApp, hits: &mut Vec<HitArea>) {
    let targets = app.focus_targets_for_active_tab();
    let selected = app.selected_focus_target();
    let rows = targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let marker = if Some(*target) == selected { ">" } else { " " };
            let hovered = app.is_hovered(hit_target_for_focus(*target));
            let row = Row::new([
                Cell::from(marker),
                Cell::from(target.label()),
                Cell::from(app.focus_target_value(*target)),
                action_cell(target.action_hint(), hovered),
            ]);
            if Some(*target) == selected {
                row.style(Style::default().fg(Color::Black).bg(Color::LightCyan))
            } else if hovered {
                row.style(Style::default().fg(Color::Black).bg(Color::Gray))
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

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &TuiApp) {
    let status_style = Style::default().fg(status_color(app.status().kind));
    let mut spans = vec![
        Span::styled(app.status().text.clone(), status_style),
        Span::raw("   "),
        Span::styled("Tab/Shift-Tab", Style::default().fg(Color::Gray)),
        Span::raw(" tabs  "),
        Span::styled("Up/Down", Style::default().fg(Color::Gray)),
        Span::raw(" select  "),
        Span::styled("Enter/Space/Click", Style::default().fg(Color::Gray)),
        Span::raw(" edit/open  "),
        Span::styled("w", Style::default().fg(Color::Gray)),
        Span::raw(" watch  "),
    ];
    if app.active_tab() == TuiTab::Traffic {
        spans.extend([
            Span::styled("d", Style::default().fg(Color::Gray)),
            Span::raw(" data path  "),
            Span::styled("v", Style::default().fg(Color::Gray)),
            Span::raw(" view  "),
            Span::styled("h", Style::default().fg(Color::Gray)),
            Span::raw(" filter  "),
            Span::styled("t", Style::default().fg(Color::Gray)),
            Span::raw(" live  "),
            Span::styled("a/e/l/m", Style::default().fg(Color::Gray)),
            Span::raw(" observe  "),
            Span::styled("x", Style::default().fg(Color::Gray)),
            Span::raw(" mitm off  "),
        ]);
    }
    spans.extend([
        Span::styled("Ctrl-S", Style::default().fg(Color::Gray)),
        Span::raw(" save  "),
        Span::styled("q", Style::default().fg(Color::Gray)),
        Span::raw(" quit"),
    ]);
    let text = Line::from(spans);
    frame.render_widget(Paragraph::new(text), area);
}

fn render_text_edit(
    frame: &mut Frame<'_>,
    area: Rect,
    edit: &TextEditSession,
    submit_hovered: bool,
    cancel_hovered: bool,
    hits: &mut Vec<HitArea>,
) {
    let available_width = area.width.saturating_sub(2).max(1);
    let width = available_width.min(92).max(available_width.min(40));
    let available_height = area.height.saturating_sub(2).max(1);
    let height = available_height.min(8).max(available_height.min(6));
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let modal = Rect::new(x, y, width, height);
    hits.push(HitArea::new(area, HitTarget::TextEditPanel));
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
    render_button(
        frame,
        hits,
        apply,
        "Apply",
        HitTarget::TextEditSubmit,
        submit_hovered,
    );
    render_button(
        frame,
        hits,
        cancel,
        "Cancel",
        HitTarget::TextEditCancel,
        cancel_hovered,
    );
}

fn render_button(
    frame: &mut Frame<'_>,
    hits: &mut Vec<HitArea>,
    area: Rect,
    label: &str,
    target: HitTarget,
    hovered: bool,
) {
    hits.push(HitArea::new(area, target));
    let style = if hovered {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(Color::LightYellow)
            .add_modifier(Modifier::BOLD)
    };
    frame.render_widget(Paragraph::new(format!("[{label}]")).style(style), area);
}

fn action_cell(label: &'static str, hovered: bool) -> Cell<'static> {
    let background = if hovered {
        Color::Cyan
    } else {
        Color::LightYellow
    };
    Cell::from(format!("[{label}]")).style(
        Style::default()
            .fg(Color::Black)
            .bg(background)
            .add_modifier(Modifier::BOLD),
    )
}

fn table_data_row_start(area: Rect) -> u16 {
    area.y.saturating_add(2)
}

fn table_scroll_track(area: Rect) -> Rect {
    Rect::new(
        area.x,
        table_data_row_start(area),
        area.width,
        area.height.saturating_sub(3),
    )
}

fn render_vertical_scrollbar(
    frame: &mut Frame<'_>,
    area: Rect,
    content_len: usize,
    position: usize,
    viewport_len: usize,
) {
    if content_len <= viewport_len || area.width == 0 || area.height == 0 {
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
            hit::ScrollTarget,
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
        assert!(output.contains("Config"));
        assert!(output.contains("processes=1"));
        assert!(output.contains("Data path source"));
        assert!(output.contains("Data path"));
        assert!(output.contains("MITM"));
        assert!(output.contains("Next"));
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

        let output = terminal.backend().to_string();
        assert!(output.contains("filter"));
        assert!(output.contains("matches"));
        assert_eq!(hit_map.hit(23, 4), Some(HitTarget::Tab(TuiTab::Capture)));
        assert!(scroll_target_exists(
            &hit_map,
            Some(ScrollTarget::ProcessList),
            100,
            24
        ));
        assert!(hit_exists(&hit_map, Some(HitTarget::Process(0)), 100, 24));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::ProcessArgv(0)),
            100,
            24
        ));
        assert_eq!(
            hit_map.hit(2, 6),
            Some(HitTarget::Control(ControlId::SearchProcesses))
        );
        Ok(())
    }

    fn hit_exists(hit_map: &HitMap, target: Option<HitTarget>, width: u16, height: u16) -> bool {
        (0..height).any(|row| (0..width).any(|column| hit_map.hit(column, row) == target))
    }

    fn scroll_target_exists(
        hit_map: &HitMap,
        target: Option<ScrollTarget>,
        width: u16,
        height: u16,
    ) -> bool {
        (0..height).any(|row| (0..width).any(|column| hit_map.scroll_target(column, row) == target))
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
        assert_eq!(hit_map.hit(23, 4), Some(HitTarget::TextEditPanel));
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
    fn render_tabs_show_hover_background() -> Result<(), Box<dyn std::error::Error>> {
        let mut app = test_app();
        app.handle_action(TuiAction::Hover {
            target: Some(HitTarget::Tab(TuiTab::Traffic)),
            column: 13,
            row: 4,
        });
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;
        let (column, row) =
            first_hit_coordinate(&hit_map, HitTarget::Tab(TuiTab::Traffic), 100, 24)
                .expect("traffic tab should be clickable");

        assert_eq!(
            terminal
                .backend()
                .buffer()
                .cell((column, row))
                .map(|cell| cell.style().bg),
            Some(Some(Color::Gray))
        );
        Ok(())
    }

    #[test]
    fn render_process_rows_show_hover_background() -> Result<(), Box<dyn std::error::Error>> {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::from_entries([
                ProcessEntry {
                    pid: 42,
                    name: "curl".to_string(),
                    exe_path: Some(PathBuf::from("/usr/bin/curl")),
                    argv: vec!["curl".to_string()],
                    uid: 1000,
                    gid: 1000,
                    cgroup_path: Some(
                        "user.slice/user-1000.slice/app.slice/curl.scope".to_string(),
                    ),
                },
                ProcessEntry {
                    pid: 43,
                    name: "nginx".to_string(),
                    exe_path: Some(PathBuf::from("/usr/sbin/nginx")),
                    argv: vec!["nginx".to_string()],
                    uid: 0,
                    gid: 0,
                    cgroup_path: Some("system.slice/nginx.service".to_string()),
                },
            ]),
        );
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Processes)));
        app.handle_action(TuiAction::Hover {
            target: Some(HitTarget::ProcessArgv(1)),
            column: 60,
            row: 11,
        });
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;
        let (column, row) = first_hit_coordinate(&hit_map, HitTarget::ProcessArgv(1), 100, 24)
            .expect("process argv should be hoverable");

        assert_eq!(
            terminal
                .backend()
                .buffer()
                .cell((column, row))
                .map(|cell| cell.style().bg),
            Some(Some(Color::Gray))
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
    fn render_traffic_registers_capture_and_mitm_action_hits()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut app = test_app();
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Traffic)));
        let data_path_summary = app.traffic_data_path_summary();
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;

        let output = terminal.backend().to_string();
        assert!(output.contains("[Data Path]"));
        assert!(output.contains("[Tail Live]"));
        assert!(output.contains("[Search]"));
        assert!(output.contains("[Watch]"));
        assert!(output.contains("[Auto]"));
        assert!(output.contains("[eBPF]"));
        assert!(output.contains("[libpcap]"));
        assert!(!output.contains("[MITM]"));
        assert!(output.contains("Traffic Readiness"));
        assert!(output.contains("Data path source: local config"));
        assert!(
            data_path_summary.capture.contains("ebpf selected"),
            "capture readiness should remain a separate summary field: {data_path_summary:?}"
        );
        assert!(output.contains("capture ebpf selected"));
        assert!(output.contains("next configure reliable MITM proxy data path"));
        assert!(output.contains("MITM not configured;"));
        assert!(scroll_target_exists(
            &hit_map,
            Some(ScrollTarget::TrafficProcessList),
            100,
            24
        ));
        assert!(scroll_target_exists(
            &hit_map,
            Some(ScrollTarget::TrafficEvents),
            100,
            24
        ));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::ProcessMonitor(0)),
            100,
            24
        ));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::Control(ControlId::SearchProcesses)),
            100,
            24
        ));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::Control(ControlId::OpenTrafficDiagnostics)),
            100,
            24
        ));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::Control(ControlId::TrafficTailFollow)),
            100,
            24
        ));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::Control(ControlId::ObserveAuto)),
            100,
            24
        ));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::Control(ControlId::ObserveEbpf)),
            100,
            24
        ));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::Control(ControlId::ObserveLibpcap)),
            100,
            24
        ));
        Ok(())
    }

    #[test]
    fn table_scroll_track_matches_table_data_rows() {
        let table = Rect::new(10, 20, 80, 15);

        assert_eq!(table_data_row_start(table), 22);
        assert_eq!(table_scroll_track(table), Rect::new(10, 22, 80, 12));
    }

    #[test]
    fn traffic_process_search_hits_filter_in_place() -> Result<(), Box<dyn std::error::Error>> {
        let mut app = test_app();
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Traffic)));
        let mut terminal = Terminal::new(TestBackend::new(100, 24))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;
        let (search_column, search_row) = first_hit_coordinate(
            &hit_map,
            HitTarget::Control(ControlId::SearchProcesses),
            100,
            24,
        )
        .expect("traffic search should be clickable");
        assert_eq!(
            hit_map.scroll_target(search_column, search_row),
            Some(ScrollTarget::TrafficProcessList)
        );

        app.handle_action(TuiAction::Click(
            hit_map
                .hit(search_column, search_row)
                .expect("traffic search hit"),
        ));
        for character in "curl".chars() {
            app.handle_action(TuiAction::TextInput(character));
        }
        app.handle_action(TuiAction::TextSubmit);

        assert_eq!(app.active_tab(), TuiTab::Traffic);
        assert_eq!(app.process_filter(), "curl");

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;
        let output = terminal.backend().to_string();
        assert!(output.contains("[Clear]"));
        let (clear_column, clear_row) = first_hit_coordinate(
            &hit_map,
            HitTarget::Control(ControlId::ClearProcessSearch),
            100,
            24,
        )
        .expect("traffic clear should be clickable");
        assert_eq!(
            hit_map.scroll_target(clear_column, clear_row),
            Some(ScrollTarget::TrafficProcessList)
        );

        app.handle_action(TuiAction::Click(
            hit_map
                .hit(clear_column, clear_row)
                .expect("traffic clear hit"),
        ));

        assert_eq!(app.active_tab(), TuiTab::Traffic);
        assert!(app.process_filter().is_empty());
        Ok(())
    }

    #[test]
    fn render_traffic_data_path_popup_without_selected_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut app = test_app();
        app.handle_action(TuiAction::Click(HitTarget::Tab(TuiTab::Traffic)));
        app.handle_action(TuiAction::Click(HitTarget::Control(
            ControlId::OpenTrafficDiagnostics,
        )));
        let mut terminal = Terminal::new(TestBackend::new(110, 28))?;
        let mut hit_map = HitMap::default();

        terminal.draw(|frame| {
            hit_map = draw(frame, &mut app);
        })?;

        let output = terminal.backend().to_string();
        assert!(output.contains("Data Path Diagnostics"));
        assert!(output.contains("Data path source: local config"));
        assert!(output.contains("Capture diagnostics"));
        assert!(hit_exists(
            &hit_map,
            Some(HitTarget::TrafficPopupClose),
            110,
            28
        ));
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
                argv: vec!["curl".to_string(), "https://example.com".to_string()],
                uid: 1000,
                gid: 1000,
                cgroup_path: Some("user.slice/user-1000.slice/app.slice/curl.scope".to_string()),
            }]),
        )
    }
}

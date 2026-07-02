mod client;
mod rows;

use std::path::Path;

use probe_core::Selector;

use self::{client::request_tail_events, rows::TrafficRow};
use crate::admin::EventTailSnapshot;

pub(crate) use rows::TrafficRow as TrafficTableRow;

const MAX_ROWS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficState {
    after_sequence: u64,
    selector_key: Option<String>,
    rows: Vec<TrafficRow>,
    selected_index: usize,
    scroll: usize,
    status: TrafficStatus,
    last_export_sequence: u64,
}

impl Default for TrafficState {
    fn default() -> Self {
        Self {
            after_sequence: 0,
            selector_key: None,
            rows: Vec::new(),
            selected_index: 0,
            scroll: 0,
            status: TrafficStatus::idle("Traffic view uses the running admin socket"),
            last_export_sequence: 0,
        }
    }
}

impl TrafficState {
    pub(crate) fn rows(&self) -> &[TrafficTableRow] {
        &self.rows
    }

    pub(crate) fn selected_index(&self) -> usize {
        self.selected_index
    }

    pub(crate) fn scroll(&self) -> usize {
        self.scroll
    }

    pub(crate) fn status(&self) -> &TrafficStatus {
        &self.status
    }

    pub(crate) fn last_export_sequence(&self) -> u64 {
        self.last_export_sequence
    }

    pub(crate) async fn refresh(&mut self, socket_path: &Path, selector: Selector) {
        let selector_key = selector_key(&selector);
        if Some(selector_key.clone()) != self.selector_key {
            self.reset_for_selector(selector_key);
        }

        match request_tail_events(socket_path, self.after_sequence, selector).await {
            Ok(snapshot) => self.apply_snapshot(snapshot),
            Err(error) => {
                self.status = TrafficStatus::error(error.to_string());
            }
        }
    }

    pub(crate) fn mark_admin_disabled(&mut self) {
        self.status = TrafficStatus::error(
            "Admin socket is disabled in config; enable admin to view traffic",
        );
    }

    pub(crate) fn mark_filter_unavailable(&mut self, message: impl Into<String>) {
        self.after_sequence = 0;
        self.selector_key = None;
        self.rows.clear();
        self.selected_index = 0;
        self.scroll = 0;
        self.status = TrafficStatus::error(message);
    }

    pub(crate) fn move_selection(&mut self, delta: isize, visible_rows: usize) {
        if self.rows.is_empty() {
            return;
        }
        let raw = self.selected_index as isize + delta;
        self.selected_index = raw.clamp(0, self.rows.len().saturating_sub(1) as isize) as usize;
        self.keep_selected_visible(visible_rows);
    }

    pub(crate) fn select_row(&mut self, index: usize, visible_rows: usize) {
        if index < self.rows.len() {
            self.selected_index = index;
            self.keep_selected_visible(visible_rows);
        }
    }

    fn reset_for_selector(&mut self, selector_key: String) {
        self.after_sequence = 0;
        self.selector_key = Some(selector_key);
        self.rows.clear();
        self.selected_index = 0;
        self.scroll = 0;
        self.status = TrafficStatus::idle("Traffic filter changed");
    }

    fn apply_snapshot(&mut self, snapshot: EventTailSnapshot) {
        self.after_sequence = snapshot.next_after_sequence;
        self.last_export_sequence = snapshot.last_export_sequence;
        let received = snapshot.events.len();
        let omitted = snapshot.omissions.len();
        self.rows
            .extend(snapshot.events.into_iter().map(TrafficRow::from_record));
        if self.rows.len() > MAX_ROWS {
            let drop_count = self.rows.len() - MAX_ROWS;
            self.rows.drain(0..drop_count);
            self.selected_index = self.selected_index.saturating_sub(drop_count);
            self.scroll = self.scroll.saturating_sub(drop_count);
        }
        self.clamp_selection();
        self.status = traffic_status_for_snapshot(received, omitted, snapshot.scanned);
    }

    fn clamp_selection(&mut self) {
        if self.selected_index >= self.rows.len() {
            self.selected_index = self.rows.len().saturating_sub(1);
        }
        if self.scroll >= self.rows.len() {
            self.scroll = self.rows.len().saturating_sub(1);
        }
    }

    fn keep_selected_visible(&mut self, visible_rows: usize) {
        if self.selected_index < self.scroll {
            self.scroll = self.selected_index;
        }
        if visible_rows > 0 {
            let end = self.scroll.saturating_add(visible_rows);
            if self.selected_index >= end {
                self.scroll = self
                    .selected_index
                    .saturating_sub(visible_rows.saturating_sub(1));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrafficStatusKind {
    Idle,
    Active,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficStatus {
    pub(crate) kind: TrafficStatusKind,
    pub(crate) text: String,
}

impl TrafficStatus {
    fn idle(text: impl Into<String>) -> Self {
        Self {
            kind: TrafficStatusKind::Idle,
            text: text.into(),
        }
    }

    fn active(text: impl Into<String>) -> Self {
        Self {
            kind: TrafficStatusKind::Active,
            text: text.into(),
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Self {
            kind: TrafficStatusKind::Error,
            text: text.into(),
        }
    }
}

fn traffic_status_for_snapshot(received: usize, omitted: usize, scanned: usize) -> TrafficStatus {
    if omitted > 0 {
        TrafficStatus::error(format!(
            "Received {received} events; omitted {omitted} oversized events"
        ))
    } else if received == 0 {
        TrafficStatus::idle(format!("No new matching events; scanned {scanned} records"))
    } else {
        TrafficStatus::active(format!("Received {received} matching events"))
    }
}

fn selector_key(selector: &Selector) -> String {
    serde_json::to_string(selector).unwrap_or_else(|_| format!("{selector:?}"))
}

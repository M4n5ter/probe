use std::{collections::BTreeMap, path::PathBuf};

use probe_core::Selector;

use super::{
    client::{TrafficClientError, request_event_detail, request_tail_events},
    filter::TrafficEventFilter,
    http::{HttpExchangeIdentity, HttpExchangeRow, build_http_exchange_rows},
    rows::TrafficRow,
    websocket::{WebSocketSessionIdentity, WebSocketSessionRow, build_websocket_session_rows},
};
use crate::{
    admin::{
        AdminClientError, EventDetailSnapshot, EventTailAttributionMode, EventTailOmission,
        EventTailSnapshot, UnknownProcessCandidateSelector,
    },
    tui::{
        runtime_status::{
            CaptureDiagnosticMessage, missing_mitm_configuration_action,
            mitm_data_path_coverage_line, mitm_visibility_lines,
        },
        scrollbar::drag_position_to_scroll,
        text::terminal_safe_inline_text,
    },
};

const MAX_TRAFFIC_EVENT_ROWS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficDetailLoadRequest {
    pub(crate) socket_path: PathBuf,
    pub(crate) sequence: u64,
    pub(crate) request_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficDetailLoadResult {
    pub(crate) sequence: u64,
    request_id: u64,
    result: Result<EventDetailSnapshot, String>,
}

impl TrafficDetailLoadResult {
    pub(crate) fn failed(sequence: u64, request_id: u64, message: impl Into<String>) -> Self {
        Self {
            sequence,
            request_id,
            result: Err(terminal_safe_inline_text(message)),
        }
    }
}

pub(crate) async fn load_traffic_detail(
    request: TrafficDetailLoadRequest,
) -> TrafficDetailLoadResult {
    let result = request_event_detail(&request.socket_path, request.sequence)
        .await
        .map_err(|error| error.to_string());
    TrafficDetailLoadResult {
        sequence: request.sequence,
        request_id: request.request_id,
        result,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficRefreshRequest {
    socket_path: PathBuf,
    selector: Option<Selector>,
    unknown_process_candidate_selector: Option<UnknownProcessCandidateSelector>,
    selector_key: String,
    after_sequence: u64,
    latest_window: bool,
    event_filter: TrafficEventFilter,
}

impl TrafficRefreshRequest {
    pub(crate) fn selector_key(&self) -> &str {
        &self.selector_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficRefreshResult {
    selector_key: String,
    event_filter: TrafficEventFilter,
    result: Result<TrafficRefreshSnapshot, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrafficRefreshSnapshot {
    tail: EventTailSnapshot,
    empty_filter_diagnostics: Option<EmptyFilterDiagnostics>,
}

pub(crate) async fn load_traffic_refresh(request: TrafficRefreshRequest) -> TrafficRefreshResult {
    let event_types = request
        .event_filter
        .event_type_filter()
        .to_admin_event_types();
    let tail = request_tail_events(
        &request.socket_path,
        request.after_sequence,
        request.latest_window,
        request.selector.clone(),
        request.unknown_process_candidate_selector.clone(),
        &event_types,
    )
    .await;
    let result = match tail {
        Ok(tail) => {
            let empty_filter_diagnostics = if should_probe_empty_filter(request.event_filter, &tail)
            {
                request_tail_events(
                    &request.socket_path,
                    request.after_sequence,
                    request.latest_window,
                    request.selector,
                    request.unknown_process_candidate_selector,
                    &[],
                )
                .await
                .ok()
                .and_then(|snapshot| {
                    EmptyFilterDiagnostics::from_snapshot(request.event_filter.label(), snapshot)
                })
            } else {
                None
            };
            Ok(TrafficRefreshSnapshot {
                tail,
                empty_filter_diagnostics,
            })
        }
        Err(error) => Err(traffic_refresh_error_message(&error)),
    };
    TrafficRefreshResult {
        selector_key: request.selector_key,
        event_filter: request.event_filter,
        result,
    }
}

#[cfg(test)]
impl TrafficRefreshResult {
    pub(crate) fn from_request_for_test(
        request: &TrafficRefreshRequest,
        tail: EventTailSnapshot,
    ) -> Self {
        Self {
            selector_key: request.selector_key.clone(),
            event_filter: request.event_filter,
            result: Ok(TrafficRefreshSnapshot {
                tail,
                empty_filter_diagnostics: None,
            }),
        }
    }

    pub(crate) fn failed_from_request_for_test(
        request: &TrafficRefreshRequest,
        message: impl Into<String>,
    ) -> Self {
        Self {
            selector_key: request.selector_key.clone(),
            event_filter: request.event_filter,
            result: Err(message.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficState {
    after_sequence: u64,
    latest_window: bool,
    selector_key: Option<String>,
    rows: Vec<TrafficRow>,
    http_exchanges: Vec<HttpExchangeRow>,
    websocket_sessions: Vec<WebSocketSessionRow>,
    visible_projection: TrafficVisibleProjection,
    event_view: TrafficViewport,
    http_view: TrafficViewport,
    websocket_view: TrafficViewport,
    viewport_rows: usize,
    follow_tail: bool,
    status: TrafficStatus,
    last_export_sequence: u64,
    detail_state: TrafficDetailState,
    event_filter: TrafficEventFilter,
    view_mode: TrafficViewMode,
    search_query: String,
    attribution_mode: EventTailAttributionMode,
    empty_filter_diagnostics: Option<EmptyFilterDiagnostics>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrafficVisibleProjection {
    rows: Vec<usize>,
    http_exchanges: Vec<usize>,
    websocket_sessions: Vec<usize>,
}

impl TrafficVisibleProjection {
    fn from_parts(
        rows: &[TrafficRow],
        http_exchanges: &[HttpExchangeRow],
        websocket_sessions: &[WebSocketSessionRow],
        search_query: &str,
    ) -> Self {
        if search_query.is_empty() {
            return Self {
                rows: all_indexes(rows.len()),
                http_exchanges: all_indexes(http_exchanges.len()),
                websocket_sessions: all_indexes(websocket_sessions.len()),
            };
        }
        let normalized_query = search_query.to_lowercase();
        Self {
            rows: matching_indexes(rows, |row| row_matches_search(&normalized_query, row)),
            http_exchanges: matching_indexes(http_exchanges, |exchange| {
                http_exchange_matches_search(&normalized_query, exchange)
            }),
            websocket_sessions: matching_indexes(websocket_sessions, |session| {
                websocket_session_matches_search(&normalized_query, session)
            }),
        }
    }

    fn len(&self, mode: TrafficViewMode) -> usize {
        self.indexes(mode).len()
    }

    fn indexes(&self, mode: TrafficViewMode) -> &[usize] {
        match mode {
            TrafficViewMode::Http => &self.http_exchanges,
            TrafficViewMode::WebSocket => &self.websocket_sessions,
            TrafficViewMode::Events => &self.rows,
        }
    }

    fn clear(&mut self) {
        self.rows.clear();
        self.http_exchanges.clear();
        self.websocket_sessions.clear();
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProjectedItems<'a, T> {
    items: &'a [T],
    indexes: &'a [usize],
}

impl<'a, T> ProjectedItems<'a, T> {
    fn new(items: &'a [T], indexes: &'a [usize]) -> Self {
        Self { items, indexes }
    }

    pub(crate) fn len(&self) -> usize {
        self.indexes.len()
    }

    pub(crate) fn get(&self, index: usize) -> Option<&'a T> {
        self.indexes
            .get(index)
            .and_then(|backing_index| self.items.get(*backing_index))
    }

    fn iter(&self) -> impl Iterator<Item = &'a T> + '_ {
        self.indexes
            .iter()
            .filter_map(|backing_index| self.items.get(*backing_index))
    }

    fn position(&self, mut matches: impl FnMut(&T) -> bool) -> Option<usize> {
        self.iter().position(&mut matches)
    }

    fn nearest_index_by_key(&self, key: u64, item_key: impl Fn(&T) -> u64) -> Option<usize> {
        self.iter()
            .enumerate()
            .min_by_key(|(_, item)| item_key(item).abs_diff(key))
            .map(|(index, _)| index)
    }
}

impl<T> std::ops::Index<usize> for ProjectedItems<'_, T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.items[self.indexes[index]]
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TrafficViewport {
    selected_index: usize,
    scroll: usize,
}

impl TrafficViewport {
    fn selected_index(self) -> usize {
        self.selected_index
    }

    fn scroll(self) -> usize {
        self.scroll
    }

    fn anchor_scroll(&mut self, len: usize, index: usize, visible_rows: usize) {
        if len == 0 {
            self.reset();
            return;
        }
        self.scroll = index.min(Self::max_scroll(len, visible_rows));
        self.clamp_selection_to_viewport(len, visible_rows);
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn clamp_to_len(&mut self, len: usize) {
        self.selected_index = self.selected_index.min(len.saturating_sub(1));
        self.scroll = self.scroll.min(len.saturating_sub(1));
    }

    fn select_tail(&mut self, len: usize, visible_rows: usize) {
        if len == 0 {
            self.reset();
            return;
        }
        self.selected_index = len.saturating_sub(1);
        self.scroll = Self::max_scroll(len, visible_rows);
    }

    fn move_selection(&mut self, len: usize, delta: isize, visible_rows: usize) -> Option<bool> {
        if len == 0 {
            return None;
        }
        let raw = self.selected_index as isize + delta;
        self.selected_index = raw.clamp(0, len.saturating_sub(1) as isize) as usize;
        self.keep_selected_visible(visible_rows);
        Some(self.selection_is_at_tail(len))
    }

    fn select_row(&mut self, len: usize, index: usize, visible_rows: usize) -> Option<bool> {
        if index >= len {
            return None;
        }
        self.selected_index = index;
        self.keep_selected_visible(visible_rows);
        Some(self.selection_is_at_tail(len))
    }

    fn scroll_viewport(&mut self, len: usize, delta: isize, visible_rows: usize) -> Option<bool> {
        if len == 0 {
            return None;
        }
        let max_scroll = Self::max_scroll(len, visible_rows);
        self.scroll = scroll_position(self.scroll, delta, max_scroll);
        self.clamp_selection_to_viewport(len, visible_rows);
        if self.viewport_is_at_tail(len, visible_rows) {
            self.selected_index = len.saturating_sub(1);
            Some(true)
        } else {
            Some(false)
        }
    }

    fn drag_scrollbar(
        &mut self,
        len: usize,
        offset: usize,
        height: usize,
        visible_rows: usize,
    ) -> Option<bool> {
        if len == 0 {
            return None;
        }
        let max_scroll = Self::max_scroll(len, visible_rows);
        if max_scroll == 0 {
            self.scroll = 0;
            self.selected_index = len.saturating_sub(1);
            return Some(true);
        }
        self.scroll = drag_position_to_scroll(offset, height, max_scroll);
        self.clamp_selection_to_viewport(len, visible_rows);
        if self.viewport_is_at_tail(len, visible_rows) {
            self.selected_index = len.saturating_sub(1);
            Some(true)
        } else {
            Some(false)
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

    fn clamp_selection_to_viewport(&mut self, len: usize, visible_rows: usize) {
        let max_index = len.saturating_sub(1);
        if self.selected_index < self.scroll {
            self.selected_index = self.scroll;
        }
        if visible_rows > 0 {
            let bottom = self.scroll.saturating_add(visible_rows.saturating_sub(1));
            if self.selected_index > bottom {
                self.selected_index = bottom.min(max_index);
            }
        }
        self.selected_index = self.selected_index.min(max_index);
    }

    fn selection_is_at_tail(self, len: usize) -> bool {
        len > 0 && self.selected_index == len.saturating_sub(1)
    }

    fn viewport_is_at_tail(self, len: usize, visible_rows: usize) -> bool {
        self.scroll == Self::max_scroll(len, visible_rows)
    }

    fn max_scroll(len: usize, visible_rows: usize) -> usize {
        len.saturating_sub(visible_rows.max(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrafficProjection {
    mode: TrafficViewMode,
    len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpSelection {
    identity: HttpExchangeIdentity,
    order_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketSelection {
    identity: WebSocketSessionIdentity,
    order_sequence: u64,
}

impl Default for TrafficState {
    fn default() -> Self {
        Self {
            after_sequence: 0,
            latest_window: true,
            selector_key: None,
            rows: Vec::new(),
            http_exchanges: Vec::new(),
            websocket_sessions: Vec::new(),
            visible_projection: TrafficVisibleProjection::default(),
            event_view: TrafficViewport::default(),
            http_view: TrafficViewport::default(),
            websocket_view: TrafficViewport::default(),
            viewport_rows: 12,
            follow_tail: true,
            status: TrafficStatus::idle("Traffic view uses the running admin socket"),
            last_export_sequence: 0,
            detail_state: TrafficDetailState::default(),
            event_filter: TrafficEventFilter::Application,
            view_mode: TrafficViewMode::Http,
            search_query: String::new(),
            attribution_mode: EventTailAttributionMode::Strict,
            empty_filter_diagnostics: None,
        }
    }
}

impl TrafficState {
    pub(crate) fn rows(&self) -> &[TrafficRow] {
        &self.rows
    }

    pub(crate) fn visible_rows(&self) -> ProjectedItems<'_, TrafficRow> {
        ProjectedItems::new(&self.rows, &self.visible_projection.rows)
    }

    #[cfg(test)]
    pub(crate) fn seed_capture_loss_row_for_test(&mut self) {
        let event = probe_core::EventEnvelope::from_provider(
            probe_core::Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            probe_core::CaptureOrigin::from_source(probe_core::CaptureSource::Replay),
            "test",
            probe_core::EventKind::CaptureLoss(probe_core::CaptureLoss {
                lost_events: 1,
                reason: "seeded traffic row".to_string(),
            }),
        );
        self.apply_snapshot(EventTailSnapshot {
            after_sequence: 0,
            next_after_sequence: 1,
            last_export_sequence: 1,
            attribution_mode: EventTailAttributionMode::Strict,
            limit: 1,
            scan_limit: 1,
            scanned: 1,
            budget: crate::admin::EventTailBudgetSnapshot {
                max_event_payload_bytes: 512,
                max_record_bytes: 4096,
                included_record_bytes: 0,
                truncated: false,
            },
            events: vec![crate::admin::EventTailRecord {
                sequence: 1,
                stored_at_unix_ns: 1,
                event: crate::admin::EventTailEvent::from_envelope(&event),
            }],
            omissions: Vec::new(),
        });
    }

    pub(crate) fn selected_index(&self) -> usize {
        self.event_view.selected_index()
    }

    pub(crate) fn selected_row(&self) -> Option<&TrafficRow> {
        self.visible_rows().get(self.event_view.selected_index())
    }

    #[cfg(test)]
    pub(crate) fn http_exchanges(&self) -> &[HttpExchangeRow] {
        &self.http_exchanges
    }

    pub(crate) fn visible_http_exchanges(&self) -> ProjectedItems<'_, HttpExchangeRow> {
        ProjectedItems::new(
            &self.http_exchanges,
            &self.visible_projection.http_exchanges,
        )
    }

    #[cfg(test)]
    pub(crate) fn websocket_sessions(&self) -> &[WebSocketSessionRow] {
        &self.websocket_sessions
    }

    pub(crate) fn visible_websocket_sessions(&self) -> ProjectedItems<'_, WebSocketSessionRow> {
        ProjectedItems::new(
            &self.websocket_sessions,
            &self.visible_projection.websocket_sessions,
        )
    }

    pub(crate) fn selected_http_exchange_index(&self) -> usize {
        self.http_view.selected_index()
    }

    pub(crate) fn selected_websocket_session_index(&self) -> usize {
        self.websocket_view.selected_index()
    }

    pub(crate) fn http_scroll(&self) -> usize {
        self.http_view.scroll()
    }

    pub(crate) fn websocket_scroll(&self) -> usize {
        self.websocket_view.scroll()
    }

    pub(crate) fn active_row_count(&self) -> usize {
        self.active_projection().len
    }

    pub(crate) fn showing_http_exchanges(&self) -> bool {
        self.active_view().active == TrafficViewMode::Http
    }

    pub(crate) fn showing_websocket_sessions(&self) -> bool {
        self.active_view().active == TrafficViewMode::WebSocket
    }

    pub(crate) fn selected_detail_title(&self) -> &'static str {
        match self.active_view().active {
            TrafficViewMode::Http => "HTTP Exchange Detail",
            TrafficViewMode::WebSocket => "WebSocket Session Detail",
            TrafficViewMode::Events => "Traffic Event Detail",
        }
    }

    pub(crate) fn selected_detail_lines(&self) -> Option<Vec<String>> {
        match self.active_view().active {
            TrafficViewMode::Http => {
                let visible = self.visible_http_exchanges();
                let exchange = visible.get(self.http_view.selected_index())?;
                let fetch_sequences = exchange.detail_fetch_sequences();
                let loaded_rows = self.loaded_detail_rows(&fetch_sequences);
                let mut lines = exchange.detail_lines_with_loaded_rows(loaded_rows);
                self.append_detail_load_state(
                    &mut lines,
                    &fetch_sequences,
                    DetailLoadLabels::payload(),
                );
                return Some(lines);
            }
            TrafficViewMode::WebSocket => {
                let visible = self.visible_websocket_sessions();
                let session = visible.get(self.websocket_view.selected_index())?;
                let fetch_sequences = session.detail_fetch_sequences();
                let loaded_rows = self.loaded_detail_rows(&fetch_sequences);
                let mut lines = session.detail_lines_with_loaded_rows(loaded_rows);
                self.append_detail_load_state(
                    &mut lines,
                    &fetch_sequences,
                    DetailLoadLabels::payload(),
                );
                return Some(lines);
            }
            TrafficViewMode::Events => {}
        }
        let row = self.selected_row()?;
        let mut lines = row.detail_lines();
        match row.detail_fetch_sequence() {
            Some(row_sequence) if self.detail_state.loaded(row_sequence).is_some() => {
                return self
                    .detail_state
                    .loaded(row_sequence)
                    .map(TrafficRow::detail_lines);
            }
            Some(row_sequence) if self.detail_state.is_loading(row_sequence) => {
                lines.push("Full event detail: loading from admin event_detail".to_string());
            }
            Some(row_sequence) if self.detail_state.failure(row_sequence).is_some() => {
                lines.push("Full event detail fetch failed".to_string());
                let message = self
                    .detail_state
                    .failure(row_sequence)
                    .expect("failure was checked");
                lines.push(format!("Reason: {message}"));
            }
            _ => {}
        }
        Some(lines)
    }

    fn loaded_detail_rows<'a>(&'a self, sequences: &[u64]) -> Vec<&'a TrafficRow> {
        sequences
            .iter()
            .filter_map(|sequence| self.detail_state.loaded(*sequence))
            .collect()
    }

    fn loaded_detail_sequences(&self, sequences: &[u64]) -> Vec<u64> {
        sequences
            .iter()
            .copied()
            .filter(|sequence| self.detail_state.loaded(*sequence).is_some())
            .collect()
    }

    pub(crate) fn selected_detail_auto_fetch_sequence(&self) -> Option<u64> {
        self.selected_detail_fetch_sequence(DetailFetchMode::Auto)
    }

    pub(crate) fn selected_detail_manual_fetch_sequence(&self) -> Option<u64> {
        self.selected_detail_fetch_sequence(DetailFetchMode::Manual)
    }

    fn selected_detail_fetch_sequence(&self, mode: DetailFetchMode) -> Option<u64> {
        self.selected_detail_fetch_sequences()?
            .into_iter()
            .find(|sequence| match mode {
                DetailFetchMode::Auto => self.detail_state.should_auto_fetch(*sequence),
                DetailFetchMode::Manual => self.detail_state.should_manual_fetch(*sequence),
            })
    }

    fn selected_detail_fetch_sequences(&self) -> Option<Vec<u64>> {
        let sequences = match self.active_view().active {
            TrafficViewMode::Http => self
                .visible_http_exchanges()
                .get(self.http_view.selected_index())?
                .detail_fetch_sequences(),
            TrafficViewMode::WebSocket => self
                .visible_websocket_sessions()
                .get(self.websocket_view.selected_index())?
                .detail_fetch_sequences(),
            TrafficViewMode::Events => self
                .selected_row()?
                .detail_fetch_sequence()
                .into_iter()
                .collect(),
        };
        Some(sequences)
    }

    fn append_detail_load_state(
        &self,
        lines: &mut Vec<String>,
        sequences: &[u64],
        labels: DetailLoadLabels,
    ) {
        if sequences.is_empty() {
            return;
        }
        let mut pending = Vec::new();
        for row_sequence in sequences {
            if self.detail_state.loaded(*row_sequence).is_some() {
                continue;
            } else if self.detail_state.is_loading(*row_sequence) {
                lines.push(String::new());
                lines.push(format!(
                    "{} {row_sequence}: loading from admin event_detail",
                    labels.item
                ));
            } else if let Some(message) = self.detail_state.failure(*row_sequence) {
                lines.push(String::new());
                lines.push(format!("{} {row_sequence} fetch failed", labels.item));
                lines.push(format!("Reason: {message}"));
            } else {
                pending.push(row_sequence.to_string());
            }
        }
        if !pending.is_empty() {
            lines.push(String::new());
            lines.push(format!("{}: {}", labels.pending, pending.join(", ")));
        }
    }

    pub(crate) fn scroll(&self) -> usize {
        self.event_view.scroll()
    }

    #[cfg(test)]
    fn following_tail(&self) -> bool {
        self.follow_tail
    }

    pub(crate) fn tail_mode_label(&self) -> &'static str {
        if self.follow_tail { "Live" } else { "Paused" }
    }

    pub(crate) fn view_mode_label(&self) -> String {
        self.active_view().label()
    }

    pub(crate) fn set_viewport_rows(&mut self, rows: usize) {
        self.viewport_rows = rows.max(1);
        if self.follow_tail {
            self.sync_tail_viewports(self.viewport_rows);
        } else {
            self.clamp_viewports_to_visible_rows();
        }
    }

    pub(crate) fn status(&self) -> &TrafficStatus {
        &self.status
    }

    pub(crate) fn last_export_sequence(&self) -> u64 {
        self.last_export_sequence
    }

    pub(crate) fn event_filter_label(&self) -> &'static str {
        self.event_filter.label()
    }

    pub(crate) fn search_query(&self) -> &str {
        &self.search_query
    }

    pub(crate) fn search_label(&self) -> String {
        if self.search_query.is_empty() {
            return "<none>".to_string();
        }
        self.search_query.clone()
    }

    pub(crate) fn visible_match_count(&self) -> usize {
        self.projection_len(self.active_view().active)
    }

    pub(crate) fn active_unfiltered_count(&self) -> usize {
        self.unfiltered_projection_len(self.active_view().active)
    }

    #[cfg(test)]
    pub(crate) fn requested_view_mode_is(&self, mode: TrafficViewMode) -> bool {
        self.view_mode == mode
    }

    pub(crate) fn active_view_mode_is(&self, mode: TrafficViewMode) -> bool {
        self.active_view().active == mode
    }

    pub(crate) fn event_filter_is(&self, filter: TrafficEventFilter) -> bool {
        self.event_filter == filter
    }

    pub(crate) fn diagnostic_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(diagnostics) = &self.empty_filter_diagnostics {
            lines.extend(diagnostics.lines());
            lines.push(String::new());
        }
        lines.extend([
            "Select a traffic row to inspect details".to_string(),
            "Open Data Path diagnostics for capture and MITM readiness".to_string(),
            mitm_data_path_coverage_line(),
        ]);
        lines.extend(mitm_visibility_lines());
        lines.push(format!(
            "configuration: {}",
            missing_mitm_configuration_action()
        ));
        lines
    }

    pub(crate) fn detail_preview_lines(&self, max_lines: usize) -> Vec<String> {
        match self.active_view().active {
            TrafficViewMode::Http => {
                return self
                    .visible_http_exchanges()
                    .get(self.http_view.selected_index)
                    .map(|exchange| {
                        let fetch_sequences = exchange.detail_fetch_sequences();
                        let loaded_sequences = self.loaded_detail_sequences(&fetch_sequences);
                        exchange.preview_lines_with_loaded_sequences(
                            &loaded_sequences,
                            max_lines.max(1),
                        )
                    })
                    .unwrap_or_else(|| self.diagnostic_lines());
            }
            TrafficViewMode::WebSocket => {
                return self
                    .visible_websocket_sessions()
                    .get(self.websocket_view.selected_index)
                    .map(|session| {
                        let fetch_sequences = session.detail_fetch_sequences();
                        let loaded_sequences = self.loaded_detail_sequences(&fetch_sequences);
                        session.preview_lines_with_loaded_sequences(
                            &loaded_sequences,
                            max_lines.max(1),
                        )
                    })
                    .unwrap_or_else(|| self.diagnostic_lines());
            }
            TrafficViewMode::Events => {}
        }
        self.selected_row()
            .map(|row| row.preview_lines(max_lines.max(1)))
            .unwrap_or_else(|| self.diagnostic_lines())
    }

    pub(crate) fn begin_refresh(
        &mut self,
        socket_path: PathBuf,
        selector: Option<Selector>,
        unknown_process_candidate_selector: Option<UnknownProcessCandidateSelector>,
    ) -> TrafficRefreshRequest {
        let selector_key = traffic_refresh_selector_key(
            selector.as_ref(),
            unknown_process_candidate_selector.as_ref(),
        );
        if Some(selector_key.clone()) != self.selector_key {
            self.reset_for_selector(selector_key);
        }
        TrafficRefreshRequest {
            socket_path,
            selector,
            unknown_process_candidate_selector,
            selector_key: self
                .selector_key
                .clone()
                .expect("selector key is set before building refresh request"),
            after_sequence: self.after_sequence,
            latest_window: self.latest_window,
            event_filter: self.event_filter,
        }
    }

    pub(crate) fn apply_refresh_result(&mut self, result: TrafficRefreshResult) -> bool {
        if self.selector_key.as_deref() != Some(result.selector_key.as_str())
            || self.event_filter != result.event_filter
        {
            return false;
        }
        match result.result {
            Ok(snapshot) => {
                self.apply_snapshot(snapshot.tail);
                self.apply_empty_filter_diagnostics(snapshot.empty_filter_diagnostics);
            }
            Err(error) => {
                self.status = TrafficStatus::error(error);
            }
        }
        true
    }

    pub(crate) fn mark_detail_loading(&mut self, sequence: u64, request_id: u64) {
        self.detail_state.mark_loading(sequence, request_id);
        self.status = TrafficStatus::active(format!("Loading full event detail {sequence}"));
    }

    pub(crate) fn mark_detail_failed(&mut self, sequence: u64, message: impl Into<String>) {
        self.mark_detail_error(sequence, message.into());
    }

    pub(crate) fn is_detail_loading_request(&self, sequence: u64, request_id: u64) -> bool {
        self.detail_state.is_loading_request(sequence, request_id)
    }

    pub(crate) fn apply_detail_load_result(&mut self, result: TrafficDetailLoadResult) -> bool {
        if !self
            .detail_state
            .is_loading_request(result.sequence, result.request_id)
        {
            return false;
        }
        self.detail_state.complete_loading(result.sequence);
        match result.result {
            Ok(detail) => self.apply_detail(detail),
            Err(message) => self.mark_detail_error(result.sequence, message),
        }
        true
    }

    pub(crate) fn clear_detail_state(&mut self) {
        self.detail_state.clear();
    }

    pub(crate) fn mark_admin_unavailable(&mut self, message: impl Into<String>) {
        self.clear_detail_state();
        self.status = TrafficStatus::error(message);
    }

    pub(crate) fn mark_refresh_paused(&mut self, message: impl Into<String>) {
        self.status = TrafficStatus::warning(message);
    }

    pub(crate) fn mark_refresh_waiting(&mut self, message: impl Into<String>) {
        self.status = TrafficStatus::idle(message);
    }

    pub(crate) fn cycle_event_filter(&mut self) {
        self.set_event_filter(self.event_filter.next());
    }

    pub(crate) fn set_event_filter(&mut self, event_filter: TrafficEventFilter) {
        if self.event_filter == event_filter {
            self.status = TrafficStatus::idle(format!(
                "Traffic event filter is already {}; showing {} view",
                self.event_filter.label(),
                self.view_mode.label()
            ));
            return;
        }
        self.event_filter = event_filter;
        self.view_mode = preferred_view_for_event_filter(self.event_filter);
        self.reset_tail();
        self.status = TrafficStatus::idle(format!(
            "Traffic event filter changed to {}; showing {} view",
            self.event_filter.label(),
            self.view_mode.label()
        ));
    }

    pub(crate) fn set_search_query(&mut self, query: String) {
        self.search_query = terminal_safe_inline_text(query.trim());
        self.rebuild_visible_projection();
        self.reset_viewports();
        if self.follow_tail {
            self.sync_tail_viewports(self.viewport_rows);
        } else {
            self.clamp_selection();
        }
        if self.search_query.is_empty() {
            self.status = TrafficStatus::idle("Traffic search cleared");
        } else {
            self.status = TrafficStatus::idle(format!(
                "Traffic search matched {}/{} {} row(s)",
                self.visible_match_count(),
                self.active_unfiltered_count(),
                self.active_view().label()
            ));
        }
    }

    pub(crate) fn clear_search_query(&mut self) -> bool {
        if self.search_query.is_empty() {
            return false;
        }
        self.search_query.clear();
        self.rebuild_visible_projection();
        self.reset_viewports();
        if self.follow_tail {
            self.sync_tail_viewports(self.viewport_rows);
        } else {
            self.clamp_selection();
        }
        self.status = TrafficStatus::idle("Traffic search cleared");
        true
    }

    pub(crate) fn cycle_view_mode(&mut self) {
        self.set_view_mode(self.view_mode.next());
    }

    pub(crate) fn set_view_mode(&mut self, view_mode: TrafficViewMode) {
        if self.view_mode == view_mode {
            self.status = TrafficStatus::idle(format!(
                "Traffic view is already {}",
                self.view_mode_label()
            ));
            return;
        }
        self.view_mode = view_mode;
        if self.follow_tail {
            self.sync_tail_viewports(self.viewport_rows);
        } else {
            self.clamp_selection();
        }
        self.status = TrafficStatus::idle(format!(
            "Traffic view changed to {}",
            self.view_mode_label()
        ));
    }

    pub(crate) fn apply_runtime_diagnostic_message(
        &mut self,
        message: Option<CaptureDiagnosticMessage>,
    ) {
        if self.status.kind != TrafficStatusKind::Error
            && let Some(message) = message
        {
            self.status = match message {
                CaptureDiagnosticMessage::Info(message) => TrafficStatus::idle(message),
                CaptureDiagnosticMessage::Warning(message) => TrafficStatus::warning(message),
                CaptureDiagnosticMessage::Error(message) => TrafficStatus::error(message),
            };
        }
    }

    pub(crate) fn move_selection(&mut self, delta: isize, visible_rows: usize) {
        let projection = self.active_projection();
        let follow_tail =
            self.viewport_mut(projection.mode)
                .move_selection(projection.len, delta, visible_rows);
        if let Some(follow_tail) = follow_tail {
            self.set_follow_tail(follow_tail, visible_rows);
        }
    }

    pub(crate) fn select_row(&mut self, index: usize, visible_rows: usize) {
        let projection = self.active_projection();
        let follow_tail =
            self.viewport_mut(projection.mode)
                .select_row(projection.len, index, visible_rows);
        if let Some(follow_tail) = follow_tail {
            self.set_follow_tail(follow_tail, visible_rows);
        }
    }

    pub(crate) fn scroll_viewport(&mut self, delta: isize, visible_rows: usize) {
        let projection = self.active_projection();
        let follow_tail =
            self.viewport_mut(projection.mode)
                .scroll_viewport(projection.len, delta, visible_rows);
        if let Some(follow_tail) = follow_tail {
            self.set_follow_tail(follow_tail, visible_rows);
        }
    }

    pub(crate) fn drag_scrollbar(&mut self, offset: usize, height: usize, visible_rows: usize) {
        let projection = self.active_projection();
        let follow_tail = self.viewport_mut(projection.mode).drag_scrollbar(
            projection.len,
            offset,
            height,
            visible_rows,
        );
        if let Some(follow_tail) = follow_tail {
            self.set_follow_tail(follow_tail, visible_rows);
        }
    }

    pub(crate) fn jump_to_tail(&mut self, visible_rows: usize) {
        if self.active_row_count() == 0 {
            self.reset_viewports();
            self.follow_tail = true;
            self.status = TrafficStatus::idle("Following latest matching traffic events");
            return;
        }
        self.sync_tail_viewports(visible_rows);
        self.status = TrafficStatus::active("Following latest matching traffic events");
    }

    fn reset_for_selector(&mut self, selector_key: String) {
        self.reset_tail();
        self.selector_key = Some(selector_key);
        self.status = TrafficStatus::idle("Traffic filter changed");
    }

    fn reset_tail(&mut self) {
        self.after_sequence = 0;
        self.latest_window = true;
        self.rows.clear();
        self.http_exchanges.clear();
        self.websocket_sessions.clear();
        self.visible_projection.clear();
        self.event_view.reset();
        self.http_view.reset();
        self.websocket_view.reset();
        self.follow_tail = true;
        self.detail_state.clear();
        self.attribution_mode = EventTailAttributionMode::Strict;
        self.empty_filter_diagnostics = None;
    }

    fn apply_snapshot(&mut self, snapshot: EventTailSnapshot) {
        self.empty_filter_diagnostics = None;
        self.after_sequence = snapshot.next_after_sequence;
        self.latest_window = false;
        self.last_export_sequence = snapshot.last_export_sequence;
        self.attribution_mode = snapshot.attribution_mode;
        let received = snapshot.events.len();
        let has_new_rows = !snapshot.events.is_empty() || !snapshot.omissions.is_empty();
        let selected_event_sequence = (!self.follow_tail)
            .then(|| {
                self.visible_rows()
                    .get(self.event_view.selected_index())
                    .map(|row| row.sequence)
            })
            .flatten();
        let event_anchor_sequence = (!self.follow_tail)
            .then(|| {
                self.visible_rows()
                    .get(self.event_view.scroll())
                    .map(|row| row.sequence)
            })
            .flatten();
        let selected_http = (!self.follow_tail)
            .then(|| self.http_selection_at(self.http_view.selected_index()))
            .flatten();
        let http_anchor = (!self.follow_tail)
            .then(|| self.http_selection_at(self.http_view.scroll()))
            .flatten();
        let selected_websocket = (!self.follow_tail)
            .then(|| self.websocket_selection_at(self.websocket_view.selected_index()))
            .flatten();
        let websocket_anchor = (!self.follow_tail)
            .then(|| self.websocket_selection_at(self.websocket_view.scroll()))
            .flatten();
        let status = traffic_status_for_snapshot(
            received,
            &snapshot.omissions,
            snapshot.scanned,
            self.attribution_mode,
        );
        self.rows.extend(traffic_rows_for_snapshot(snapshot));
        self.rows.sort_by_key(|row| row.sequence);
        self.rows.dedup_by_key(|row| row.sequence);
        self.rebuild_protocol_views();
        if self.rows.len() > MAX_TRAFFIC_EVENT_ROWS {
            let overflow = self.rows.len() - MAX_TRAFFIC_EVENT_ROWS;
            self.rows.drain(0..overflow);
            self.rebuild_protocol_views();
        }
        if self.follow_tail && has_new_rows {
            self.sync_tail_viewports(self.viewport_rows);
        } else if !self.follow_tail {
            self.restore_viewport_anchors(event_anchor_sequence, http_anchor, websocket_anchor);
            self.restore_event_selection(selected_event_sequence);
            self.restore_protocol_selections(selected_http, selected_websocket);
        } else {
            self.clamp_selection();
        }
        self.status = status;
    }

    fn apply_empty_filter_diagnostics(&mut self, diagnostics: Option<EmptyFilterDiagnostics>) {
        let Some(diagnostics) = diagnostics else {
            return;
        };
        self.status = TrafficStatus::warning(diagnostics.status_line());
        self.empty_filter_diagnostics = Some(diagnostics);
    }

    fn apply_detail(&mut self, detail: EventDetailSnapshot) {
        let row = TrafficRow::from_detail(detail);
        self.status = TrafficStatus::active(format!("Loaded full event detail {}", row.sequence));
        self.detail_state.insert_loaded(row);
    }

    fn mark_detail_error(&mut self, sequence: u64, message: String) {
        self.detail_state
            .insert_failure(sequence, terminal_safe_inline_text(message));
        self.status =
            TrafficStatus::warning(format!("Failed to load full event detail {sequence}"));
    }

    fn clamp_selection(&mut self) {
        for mode in TrafficViewMode::all() {
            let len = self.projection_len(mode);
            self.viewport_mut(mode).clamp_to_len(len);
        }
    }

    fn set_follow_tail(&mut self, follow_tail: bool, visible_rows: usize) {
        self.follow_tail = follow_tail;
        if follow_tail {
            self.sync_tail_viewports(visible_rows);
        }
    }

    fn sync_tail_viewports(&mut self, visible_rows: usize) {
        for mode in TrafficViewMode::all() {
            let len = self.projection_len(mode);
            self.viewport_mut(mode).select_tail(len, visible_rows);
        }
        self.follow_tail = true;
    }

    fn clamp_viewports_to_visible_rows(&mut self) {
        for mode in TrafficViewMode::all() {
            let len = self.projection_len(mode);
            let visible_rows = self.viewport_rows;
            self.viewport_mut(mode)
                .clamp_selection_to_viewport(len, visible_rows);
        }
    }

    fn reset_viewports(&mut self) {
        for mode in TrafficViewMode::all() {
            self.viewport_mut(mode).reset();
        }
    }

    fn rebuild_protocol_views(&mut self) {
        self.http_exchanges = build_http_exchange_rows(&self.rows);
        self.websocket_sessions = build_websocket_session_rows(&self.rows);
        self.rebuild_visible_projection();
        self.clamp_selection();
    }

    fn rebuild_visible_projection(&mut self) {
        self.visible_projection = TrafficVisibleProjection::from_parts(
            &self.rows,
            &self.http_exchanges,
            &self.websocket_sessions,
            &self.search_query,
        );
    }

    fn http_selection_at(&self, index: usize) -> Option<HttpSelection> {
        self.visible_http_exchanges()
            .get(index)
            .map(|row| HttpSelection {
                identity: row.identity(),
                order_sequence: row.order_sequence(),
            })
    }

    fn websocket_selection_at(&self, index: usize) -> Option<WebSocketSelection> {
        self.visible_websocket_sessions()
            .get(index)
            .map(|row| WebSocketSelection {
                identity: row.identity(),
                order_sequence: row.order_sequence(),
            })
    }

    fn restore_viewport_anchors(
        &mut self,
        event_sequence: Option<u64>,
        http_selection: Option<HttpSelection>,
        websocket_selection: Option<WebSocketSelection>,
    ) {
        if let Some(index) = event_sequence.and_then(|sequence| {
            let visible = self.visible_rows();
            visible.nearest_index_by_key(sequence, |row| row.sequence)
        }) {
            let len = self.projection_len(TrafficViewMode::Events);
            self.event_view
                .anchor_scroll(len, index, self.viewport_rows);
        }

        if let Some(index) =
            http_selection.and_then(|selection| self.http_index_for_selection(&selection))
        {
            let len = self.projection_len(TrafficViewMode::Http);
            self.http_view.anchor_scroll(len, index, self.viewport_rows);
        }

        if let Some(index) =
            websocket_selection.and_then(|selection| self.websocket_index_for_selection(&selection))
        {
            let len = self.projection_len(TrafficViewMode::WebSocket);
            self.websocket_view
                .anchor_scroll(len, index, self.viewport_rows);
        }
    }

    fn restore_protocol_selections(
        &mut self,
        http_selection: Option<HttpSelection>,
        websocket_selection: Option<WebSocketSelection>,
    ) {
        let http_index =
            http_selection.and_then(|selection| self.http_index_for_selection(&selection));
        if let Some(index) = http_index {
            let len = self.projection_len(TrafficViewMode::Http);
            self.http_view.select_row(len, index, self.viewport_rows);
        }

        let websocket_index = websocket_selection
            .and_then(|selection| self.websocket_index_for_selection(&selection));
        if let Some(index) = websocket_index {
            let len = self.projection_len(TrafficViewMode::WebSocket);
            self.websocket_view
                .select_row(len, index, self.viewport_rows);
        }
    }

    fn http_index_for_selection(&self, selection: &HttpSelection) -> Option<usize> {
        let visible = self.visible_http_exchanges();
        visible
            .position(|row| row.matches_identity(&selection.identity))
            .or_else(|| visible.position(|row| row.matches_selection_fallback(&selection.identity)))
            .or_else(|| {
                visible.nearest_index_by_key(selection.order_sequence, |row| row.order_sequence())
            })
    }

    fn websocket_index_for_selection(&self, selection: &WebSocketSelection) -> Option<usize> {
        let visible = self.visible_websocket_sessions();
        visible
            .position(|row| row.matches_identity(&selection.identity))
            .or_else(|| {
                visible.nearest_index_by_key(selection.order_sequence, |row| row.order_sequence())
            })
    }

    fn restore_event_selection(&mut self, event_sequence: Option<u64>) {
        let Some(index) = event_sequence.and_then(|sequence| {
            let visible = self.visible_rows();
            visible.nearest_index_by_key(sequence, |row| row.sequence)
        }) else {
            return;
        };
        let len = self.projection_len(TrafficViewMode::Events);
        self.event_view.select_row(len, index, self.viewport_rows);
    }

    fn active_view(&self) -> TrafficActiveView {
        TrafficActiveView::from_state(
            self.view_mode,
            self.unfiltered_projection_len(TrafficViewMode::Http) > 0,
            self.unfiltered_projection_len(TrafficViewMode::WebSocket) > 0,
            self.unfiltered_projection_len(TrafficViewMode::Events) > 0,
        )
    }

    fn active_projection(&self) -> TrafficProjection {
        let mode = self.active_view().active;
        TrafficProjection {
            mode,
            len: self.projection_len(mode),
        }
    }

    fn projection_len(&self, mode: TrafficViewMode) -> usize {
        self.visible_projection.len(mode)
    }

    fn unfiltered_projection_len(&self, mode: TrafficViewMode) -> usize {
        match mode {
            TrafficViewMode::Http => self.http_exchanges.len(),
            TrafficViewMode::WebSocket => self.websocket_sessions.len(),
            TrafficViewMode::Events => self.rows.len(),
        }
    }

    fn viewport_mut(&mut self, mode: TrafficViewMode) -> &mut TrafficViewport {
        match mode {
            TrafficViewMode::Http => &mut self.http_view,
            TrafficViewMode::WebSocket => &mut self.websocket_view,
            TrafficViewMode::Events => &mut self.event_view,
        }
    }
}

fn all_indexes(len: usize) -> Vec<usize> {
    (0..len).collect()
}

fn matching_indexes<T>(items: &[T], matches: impl Fn(&T) -> bool) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| matches(item).then_some(index))
        .collect()
}

fn row_matches_search(query: &str, row: &TrafficRow) -> bool {
    searchable_text_matches(
        query,
        [
            row.sequence.to_string(),
            row.process.clone(),
            row.capture_path.to_string(),
            row.event_type.clone(),
            row.direction.clone(),
            row.endpoint.clone(),
            row.summary.clone(),
        ],
    )
}

fn http_exchange_matches_search(query: &str, exchange: &HttpExchangeRow) -> bool {
    searchable_text_matches(
        query,
        [
            exchange.sequence.to_string(),
            exchange.process.clone(),
            exchange.method.clone(),
            exchange.target.clone(),
            exchange.status.clone(),
            exchange.request_body.clone(),
            exchange.response_body.clone(),
            exchange.direction.clone(),
            exchange.endpoint.clone(),
            exchange.summary.clone(),
        ],
    )
}

fn websocket_session_matches_search(query: &str, session: &WebSocketSessionRow) -> bool {
    searchable_text_matches(
        query,
        [
            session.sequence.to_string(),
            session.process.clone(),
            session.target.clone(),
            session.direction.clone(),
            session.endpoint.clone(),
            session.frames.to_string(),
            session.messages.to_string(),
            session.payload_bytes.to_string(),
            session.summary.clone(),
        ],
    )
}

fn searchable_text_matches<const N: usize>(query: &str, fields: [String; N]) -> bool {
    fields
        .into_iter()
        .any(|field| field.to_lowercase().contains(query))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrafficViewMode {
    Http,
    WebSocket,
    Events,
}

impl TrafficViewMode {
    const fn all() -> [Self; 3] {
        [Self::Http, Self::WebSocket, Self::Events]
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::WebSocket => "WebSocket",
            Self::Events => "Events",
        }
    }

    pub(crate) fn short_label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::WebSocket => "WS",
            Self::Events => "Events",
        }
    }

    pub(crate) fn control_label(self) -> &'static str {
        match self {
            Self::Http => "Show HTTP exchanges",
            Self::WebSocket => "Show WebSocket sessions",
            Self::Events => "Show raw traffic events",
        }
    }

    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::Http => "HTTP exchanges",
            Self::WebSocket => "WebSocket sessions",
            Self::Events => "raw traffic events",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Http => Self::WebSocket,
            Self::WebSocket => Self::Events,
            Self::Events => Self::Http,
        }
    }
}

fn preferred_view_for_event_filter(event_filter: TrafficEventFilter) -> TrafficViewMode {
    match event_filter {
        TrafficEventFilter::Application | TrafficEventFilter::Http => TrafficViewMode::Http,
        TrafficEventFilter::WebSocket => TrafficViewMode::WebSocket,
        TrafficEventFilter::Security
        | TrafficEventFilter::Diagnostics
        | TrafficEventFilter::All => TrafficViewMode::Events,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrafficActiveView {
    requested: TrafficViewMode,
    active: TrafficViewMode,
    fallback: Option<TrafficViewFallback>,
}

impl TrafficActiveView {
    fn from_state(
        requested: TrafficViewMode,
        has_http_exchanges: bool,
        has_websocket_sessions: bool,
        has_events: bool,
    ) -> Self {
        match (
            requested,
            has_http_exchanges,
            has_websocket_sessions,
            has_events,
        ) {
            (TrafficViewMode::Http, false, true, _) => Self {
                requested,
                active: TrafficViewMode::WebSocket,
                fallback: Some(TrafficViewFallback::NoHttpExchanges),
            },
            (TrafficViewMode::Http, false, false, true) => Self {
                requested,
                active: TrafficViewMode::Events,
                fallback: Some(TrafficViewFallback::NoHttpExchanges),
            },
            (TrafficViewMode::WebSocket, _, false, true) => Self {
                requested,
                active: TrafficViewMode::Events,
                fallback: Some(TrafficViewFallback::NoWebSocketSessions),
            },
            _ => Self {
                requested,
                active: requested,
                fallback: None,
            },
        }
    }

    fn label(self) -> String {
        match self.fallback {
            Some(TrafficViewFallback::NoHttpExchanges) => {
                format!("{} (no HTTP)", self.active.label())
            }
            Some(TrafficViewFallback::NoWebSocketSessions) => {
                format!("{} (no WebSocket)", self.active.label())
            }
            None => self.requested.label().to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrafficViewFallback {
    NoHttpExchanges,
    NoWebSocketSessions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmptyFilterDiagnostics {
    filter_label: &'static str,
    scanned: usize,
    event_count: usize,
    type_counts: Vec<(String, usize)>,
}

impl EmptyFilterDiagnostics {
    fn from_snapshot(filter_label: &'static str, snapshot: EventTailSnapshot) -> Option<Self> {
        if snapshot.events.is_empty() {
            return None;
        }
        let mut type_counts = BTreeMap::<String, usize>::new();
        for record in &snapshot.events {
            let event_type = record.event.kind.event_type().as_str().to_string();
            *type_counts.entry(event_type).or_default() += 1;
        }
        Some(Self {
            filter_label,
            scanned: snapshot.scanned,
            event_count: snapshot.events.len(),
            type_counts: type_counts.into_iter().collect(),
        })
    }

    fn status_line(&self) -> String {
        format!(
            "{} view is empty; saw {} matching event(s) outside this filter: {}",
            self.filter_label,
            self.event_count,
            self.type_summary()
        )
    }

    fn lines(&self) -> Vec<String> {
        vec![
            "Current traffic view is filtered".to_string(),
            format!("View: {}", self.filter_label),
            format!("Scanned records: {}", self.scanned),
            format!("Matching events outside this view: {}", self.event_count),
            format!("Event types: {}", self.type_summary()),
            "Use Events to switch to All or Diagnostics when parsed protocol rows are empty"
                .to_string(),
        ]
    }

    fn type_summary(&self) -> String {
        self.type_counts
            .iter()
            .map(|(event_type, count)| format!("{event_type}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn should_probe_empty_filter(
    event_filter: TrafficEventFilter,
    snapshot: &EventTailSnapshot,
) -> bool {
    event_filter.is_filtered() && snapshot.events.is_empty() && snapshot.omissions.is_empty()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailFetchMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DetailLoadLabels {
    item: &'static str,
    pending: &'static str,
}

impl DetailLoadLabels {
    fn payload() -> Self {
        Self {
            item: "Payload detail",
            pending: "Payload details pending",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrafficDetailState {
    loading: BTreeMap<u64, u64>,
    loaded: BTreeMap<u64, TrafficRow>,
    failures: BTreeMap<u64, String>,
}

impl TrafficDetailState {
    fn mark_loading(&mut self, sequence: u64, request_id: u64) {
        self.failures.remove(&sequence);
        self.loading.insert(sequence, request_id);
    }

    fn is_loading_request(&self, sequence: u64, request_id: u64) -> bool {
        self.loading
            .get(&sequence)
            .is_some_and(|loading_request_id| *loading_request_id == request_id)
    }

    fn is_loading(&self, sequence: u64) -> bool {
        self.loading.contains_key(&sequence)
    }

    fn complete_loading(&mut self, sequence: u64) {
        self.loading.remove(&sequence);
    }

    fn insert_loaded(&mut self, row: TrafficRow) {
        self.failures.remove(&row.sequence);
        self.loaded.insert(row.sequence, row);
    }

    fn insert_failure(&mut self, sequence: u64, message: String) {
        self.failures.insert(sequence, message);
    }

    fn loaded(&self, sequence: u64) -> Option<&TrafficRow> {
        self.loaded.get(&sequence)
    }

    fn failure(&self, sequence: u64) -> Option<&String> {
        self.failures.get(&sequence)
    }

    fn should_auto_fetch(&self, sequence: u64) -> bool {
        !self.loaded.contains_key(&sequence)
            && !self.is_loading(sequence)
            && !self.failures.contains_key(&sequence)
    }

    fn should_manual_fetch(&self, sequence: u64) -> bool {
        !self.loaded.contains_key(&sequence) && !self.is_loading(sequence)
    }

    fn clear(&mut self) {
        self.loading.clear();
        self.loaded.clear();
        self.failures.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrafficStatusKind {
    Idle,
    Active,
    Warning,
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
            text: terminal_safe_inline_text(text),
        }
    }

    fn active(text: impl Into<String>) -> Self {
        Self {
            kind: TrafficStatusKind::Active,
            text: terminal_safe_inline_text(text),
        }
    }

    fn warning(text: impl Into<String>) -> Self {
        Self {
            kind: TrafficStatusKind::Warning,
            text: terminal_safe_inline_text(text),
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Self {
            kind: TrafficStatusKind::Error,
            text: terminal_safe_inline_text(text),
        }
    }
}

fn traffic_status_for_snapshot(
    received: usize,
    omissions: &[EventTailOmission],
    scanned: usize,
    attribution_mode: EventTailAttributionMode,
) -> TrafficStatus {
    let attribution_note = tail_attribution_status_note(attribution_mode);
    if let Some(reason) = omission_summary(omissions) {
        TrafficStatus::error(format!(
            "Received {received} events{attribution_note}; {reason}"
        ))
    } else if received == 0 {
        TrafficStatus::idle(format!(
            "No new matching events{attribution_note}; scanned {scanned} records"
        ))
    } else {
        TrafficStatus::active(format!(
            "Received {received} matching events{attribution_note}"
        ))
    }
}

fn tail_attribution_status_note(mode: EventTailAttributionMode) -> &'static str {
    match mode {
        EventTailAttributionMode::Strict => "",
        EventTailAttributionMode::IncludeUnknownProcess => {
            " including libpcap unknown-process candidates"
        }
    }
}

fn traffic_rows_for_snapshot(snapshot: EventTailSnapshot) -> Vec<TrafficRow> {
    let EventTailSnapshot {
        scanned,
        budget,
        events,
        omissions,
        ..
    } = snapshot;
    let mut rows = events
        .into_iter()
        .map(TrafficRow::from_record)
        .chain(
            omissions
                .into_iter()
                .map(|omission| TrafficRow::from_omission(omission, scanned, budget.clone())),
        )
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row.sequence);
    rows
}

fn omission_summary(omissions: &[EventTailOmission]) -> Option<String> {
    let first = omissions.first()?;
    let suffix = match omissions.len() {
        1 => String::new(),
        extra => format!(" and {} more", extra - 1),
    };
    Some(format!(
        "omitted {}: {}{}",
        event_count_label(omissions.len()),
        first.reason.label(),
        suffix
    ))
}

fn event_count_label(count: usize) -> String {
    match count {
        1 => "1 event".to_string(),
        count => format!("{count} events"),
    }
}

fn scroll_position(current: usize, delta: isize, max_scroll: usize) -> usize {
    if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs())
    } else {
        current.saturating_add(delta as usize).min(max_scroll)
    }
}

pub(crate) fn traffic_selector_key(selector: &Selector) -> String {
    serde_json::to_string(selector).unwrap_or_else(|_| format!("{selector:?}"))
}

pub(crate) fn traffic_refresh_selector_key(
    selector: Option<&Selector>,
    unknown_process_candidate_selector: Option<&UnknownProcessCandidateSelector>,
) -> String {
    let selector = selector
        .map(traffic_selector_key)
        .unwrap_or_else(|| "-".to_string());
    let candidate = unknown_process_candidate_selector
        .and_then(|selector| serde_json::to_string(selector).ok())
        .unwrap_or_else(|| "-".to_string());
    format!("selector={selector};candidate={candidate}")
}

fn traffic_refresh_error_message(error: &TrafficClientError) -> String {
    match error {
        TrafficClientError::AdminClient(AdminClientError::Connect { path, source })
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            format!(
                "No running agent is listening on admin socket {}; restart the TUI agent or check the configured socket",
                path.display()
            )
        }
        TrafficClientError::TailResponseTooLarge {
            event_limit,
            response_limit_bytes,
        } => format!(
            "tail_events refresh exceeded {response_limit_bytes} bytes after reducing the list batch to {event_limit}"
        ),
        _ => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::ops::RangeInclusive;

    use probe_config::{CaptureBackend, CaptureSelection};
    use probe_core::{
        AddressPort, BodyChunk, CaptureOrigin, CaptureSource, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, Gap, ProcessContext, ProcessIdentity, RuntimeMode,
        SpoolPayloadSchema, Timestamp, TransportProtocol, WebSocketHandoff, WebSocketMessage,
        WebSocketMessageOpcode,
    };
    use runtime::{CaptureEvidenceMode, CaptureInputSource, CapturePlanMode};

    use super::*;
    use crate::{
        admin::{
            EventDetailSnapshot, EventTailBudgetSnapshot, EventTailEvent, EventTailOmissionReason,
            EventTailRecord, EventTailSnapshot,
        },
        status::{
            CaptureCandidateStatusSnapshot, CaptureOpenFailureStatusSnapshot,
            CaptureStatusSnapshot, EbpfExpectedContractStatusSnapshot,
        },
        tui::{runtime_status::TrafficRuntimeDiagnostics, text::INLINE_TEXT_MAX_CHARS},
    };

    #[test]
    fn traffic_status_text_is_terminal_safe() {
        let raw = format!(
            "tail_events failed\nstderr: \x1b[32m{}",
            "x".repeat(INLINE_TEXT_MAX_CHARS * 2)
        );

        let status = TrafficStatus::error(raw);

        assert_eq!(status.kind, TrafficStatusKind::Error);
        assert!(!status.text.chars().any(char::is_control));
        assert!(status.text.chars().count() <= INLINE_TEXT_MAX_CHARS);
        assert!(status.text.contains("tail_events failed stderr:"));
        assert!(status.text.ends_with("..."));
    }

    #[test]
    fn traffic_detail_error_text_is_terminal_safe() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());
        traffic.mark_detail_loading(2, 11);
        traffic.apply_detail_load_result(TrafficDetailLoadResult::failed(
            2,
            11,
            format!(
                "admin error\nstderr: \x1b[31m{}",
                "x".repeat(INLINE_TEXT_MAX_CHARS * 2)
            ),
        ));

        let lines = traffic
            .selected_detail_lines()
            .expect("selected detail should remain visible")
            .into_iter()
            .filter(|line| line.starts_with("Reason: "))
            .collect::<Vec<_>>();
        let detail_error = lines
            .iter()
            .find(|line| line.contains("admin error"))
            .expect("detail error reason should be visible");

        assert!(!detail_error.chars().any(char::is_control));
        assert!(detail_error.chars().count() <= INLINE_TEXT_MAX_CHARS + "Reason: ".len());
    }

    #[test]
    fn traffic_detail_state_tracks_multiple_loading_requests_independently() {
        let mut traffic = TrafficState::default();
        traffic.mark_detail_loading(2, 11);
        traffic.mark_detail_loading(3, 12);

        assert!(
            !traffic.apply_detail_load_result(TrafficDetailLoadResult::failed(
                2,
                99,
                "stale request",
            ))
        );
        assert!(traffic.detail_state.is_loading(2));
        assert!(traffic.detail_state.is_loading(3));

        assert!(
            traffic.apply_detail_load_result(TrafficDetailLoadResult::failed(
                2,
                11,
                "detail failed",
            ))
        );
        assert!(!traffic.detail_state.is_loading(2));
        assert!(traffic.detail_state.is_loading(3));

        assert!(
            traffic.apply_detail_load_result(TrafficDetailLoadResult {
                sequence: 3,
                request_id: 12,
                result: Ok(EventDetailSnapshot {
                    sequence: 3,
                    stored_at_unix_ns: 3,
                    payload_schema: SpoolPayloadSchema::EventEnvelopeSubjectOriginJson
                        .as_str()
                        .to_string(),
                    payload_bytes: 128,
                    event: body_event(b"ok"),
                }),
            })
        );
        assert!(!traffic.detail_state.is_loading(3));
        assert!(traffic.detail_state.loaded(3).is_some());
    }

    #[test]
    fn filter_reset_scans_existing_matching_events() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());

        traffic.reset_for_selector("exe:/app/backend".to_string());

        assert_eq!(traffic.after_sequence, 0);
        assert_eq!(traffic.last_export_sequence(), 2);
        assert!(traffic.rows().is_empty());
        assert_eq!(traffic.active_row_count(), 0);
        assert_eq!(traffic.visible_http_exchanges().len(), 0);
        assert_eq!(traffic.status().kind, TrafficStatusKind::Idle);
        assert_eq!(traffic.status().text, "Traffic filter changed");
    }

    #[test]
    fn empty_filtered_view_explains_matching_events_outside_filter() {
        let mut traffic = TrafficState::default();
        let empty_filtered = empty_tail_snapshot(3);
        let diagnostics =
            EmptyFilterDiagnostics::from_snapshot("Parsed", tail_snapshot_with_gap_events(1..=3));

        assert!(should_probe_empty_filter(
            TrafficEventFilter::Application,
            &empty_filtered
        ));
        traffic.apply_snapshot(empty_filtered);
        traffic.apply_empty_filter_diagnostics(diagnostics);

        assert!(traffic.rows().is_empty());
        assert_eq!(traffic.status().kind, TrafficStatusKind::Warning);
        assert_eq!(
            traffic.status().text,
            "Parsed view is empty; saw 3 matching event(s) outside this filter: gap=3"
        );
        let lines = traffic.detail_preview_lines(12);
        assert!(lines.iter().any(|line| line == "View: Parsed"));
        assert!(lines.iter().any(|line| line == "Event types: gap=3"));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("switch to All or Diagnostics"))
        );
    }

    #[test]
    fn event_filter_defaults_to_parsed_application_events_and_cycles_with_tail_reset() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());

        assert_eq!(traffic.event_filter_label(), "Parsed");
        assert!(!traffic.rows().is_empty());

        traffic.cycle_event_filter();

        assert_eq!(traffic.event_filter_label(), "HTTP");
        assert_eq!(traffic.view_mode_label(), "HTTP");
        assert!(traffic.rows().is_empty());
        assert_eq!(traffic.active_row_count(), 0);
        assert_eq!(traffic.visible_http_exchanges().len(), 0);
        assert_eq!(traffic.after_sequence, 0);
        assert_eq!(
            traffic.status().text,
            "Traffic event filter changed to HTTP; showing HTTP view"
        );
    }

    #[test]
    fn event_filter_switches_to_the_matching_reader_view() {
        let mut traffic = TrafficState::default();

        traffic.cycle_event_filter();
        assert_eq!(traffic.event_filter_label(), "HTTP");
        assert_eq!(traffic.view_mode_label(), "HTTP");

        traffic.cycle_event_filter();
        assert_eq!(traffic.event_filter_label(), "WebSocket");
        assert_eq!(traffic.view_mode_label(), "WebSocket");

        traffic.cycle_event_filter();
        assert_eq!(traffic.event_filter_label(), "Security");
        assert_eq!(traffic.view_mode_label(), "Events");

        traffic.cycle_event_filter();
        assert_eq!(traffic.event_filter_label(), "Diagnostics");
        assert_eq!(traffic.view_mode_label(), "Events");

        traffic.cycle_event_filter();
        assert_eq!(traffic.event_filter_label(), "All");
        assert_eq!(traffic.view_mode_label(), "Events");

        traffic.cycle_event_filter();
        assert_eq!(traffic.event_filter_label(), "Parsed");
        assert_eq!(traffic.view_mode_label(), "HTTP");
    }

    #[test]
    fn stale_refresh_result_is_ignored_after_event_filter_changes() {
        let mut traffic = TrafficState::default();
        let request = traffic.begin_refresh(PathBuf::from("/tmp/admin.sock"), None, None);

        traffic.cycle_event_filter();
        let applied = traffic.apply_refresh_result(TrafficRefreshResult {
            selector_key: request.selector_key,
            event_filter: request.event_filter,
            result: Ok(TrafficRefreshSnapshot {
                tail: tail_snapshot_with_gap_events(1..=1),
                empty_filter_diagnostics: None,
            }),
        });

        assert!(!applied);
        assert!(traffic.rows().is_empty());
        assert_eq!(traffic.event_filter_label(), "HTTP");
        assert_eq!(
            traffic.status().text,
            "Traffic event filter changed to HTTP; showing HTTP view"
        );
    }

    #[test]
    fn diagnostics_preserve_warning_severity() {
        let mut traffic = TrafficState::default();

        let diagnostics =
            TrafficRuntimeDiagnostics::from_capture_snapshot(fallback_capture_snapshot());
        traffic.apply_runtime_diagnostic_message(diagnostics.status_message(true));

        assert_eq!(traffic.status().kind, TrafficStatusKind::Warning);
        assert_eq!(
            traffic.status().text,
            "Capture using libpcap; passive fallback occurred (ebpf: permission denied)"
        );
    }

    #[test]
    fn diagnostics_do_not_overwrite_existing_refresh_error() {
        let mut traffic = TrafficState::default();
        traffic.mark_admin_unavailable("tail_events failed");

        let diagnostics =
            TrafficRuntimeDiagnostics::from_capture_snapshot(fallback_capture_snapshot());
        traffic.apply_runtime_diagnostic_message(diagnostics.status_message(true));

        assert_eq!(traffic.status().kind, TrafficStatusKind::Error);
        assert_eq!(traffic.status().text, "tail_events failed");
    }

    #[test]
    fn refresh_pause_preserves_existing_traffic_rows() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_http_exchange());

        traffic.mark_refresh_paused("No readable process entries are available");

        assert_eq!(traffic.status().kind, TrafficStatusKind::Warning);
        assert_eq!(traffic.rows().len(), 4);
        assert_eq!(traffic.http_exchanges().len(), 1);
    }

    #[test]
    fn tail_response_too_large_error_keeps_operator_context() {
        let message = traffic_refresh_error_message(&TrafficClientError::TailResponseTooLarge {
            event_limit: 1,
            response_limit_bytes: 16_777_216,
        });

        assert_eq!(
            message,
            "tail_events refresh exceeded 16777216 bytes after reducing the list batch to 1"
        );
    }

    #[test]
    fn diagnostics_explain_active_mitm_plaintext_bridge_coverage() {
        let mut traffic = TrafficState::default();

        let diagnostics =
            TrafficRuntimeDiagnostics::from_capture_snapshot(active_mitm_bridge_capture_snapshot());
        traffic.apply_runtime_diagnostic_message(diagnostics.status_message(true));

        assert_eq!(traffic.status().kind, TrafficStatusKind::Idle);
        assert_eq!(traffic.status().text, diagnostics.running_status_text(true));
    }

    #[test]
    fn empty_traffic_diagnostics_explain_mitm_visibility_labels() {
        let traffic = TrafficState::default();
        let lines = traffic.diagnostic_lines();

        assert!(lines.contains(&mitm_data_path_coverage_line()));
        for expected in mitm_visibility_lines() {
            assert!(lines.contains(&expected), "missing {expected}");
        }
        assert!(
            lines
                .iter()
                .any(|line| line.contains("MITM") && line.contains("bidirectional"))
        );
    }

    #[test]
    fn default_view_groups_http_events_into_exchange_rows() {
        let mut traffic = TrafficState::default();

        traffic.apply_snapshot(tail_snapshot_with_http_exchange());

        assert_eq!(traffic.view_mode_label(), "HTTP");
        assert!(traffic.showing_http_exchanges());
        assert_eq!(traffic.active_row_count(), 1);
        assert_eq!(
            traffic.http_exchanges()[0].summary,
            "POST /api/tasks -> 200 OK (req 5 B, resp 2 B)"
        );
        assert!(
            traffic
                .detail_preview_lines(9)
                .iter()
                .any(|line| line == "Request body: 5 bytes (not loaded)")
        );
        assert!(
            traffic
                .selected_detail_lines()
                .expect("HTTP exchange detail")
                .iter()
                .any(|line| line == "  Body chunk offset=0 len=5 end_stream=true not_loaded=true")
        );
        assert!(
            traffic
                .selected_detail_lines()
                .expect("HTTP exchange detail")
                .iter()
                .any(|line| line == "  Body payload: not loaded in tail response")
        );
        assert_eq!(traffic.selected_detail_auto_fetch_sequence(), Some(2));
        traffic.mark_detail_loading(2, 41);
        assert!(
            traffic
                .selected_detail_lines()
                .expect("HTTP exchange detail")
                .iter()
                .any(|line| line == "Payload detail 2: loading from admin event_detail")
        );
        traffic.apply_detail_load_result(TrafficDetailLoadResult {
            sequence: 2,
            request_id: 41,
            result: Ok(EventDetailSnapshot {
                sequence: 2,
                stored_at_unix_ns: 200,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: 5,
                event: body_event(b"hello"),
            }),
        });
        assert_eq!(traffic.selected_detail_auto_fetch_sequence(), Some(4));
        assert!(
            traffic
                .selected_detail_lines()
                .expect("HTTP exchange detail")
                .iter()
                .any(|line| line == "  Body payload: hello")
        );
        assert!(
            traffic
                .detail_preview_lines(9)
                .iter()
                .any(|line| line == "Request body: 5 bytes (loaded)")
        );
        assert!(
            traffic
                .detail_preview_lines(9)
                .iter()
                .any(|line| line == "Response body: 2 bytes (not loaded)")
        );
        traffic.mark_detail_loading(4, 42);
        traffic.apply_detail_load_result(TrafficDetailLoadResult {
            sequence: 4,
            request_id: 42,
            result: Ok(EventDetailSnapshot {
                sequence: 4,
                stored_at_unix_ns: 400,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: 2,
                event: response_body_event(b"ok"),
            }),
        });
        assert_eq!(traffic.selected_detail_auto_fetch_sequence(), None);
        let details = traffic
            .selected_detail_lines()
            .expect("HTTP exchange detail");
        assert!(details.iter().any(|line| line == "  Body payload: ok"));
        assert!(
            traffic
                .detail_preview_lines(9)
                .iter()
                .any(|line| line == "Response body: 2 bytes (loaded)")
        );
        assert!(!details.iter().any(|line| line.contains("Raw event detail")));
    }

    #[test]
    fn traffic_search_filters_http_exchanges_without_changing_the_view() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_mixed_projection_events());

        assert!(traffic.showing_http_exchanges());
        assert_eq!(traffic.http_exchanges().len(), 2);

        traffic.set_search_query("/http/2".to_string());

        assert!(traffic.showing_http_exchanges());
        assert_eq!(traffic.active_row_count(), 1);
        assert_eq!(traffic.visible_match_count(), 1);
        assert_eq!(traffic.active_unfiltered_count(), 2);
        assert_eq!(traffic.visible_http_exchanges()[0].target, "/http/2");
        assert!(
            traffic
                .status()
                .text
                .contains("Traffic search matched 1/2 HTTP")
        );

        traffic.set_search_query("does-not-exist".to_string());

        assert!(traffic.showing_http_exchanges());
        assert_eq!(traffic.active_row_count(), 0);
        assert_eq!(traffic.visible_match_count(), 0);
        assert_eq!(traffic.active_unfiltered_count(), 2);
        assert_eq!(traffic.visible_http_exchanges().len(), 0);

        assert!(traffic.clear_search_query());
        assert_eq!(traffic.active_row_count(), 2);
        assert_eq!(traffic.visible_http_exchanges().len(), 2);
    }

    #[test]
    fn traffic_search_filters_raw_event_rows() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_mixed_projection_events());
        traffic.set_view_mode(TrafficViewMode::Events);

        traffic.set_search_query("gap".to_string());

        assert!(traffic.active_view_mode_is(TrafficViewMode::Events));
        assert_eq!(traffic.active_row_count(), 1);
        let row = traffic.selected_row().expect("matching raw event row");
        assert_eq!(row.event_type, "gap");
        assert_eq!(row.sequence, 5);
    }

    #[test]
    fn traffic_search_filters_websocket_sessions() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_mixed_projection_events());
        traffic.set_view_mode(TrafficViewMode::WebSocket);

        traffic.set_search_query("/ws/2".to_string());

        assert!(traffic.showing_websocket_sessions());
        assert_eq!(traffic.active_row_count(), 1);
        assert_eq!(traffic.visible_websocket_sessions()[0].target, "/ws/2");
    }

    #[test]
    fn paused_http_search_selection_survives_new_matching_snapshot() {
        let mut traffic = TrafficState::default();
        traffic.set_viewport_rows(2);
        traffic.apply_snapshot(tail_snapshot_from_records(vec![
            (
                1,
                request_event_with_flow("keep-flow-1", 1, "GET", "/keep/1"),
            ),
            (2, request_event_with_flow("other-flow", 2, "GET", "/other")),
            (
                3,
                request_event_with_flow("keep-flow-2", 3, "GET", "/keep/2"),
            ),
            (
                4,
                request_event_with_flow("keep-flow-3", 4, "GET", "/keep/3"),
            ),
        ]));
        traffic.set_search_query("/keep".to_string());
        traffic.select_row(1, 2);

        assert!(!traffic.following_tail());
        assert_eq!(traffic.visible_http_exchanges()[1].target, "/keep/2");

        traffic.apply_snapshot(tail_snapshot_from_records(vec![(
            5,
            request_event_with_flow("keep-flow-4", 5, "GET", "/keep/4"),
        )]));

        assert!(!traffic.following_tail());
        assert_eq!(traffic.active_row_count(), 4);
        assert_eq!(traffic.selected_http_exchange_index(), 1);
        assert_eq!(traffic.visible_http_exchanges()[1].target, "/keep/2");
    }

    #[test]
    fn filtered_http_detail_fetch_uses_visible_exchange_sequence() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_from_records(vec![
            (
                1,
                request_event_with_flow("detail-flow-1", 1, "POST", "/api/first"),
            ),
            (2, body_event_with_flow("detail-flow-1", 2, b"first")),
            (
                3,
                request_event_with_flow("detail-flow-2", 3, "POST", "/api/second"),
            ),
            (4, body_event_with_flow("detail-flow-2", 4, b"second")),
        ]));

        traffic.set_search_query("/api/second".to_string());

        assert_eq!(traffic.active_row_count(), 1);
        assert_eq!(traffic.visible_http_exchanges()[0].target, "/api/second");
        assert_eq!(traffic.selected_detail_auto_fetch_sequence(), Some(4));

        traffic.mark_detail_loading(4, 77);
        traffic.apply_detail_load_result(TrafficDetailLoadResult {
            sequence: 4,
            request_id: 77,
            result: Ok(EventDetailSnapshot {
                sequence: 4,
                stored_at_unix_ns: 400,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: 6,
                event: body_event_with_flow("detail-flow-2", 4, b"second"),
            }),
        });

        let details = traffic
            .selected_detail_lines()
            .expect("filtered HTTP exchange detail");
        assert!(details.iter().any(|line| line == "  Body payload: second"));
        assert!(!details.iter().any(|line| line == "  Body payload: first"));
    }

    #[test]
    fn http_exchange_context_survives_large_live_event_window() {
        let mut traffic = TrafficState::default();
        let mut records = vec![
            (
                1,
                request_event_with_flow("flow-long-lived", 1, "GET", "/long-lived"),
            ),
            (2, response_event_with_flow("flow-long-lived", 2, 200, "OK")),
        ];
        records.extend((3..=300).map(|sequence| (sequence, gap_event(sequence))));

        traffic.apply_snapshot(tail_snapshot_from_records(records));

        assert_eq!(traffic.rows().len(), 300);
        assert!(traffic.showing_http_exchanges());
        assert_eq!(traffic.http_exchanges().len(), 1);
        assert_eq!(traffic.http_exchanges()[0].target, "/long-lived");
        assert_eq!(traffic.http_exchanges()[0].status, "200 OK");
    }

    #[test]
    fn http_view_label_reports_events_when_no_http_exchanges_are_visible() {
        let mut traffic = TrafficState::default();

        assert_eq!(traffic.view_mode_label(), "HTTP");
        assert_eq!(
            traffic.active_view(),
            TrafficActiveView {
                requested: TrafficViewMode::Http,
                active: TrafficViewMode::Http,
                fallback: None
            }
        );

        traffic.apply_snapshot(tail_snapshot_with_gap_events(1..=3));

        assert_eq!(traffic.view_mode_label(), "Events (no HTTP)");
        assert_eq!(
            traffic.active_view(),
            TrafficActiveView {
                requested: TrafficViewMode::Http,
                active: TrafficViewMode::Events,
                fallback: Some(TrafficViewFallback::NoHttpExchanges)
            }
        );
        assert!(!traffic.showing_http_exchanges());
    }

    #[test]
    fn default_view_uses_websocket_sessions_when_http_is_empty() {
        let mut traffic = TrafficState::default();

        traffic.apply_snapshot(tail_snapshot_with_websocket_session());

        assert_eq!(traffic.view_mode_label(), "WebSocket (no HTTP)");
        assert!(traffic.showing_websocket_sessions());
        assert_eq!(traffic.active_row_count(), 1);
        assert_eq!(
            traffic.websocket_sessions()[0].summary,
            "/ws (0 frames, 1 messages, 5 B)"
        );
        assert!(
            traffic
                .detail_preview_lines(9)
                .iter()
                .any(|line| line == "Message payload: 5 bytes (not loaded)")
        );
        assert!(
            traffic
                .selected_detail_lines()
                .expect("WebSocket session detail")
                .iter()
                .any(|line| line == "    Payload: not loaded in tail response")
        );
        assert_eq!(traffic.selected_detail_auto_fetch_sequence(), Some(2));
        traffic.mark_detail_loading(2, 42);
        traffic.apply_detail_load_result(TrafficDetailLoadResult {
            sequence: 2,
            request_id: 42,
            result: Ok(EventDetailSnapshot {
                sequence: 2,
                stored_at_unix_ns: 200,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: 5,
                event: websocket_message_event(b"hello"),
            }),
        });
        assert!(
            traffic
                .selected_detail_lines()
                .expect("WebSocket session detail")
                .iter()
                .any(|line| line == "    Payload: hello")
        );
        assert!(
            traffic
                .detail_preview_lines(9)
                .iter()
                .any(|line| line == "Message payload: 5 bytes (loaded)")
        );
        assert!(
            !traffic
                .selected_detail_lines()
                .expect("WebSocket session detail")
                .iter()
                .any(|line| line.contains("Raw event detail"))
        );
    }

    #[test]
    fn websocket_view_falls_back_to_events_when_no_websocket_sessions_are_visible() {
        let mut traffic = TrafficState::default();
        traffic.cycle_view_mode();
        assert_eq!(traffic.view_mode_label(), "WebSocket");

        traffic.apply_snapshot(tail_snapshot_with_gap_events(1..=3));

        assert_eq!(traffic.view_mode_label(), "Events (no WebSocket)");
        assert!(!traffic.showing_websocket_sessions());
    }

    #[test]
    fn empty_tail_jump_resets_all_projection_viewports() {
        let mut traffic = TrafficState {
            event_view: TrafficViewport {
                selected_index: 3,
                scroll: 2,
            },
            http_view: TrafficViewport {
                selected_index: 4,
                scroll: 3,
            },
            websocket_view: TrafficViewport {
                selected_index: 5,
                scroll: 4,
            },
            ..Default::default()
        };

        traffic.jump_to_tail(10);

        assert_eq!(traffic.scroll(), 0);
        assert_eq!(traffic.selected_index(), 0);
        assert_eq!(traffic.http_scroll(), 0);
        assert_eq!(traffic.selected_http_exchange_index(), 0);
        assert_eq!(traffic.websocket_scroll(), 0);
        assert_eq!(traffic.selected_websocket_session_index(), 0);
    }

    #[test]
    fn paused_websocket_selection_moves_to_nearest_surviving_session_after_window_rolls() {
        let mut traffic = TrafficState::default();
        traffic.set_viewport_rows(10);
        traffic.apply_snapshot(tail_snapshot_with_websocket_handoffs(
            1..=MAX_TRAFFIC_EVENT_ROWS as u64,
        ));

        let old_session_index = 5;
        traffic.select_row(old_session_index, 10);
        assert!(!traffic.following_tail());
        assert_eq!(traffic.websocket_sessions()[old_session_index].sequence, 6);

        traffic.apply_snapshot(tail_snapshot_with_websocket_handoffs(
            (MAX_TRAFFIC_EVENT_ROWS as u64 + 1)..=(MAX_TRAFFIC_EVENT_ROWS as u64 + 10),
        ));

        let selected = traffic.selected_websocket_session_index();
        assert_eq!(traffic.websocket_sessions()[selected].sequence, 11);
        assert_eq!(traffic.websocket_sessions()[selected].target, "/ws/11");
    }

    #[test]
    fn paused_websocket_selection_restores_same_surviving_session_when_order_moves() {
        let mut traffic = TrafficState::default();
        traffic.set_viewport_rows(10);
        traffic.apply_snapshot(tail_snapshot_from_records(vec![
            (1, websocket_handoff_event_with_flow("flow-b", 1, "/b")),
            (20, websocket_message_event_with_flow("flow-b", 20, b"b1")),
            (25, websocket_handoff_event_with_flow("flow-d", 25, "/d")),
        ]));

        assert_eq!(traffic.websocket_sessions()[0].target, "/b");
        traffic.select_row(0, 10);
        assert!(!traffic.following_tail());

        traffic.apply_snapshot(tail_snapshot_from_records(vec![
            (30, websocket_handoff_event_with_flow("flow-c", 30, "/c")),
            (40, websocket_message_event_with_flow("flow-b", 40, b"b2")),
        ]));

        let selected = traffic.selected_websocket_session_index();
        assert_eq!(traffic.websocket_sessions()[selected].target, "/b");
    }

    #[test]
    fn paused_http_view_preserves_top_visible_exchange_when_newer_rows_arrive() {
        let mut traffic = TrafficState::default();
        traffic.set_viewport_rows(3);
        traffic.apply_snapshot(tail_snapshot_from_records(
            (1..=6)
                .map(|sequence| {
                    (
                        sequence,
                        request_event_with_flow(
                            &format!("http-flow-{sequence}"),
                            sequence,
                            "GET",
                            &format!("/http/{sequence}"),
                        ),
                    )
                })
                .collect(),
        ));

        traffic.select_row(3, 3);
        assert_eq!(
            traffic.http_exchanges()[traffic.http_scroll()].target,
            "/http/4"
        );
        assert!(!traffic.following_tail());

        traffic.apply_snapshot(tail_snapshot_from_records(
            (7..=8)
                .map(|sequence| {
                    (
                        sequence,
                        request_event_with_flow(
                            &format!("http-flow-{sequence}"),
                            sequence,
                            "GET",
                            &format!("/http/{sequence}"),
                        ),
                    )
                })
                .collect(),
        ));

        assert_eq!(
            traffic.http_exchanges()[traffic.http_scroll()].target,
            "/http/4"
        );
        assert_eq!(traffic.http_scroll(), 3);
        assert!(!traffic.following_tail());
    }

    #[test]
    fn paused_websocket_view_preserves_top_visible_session_when_newer_rows_arrive() {
        let mut traffic = TrafficState::default();
        traffic.cycle_view_mode();
        traffic.set_viewport_rows(3);
        traffic.apply_snapshot(tail_snapshot_from_records(
            (1..=6)
                .map(|sequence| {
                    (
                        sequence,
                        websocket_handoff_event_with_flow(
                            &format!("websocket-flow-{sequence}"),
                            sequence,
                            &format!("/ws/{sequence}"),
                        ),
                    )
                })
                .collect(),
        ));

        traffic.select_row(3, 3);
        assert_eq!(
            traffic.websocket_sessions()[traffic.websocket_scroll()].target,
            "/ws/4"
        );
        assert!(!traffic.following_tail());

        traffic.apply_snapshot(tail_snapshot_from_records(
            (7..=8)
                .map(|sequence| {
                    (
                        sequence,
                        websocket_handoff_event_with_flow(
                            &format!("websocket-flow-{sequence}"),
                            sequence,
                            &format!("/ws/{sequence}"),
                        ),
                    )
                })
                .collect(),
        ));

        assert_eq!(
            traffic.websocket_sessions()[traffic.websocket_scroll()].target,
            "/ws/4"
        );
        assert_eq!(traffic.websocket_scroll(), 3);
        assert!(!traffic.following_tail());
    }

    #[test]
    fn paused_http_selection_restores_same_surviving_exchange_after_window_truncates_first_event() {
        let mut traffic = TrafficState::default();
        traffic.set_viewport_rows(10);
        traffic.apply_snapshot(tail_snapshot_from_records(vec![
            (1, request_event_with_flow("flow-long", 1, "GET", "/long")),
            (20, response_event_with_flow("flow-long", 20, 200, "OK")),
            (
                30,
                request_event_with_flow("flow-other", 30, "GET", "/other"),
            ),
        ]));

        assert_eq!(traffic.http_exchanges()[0].target, "/long");
        traffic.select_row(0, 10);
        assert!(!traffic.following_tail());

        let long_late_sequence = MAX_TRAFFIC_EVENT_ROWS as u64 + 40;
        let other_late_sequence = MAX_TRAFFIC_EVENT_ROWS as u64 + 10;
        let records = (31..=(MAX_TRAFFIC_EVENT_ROWS as u64 + 50))
            .map(|sequence| {
                let event = if sequence == long_late_sequence {
                    response_event_with_flow("flow-long", sequence, 204, "No Content")
                } else if sequence == other_late_sequence {
                    response_event_with_flow("flow-other", sequence, 202, "Accepted")
                } else {
                    gap_event(sequence)
                };
                (sequence, event)
            })
            .collect::<Vec<_>>();
        traffic.apply_snapshot(tail_snapshot_from_records(records));

        let selected = traffic.selected_http_exchange_index();
        assert_eq!(
            traffic.http_exchanges()[selected].order_sequence(),
            long_late_sequence
        );
    }

    #[test]
    fn paused_http_selection_prefers_strict_orphan_response_over_stale_request_fallback() {
        let mut traffic = TrafficState::default();
        traffic.set_viewport_rows(10);
        let records = vec![
            (
                1,
                request_event_with_flow("flow-stale-orphan", 1, "GET", "/stale"),
            ),
            (2, unknown_gap_event_with_flow("flow-stale-orphan", 2)),
            (
                3,
                response_event_with_flow("flow-stale-orphan", 3, 200, "OK"),
            ),
            (4, request_event_with_flow("flow-later", 4, "GET", "/later")),
        ];
        traffic.apply_snapshot(tail_snapshot_from_records(records.clone()));
        let orphan_index = traffic
            .http_exchanges()
            .iter()
            .position(|exchange| exchange.status == "200 OK")
            .expect("orphan response exchange should exist");

        traffic.select_row(orphan_index, 10);
        assert!(!traffic.following_tail());
        traffic.apply_snapshot(tail_snapshot_from_records(records));

        let selected = traffic.selected_http_exchange_index();
        assert_eq!(traffic.http_exchanges()[selected].status, "200 OK");
        assert_eq!(traffic.http_exchanges()[selected].target, "-");
    }

    #[test]
    fn live_tail_applies_to_each_projection_when_switching_views() {
        let mut traffic = TrafficState::default();
        traffic.set_viewport_rows(3);

        traffic.apply_snapshot(tail_snapshot_with_mixed_projection_events());

        assert!(traffic.following_tail());
        assert_eq!(
            traffic.http_exchanges()[traffic.selected_http_exchange_index()].target,
            "/http/2"
        );

        traffic.cycle_view_mode();
        assert_eq!(traffic.view_mode_label(), "WebSocket");
        assert_eq!(
            traffic.websocket_sessions()[traffic.selected_websocket_session_index()].target,
            "/ws/2"
        );

        traffic.cycle_view_mode();
        assert_eq!(traffic.view_mode_label(), "Events");
        let row = traffic
            .selected_row()
            .expect("latest event row is selected");
        assert_eq!(row.sequence, 5);
        assert!(traffic.following_tail());
    }

    #[test]
    fn paused_projection_selection_survives_view_switching() {
        let mut traffic = TrafficState::default();
        traffic.set_viewport_rows(3);
        traffic.apply_snapshot(tail_snapshot_with_mixed_projection_events());
        traffic.cycle_view_mode();
        assert_eq!(traffic.view_mode_label(), "WebSocket");

        traffic.select_row(0, 3);
        assert!(!traffic.following_tail());
        assert_eq!(
            traffic.websocket_sessions()[traffic.selected_websocket_session_index()].target,
            "/ws/1"
        );

        traffic.cycle_view_mode();
        assert_eq!(traffic.view_mode_label(), "Events");
        traffic.cycle_view_mode();
        assert_eq!(traffic.view_mode_label(), "HTTP");
        traffic.cycle_view_mode();
        assert_eq!(traffic.view_mode_label(), "WebSocket");

        assert_eq!(traffic.tail_mode_label(), "Paused");
        assert_eq!(
            traffic.websocket_sessions()[traffic.selected_websocket_session_index()].target,
            "/ws/1"
        );
    }

    #[test]
    fn traffic_tail_follows_new_events_by_default() {
        let mut traffic = traffic_in_events_view();
        traffic.set_viewport_rows(5);

        traffic.apply_snapshot(tail_snapshot_with_body_events(1..=10));

        assert_eq!(traffic.rows().len(), 10);
        assert_eq!(traffic.rows()[9].sequence, 10);
        assert_eq!(traffic.selected_index(), 9);
        assert_eq!(traffic.scroll(), 5);
        assert!(traffic.following_tail());

        traffic.apply_snapshot(tail_snapshot_with_body_events(11..=12));

        assert_eq!(traffic.rows().len(), 12);
        assert_eq!(traffic.rows()[11].sequence, 12);
        assert_eq!(traffic.selected_index(), 11);
        assert_eq!(traffic.scroll(), 7);
        assert!(traffic.following_tail());
    }

    #[test]
    fn traffic_scroll_pauses_tail_follow_until_user_returns_to_latest_viewport() {
        let mut traffic = traffic_in_events_view();
        traffic.set_viewport_rows(5);
        traffic.apply_snapshot(tail_snapshot_with_body_events(1..=10));

        traffic.scroll_viewport(-3, 5);

        assert_eq!(traffic.scroll(), 2);
        assert_eq!(traffic.selected_index(), 6);
        assert_eq!(traffic.rows()[traffic.selected_index()].sequence, 7);
        assert_eq!(traffic.rows()[traffic.scroll()].sequence, 3);
        assert!(!traffic.following_tail());

        traffic.apply_snapshot(tail_snapshot_with_body_events(11..=12));

        assert_eq!(traffic.rows()[traffic.selected_index()].sequence, 7);
        assert_eq!(traffic.rows()[traffic.scroll()].sequence, 3);
        assert_eq!(traffic.scroll(), 2);
        assert!(!traffic.following_tail());

        traffic.scroll_viewport(5, 5);

        assert_eq!(traffic.selected_index(), 11);
        assert_eq!(traffic.scroll(), 7);
        assert!(traffic.following_tail());

        traffic.set_viewport_rows(5);

        assert_eq!(traffic.selected_index(), 11);
        assert_eq!(traffic.scroll(), 7);
        assert!(traffic.following_tail());

        traffic.apply_snapshot(tail_snapshot_with_body_events(13..=14));

        assert_eq!(traffic.rows()[13].sequence, 14);
        assert_eq!(traffic.selected_index(), 13);
        assert_eq!(traffic.scroll(), 9);
        assert!(traffic.following_tail());
    }

    #[test]
    fn traffic_scrollbar_drag_to_latest_viewport_resumes_tail_follow() {
        let mut traffic = traffic_in_events_view();
        traffic.set_viewport_rows(5);
        traffic.apply_snapshot(tail_snapshot_with_body_events(1..=10));

        traffic.scroll_viewport(-3, 5);
        traffic.apply_snapshot(tail_snapshot_with_body_events(11..=12));
        assert_eq!(traffic.rows()[traffic.selected_index()].sequence, 7);
        assert_eq!(traffic.rows()[traffic.scroll()].sequence, 3);
        assert_eq!(traffic.scroll(), 2);
        assert!(!traffic.following_tail());

        traffic.drag_scrollbar(9, 10, 5);

        assert_eq!(traffic.selected_index(), 11);
        assert_eq!(traffic.scroll(), 7);
        assert!(traffic.following_tail());
    }

    #[test]
    fn live_tail_selects_new_omission_rows_after_viewport_returns_to_latest() {
        let mut traffic = traffic_in_events_view();
        traffic.set_viewport_rows(5);
        traffic.apply_snapshot(tail_snapshot_with_body_events(1..=10));

        traffic.scroll_viewport(-3, 5);
        traffic.apply_snapshot(tail_snapshot_with_body_events(11..=12));
        traffic.scroll_viewport(5, 5);
        assert!(traffic.following_tail());
        assert_eq!(traffic.selected_index(), 11);

        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission_at(13));

        assert_eq!(traffic.selected_index(), 12);
        let row = traffic.selected_row().expect("omission row is selected");
        assert_eq!(row.sequence, 13);
        assert_eq!(row.event_type, "tail omission");
    }

    #[test]
    fn traffic_jump_to_tail_resumes_live_follow_after_scroll_pause() {
        let mut traffic = traffic_in_events_view();
        traffic.set_viewport_rows(5);
        traffic.apply_snapshot(tail_snapshot_with_body_events(1..=10));

        traffic.scroll_viewport(-3, 5);
        traffic.apply_snapshot(tail_snapshot_with_body_events(11..=12));
        assert_eq!(traffic.tail_mode_label(), "Paused");
        assert!(!traffic.following_tail());

        traffic.jump_to_tail(5);

        assert_eq!(traffic.tail_mode_label(), "Live");
        assert_eq!(traffic.selected_index(), 11);
        assert_eq!(traffic.scroll(), 7);
        assert!(traffic.following_tail());
    }

    #[test]
    fn tail_omissions_are_visible_as_selectable_traffic_rows() {
        let mut traffic = TrafficState::default();

        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());

        assert_eq!(traffic.status().kind, TrafficStatusKind::Error);
        assert_eq!(
            traffic.status().text,
            "Received 0 events; omitted 1 event: response budget exceeded"
        );
        assert_eq!(traffic.rows().len(), 1);
        let row = traffic.selected_row().expect("omission row is selected");
        assert_eq!(row.event_type, "tail omission");
        assert_eq!(row.summary, "response budget exceeded, payload 4096 bytes");
        assert!(
            traffic
                .detail_preview_lines(8)
                .iter()
                .any(|line| line == "Reason: response budget exceeded")
        );
        let details = row.detail_lines();
        assert!(details.iter().any(|line| line == "Tail diagnostics"));
        assert!(
            details
                .iter()
                .any(|line| line == "record budget: 128/256 bytes (truncated)")
        );
        assert!(details.iter().any(|line| {
            line == "Payload schema: traffic.probe.event_envelope.subject_origin.json"
        }));
    }

    #[test]
    fn omitted_tail_row_can_be_replaced_by_full_event_detail() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());

        assert_eq!(traffic.selected_detail_auto_fetch_sequence(), Some(2));
        traffic.mark_detail_loading(2, 11);
        assert!(
            traffic
                .selected_detail_lines()
                .expect("selected detail")
                .iter()
                .any(|line| line == "Full event detail: loading from admin event_detail")
        );

        let payload = "large response body ".repeat(128);
        traffic.apply_detail_load_result(TrafficDetailLoadResult {
            sequence: 2,
            request_id: 11,
            result: Ok(EventDetailSnapshot {
                sequence: 2,
                stored_at_unix_ns: 99,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: payload.len(),
                event: body_event(payload.as_bytes()),
            }),
        });

        assert_eq!(traffic.selected_detail_auto_fetch_sequence(), None);
        assert!(
            traffic
                .selected_detail_lines()
                .expect("selected detail")
                .iter()
                .any(|line| line == &format!("Body payload: {payload}"))
        );
    }

    #[test]
    fn omitted_tail_row_detail_reports_fetch_errors() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());

        traffic.mark_detail_loading(2, 11);
        traffic.apply_detail_load_result(TrafficDetailLoadResult::failed(
            2,
            11,
            "admin socket is unavailable",
        ));

        let lines = traffic
            .selected_detail_lines()
            .expect("selected detail should remain visible");
        assert!(
            lines
                .iter()
                .any(|line| line == "Full event detail fetch failed")
        );
        assert!(
            lines
                .iter()
                .any(|line| line == "Reason: admin socket is unavailable")
        );
        assert_eq!(traffic.selected_detail_auto_fetch_sequence(), None);
        assert_eq!(traffic.selected_detail_manual_fetch_sequence(), Some(2));
    }

    #[test]
    fn stale_detail_result_does_not_override_current_request() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());
        traffic.mark_detail_loading(2, 11);
        traffic.mark_detail_loading(2, 12);

        let stale_payload = b"stale detail";
        assert!(!traffic.apply_detail_load_result(TrafficDetailLoadResult {
            sequence: 2,
            request_id: 11,
            result: Ok(EventDetailSnapshot {
                sequence: 2,
                stored_at_unix_ns: 99,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: stale_payload.len(),
                event: body_event(stale_payload),
            }),
        }));
        assert!(
            traffic
                .selected_detail_lines()
                .expect("selected detail")
                .iter()
                .any(|line| line == "Full event detail: loading from admin event_detail")
        );

        let current_payload = b"current detail";
        assert!(traffic.apply_detail_load_result(TrafficDetailLoadResult {
            sequence: 2,
            request_id: 12,
            result: Ok(EventDetailSnapshot {
                sequence: 2,
                stored_at_unix_ns: 99,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: current_payload.len(),
                event: body_event(current_payload),
            }),
        }));
        assert!(
            traffic
                .selected_detail_lines()
                .expect("selected detail")
                .iter()
                .any(|line| line == "Body payload: current detail")
        );
    }

    #[test]
    fn stale_detail_result_after_selector_reset_is_ignored() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());
        traffic.mark_detail_loading(2, 11);

        traffic.begin_refresh(
            PathBuf::from("/tmp/admin.sock"),
            Some(Selector::default()),
            None,
        );

        assert!(!traffic.apply_detail_load_result(TrafficDetailLoadResult {
            sequence: 2,
            request_id: 11,
            result: Ok(EventDetailSnapshot {
                sequence: 2,
                stored_at_unix_ns: 99,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: 0,
                event: body_event(b"stale detail"),
            }),
        }));
        assert!(traffic.selected_detail_lines().is_none());
        assert_eq!(traffic.status().kind, TrafficStatusKind::Idle);
    }

    fn fallback_capture_snapshot() -> CaptureStatusSnapshot {
        CaptureStatusSnapshot {
            selection: CaptureSelection::Auto,
            selected_backend: Some(CaptureBackend::Libpcap),
            selected_input_source: None,
            ebpf_expected_contract: Some(EbpfExpectedContractStatusSnapshot::current_agent()),
            provider_runtime_mode: Some(RuntimeMode::Available),
            mode: CapturePlanMode::Live,
            reason: None,
            evidence_mode: Some(CaptureEvidenceMode::BestEffort),
            evidence_reason: Some("libpcap stream assembly is best-effort".to_string()),
            candidates: vec![
                CaptureCandidateStatusSnapshot {
                    backend: CaptureBackend::Ebpf,
                    runtime_mode: RuntimeMode::Unavailable,
                    capability_mode: RuntimeMode::Unavailable,
                    evidence_mode: CaptureEvidenceMode::Nominal,
                    reason: Some("permission denied".to_string()),
                    evidence_reason: None,
                },
                CaptureCandidateStatusSnapshot {
                    backend: CaptureBackend::Libpcap,
                    runtime_mode: RuntimeMode::Available,
                    capability_mode: RuntimeMode::Degraded,
                    evidence_mode: CaptureEvidenceMode::BestEffort,
                    reason: None,
                    evidence_reason: Some("best-effort attribution".to_string()),
                },
            ],
            auto_mitm_plaintext_bridge_candidate: None,
            open_failures: vec![CaptureOpenFailureStatusSnapshot {
                backend: CaptureBackend::Ebpf,
                reason: "permission denied".to_string(),
            }],
            provider: None,
            input_activity: None,
        }
    }

    fn active_mitm_bridge_capture_snapshot() -> CaptureStatusSnapshot {
        CaptureStatusSnapshot {
            selection: CaptureSelection::Auto,
            selected_backend: Some(CaptureBackend::CaptureEventFeed),
            selected_input_source: Some(CaptureInputSource::MitmPlaintextBridge),
            ebpf_expected_contract: Some(EbpfExpectedContractStatusSnapshot::current_agent()),
            provider_runtime_mode: Some(RuntimeMode::Available),
            mode: CapturePlanMode::CaptureEventFeed,
            reason: None,
            evidence_mode: Some(CaptureEvidenceMode::Nominal),
            evidence_reason: None,
            candidates: vec![CaptureCandidateStatusSnapshot {
                backend: CaptureBackend::CaptureEventFeed,
                runtime_mode: RuntimeMode::Available,
                capability_mode: RuntimeMode::Available,
                evidence_mode: CaptureEvidenceMode::Nominal,
                reason: None,
                evidence_reason: None,
            }],
            auto_mitm_plaintext_bridge_candidate: None,
            open_failures: Vec::new(),
            provider: None,
            input_activity: None,
        }
    }

    fn tail_budget(
        max_record_bytes: usize,
        included_record_bytes: usize,
        truncated: bool,
    ) -> EventTailBudgetSnapshot {
        EventTailBudgetSnapshot {
            max_event_payload_bytes: 512,
            max_record_bytes,
            included_record_bytes,
            truncated,
        }
    }

    fn tail_snapshot_with_response_budget_omission() -> EventTailSnapshot {
        tail_snapshot_with_response_budget_omission_at(2)
    }

    fn tail_snapshot_with_response_budget_omission_at(sequence: u64) -> EventTailSnapshot {
        tail_snapshot(
            0,
            sequence,
            64,
            sequence as usize,
            tail_budget(256, 128, true),
            Vec::new(),
            vec![EventTailOmission {
                sequence,
                stored_at_unix_ns: sequence * 100,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: 4096,
                reason: EventTailOmissionReason::ResponseBudgetExceeded,
            }],
        )
    }

    fn empty_tail_snapshot(scanned: usize) -> EventTailSnapshot {
        tail_snapshot(
            0,
            scanned as u64,
            64,
            scanned,
            tail_budget(4096, 0, false),
            Vec::new(),
            Vec::new(),
        )
    }

    fn tail_snapshot_with_gap_events(range: std::ops::RangeInclusive<u64>) -> EventTailSnapshot {
        let after_sequence = range.start().saturating_sub(1);
        let last_export_sequence = *range.end();
        let events = range
            .map(|sequence| tail_record(sequence, sequence * 100, gap_event(sequence)))
            .collect::<Vec<_>>();
        tail_snapshot(
            after_sequence,
            last_export_sequence,
            events.len(),
            events.len(),
            tail_budget(4096, 0, false),
            events,
            Vec::new(),
        )
    }

    fn tail_snapshot_with_body_events(range: std::ops::RangeInclusive<u64>) -> EventTailSnapshot {
        let after_sequence = range.start().saturating_sub(1);
        let last_export_sequence = *range.end();
        let events = range
            .map(|sequence| {
                tail_record(
                    sequence,
                    sequence * 100,
                    body_event(format!("body {sequence}").as_bytes()),
                )
            })
            .collect::<Vec<_>>();
        tail_snapshot(
            after_sequence,
            last_export_sequence,
            events.len(),
            events.len(),
            tail_budget(4096, 0, false),
            events,
            Vec::new(),
        )
    }

    fn tail_snapshot_with_http_exchange() -> EventTailSnapshot {
        let events = vec![
            tail_record(1, 100, request_event("POST", "/api/tasks")),
            tail_record(2, 200, body_event(b"hello")),
            tail_record(3, 300, response_event(200, "OK")),
            tail_record(4, 400, response_body_event(b"ok")),
        ];
        tail_snapshot(
            0,
            4,
            events.len(),
            events.len(),
            tail_budget(4096, 0, false),
            events,
            Vec::new(),
        )
    }

    fn tail_snapshot_with_websocket_session() -> EventTailSnapshot {
        let events = vec![
            tail_record(1, 100, websocket_handoff_event("/ws")),
            tail_record(2, 200, websocket_message_event(b"hello")),
        ];
        tail_snapshot(
            0,
            2,
            events.len(),
            events.len(),
            tail_budget(4096, 0, false),
            events,
            Vec::new(),
        )
    }

    fn tail_snapshot_with_websocket_handoffs(range: RangeInclusive<u64>) -> EventTailSnapshot {
        let after_sequence = range.start().saturating_sub(1);
        let next_after_sequence = *range.end();
        let events = range
            .map(|sequence| {
                tail_record(
                    sequence,
                    sequence,
                    websocket_handoff_event_for_flow(sequence),
                )
            })
            .collect::<Vec<_>>();
        tail_snapshot(
            after_sequence,
            next_after_sequence,
            events.len(),
            events.len(),
            tail_budget(4096, 0, false),
            events,
            Vec::new(),
        )
    }

    fn tail_snapshot_with_mixed_projection_events() -> EventTailSnapshot {
        tail_snapshot_from_records(vec![
            (
                1,
                request_event_with_flow("http-flow-1", 1, "GET", "/http/1"),
            ),
            (
                2,
                websocket_handoff_event_with_flow("ws-flow-1", 2, "/ws/1"),
            ),
            (
                3,
                request_event_with_flow("http-flow-2", 3, "GET", "/http/2"),
            ),
            (
                4,
                websocket_handoff_event_with_flow("ws-flow-2", 4, "/ws/2"),
            ),
            (5, gap_event(5)),
        ])
    }

    fn tail_snapshot_from_records(records: Vec<(u64, EventEnvelope)>) -> EventTailSnapshot {
        let next_after_sequence = records
            .iter()
            .map(|(sequence, _)| *sequence)
            .max()
            .unwrap_or_default();
        let events = records
            .into_iter()
            .map(|(sequence, event)| tail_record(sequence, sequence, event))
            .collect::<Vec<_>>();
        tail_snapshot(
            0,
            next_after_sequence,
            events.len(),
            events.len(),
            tail_budget(4096, 0, false),
            events,
            Vec::new(),
        )
    }

    fn tail_snapshot(
        after_sequence: u64,
        next_after_sequence: u64,
        limit: usize,
        scanned: usize,
        budget: EventTailBudgetSnapshot,
        events: Vec<EventTailRecord>,
        omissions: Vec<EventTailOmission>,
    ) -> EventTailSnapshot {
        EventTailSnapshot {
            after_sequence,
            next_after_sequence,
            last_export_sequence: next_after_sequence,
            attribution_mode: EventTailAttributionMode::Strict,
            limit,
            scan_limit: limit,
            scanned,
            budget,
            events,
            omissions,
        }
    }

    fn tail_record(sequence: u64, stored_at_unix_ns: u64, event: EventEnvelope) -> EventTailRecord {
        EventTailRecord {
            sequence,
            stored_at_unix_ns,
            event: EventTailEvent::from_envelope(&event),
        }
    }

    fn request_event(method: &str, target: &str) -> EventEnvelope {
        let flow_id = test_flow().id.0;
        request_event_with_flow(&flow_id, 1, method, target)
    }

    fn request_event_with_flow(
        flow_id: &str,
        sequence: u64,
        method: &str,
        target: &str,
    ) -> EventEnvelope {
        let mut flow = test_flow();
        flow.id = FlowIdentity(flow_id.to_string());
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: sequence,
                wall_time_unix_ns: sequence as i64,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(probe_core::HttpHeaders {
                direction: probe_core::Direction::Outbound,
                stream_sequence: 1,
                method: Some(method.to_string()),
                target: Some(target.to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn websocket_handoff_event(target: &str) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            test_flow(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::WebSocketHandoff(WebSocketHandoff {
                direction: probe_core::Direction::Outbound,
                stream_sequence: 1,
                target: Some(target.to_string()),
                subprotocol: None,
                extensions: Vec::new(),
            }),
        )
    }

    fn websocket_handoff_event_for_flow(sequence: u64) -> EventEnvelope {
        websocket_handoff_event_with_flow(
            &format!("websocket-flow-{sequence}"),
            sequence,
            &format!("/ws/{sequence}"),
        )
    }

    fn websocket_handoff_event_with_flow(
        flow_id: &str,
        sequence: u64,
        target: &str,
    ) -> EventEnvelope {
        let mut flow = test_flow();
        flow.id = FlowIdentity(flow_id.to_string());
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: sequence,
                wall_time_unix_ns: sequence as i64,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::WebSocketHandoff(WebSocketHandoff {
                direction: probe_core::Direction::Outbound,
                stream_sequence: 1,
                target: Some(target.to_string()),
                subprotocol: None,
                extensions: Vec::new(),
            }),
        )
    }

    fn websocket_message_event_with_flow(
        flow_id: &str,
        sequence: u64,
        payload: &[u8],
    ) -> EventEnvelope {
        let mut flow = test_flow();
        flow.id = FlowIdentity(flow_id.to_string());
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: sequence,
                wall_time_unix_ns: sequence as i64,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::WebSocketMessage(WebSocketMessage {
                direction: probe_core::Direction::Outbound,
                stream_sequence: 1,
                message_sequence: sequence,
                first_frame_sequence: sequence,
                final_frame_sequence: sequence,
                opcode: WebSocketMessageOpcode::Text,
                payload_len: payload.len() as u64,
                payload: payload.to_vec().into(),
                payload_fingerprint: vec![0xab],
            }),
        )
    }

    fn websocket_message_event(payload: &[u8]) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            test_flow(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::WebSocketMessage(WebSocketMessage {
                direction: probe_core::Direction::Outbound,
                stream_sequence: 1,
                message_sequence: 1,
                first_frame_sequence: 1,
                final_frame_sequence: 1,
                opcode: WebSocketMessageOpcode::Text,
                payload_len: payload.len() as u64,
                payload: payload.to_vec().into(),
                payload_fingerprint: vec![0xab],
            }),
        )
    }

    fn response_event(status: u16, reason: &str) -> EventEnvelope {
        let flow_id = test_flow().id.0;
        response_event_with_flow(&flow_id, 1, status, reason)
    }

    fn response_event_with_flow(
        flow_id: &str,
        sequence: u64,
        status: u16,
        reason: &str,
    ) -> EventEnvelope {
        let mut flow = test_flow();
        flow.id = FlowIdentity(flow_id.to_string());
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: sequence,
                wall_time_unix_ns: sequence as i64,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpResponseHeaders(probe_core::HttpHeaders {
                direction: probe_core::Direction::Inbound,
                stream_sequence: 1,
                method: None,
                target: None,
                status: Some(status),
                reason: Some(reason.to_string()),
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn body_event(body: &[u8]) -> EventEnvelope {
        body_event_with_flow(&test_flow().id.0, 1, body)
    }

    fn body_event_with_flow(flow_id: &str, sequence: u64, body: &[u8]) -> EventEnvelope {
        let mut flow = test_flow();
        flow.id = FlowIdentity(flow_id.to_string());
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: sequence,
                wall_time_unix_ns: sequence as i64,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpBodyChunk(BodyChunk {
                direction: probe_core::Direction::Outbound,
                stream_sequence: 1,
                offset: 0,
                data: body.to_vec().into(),
                end_stream: true,
            }),
        )
    }

    fn response_body_event(body: &[u8]) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            test_flow(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpBodyChunk(BodyChunk {
                direction: probe_core::Direction::Inbound,
                stream_sequence: 1,
                offset: 0,
                data: body.to_vec().into(),
                end_stream: true,
            }),
        )
    }

    fn traffic_in_events_view() -> TrafficState {
        let mut traffic = TrafficState::default();
        traffic.cycle_view_mode();
        traffic.cycle_view_mode();
        traffic
    }

    fn gap_event(sequence: u64) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: sequence,
                wall_time_unix_ns: sequence as i64,
            },
            test_flow(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::Gap(Gap {
                direction: probe_core::Direction::Inbound,
                expected_offset: sequence,
                next_offset: Some(sequence + 1),
                reason: "test gap".to_string(),
            }),
        )
    }

    fn unknown_gap_event_with_flow(flow_id: &str, sequence: u64) -> EventEnvelope {
        let mut flow = test_flow();
        flow.id = FlowIdentity(flow_id.to_string());
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: sequence,
                wall_time_unix_ns: sequence as i64,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::Gap(Gap {
                direction: probe_core::Direction::Inbound,
                expected_offset: sequence,
                next_offset: None,
                reason: "unknown gap".to_string(),
            }),
        )
    }

    fn test_flow() -> FlowContext {
        let process = ProcessContext {
            identity: ProcessIdentity {
                pid: 42,
                tgid: 42,
                start_time_ticks: 7,
                boot_id: "boot".to_string(),
                exe_path: "/usr/bin/curl".to_string(),
                cmdline_hash: "hash".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "curl".to_string(),
            cmdline: vec!["curl".to_string()],
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process.identity,
                &local,
                &remote,
                TransportProtocol::Tcp,
                1,
                None,
            ),
            process,
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

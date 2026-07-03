mod client;
mod rows;

use std::path::{Path, PathBuf};

use probe_core::{EventType, Selector};

use self::{
    client::{request_event_detail, request_tail_events},
    rows::TrafficRow,
};
use crate::{
    admin::{AdminClientError, EventDetailSnapshot, EventTailOmission, EventTailSnapshot},
    tui::{
        runtime_status::{
            CaptureDiagnosticMessage, missing_mitm_configuration_action,
            mitm_data_path_coverage_line, mitm_visibility_lines,
        },
        text::terminal_safe_inline_text,
    },
};

pub(crate) use rows::TrafficRow as TrafficTableRow;

const MAX_ROWS: usize = 256;

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
pub(crate) struct TrafficState {
    after_sequence: u64,
    selector_key: Option<String>,
    anchor_to_latest: bool,
    rows: Vec<TrafficRow>,
    selected_index: usize,
    scroll: usize,
    status: TrafficStatus,
    last_export_sequence: u64,
    detail_state: TrafficDetailState,
    event_filter: TrafficEventFilter,
}

impl Default for TrafficState {
    fn default() -> Self {
        Self {
            after_sequence: 0,
            selector_key: None,
            anchor_to_latest: true,
            rows: Vec::new(),
            selected_index: 0,
            scroll: 0,
            status: TrafficStatus::idle("Traffic view uses the running admin socket"),
            last_export_sequence: 0,
            detail_state: TrafficDetailState::Idle,
            event_filter: TrafficEventFilter::Http,
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

    pub(crate) fn selected_row(&self) -> Option<&TrafficTableRow> {
        self.rows.get(self.selected_index)
    }

    pub(crate) fn selected_detail_lines(&self) -> Option<Vec<String>> {
        let row = self.selected_row()?;
        let mut lines = row.detail_lines();
        match (&self.detail_state, row.detail_fetch_sequence()) {
            (
                TrafficDetailState::Loaded {
                    sequence,
                    row: detail,
                },
                Some(row_sequence),
            ) if *sequence == row_sequence => return Some(detail.detail_lines()),
            (TrafficDetailState::Loading { sequence, .. }, Some(row_sequence))
                if *sequence == row_sequence =>
            {
                lines.push("Full event detail: loading from admin event_detail".to_string());
            }
            (TrafficDetailState::Failed { sequence, message }, Some(row_sequence))
                if *sequence == row_sequence =>
            {
                lines.push("Full event detail fetch failed".to_string());
                lines.push(format!("Reason: {message}"));
            }
            _ => {}
        }
        Some(lines)
    }

    pub(crate) fn selected_detail_fetch_sequence(&self) -> Option<u64> {
        let row = self.selected_row()?;
        let sequence = row.detail_fetch_sequence()?;
        match &self.detail_state {
            TrafficDetailState::Loading {
                sequence: loading, ..
            }
            | TrafficDetailState::Loaded {
                sequence: loading, ..
            } if *loading == sequence => None,
            _ => Some(sequence),
        }
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

    pub(crate) fn event_filter_label(&self) -> &'static str {
        self.event_filter.label()
    }

    pub(crate) fn diagnostic_lines(&self) -> Vec<String> {
        let mut lines = vec![
            "Select a traffic row to inspect details".to_string(),
            "Open Data Path diagnostics for capture and MITM readiness".to_string(),
            mitm_data_path_coverage_line(),
        ];
        lines.extend(mitm_visibility_lines());
        lines.push(format!(
            "configuration: {}",
            missing_mitm_configuration_action()
        ));
        lines
    }

    pub(crate) fn detail_preview_lines(&self, max_lines: usize) -> Vec<String> {
        self.selected_row()
            .map(|row| row.preview_lines(max_lines.max(1)))
            .unwrap_or_else(|| self.diagnostic_lines())
    }

    pub(crate) async fn refresh(&mut self, socket_path: &Path, selector: Selector) {
        let selector_key = selector_key(&selector);
        if Some(selector_key.clone()) != self.selector_key {
            self.reset_for_selector(selector_key);
        }
        let event_types = self.event_filter.event_types();

        if self.anchor_to_latest {
            match request_tail_events(socket_path, u64::MAX, selector.clone(), &event_types).await {
                Ok(snapshot) => self.apply_anchor_snapshot(snapshot),
                Err(error) => {
                    self.status = TrafficStatus::error(traffic_refresh_error_message(&error));
                    return;
                }
            }
        }

        match request_tail_events(socket_path, self.after_sequence, selector, &event_types).await {
            Ok(snapshot) => self.apply_snapshot(snapshot),
            Err(error) => {
                self.status = TrafficStatus::error(traffic_refresh_error_message(&error));
            }
        }
    }

    pub(crate) fn mark_detail_loading(&mut self, sequence: u64, request_id: u64) {
        self.detail_state = TrafficDetailState::Loading {
            sequence,
            request_id,
        };
        self.status = TrafficStatus::active(format!("Loading full event detail {sequence}"));
    }

    pub(crate) fn mark_detail_failed(&mut self, sequence: u64, message: impl Into<String>) {
        self.mark_detail_error(sequence, message.into());
    }

    pub(crate) fn apply_detail_load_result(&mut self, result: TrafficDetailLoadResult) -> bool {
        if !matches!(
            self.detail_state,
            TrafficDetailState::Loading {
                sequence,
                request_id
            } if sequence == result.sequence && request_id == result.request_id
        ) {
            return false;
        }
        match result.result {
            Ok(detail) => self.apply_detail(detail),
            Err(message) => self.mark_detail_error(result.sequence, message),
        }
        true
    }

    pub(crate) fn clear_detail_state(&mut self) {
        self.detail_state = TrafficDetailState::Idle;
    }

    pub(crate) fn mark_admin_unavailable(&mut self, message: impl Into<String>) {
        self.clear_detail_state();
        self.status = TrafficStatus::error(message);
    }

    pub(crate) fn cycle_event_filter(&mut self) {
        self.event_filter = self.event_filter.next();
        self.reset_tail();
        self.status = TrafficStatus::idle(format!(
            "Traffic event filter changed to {}",
            self.event_filter.label()
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

    pub(crate) fn mark_filter_unavailable(&mut self, message: impl Into<String>) {
        self.after_sequence = 0;
        self.selector_key = None;
        self.rows.clear();
        self.selected_index = 0;
        self.scroll = 0;
        self.clear_detail_state();
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
        self.reset_tail();
        self.selector_key = Some(selector_key);
        self.status = TrafficStatus::idle("Traffic filter changed");
    }

    fn reset_tail(&mut self) {
        self.after_sequence = 0;
        self.anchor_to_latest = true;
        self.rows.clear();
        self.selected_index = 0;
        self.scroll = 0;
        self.detail_state = TrafficDetailState::Idle;
    }

    fn apply_anchor_snapshot(&mut self, snapshot: EventTailSnapshot) {
        self.after_sequence = snapshot.last_export_sequence;
        self.last_export_sequence = snapshot.last_export_sequence;
        self.anchor_to_latest = false;
        self.status = TrafficStatus::idle(format!(
            "Watching new matching events after export sequence {}",
            snapshot.last_export_sequence
        ));
    }

    fn apply_snapshot(&mut self, snapshot: EventTailSnapshot) {
        self.after_sequence = snapshot.next_after_sequence;
        self.last_export_sequence = snapshot.last_export_sequence;
        let received = snapshot.events.len();
        let status = traffic_status_for_snapshot(received, &snapshot.omissions, snapshot.scanned);
        self.rows.extend(traffic_rows_for_snapshot(snapshot));
        if self.rows.len() > MAX_ROWS {
            let drop_count = self.rows.len() - MAX_ROWS;
            self.rows.drain(0..drop_count);
            self.selected_index = self.selected_index.saturating_sub(drop_count);
            self.scroll = self.scroll.saturating_sub(drop_count);
        }
        self.clamp_selection();
        self.status = status;
    }

    fn apply_detail(&mut self, detail: EventDetailSnapshot) {
        let row = TrafficRow::from_detail(detail);
        self.status = TrafficStatus::active(format!("Loaded full event detail {}", row.sequence));
        self.detail_state = TrafficDetailState::Loaded {
            sequence: row.sequence,
            row: Box::new(row),
        };
    }

    fn mark_detail_error(&mut self, sequence: u64, message: String) {
        self.detail_state = TrafficDetailState::Failed {
            sequence,
            message: terminal_safe_inline_text(message),
        };
        self.status =
            TrafficStatus::warning(format!("Failed to load full event detail {sequence}"));
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
pub(crate) enum TrafficEventFilter {
    Http,
    All,
}

impl TrafficEventFilter {
    fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::All => "All",
        }
    }

    fn event_types(self) -> Vec<EventType> {
        match self {
            Self::Http => vec![
                EventType::HttpRequestHeaders,
                EventType::HttpResponseHeaders,
                EventType::HttpBodyChunk,
            ],
            Self::All => Vec::new(),
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Http => Self::All,
            Self::All => Self::Http,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrafficDetailState {
    Idle,
    Loading { sequence: u64, request_id: u64 },
    Loaded { sequence: u64, row: Box<TrafficRow> },
    Failed { sequence: u64, message: String },
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
) -> TrafficStatus {
    if let Some(reason) = omission_summary(omissions) {
        TrafficStatus::error(format!("Received {received} events; {reason}"))
    } else if received == 0 {
        TrafficStatus::idle(format!("No new matching events; scanned {scanned} records"))
    } else {
        TrafficStatus::active(format!("Received {received} matching events"))
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

fn selector_key(selector: &Selector) -> String {
    serde_json::to_string(selector).unwrap_or_else(|_| format!("{selector:?}"))
}

fn traffic_refresh_error_message(error: &client::TrafficClientError) -> String {
    match error {
        client::TrafficClientError::AdminClient(AdminClientError::Connect { path, source })
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
        _ => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{CaptureBackend, CaptureSelection};
    use probe_core::{
        AddressPort, BodyChunk, CaptureOrigin, CaptureSource, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, RuntimeMode,
        SpoolPayloadSchema, Timestamp, TransportProtocol,
    };
    use runtime::{CaptureEvidenceMode, CaptureInputSource, CapturePlanMode};

    use super::*;
    use crate::{
        admin::{
            EventDetailSnapshot, EventTailBudgetSnapshot, EventTailOmissionReason,
            EventTailSnapshot,
        },
        status::{
            CaptureCandidateStatusSnapshot, CaptureOpenFailureStatusSnapshot, CaptureStatusSnapshot,
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
    fn filter_reset_anchors_live_tail_to_latest_export_sequence() {
        let mut traffic = TrafficState::default();

        traffic.reset_for_selector("exe:/app/backend".to_string());
        assert!(traffic.anchor_to_latest);

        traffic.apply_anchor_snapshot(empty_tail_snapshot(12_345));

        assert!(!traffic.anchor_to_latest);
        assert_eq!(traffic.after_sequence, 12_345);
        assert_eq!(traffic.last_export_sequence(), 12_345);
        assert!(traffic.rows().is_empty());
        assert_eq!(traffic.status().kind, TrafficStatusKind::Idle);
        assert_eq!(
            traffic.status().text,
            "Watching new matching events after export sequence 12345"
        );
    }

    #[test]
    fn event_filter_defaults_to_http_and_cycles_with_tail_reset() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());

        assert_eq!(traffic.event_filter_label(), "HTTP");
        assert!(!traffic.rows().is_empty());

        traffic.cycle_event_filter();

        assert_eq!(traffic.event_filter_label(), "All");
        assert!(traffic.rows().is_empty());
        assert!(traffic.anchor_to_latest);
        assert_eq!(traffic.status().text, "Traffic event filter changed to All");
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
                .any(|line| line == "response budget: 128/256 bytes (truncated)")
        );
        assert!(details.iter().any(|line| {
            line == "Payload schema: traffic.probe.event_envelope.subject_origin.json"
        }));
    }

    #[test]
    fn omitted_tail_row_can_be_replaced_by_full_event_detail() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());

        assert_eq!(traffic.selected_detail_fetch_sequence(), Some(2));
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

        assert_eq!(traffic.selected_detail_fetch_sequence(), None);
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
    fn stale_detail_result_after_filter_unavailable_is_ignored() {
        let mut traffic = TrafficState::default();
        traffic.apply_snapshot(tail_snapshot_with_response_budget_omission());
        traffic.mark_detail_loading(2, 11);

        traffic.mark_filter_unavailable("Selected process has no readable executable path");

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
        assert_eq!(traffic.status().kind, TrafficStatusKind::Error);
    }

    fn fallback_capture_snapshot() -> CaptureStatusSnapshot {
        CaptureStatusSnapshot {
            selection: CaptureSelection::Auto,
            selected_backend: Some(CaptureBackend::Libpcap),
            selected_input_source: None,
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

    fn tail_snapshot_with_response_budget_omission() -> EventTailSnapshot {
        EventTailSnapshot {
            after_sequence: 0,
            next_after_sequence: 2,
            last_export_sequence: 2,
            limit: 64,
            scanned: 2,
            budget: EventTailBudgetSnapshot {
                max_event_payload_bytes: 512,
                max_response_payload_bytes: 256,
                included_payload_bytes: 128,
                truncated: true,
            },
            events: Vec::new(),
            omissions: vec![EventTailOmission {
                sequence: 2,
                stored_at_unix_ns: 200,
                payload_schema: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.to_string(),
                payload_bytes: 4096,
                reason: EventTailOmissionReason::ResponseBudgetExceeded,
            }],
        }
    }

    fn empty_tail_snapshot(last_export_sequence: u64) -> EventTailSnapshot {
        EventTailSnapshot {
            after_sequence: u64::MAX,
            next_after_sequence: u64::MAX,
            last_export_sequence,
            limit: 64,
            scanned: 0,
            budget: EventTailBudgetSnapshot {
                max_event_payload_bytes: 512,
                max_response_payload_bytes: 256,
                included_payload_bytes: 0,
                truncated: false,
            },
            events: Vec::new(),
            omissions: Vec::new(),
        }
    }

    fn body_event(body: &[u8]) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            test_flow(),
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

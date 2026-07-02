mod client;
mod rows;

use std::path::Path;

use probe_core::Selector;

use self::{client::request_tail_events, rows::TrafficRow};
use crate::{
    admin::{AdminClientError, EventTailOmission, EventTailSnapshot},
    tui::{
        copy::{MITM_PLAINTEXT_COVERAGE, MITM_PROXY_FALLBACK_LABEL},
        runtime_status::{
            CaptureDiagnosticMessage, TrafficRuntimeDiagnostics, missing_mitm_quick_setup_action,
        },
    },
};

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
    runtime_diagnostics: Option<TrafficRuntimeDiagnostics>,
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
            runtime_diagnostics: None,
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

    pub(crate) fn scroll(&self) -> usize {
        self.scroll
    }

    pub(crate) fn status(&self) -> &TrafficStatus {
        &self.status
    }

    pub(crate) fn last_export_sequence(&self) -> u64 {
        self.last_export_sequence
    }

    pub(crate) fn diagnostic_lines(&self) -> Vec<String> {
        let mut lines = vec!["Select a traffic row to inspect details".to_string()];
        lines.extend(self.data_path_diagnostic_lines());
        lines
    }

    pub(crate) fn data_path_diagnostic_lines(&self) -> Vec<String> {
        self.runtime_diagnostics
            .as_ref()
            .map(TrafficRuntimeDiagnostics::detail_lines)
            .unwrap_or_else(|| {
                vec![
                    "Capture diagnostics will appear here after the first refresh".to_string(),
                    format!(
                        "{MITM_PROXY_FALLBACK_LABEL} can capture {MITM_PLAINTEXT_COVERAGE} when eBPF and libpcap are unavailable"
                    ),
                    "Traffic rows separate passive capture, plain HTTP, and TLS-decrypted HTTP after runtime diagnostics are available".to_string(),
                    format!("MITM setup: {}", missing_mitm_quick_setup_action()),
                ]
            })
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

        match request_tail_events(socket_path, self.after_sequence, selector).await {
            Ok(snapshot) => self.apply_snapshot(snapshot),
            Err(error) => {
                self.status = TrafficStatus::error(traffic_refresh_error_message(&error));
            }
        }
    }

    pub(crate) fn mark_admin_unavailable(&mut self, message: impl Into<String>) {
        self.runtime_diagnostics = None;
        self.status = TrafficStatus::error(message);
    }

    pub(crate) fn mark_admin_unavailable_with_diagnostics(
        &mut self,
        message: impl Into<String>,
        diagnostics: TrafficRuntimeDiagnostics,
    ) {
        let message = message.into();
        let diagnostic_message = diagnostics
            .status_message(self.rows.is_empty())
            .and_then(capture_diagnostic_warning_or_error_text);
        self.runtime_diagnostics = Some(diagnostics);
        self.status = TrafficStatus::error(match diagnostic_message {
            Some(diagnostic_message) => format!("{message}; {diagnostic_message}"),
            None => message,
        });
    }

    pub(crate) fn set_runtime_diagnostics(&mut self, diagnostics: TrafficRuntimeDiagnostics) {
        if self.status.kind != TrafficStatusKind::Error
            && let Some(message) = diagnostics.status_message(self.rows.is_empty())
        {
            self.status = match message {
                CaptureDiagnosticMessage::Info(message) => TrafficStatus::idle(message),
                CaptureDiagnosticMessage::Warning(message) => TrafficStatus::warning(message),
                CaptureDiagnosticMessage::Error(message) => TrafficStatus::error(message),
            };
        }
        self.runtime_diagnostics = Some(diagnostics);
    }

    pub(crate) fn mark_filter_unavailable(&mut self, message: impl Into<String>) {
        self.after_sequence = 0;
        self.selector_key = None;
        self.rows.clear();
        self.selected_index = 0;
        self.scroll = 0;
        self.runtime_diagnostics = None;
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
        self.runtime_diagnostics = None;
        self.status = TrafficStatus::idle("Traffic filter changed");
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

fn capture_diagnostic_warning_or_error_text(message: CaptureDiagnosticMessage) -> Option<String> {
    match message {
        CaptureDiagnosticMessage::Info(_) => None,
        CaptureDiagnosticMessage::Warning(message) | CaptureDiagnosticMessage::Error(message) => {
            Some(message)
        }
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
            text: text.into(),
        }
    }

    fn active(text: impl Into<String>) -> Self {
        Self {
            kind: TrafficStatusKind::Active,
            text: text.into(),
        }
    }

    fn warning(text: impl Into<String>) -> Self {
        Self {
            kind: TrafficStatusKind::Warning,
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
    use probe_core::{RuntimeMode, SpoolPayloadSchema};
    use runtime::{CaptureEvidenceMode, CaptureInputSource, CapturePlanMode};

    use super::*;
    use crate::{
        admin::{EventTailBudgetSnapshot, EventTailOmissionReason, EventTailSnapshot},
        status::{
            CaptureCandidateStatusSnapshot, CaptureOpenFailureStatusSnapshot, CaptureStatusSnapshot,
        },
        tui::{
            copy::{MITM_PLAINTEXT_COVERAGE, MITM_PROXY_FALLBACK_LABEL},
            runtime_status::TrafficRuntimeDiagnostics,
        },
    };

    #[test]
    fn diagnostics_preserve_warning_severity() {
        let mut traffic = TrafficState::default();

        traffic.set_runtime_diagnostics(TrafficRuntimeDiagnostics::from_capture_snapshot(
            fallback_capture_snapshot(),
        ));

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

        traffic.set_runtime_diagnostics(TrafficRuntimeDiagnostics::from_capture_snapshot(
            fallback_capture_snapshot(),
        ));

        assert_eq!(traffic.status().kind, TrafficStatusKind::Error);
        assert_eq!(traffic.status().text, "tail_events failed");
    }

    #[test]
    fn admin_unavailable_can_keep_local_data_path_diagnostics() {
        let mut traffic = TrafficState::default();

        traffic.mark_admin_unavailable_with_diagnostics(
            "tail_events failed",
            TrafficRuntimeDiagnostics::from_capture_snapshot(fallback_capture_snapshot()),
        );

        assert_eq!(traffic.status().kind, TrafficStatusKind::Error);
        assert!(traffic.status().text.contains("tail_events failed"));
        assert!(traffic.status().text.contains("passive fallback occurred"));
        assert!(
            traffic
                .data_path_diagnostic_lines()
                .iter()
                .any(|line| line == "provider candidates:")
        );
    }

    #[test]
    fn admin_unavailable_suppresses_plan_only_info_status() {
        let mut traffic = TrafficState::default();

        traffic.mark_admin_unavailable_with_diagnostics(
            "tail_events failed",
            TrafficRuntimeDiagnostics::from_capture_snapshot(active_mitm_bridge_capture_snapshot()),
        );

        assert_eq!(traffic.status().kind, TrafficStatusKind::Error);
        assert_eq!(traffic.status().text, "tail_events failed");
        assert!(
            traffic
                .data_path_diagnostic_lines()
                .iter()
                .any(|line| line == &format!("coverage: {MITM_PLAINTEXT_COVERAGE}"))
        );
    }

    #[test]
    fn diagnostics_explain_active_mitm_plaintext_bridge_coverage() {
        let mut traffic = TrafficState::default();

        traffic.set_runtime_diagnostics(TrafficRuntimeDiagnostics::from_capture_snapshot(
            active_mitm_bridge_capture_snapshot(),
        ));

        assert_eq!(traffic.status().kind, TrafficStatusKind::Idle);
        assert_eq!(
            traffic.status().text,
            format!(
                "{MITM_PROXY_FALLBACK_LABEL} active for {MITM_PLAINTEXT_COVERAGE}; no matching events yet"
            )
        );
        assert!(
            traffic
                .diagnostic_lines()
                .iter()
                .any(|line| line == &format!("coverage: {MITM_PLAINTEXT_COVERAGE}"))
        );
    }

    #[test]
    fn filter_failure_clears_stale_diagnostics() {
        let mut traffic = TrafficState::default();
        traffic.set_runtime_diagnostics(TrafficRuntimeDiagnostics::from_capture_snapshot(
            fallback_capture_snapshot(),
        ));

        traffic.mark_filter_unavailable("missing process selector");

        assert!(
            traffic
                .diagnostic_lines()
                .iter()
                .any(|line| line.contains("after the first refresh"))
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
}

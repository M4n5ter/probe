use probe_config::CaptureBackend;
use runtime::{CaptureEvidenceMode, CaptureInputSource, CapturePlanMode};

use crate::{
    status::{
        CaptureCandidateStatusSnapshot, CaptureOpenFailureStatusSnapshot, CaptureStatusSnapshot,
    },
    tui::{copy::MITM_PLAINTEXT_COVERAGE, wire::capture_selection_name},
};

use super::CaptureDiagnosticMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CaptureDiagnostics {
    snapshot: CaptureStatusSnapshot,
}

impl CaptureDiagnostics {
    pub(super) fn new(snapshot: CaptureStatusSnapshot) -> Self {
        Self { snapshot }
    }

    pub(super) fn status_message(
        &self,
        traffic_empty: bool,
        mitm_next_step: &str,
    ) -> Option<CaptureDiagnosticMessage> {
        if self.using_mitm_plaintext_bridge() {
            if let Some(summary) = self.open_failure_summary() {
                return Some(CaptureDiagnosticMessage::Warning(format!(
                    "Passive capture failed ({summary}); using MITM plaintext bridge for {MITM_PLAINTEXT_COVERAGE}"
                )));
            }
            if let Some(summary) = self.passive_unavailable_summary() {
                return Some(CaptureDiagnosticMessage::Warning(format!(
                    "Passive capture unavailable ({summary}); using MITM plaintext bridge for {MITM_PLAINTEXT_COVERAGE}"
                )));
            }
            return traffic_empty.then(|| {
                CaptureDiagnosticMessage::Info(
                    format!(
                        "MITM plaintext bridge active for {MITM_PLAINTEXT_COVERAGE}; no matching events yet"
                    ),
                )
            });
        }
        if self.unavailable() {
            return Some(CaptureDiagnosticMessage::Error(format!(
                "Capture unavailable: {}; {}",
                self.failure_summary(),
                mitm_next_step
            )));
        }
        if let Some(summary) = self.open_failure_summary() {
            return Some(CaptureDiagnosticMessage::Warning(format!(
                "Capture using {}; passive fallback occurred ({summary})",
                self.selected_backend_label()
            )));
        }
        traffic_empty.then(|| {
            CaptureDiagnosticMessage::Info(format!(
                "Capture {} active; no matching events yet",
                self.selected_backend_label()
            ))
        })
    }

    pub(super) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            "Capture diagnostics".to_string(),
            format!(
                "selection: {}",
                capture_selection_name(self.snapshot.selection)
            ),
            format!("selected: {}", self.selected_backend_label()),
            format!("mode: {}", capture_plan_mode_name(self.snapshot.mode)),
        ];
        if self.using_mitm_plaintext_bridge() {
            lines.push(format!("coverage: {MITM_PLAINTEXT_COVERAGE}"));
        }
        if let Some(reason) = &self.snapshot.reason {
            lines.push(format!("reason: {reason}"));
        }
        if !self.snapshot.candidates.is_empty() {
            lines.push("provider candidates:".to_string());
            lines.extend(self.snapshot.candidates.iter().map(|candidate| {
                format!(
                    "{}: {}",
                    capture_backend_name(candidate.backend),
                    capture_candidate_details(candidate).join(", ")
                )
            }));
        }
        if let Some(candidate) = &self.snapshot.auto_mitm_plaintext_bridge_candidate {
            lines.push(format!(
                "auto MITM plaintext bridge fallback: {}: {}",
                capture_backend_name(candidate.backend),
                capture_candidate_details(candidate).join(", ")
            ));
        }
        if !self.snapshot.open_failures.is_empty() {
            lines.push("runtime open failures:".to_string());
            lines.extend(self.snapshot.open_failures.iter().map(open_failure_detail));
        }
        lines
    }

    fn unavailable(&self) -> bool {
        self.snapshot.selected_backend.is_none()
            || self.snapshot.mode == CapturePlanMode::Unavailable
    }

    pub(super) fn using_live_host(&self) -> bool {
        self.snapshot.selected_input_source == Some(CaptureInputSource::LiveHost)
            || (self.snapshot.selected_input_source.is_none()
                && self.snapshot.selected_backend.is_some_and(live_backend))
    }

    fn using_mitm_plaintext_bridge(&self) -> bool {
        self.snapshot.selected_input_source == Some(CaptureInputSource::MitmPlaintextBridge)
    }

    pub(super) fn live_host_status_prefix(&self) -> Option<String> {
        self.using_live_host()
            .then(|| format!("Capture {} active", self.selected_backend_label()))
    }

    fn selected_backend_label(&self) -> &'static str {
        if self.using_mitm_plaintext_bridge() {
            return "MITM plaintext bridge";
        }
        self.snapshot
            .selected_backend
            .map(capture_backend_name)
            .unwrap_or("none")
    }

    fn failure_summary(&self) -> String {
        let mut reasons = self
            .snapshot
            .candidates
            .iter()
            .filter_map(candidate_failure_detail)
            .collect::<Vec<_>>();
        reasons.extend(self.snapshot.open_failures.iter().map(open_failure_detail));
        if reasons.is_empty() {
            self.snapshot
                .reason
                .clone()
                .unwrap_or_else(|| "no live provider is available".to_string())
        } else {
            reasons.join("; ")
        }
    }

    fn open_failure_summary(&self) -> Option<String> {
        (!self.snapshot.open_failures.is_empty()).then(|| {
            self.snapshot
                .open_failures
                .iter()
                .map(open_failure_detail)
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    fn passive_unavailable_summary(&self) -> Option<String> {
        let reasons = self
            .snapshot
            .candidates
            .iter()
            .filter(|candidate| live_backend(candidate.backend))
            .filter_map(candidate_failure_detail)
            .collect::<Vec<_>>();
        (!reasons.is_empty()).then(|| reasons.join("; "))
    }
}

fn candidate_failure_detail(candidate: &CaptureCandidateStatusSnapshot) -> Option<String> {
    candidate
        .reason
        .as_ref()
        .or(candidate.evidence_reason.as_ref())
        .map(|reason| format!("{}: {reason}", capture_backend_name(candidate.backend)))
}

fn capture_candidate_details(candidate: &CaptureCandidateStatusSnapshot) -> Vec<String> {
    let mut details = vec![
        format!("runtime={}", runtime_mode_name(candidate.runtime_mode)),
        format!(
            "capability={}",
            runtime_mode_name(candidate.capability_mode)
        ),
        format!("evidence={}", evidence_mode_name(candidate.evidence_mode)),
    ];
    if let Some(reason) = &candidate.reason {
        details.push(format!("reason={reason}"));
    }
    if let Some(reason) = &candidate.evidence_reason {
        details.push(format!("evidence_reason={reason}"));
    }
    details
}

fn open_failure_detail(failure: &CaptureOpenFailureStatusSnapshot) -> String {
    format!(
        "{}: {}",
        capture_backend_name(failure.backend),
        failure.reason
    )
}

fn live_backend(backend: CaptureBackend) -> bool {
    matches!(backend, CaptureBackend::Ebpf | CaptureBackend::Libpcap)
}

fn capture_backend_name(backend: CaptureBackend) -> &'static str {
    match backend {
        CaptureBackend::Ebpf => "ebpf",
        CaptureBackend::Libpcap => "libpcap",
        CaptureBackend::PlaintextFeed => "plaintext_feed",
        CaptureBackend::CaptureEventFeed => "capture_event_feed",
        CaptureBackend::Replay => "replay",
    }
}

fn capture_plan_mode_name(mode: CapturePlanMode) -> &'static str {
    match mode {
        CapturePlanMode::Live => "live",
        CapturePlanMode::PlaintextFeed => "plaintext_feed",
        CapturePlanMode::CaptureEventFeed => "capture_event_feed",
        CapturePlanMode::Replay => "replay",
        CapturePlanMode::Unavailable => "unavailable",
    }
}

fn runtime_mode_name(mode: probe_core::RuntimeMode) -> &'static str {
    match mode {
        probe_core::RuntimeMode::Available => "available",
        probe_core::RuntimeMode::Degraded => "degraded",
        probe_core::RuntimeMode::Unavailable => "unavailable",
    }
}

fn evidence_mode_name(mode: CaptureEvidenceMode) -> &'static str {
    match mode {
        CaptureEvidenceMode::Nominal => "nominal",
        CaptureEvidenceMode::BestEffort => "best_effort",
    }
}

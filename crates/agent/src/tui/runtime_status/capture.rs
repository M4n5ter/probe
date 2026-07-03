use probe_config::CaptureBackend;
use runtime::{CaptureEvidenceMode, CaptureInputSource, CapturePlanMode};

use crate::{
    status::{
        CaptureCandidateStatusSnapshot, CaptureOpenFailureStatusSnapshot, CaptureStatusSnapshot,
    },
    tui::{
        copy::{MITM_PLAINTEXT_COVERAGE, MITM_PROXY_DATA_PATH_LABEL},
        wire::capture_selection_name,
    },
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
            if let Some(message) = self.mitm_bridge_passive_context_message() {
                return Some(message);
            }
            return traffic_empty.then(|| {
                CaptureDiagnosticMessage::Info(
                    format!(
                        "{MITM_PROXY_DATA_PATH_LABEL} active for {MITM_PLAINTEXT_COVERAGE}; no matching events yet"
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

    pub(super) fn local_status_message(
        &self,
        mitm_next_step: &str,
    ) -> Option<CaptureDiagnosticMessage> {
        if self.using_mitm_plaintext_bridge() {
            if let Some(summary) = self.open_failure_summary() {
                return Some(CaptureDiagnosticMessage::Warning(format!(
                    "Passive capture would fail ({summary}); local config uses {MITM_PROXY_DATA_PATH_LABEL} for {MITM_PLAINTEXT_COVERAGE}"
                )));
            }
            if let Some(summary) = self.passive_unavailable_summary() {
                return Some(CaptureDiagnosticMessage::Warning(format!(
                    "Passive capture is unavailable ({summary}); local config uses {MITM_PROXY_DATA_PATH_LABEL} for {MITM_PLAINTEXT_COVERAGE}"
                )));
            }
            return Some(CaptureDiagnosticMessage::Info(format!(
                "local config uses {MITM_PROXY_DATA_PATH_LABEL} for {MITM_PLAINTEXT_COVERAGE}"
            )));
        }
        if self.unavailable() {
            return Some(CaptureDiagnosticMessage::Error(format!(
                "Capture unavailable from local config: {}; {}",
                self.failure_summary(),
                mitm_next_step
            )));
        }
        if let Some(summary) = self.open_failure_summary() {
            return Some(CaptureDiagnosticMessage::Warning(format!(
                "Local config selects {}; passive fallback would occur ({summary})",
                self.selected_backend_label()
            )));
        }
        None
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
            if let Some(backend) = self.snapshot.selected_backend {
                lines.push(format!(
                    "provider backend: {}",
                    capture_backend_name(backend)
                ));
            }
            lines.push(self.mitm_data_path_priority_line());
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
                "auto {MITM_PROXY_DATA_PATH_LABEL} candidate: {}: {}",
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

    pub(super) fn overview_line(&self) -> String {
        if self.using_mitm_plaintext_bridge() {
            return format!(
                "{} selected for {}",
                self.selected_backend_label(),
                MITM_PLAINTEXT_COVERAGE
            );
        }
        if self.unavailable() {
            return format!("unavailable: {}", self.failure_summary());
        }
        let mut line = format!(
            "{} selected, mode={}",
            self.selected_backend_label(),
            capture_plan_mode_name(self.snapshot.mode)
        );
        if let Some(summary) = self.open_failure_summary() {
            line.push_str(&format!(", fallback/open failure={summary}"));
        }
        line
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

    pub(super) fn using_mitm_plaintext_bridge(&self) -> bool {
        self.snapshot.selected_input_source == Some(CaptureInputSource::MitmPlaintextBridge)
    }

    pub(super) fn mitm_bridge_passive_context_message(&self) -> Option<CaptureDiagnosticMessage> {
        if !self.using_mitm_plaintext_bridge() {
            return None;
        }
        if let Some(summary) = self.open_failure_summary() {
            return Some(CaptureDiagnosticMessage::Warning(format!(
                "Passive capture failed ({summary}); using {MITM_PROXY_DATA_PATH_LABEL} for {MITM_PLAINTEXT_COVERAGE}"
            )));
        }
        if let Some(summary) = self.passive_unavailable_summary() {
            return Some(CaptureDiagnosticMessage::Warning(format!(
                "Passive capture unavailable ({summary}); using {MITM_PROXY_DATA_PATH_LABEL} for {MITM_PLAINTEXT_COVERAGE}"
            )));
        }
        None
    }

    pub(super) fn live_host_status_prefix(&self) -> Option<String> {
        self.using_live_host()
            .then(|| format!("Capture {} active", self.selected_backend_label()))
    }

    fn selected_backend_label(&self) -> &'static str {
        if self.using_mitm_plaintext_bridge() {
            return MITM_PROXY_DATA_PATH_LABEL;
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

    fn mitm_data_path_priority_line(&self) -> String {
        let live_backends = self.live_fallback_backend_names();
        if live_backends.is_empty() {
            return format!(
                "data path priority: scoped {MITM_PROXY_DATA_PATH_LABEL}; passive capture unavailable"
            );
        }
        format!(
            "data path priority: passive capture ({}), scoped {MITM_PROXY_DATA_PATH_LABEL}",
            live_backends.join(" -> ")
        )
    }

    fn live_fallback_backend_names(&self) -> Vec<&'static str> {
        let mut backends = self
            .snapshot
            .candidates
            .iter()
            .map(|candidate| candidate.backend)
            .filter(|backend| live_backend(*backend))
            .collect::<Vec<_>>();
        if backends.is_empty() {
            backends.extend(
                self.snapshot
                    .open_failures
                    .iter()
                    .map(|failure| failure.backend)
                    .filter(|backend| live_backend(*backend)),
            );
        }
        unique_backend_names(backends)
    }
}

fn unique_backend_names(backends: Vec<CaptureBackend>) -> Vec<&'static str> {
    backends.into_iter().fold(Vec::new(), |mut names, backend| {
        let name = capture_backend_name(backend);
        if !names.contains(&name) {
            names.push(name);
        }
        names
    })
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

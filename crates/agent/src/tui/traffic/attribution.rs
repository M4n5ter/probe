use probe_core::is_libpcap_unknown_process_candidate;

use super::event_ref::TrafficEventRef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrafficAttribution {
    Attributed {
        process_name: String,
        pid: u32,
        confidence: u8,
    },
    LibpcapUnknownProcessCandidate {
        selected_scope: Option<String>,
    },
    Provider,
}

impl TrafficAttribution {
    pub(super) fn from_eventless_provider() -> Self {
        Self::Provider
    }

    pub(super) fn from_event(event: TrafficEventRef<'_>) -> Self {
        let Some(flow) = event.flow() else {
            return Self::from_eventless_provider();
        };

        if is_libpcap_unknown_process_candidate(event.origin().source(), flow) {
            Self::LibpcapUnknownProcessCandidate {
                selected_scope: None,
            }
        } else {
            Self::Attributed {
                process_name: flow.process.name.clone(),
                pid: flow.process.identity.pid,
                confidence: flow.attribution_confidence,
            }
        }
    }

    pub(super) fn apply_unknown_process_candidate_scope(&mut self, selected_scope: Option<&str>) {
        if let Self::LibpcapUnknownProcessCandidate {
            selected_scope: scope,
        } = self
        {
            *scope = selected_scope.map(str::to_string);
        }
    }

    pub(super) fn process_label(&self) -> String {
        match self {
            Self::Attributed {
                process_name, pid, ..
            } => format!("{process_name} ({pid})"),
            Self::LibpcapUnknownProcessCandidate {
                selected_scope: Some(selected_scope),
            } => format!("{selected_scope} candidate"),
            Self::LibpcapUnknownProcessCandidate {
                selected_scope: None,
            } => "unknown candidate".to_string(),
            Self::Provider => "provider".to_string(),
        }
    }

    pub(super) fn preview_lines(&self) -> Vec<String> {
        match self {
            Self::Attributed {
                process_name, pid, ..
            } => vec![format!("Process: {process_name} pid={pid}")],
            Self::LibpcapUnknownProcessCandidate {
                selected_scope: Some(selected_scope),
            } => vec![
                format!("Process: libpcap candidate for {selected_scope}"),
                "Process match: packet flow matched the selected traffic, but process attribution is unavailable".to_string(),
            ],
            Self::LibpcapUnknownProcessCandidate {
                selected_scope: None,
            } => vec![
                "Process: unknown libpcap candidate".to_string(),
                "Process match: packet flow matched the selected traffic, but process attribution is unavailable".to_string(),
            ],
            Self::Provider => Vec::new(),
        }
    }

    pub(super) fn detail_lines(&self) -> Vec<String> {
        match self {
            Self::Attributed { confidence, .. } => {
                if *confidence < 100 {
                    vec![format!(
                        "Process match: best-effort attribution ({confidence}% confidence)"
                    )]
                } else {
                    Vec::new()
                }
            }
            Self::LibpcapUnknownProcessCandidate { selected_scope } => {
                let mut lines = vec![
                    "Process match: libpcap unknown-process candidate".to_string(),
                    "Process match reason: passive packet capture matched the selected flow constraints, but no process owner was attributed".to_string(),
                ];
                if let Some(selected_scope) = selected_scope {
                    lines.push(format!("Process candidate scope: {selected_scope}"));
                }
                lines
            }
            Self::Provider => Vec::new(),
        }
    }
}

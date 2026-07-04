use probe_core::is_libpcap_unknown_process_candidate;

use super::event_ref::TrafficEventRef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrafficAttribution {
    Attributed {
        process_name: String,
        pid: u32,
        confidence: u8,
    },
    LibpcapUnknownProcessCandidate,
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
            Self::LibpcapUnknownProcessCandidate
        } else {
            Self::Attributed {
                process_name: flow.process.name.clone(),
                pid: flow.process.identity.pid,
                confidence: flow.attribution_confidence,
            }
        }
    }

    pub(super) fn process_label(&self) -> String {
        match self {
            Self::Attributed {
                process_name, pid, ..
            } => format!("{process_name} ({pid})"),
            Self::LibpcapUnknownProcessCandidate => "unknown candidate".to_string(),
            Self::Provider => "provider".to_string(),
        }
    }

    pub(super) fn preview_lines(&self) -> Vec<String> {
        match self {
            Self::Attributed {
                process_name, pid, ..
            } => vec![format!("Process: {process_name} pid={pid}")],
            Self::LibpcapUnknownProcessCandidate => vec![
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
            Self::LibpcapUnknownProcessCandidate => vec![
                "Process match: libpcap unknown-process candidate".to_string(),
                "Process match reason: passive packet capture matched the selected flow constraints, but no process owner was attributed".to_string(),
            ],
            Self::Provider => Vec::new(),
        }
    }
}

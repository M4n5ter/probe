use std::collections::BTreeSet;

use probe_core::{
    CompiledSelector, Direction, EventType, FlowContext, Selector, SelectorError,
    is_libpcap_unknown_process_candidate,
};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::model::{EventTailAttributionMode, EventTailEvent};

const MAX_UNKNOWN_PROCESS_CANDIDATE_LISTENER_PORTS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnknownProcessCandidateSelector {
    #[serde(default)]
    listener_ports: Vec<u16>,
}

impl UnknownProcessCandidateSelector {
    pub(crate) const MAX_LISTENER_PORTS: usize = MAX_UNKNOWN_PROCESS_CANDIDATE_LISTENER_PORTS;

    pub(crate) fn from_listener_ports(ports: impl IntoIterator<Item = u16>) -> Option<Self> {
        Self::try_from_listener_ports(ports).ok().flatten()
    }

    pub(crate) fn try_from_listener_ports(
        ports: impl IntoIterator<Item = u16>,
    ) -> Result<Option<Self>, UnknownProcessCandidateSelectorError> {
        let listener_ports = sorted_ports(ports);
        if listener_ports.len() > Self::MAX_LISTENER_PORTS {
            return Err(UnknownProcessCandidateSelectorError::TooManyListenerPorts {
                count: listener_ports.len(),
                max: Self::MAX_LISTENER_PORTS,
            });
        }
        Ok((!listener_ports.is_empty()).then_some(Self { listener_ports }))
    }

    pub(crate) fn listener_ports(&self) -> &[u16] {
        &self.listener_ports
    }

    fn matches_flow(&self, flow: &FlowContext) -> bool {
        self.listener_ports.binary_search(&flow.local.port).is_ok()
            || self.listener_ports.binary_search(&flow.remote.port).is_ok()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum UnknownProcessCandidateSelectorError {
    #[error("unknown-process candidate selector has {count} listener ports, maximum is {max}")]
    TooManyListenerPorts { count: usize, max: usize },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownProcessCandidateSelectorWire {
    #[serde(default)]
    listener_ports: Vec<u16>,
}

impl<'de> Deserialize<'de> for UnknownProcessCandidateSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UnknownProcessCandidateSelectorWire::deserialize(deserializer)?;
        Self::try_from_listener_ports(wire.listener_ports)
            .map_err(serde::de::Error::custom)?
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "unknown-process candidate selector requires at least one listener port",
                )
            })
    }
}

pub(super) struct TailEventSelectorFilter {
    selector: Option<CompiledSelector>,
    unknown_process_candidate_selector: Option<UnknownProcessCandidateSelector>,
}

pub(super) struct EventTypeFilter<'a> {
    event_types: &'a [EventType],
}

impl<'a> EventTypeFilter<'a> {
    pub(super) fn new(event_types: &'a [EventType]) -> Self {
        Self { event_types }
    }

    pub(super) fn matches(&self, event: &EventTailEvent) -> bool {
        self.event_types.is_empty() || self.event_types.contains(&event.kind.event_type())
    }
}

impl TailEventSelectorFilter {
    pub(super) fn compile(
        selector: Option<&Selector>,
        unknown_process_candidate_selector: Option<UnknownProcessCandidateSelector>,
    ) -> Result<Self, SelectorError> {
        Ok(Self {
            selector: selector.map(Selector::compile).transpose()?,
            unknown_process_candidate_selector,
        })
    }

    pub(super) fn is_filtered(&self) -> bool {
        self.selector.is_some() || self.unknown_process_candidate_selector.is_some()
    }

    pub(super) fn matches(&self, event: &EventTailEvent, mode: EventTailAttributionMode) -> bool {
        if !self.is_filtered() {
            return true;
        }
        let Some(flow) = event.flow.as_ref() else {
            return false;
        };
        let direction = event.kind.direction();
        self.selector
            .as_ref()
            .is_some_and(|selector| selector_matches_tail_flow(selector, flow, direction))
            || (mode == EventTailAttributionMode::IncludeUnknownProcess
                && is_libpcap_unknown_process_event(event)
                && self
                    .unknown_process_candidate_selector
                    .as_ref()
                    .is_some_and(|selector| selector.matches_flow(flow)))
    }
}

fn selector_matches_tail_flow(
    selector: &CompiledSelector,
    flow: &FlowContext,
    direction: Option<Direction>,
) -> bool {
    direction.map_or_else(
        || selector.matches_flow_without_direction(flow),
        |direction| selector.matches_flow(flow, direction),
    )
}

fn is_libpcap_unknown_process_event(event: &EventTailEvent) -> bool {
    event
        .flow
        .as_ref()
        .is_some_and(|flow| is_libpcap_unknown_process_candidate(event.origin.source(), flow))
}

fn sorted_ports(ports: impl IntoIterator<Item = u16>) -> Vec<u16> {
    ports
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_process_candidate_selector_sorts_and_deduplicates_ports() {
        let selector = UnknownProcessCandidateSelector::from_listener_ports([8081, 8080, 8081])
            .expect("ports should produce selector");

        assert_eq!(selector.listener_ports(), &[8080, 8081]);
    }

    #[test]
    fn unknown_process_candidate_selector_deserializes_to_normalized_ports()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector: UnknownProcessCandidateSelector =
            serde_json::from_value(serde_json::json!({
                "listener_ports": [8081, 80, 8081, 8080]
            }))?;

        assert_eq!(selector.listener_ports(), &[80, 8080, 8081]);
        Ok(())
    }

    #[test]
    fn unknown_process_candidate_selector_rejects_empty_wire_ports() {
        let error = serde_json::from_value::<UnknownProcessCandidateSelector>(
            serde_json::json!({ "listener_ports": [] }),
        )
        .expect_err("empty candidate selector should be rejected");

        assert!(error.to_string().contains("at least one listener port"));
    }

    #[test]
    fn unknown_process_candidate_selector_rejects_oversized_wire_ports() {
        let error = serde_json::from_value::<UnknownProcessCandidateSelector>(serde_json::json!({
            "listener_ports": (1..=UnknownProcessCandidateSelector::MAX_LISTENER_PORTS + 1)
                .collect::<Vec<_>>()
        }))
        .expect_err("oversized candidate selector should be rejected");

        assert!(error.to_string().contains("maximum"));
    }
}

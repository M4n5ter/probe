use std::collections::{HashMap, HashSet};

use probe_core::{Direction, EnforcementEvidence, FlowContext, FlowIdentity, Gap, Timestamp};

use crate::{
    CaptureEvent, CapturedBytes, CapturedGap, EnforcementEvidencePropagation, PlaintextEvent,
    PlaintextEventKind, PlaintextGap, PlaintextSource,
};

use super::Tls13SessionSecretDecryptingStreamKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Tls13SessionSecretFlowRegistry {
    streams: HashMap<Tls13SessionSecretDecryptingStreamKey, Tls13SessionSecretSuppressedStream>,
    closed_flows: HashSet<FlowIdentity>,
}

impl Tls13SessionSecretFlowRegistry {
    pub(super) fn new() -> Self {
        Self {
            streams: HashMap::new(),
            closed_flows: HashSet::new(),
        }
    }

    pub(super) fn flow_is_closed(&self, flow: &FlowIdentity) -> bool {
        self.closed_flows.contains(flow)
    }

    pub(super) fn contains(&self, key: &Tls13SessionSecretDecryptingStreamKey) -> bool {
        self.streams.contains_key(key)
    }

    pub(super) fn insert(&mut self, key: Tls13SessionSecretDecryptingStreamKey, flow: FlowContext) {
        self.streams
            .insert(key, Tls13SessionSecretSuppressedStream::new(flow));
    }

    pub(super) fn has_flow(&self, flow: &FlowIdentity) -> bool {
        self.streams.keys().any(|key| key.flow == *flow)
    }

    pub(super) fn observe_stream(
        &mut self,
        key: &Tls13SessionSecretDecryptingStreamKey,
        observation: Tls13SessionSecretStreamObservation,
    ) {
        if let Some(stream) = self.streams.get_mut(key) {
            stream.observe(observation);
        }
    }

    pub(super) fn observe_flow_timestamp(&mut self, flow: &FlowIdentity, timestamp: Timestamp) {
        for (key, stream) in &mut self.streams {
            if key.flow == *flow {
                stream.observe_timestamp(timestamp);
            }
        }
    }

    pub(super) fn remove_flow(&mut self, flow: &FlowIdentity) {
        self.streams.retain(|key, _| key.flow != *flow);
    }

    pub(super) fn record_flow_closed(&mut self, flow: &FlowIdentity) {
        self.closed_flows.insert(flow.clone());
        self.remove_flow(flow);
    }

    pub(super) fn clear_streams(&mut self) {
        self.streams.clear();
    }

    pub(super) fn bound_flow_finish_events(&self) -> Vec<(FlowContext, Option<Timestamp>)> {
        let mut flows: Vec<(FlowContext, Option<Timestamp>)> = Vec::new();
        for stream in self.streams.values() {
            let timestamp = stream.last_timestamp();
            match flows.iter_mut().find(|(flow, _)| flow.id == stream.flow.id) {
                Some((_, existing_timestamp)) => {
                    if let Some(timestamp) = timestamp
                        && existing_timestamp
                            .map(|existing| is_later_timestamp(timestamp, existing))
                            .unwrap_or(true)
                    {
                        *existing_timestamp = Some(timestamp);
                    }
                }
                None => flows.push((stream.flow.clone(), timestamp)),
            }
        }
        flows
    }

    pub(super) fn record_plaintext_progress(&mut self, events: &[PlaintextEvent]) {
        for event in events {
            match &event.kind {
                PlaintextEventKind::Bytes(bytes) => self.record_plaintext_offset(
                    &bytes.flow.id,
                    bytes.direction,
                    bytes.stream_offset.saturating_add(bytes.bytes.len() as u64),
                ),
                PlaintextEventKind::Gap(gap) => self.record_plaintext_offset(
                    &gap.flow.id,
                    gap.gap.direction,
                    gap.gap.next_offset.unwrap_or(gap.gap.expected_offset),
                ),
                PlaintextEventKind::ConnectionOpened(_)
                | PlaintextEventKind::ConnectionClosed(_) => {}
            }
        }
    }

    pub(super) fn record_plaintext_materialized(
        &mut self,
        events: &[CaptureEvent],
        mut preserve_observation: impl FnMut(&FlowIdentity, Direction) -> bool,
    ) {
        for event in events {
            match event {
                CaptureEvent::Bytes(bytes) => {
                    if !preserve_observation(&bytes.flow.id, bytes.direction) {
                        self.clear_observation(&bytes.flow.id, bytes.direction);
                    }
                }
                CaptureEvent::Gap(gap) => {
                    if !preserve_observation(&gap.flow.id, gap.gap.direction) {
                        self.clear_observation(&gap.flow.id, gap.gap.direction);
                    }
                }
                CaptureEvent::Loss(_)
                | CaptureEvent::ConnectionOpened { .. }
                | CaptureEvent::ConnectionClosed { .. } => {}
            }
        }
    }

    pub(super) fn record_ciphertext_consumed(
        &mut self,
        key: &Tls13SessionSecretDecryptingStreamKey,
    ) {
        if let Some(stream) = self.streams.get_mut(key) {
            stream.clear_observation();
        }
    }

    pub(super) fn stream_evidence(
        &self,
        flow: &FlowIdentity,
        direction: Direction,
    ) -> Option<Tls13SessionSecretEventEvidence> {
        self.streams
            .get(&Tls13SessionSecretDecryptingStreamKey::new(
                flow.clone(),
                direction,
            ))
            .and_then(Tls13SessionSecretSuppressedStream::event_evidence)
    }

    pub(super) fn flow_evidence(
        &self,
        flow: &FlowIdentity,
    ) -> Option<Tls13SessionSecretEventEvidence> {
        self.streams
            .iter()
            .filter(|(key, _)| key.flow == *flow)
            .filter_map(|(_, stream)| stream.event_evidence())
            .reduce(|current, incoming| current.merged(incoming))
    }

    pub(super) fn observation_only_gaps_before_plaintext_finalization(
        &self,
        flow: &FlowContext,
        timestamp: Timestamp,
        plaintext_events: &[PlaintextEvent],
    ) -> Vec<PlaintextEvent> {
        let mut gaps = Vec::new();
        for direction in [Direction::Inbound, Direction::Outbound] {
            let key = Tls13SessionSecretDecryptingStreamKey::new(flow.id.clone(), direction);
            if plaintext_events_cover_stream(plaintext_events, &key) {
                continue;
            }
            let Some(stream) = self.streams.get(&key) else {
                continue;
            };
            let Some(evidence) = stream.event_evidence() else {
                continue;
            };
            if !evidence.is_observation_only() {
                continue;
            }
            gaps.push(PlaintextEvent::gap(
                PlaintextSource::TlsSessionSecret,
                PlaintextGap::new(
                    timestamp,
                    stream.flow.clone(),
                    Gap {
                        direction,
                        expected_offset: stream.next_plaintext_offset(),
                        next_offset: None,
                        reason: "TLS session-secret ciphertext suppressed after stream became undecryptable".to_string(),
                    },
                ),
            ));
        }
        gaps
    }

    fn record_plaintext_offset(
        &mut self,
        flow: &FlowIdentity,
        direction: Direction,
        next_plaintext_offset: u64,
    ) {
        if let Some(stream) = self
            .streams
            .get_mut(&Tls13SessionSecretDecryptingStreamKey::new(
                flow.clone(),
                direction,
            ))
        {
            stream.record_plaintext_offset(next_plaintext_offset);
        }
    }

    fn clear_observation(&mut self, flow: &FlowIdentity, direction: Direction) {
        if let Some(stream) = self
            .streams
            .get_mut(&Tls13SessionSecretDecryptingStreamKey::new(
                flow.clone(),
                direction,
            ))
        {
            stream.clear_observation();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tls13SessionSecretSuppressedStream {
    flow: FlowContext,
    observation: Option<Tls13SessionSecretStreamObservation>,
    next_plaintext_offset: u64,
}

impl Tls13SessionSecretSuppressedStream {
    fn new(flow: FlowContext) -> Self {
        Self {
            flow,
            observation: None,
            next_plaintext_offset: 0,
        }
    }

    fn observe(&mut self, observation: Tls13SessionSecretStreamObservation) {
        match &mut self.observation {
            Some(current) => current.merge(observation),
            None => self.observation = Some(observation),
        }
    }

    fn observe_timestamp(&mut self, timestamp: Timestamp) {
        match &mut self.observation {
            Some(observation) => observation.observe_timestamp(timestamp),
            None => {
                self.observation = Some(Tls13SessionSecretStreamObservation::default_at(timestamp));
            }
        }
    }

    fn last_timestamp(&self) -> Option<Timestamp> {
        self.observation
            .as_ref()
            .map(Tls13SessionSecretStreamObservation::timestamp)
    }

    fn event_evidence(&self) -> Option<Tls13SessionSecretEventEvidence> {
        self.observation
            .as_ref()
            .map(Tls13SessionSecretStreamObservation::event_evidence)
    }

    fn record_plaintext_offset(&mut self, next_plaintext_offset: u64) {
        self.next_plaintext_offset = next_plaintext_offset;
    }

    fn clear_observation(&mut self) {
        self.observation = None;
    }

    fn next_plaintext_offset(&self) -> u64 {
        self.next_plaintext_offset
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Tls13SessionSecretStreamObservation {
    timestamp: Timestamp,
    event_evidence: Tls13SessionSecretEventEvidence,
}

impl Tls13SessionSecretStreamObservation {
    pub(super) fn from_capture_bytes(bytes: &CapturedBytes) -> Self {
        Self {
            timestamp: bytes.timestamp,
            event_evidence: Tls13SessionSecretEventEvidence {
                enforcement_evidence: bytes.enforcement_evidence.clone(),
                enforcement_evidence_propagation: bytes.enforcement_evidence_propagation,
            },
        }
    }

    pub(super) fn from_capture_gap(gap: &CapturedGap) -> Self {
        Self {
            timestamp: gap.timestamp,
            event_evidence: Tls13SessionSecretEventEvidence {
                enforcement_evidence: gap.enforcement_evidence.clone(),
                enforcement_evidence_propagation: gap.enforcement_evidence_propagation,
            },
        }
    }

    fn default_at(timestamp: Timestamp) -> Self {
        Self {
            timestamp,
            event_evidence: Tls13SessionSecretEventEvidence::default(),
        }
    }

    fn merge(&mut self, observation: Self) {
        self.observe_timestamp(observation.timestamp);
        self.event_evidence.merge(observation.event_evidence);
    }

    fn observe_timestamp(&mut self, timestamp: Timestamp) {
        if is_later_timestamp(timestamp, self.timestamp) {
            self.timestamp = timestamp;
        }
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    fn event_evidence(&self) -> Tls13SessionSecretEventEvidence {
        self.event_evidence.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Tls13SessionSecretEventEvidence {
    enforcement_evidence: EnforcementEvidence,
    enforcement_evidence_propagation: EnforcementEvidencePropagation,
}

impl Tls13SessionSecretEventEvidence {
    fn merge(&mut self, incoming: Self) {
        self.enforcement_evidence = strongest_enforcement_evidence(
            self.enforcement_evidence.clone(),
            incoming.enforcement_evidence,
        );
        self.enforcement_evidence_propagation = strongest_enforcement_evidence_propagation(
            self.enforcement_evidence_propagation,
            incoming.enforcement_evidence_propagation,
        );
    }

    pub(super) fn merged(mut self, incoming: Self) -> Self {
        self.merge(incoming);
        self
    }

    pub(super) fn is_observation_only(&self) -> bool {
        matches!(
            self.enforcement_evidence,
            EnforcementEvidence::ObservationOnly { .. }
        )
    }
}

impl Default for Tls13SessionSecretEventEvidence {
    fn default() -> Self {
        Self {
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }
    }
}

fn is_later_timestamp(left: Timestamp, right: Timestamp) -> bool {
    (left.monotonic_ns, left.wall_time_unix_ns) > (right.monotonic_ns, right.wall_time_unix_ns)
}

pub(super) fn apply_enforcement_evidence(
    event: &mut CaptureEvent,
    evidence: Tls13SessionSecretEventEvidence,
) {
    match event {
        CaptureEvent::Bytes(bytes) => {
            bytes.enforcement_evidence = evidence.enforcement_evidence;
            bytes.enforcement_evidence_propagation = evidence.enforcement_evidence_propagation;
        }
        CaptureEvent::Gap(gap) => {
            gap.enforcement_evidence = evidence.enforcement_evidence;
            gap.enforcement_evidence_propagation = evidence.enforcement_evidence_propagation;
        }
        CaptureEvent::Loss(_)
        | CaptureEvent::ConnectionOpened { .. }
        | CaptureEvent::ConnectionClosed { .. } => {}
    }
}

fn strongest_enforcement_evidence(
    current: EnforcementEvidence,
    incoming: EnforcementEvidence,
) -> EnforcementEvidence {
    if matches!(current, EnforcementEvidence::ObservationOnly { .. }) {
        current
    } else {
        incoming
    }
}

fn plaintext_events_cover_stream(
    events: &[PlaintextEvent],
    key: &Tls13SessionSecretDecryptingStreamKey,
) -> bool {
    events.iter().any(|event| match &event.kind {
        PlaintextEventKind::Bytes(bytes) => {
            bytes.flow.id == key.flow && bytes.direction == key.direction
        }
        PlaintextEventKind::Gap(gap) => {
            gap.flow.id == key.flow && gap.gap.direction == key.direction
        }
        PlaintextEventKind::ConnectionOpened(_) | PlaintextEventKind::ConnectionClosed(_) => false,
    })
}

fn strongest_enforcement_evidence_propagation(
    current: EnforcementEvidencePropagation,
    incoming: EnforcementEvidencePropagation,
) -> EnforcementEvidencePropagation {
    if current.is_flow_carried() || incoming.is_flow_carried() {
        EnforcementEvidencePropagation::Flow
    } else {
        EnforcementEvidencePropagation::Event
    }
}

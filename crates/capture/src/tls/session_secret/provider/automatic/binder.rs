use std::collections::{HashMap, VecDeque};

use probe_core::{Direction, FlowContext, FlowIdentity};

use crate::tls::{TlsRandom, TlsSessionSecretLookupTime};
use crate::{CaptureEvent, CapturedBytes};

use super::super::super::{
    Tls13ApplicationDataDecryptor, Tls13ApplicationTrafficSecretKind,
    Tls13SessionSecretFlowBinding, Tls13SessionSecretFlowBindingPlanner,
    Tls13SessionSecretFlowCandidate, Tls13SessionSecretHandshakeObservation,
    Tls13SessionSecretHandshakeObservationKind, Tls13SessionSecretHandshakeObserver,
    Tls13SessionSecretStreamCursor, TlsCipherSuite, TlsSessionSecretStore,
    binding::Tls13SessionSecretMissingPlaintextPrefix,
    frame::{TLS13_OUTER_APPLICATION_DATA, Tls13BufferedRecord, Tls13RecordFrame, TlsRecordHeader},
};
use super::super::Tls13SessionSecretDecryptingStreamKey;
use super::TLS13_AUTO_BIND_MAX_SEQUENCE_NUMBER;
use super::buffered::{Tls13SessionSecretBufferedBytes, sliced_event};
use super::candidates::{Tls13SessionSecretCandidate, Tls13SessionSecretCandidateSet};

const TLS13_AUTO_BIND_MAX_CANDIDATES: usize = 2048;
const TLS13_AUTO_BIND_MAX_RESYNC_RECORDS: u8 = 32;

pub(in crate::tls::session_secret::provider) struct Tls13SessionSecretAutomaticBinder {
    store: Option<TlsSessionSecretStore>,
    observer: Tls13SessionSecretHandshakeObserver,
    handshake_facts: Tls13SessionSecretHandshakeFacts,
    candidates: Tls13SessionSecretCandidateSet,
}

impl Tls13SessionSecretAutomaticBinder {
    pub(in crate::tls::session_secret::provider) fn new(
        store: Option<TlsSessionSecretStore>,
    ) -> Self {
        Self {
            store,
            observer: Tls13SessionSecretHandshakeObserver::new(),
            handshake_facts: Tls13SessionSecretHandshakeFacts::new(TLS13_AUTO_BIND_MAX_CANDIDATES),
            candidates: Tls13SessionSecretCandidateSet::new(TLS13_AUTO_BIND_MAX_CANDIDATES),
        }
    }

    pub(in crate::tls::session_secret::provider) fn replace_store(
        &mut self,
        store: TlsSessionSecretStore,
    ) {
        self.store = Some(store);
        let store = self.store.as_ref();
        self.candidates
            .activate_waiting_candidates(|intent| candidate_has_usable_material(store, intent));
    }

    pub(in crate::tls::session_secret::provider) fn observe_and_bind(
        &mut self,
        event: CaptureEvent,
    ) -> Tls13SessionSecretAutomaticAction {
        let mut released_events = self.release_buffered_events_before_current_event(&event);
        released_events.extend(self.release_terminal_candidate_events(&event));
        for observation in self.observer.push_capture_event(&event) {
            released_events.extend(self.observe_handshake(observation));
        }
        let CaptureEvent::Bytes(bytes) = event else {
            released_events.push(event);
            return Tls13SessionSecretAutomaticAction::PassThrough {
                events: released_events,
            };
        };
        match self.try_bind_candidate(bytes) {
            Tls13SessionSecretCandidateAction::Process { event } => {
                released_events.push(*event);
                Tls13SessionSecretAutomaticAction::PassThrough {
                    events: released_events,
                }
            }
            Tls13SessionSecretCandidateAction::Queue { events } => {
                released_events.extend(events);
                Tls13SessionSecretAutomaticAction::PassThrough {
                    events: released_events,
                }
            }
            Tls13SessionSecretCandidateAction::Bind {
                raw_prefix_events,
                binding,
                bytes,
            } => Tls13SessionSecretAutomaticAction::BindAndProcess {
                released_events,
                raw_prefix_events,
                binding,
                bytes,
            },
        }
    }

    pub(in crate::tls::session_secret::provider) fn release_buffered_events(
        &mut self,
    ) -> Vec<CaptureEvent> {
        self.candidates.release_buffered_events()
    }

    fn release_buffered_events_before_current_event(
        &mut self,
        event: &CaptureEvent,
    ) -> Vec<CaptureEvent> {
        if !self.candidates.has_buffered_candidate() {
            return Vec::new();
        }
        let CaptureEvent::Bytes(bytes) = event else {
            return self.candidates.release_buffered_events();
        };
        let key =
            Tls13SessionSecretDecryptingStreamKey::new(bytes.flow.id.clone(), bytes.direction);
        if self.candidates.key_has_buffered_candidate(&key) {
            Vec::new()
        } else {
            self.candidates.release_buffered_events()
        }
    }

    fn observe_handshake(
        &mut self,
        observation: Tls13SessionSecretHandshakeObservation,
    ) -> Vec<CaptureEvent> {
        let Tls13SessionSecretHandshakeObservationKind::ClientHello { client_random } =
            observation.kind()
        else {
            let Tls13SessionSecretHandshakeObservationKind::ServerHello { cipher_suite, .. } =
                observation.kind()
            else {
                return Vec::new();
            };
            return self.observe_server_hello(observation.flow().id.clone(), *cipher_suite);
        };
        let Ok(lookup_time) = TlsSessionSecretLookupTime::from_timestamp(observation.timestamp())
        else {
            return Vec::new();
        };
        let lookup_time = Some(lookup_time);
        let mut released_events = self.insert_candidate(
            observation.flow().clone(),
            observation.direction(),
            *client_random,
            Tls13ApplicationTrafficSecretKind::Client,
            observation.next_record_offset(),
            lookup_time,
        );
        released_events.extend(self.insert_candidate(
            observation.flow().clone(),
            opposite_direction(observation.direction()),
            *client_random,
            Tls13ApplicationTrafficSecretKind::Server,
            0,
            lookup_time,
        ));
        released_events
    }

    fn observe_server_hello(
        &mut self,
        flow: FlowIdentity,
        cipher_suite: TlsCipherSuite,
    ) -> Vec<CaptureEvent> {
        self.handshake_facts
            .observe_server_hello(flow.clone(), cipher_suite);
        self.candidates.update_flow_candidates(&flow, |intent| {
            self.handshake_facts.apply_to_intent(intent);
        });
        let store = self.store.as_ref();
        self.candidates
            .activate_waiting_candidates(|intent| candidate_has_usable_material(store, intent));
        Vec::new()
    }

    fn insert_candidate(
        &mut self,
        flow: FlowContext,
        direction: Direction,
        client_random: TlsRandom,
        secret_kind: Tls13ApplicationTrafficSecretKind,
        next_probe_offset: u64,
        lookup_time: Option<TlsSessionSecretLookupTime>,
    ) -> Vec<CaptureEvent> {
        let key = Tls13SessionSecretDecryptingStreamKey::new(flow.id.clone(), direction);
        if self.candidates.key_has_probing_candidate(&key) {
            return Vec::new();
        }
        let mut intent = Tls13SessionSecretBindingIntent::new(
            flow,
            direction,
            client_random,
            secret_kind,
            next_probe_offset,
            lookup_time,
        );
        self.handshake_facts.apply_to_intent(&mut intent);
        if candidate_has_usable_material(self.store.as_ref(), &intent) {
            self.candidates.insert(
                key,
                Tls13SessionSecretCandidate::Probing(
                    Tls13SessionSecretBindingCandidate::from_intent(intent),
                ),
            )
        } else {
            self.candidates
                .insert(key, Tls13SessionSecretCandidate::WaitingForMaterial(intent))
        }
    }

    fn release_terminal_candidate_events(&mut self, event: &CaptureEvent) -> Vec<CaptureEvent> {
        match event {
            CaptureEvent::Gap(gap) => {
                let key = Tls13SessionSecretDecryptingStreamKey::new(
                    gap.flow.id.clone(),
                    gap.gap.direction,
                );
                self.candidates.remove_candidate(&key)
            }
            CaptureEvent::ConnectionClosed { flow, .. } => {
                self.handshake_facts.remove_flow(&flow.id);
                self.candidates.remove_flow_candidates(&flow.id)
            }
            CaptureEvent::Bytes(_)
            | CaptureEvent::ConnectionOpened { .. }
            | CaptureEvent::Loss(_) => Vec::new(),
        }
    }

    fn try_bind_candidate(&mut self, bytes: CapturedBytes) -> Tls13SessionSecretCandidateAction {
        let key =
            Tls13SessionSecretDecryptingStreamKey::new(bytes.flow.id.clone(), bytes.direction);
        let Some(mut taken) = self.candidates.take(&key) else {
            return Tls13SessionSecretCandidateAction::Process {
                event: Box::new(CaptureEvent::Bytes(bytes)),
            };
        };
        let outcome = self.probe_candidate(&mut taken.candidate, bytes);
        match outcome {
            Tls13SessionSecretCandidateProbe::Continue { event } => {
                self.candidates.restore(key, taken);
                Tls13SessionSecretCandidateAction::Process {
                    event: Box::new(event),
                }
            }
            Tls13SessionSecretCandidateProbe::Buffered { prefix_events } => {
                self.candidates.restore(key, taken);
                Tls13SessionSecretCandidateAction::Queue {
                    events: prefix_events,
                }
            }
            Tls13SessionSecretCandidateProbe::Terminal { prefix_events } => {
                Tls13SessionSecretCandidateAction::Queue {
                    events: prefix_events,
                }
            }
            Tls13SessionSecretCandidateProbe::ReleaseBuffered {
                prefix_events,
                trailing_events,
            } => {
                self.candidates.restore(key, taken);
                let mut events = prefix_events;
                events.extend(self.candidates.release_buffered_events());
                events.extend(trailing_events);
                Tls13SessionSecretCandidateAction::Queue { events }
            }
            Tls13SessionSecretCandidateProbe::Bind {
                raw_prefix_events,
                bytes,
                binding,
            } => Tls13SessionSecretCandidateAction::Bind {
                raw_prefix_events,
                binding,
                bytes: Box::new(bytes),
            },
        }
    }

    fn probe_candidate(
        &self,
        candidate: &mut Tls13SessionSecretBindingCandidate,
        bytes: CapturedBytes,
    ) -> Tls13SessionSecretCandidateProbe {
        let Some(mut held) = candidate.held.take() else {
            return self.probe_fresh_candidate(candidate, bytes);
        };
        if !held.append(&bytes) {
            candidate.held = Some(held);
            return Tls13SessionSecretCandidateProbe::ReleaseBuffered {
                prefix_events: Vec::new(),
                trailing_events: vec![CaptureEvent::Bytes(bytes)],
            };
        }
        self.probe_buffered_candidate(candidate, held, Vec::new())
    }

    fn probe_fresh_candidate(
        &self,
        candidate: &mut Tls13SessionSecretBindingCandidate,
        bytes: CapturedBytes,
    ) -> Tls13SessionSecretCandidateProbe {
        let Some(end_offset) = bytes.stream_offset.checked_add(bytes.bytes.len() as u64) else {
            return Tls13SessionSecretCandidateProbe::Terminal {
                prefix_events: vec![CaptureEvent::Bytes(bytes)],
            };
        };
        if end_offset <= candidate.intent.next_probe_offset {
            return Tls13SessionSecretCandidateProbe::Continue {
                event: CaptureEvent::Bytes(bytes),
            };
        }
        let cursor = candidate
            .intent
            .next_probe_offset
            .saturating_sub(bytes.stream_offset)
            .min(bytes.bytes.len() as u64) as usize;
        let prefix_events = sliced_event(&bytes, 0, cursor).into_iter().collect();
        let Some(held) =
            Tls13SessionSecretBufferedBytes::from_slice(&bytes, cursor, bytes.bytes.len())
        else {
            return Tls13SessionSecretCandidateProbe::Terminal {
                prefix_events: vec![CaptureEvent::Bytes(bytes)],
            };
        };
        if held.is_empty() {
            return Tls13SessionSecretCandidateProbe::Continue {
                event: CaptureEvent::Bytes(bytes),
            };
        }
        self.probe_buffered_candidate(candidate, held, prefix_events)
    }

    fn probe_buffered_candidate(
        &self,
        candidate: &mut Tls13SessionSecretBindingCandidate,
        mut held: Tls13SessionSecretBufferedBytes,
        mut prefix_events: Vec<CaptureEvent>,
    ) -> Tls13SessionSecretCandidateProbe {
        let mut cursor = candidate
            .intent
            .next_probe_offset
            .saturating_sub(held.stream_offset())
            .min(held.payload().len() as u64) as usize;
        while cursor < held.payload().len() {
            match record_at(held.payload(), cursor) {
                Tls13SessionSecretProbeRecord::Incomplete => {
                    candidate.held = Some(held);
                    return Tls13SessionSecretCandidateProbe::Buffered { prefix_events };
                }
                Tls13SessionSecretProbeRecord::Invalid => {
                    candidate.held = Some(held);
                    return Tls13SessionSecretCandidateProbe::ReleaseBuffered {
                        prefix_events,
                        trailing_events: Vec::new(),
                    };
                }
                Tls13SessionSecretProbeRecord::Complete { len, content_type } => {
                    let Some(record_end_offset) =
                        held.stream_offset().checked_add((cursor + len) as u64)
                    else {
                        candidate.held = Some(held);
                        return Tls13SessionSecretCandidateProbe::ReleaseBuffered {
                            prefix_events,
                            trailing_events: Vec::new(),
                        };
                    };
                    candidate.resync_attempts = candidate.resync_attempts.saturating_add(1);
                    if content_type != TLS13_OUTER_APPLICATION_DATA {
                        if candidate.resync_attempts >= TLS13_AUTO_BIND_MAX_RESYNC_RECORDS {
                            candidate.held = Some(held);
                            return Tls13SessionSecretCandidateProbe::ReleaseBuffered {
                                prefix_events,
                                trailing_events: Vec::new(),
                            };
                        }
                        candidate.advance_probe_offset(record_end_offset);
                        cursor += len;
                        continue;
                    }
                    let Some(ciphertext_offset) = held.stream_offset().checked_add(cursor as u64)
                    else {
                        candidate.held = Some(held);
                        return Tls13SessionSecretCandidateProbe::ReleaseBuffered {
                            prefix_events,
                            trailing_events: Vec::new(),
                        };
                    };
                    let record = &held.payload()[cursor..cursor + len];
                    if let Some(binding) =
                        self.candidate_decrypts_at(candidate, ciphertext_offset, record)
                    {
                        prefix_events.extend(held.drain_prefix(cursor));
                        return Tls13SessionSecretCandidateProbe::Bind {
                            raw_prefix_events: prefix_events,
                            bytes: held.into_bytes(),
                            binding: Box::new(binding),
                        };
                    }
                    if candidate.resync_attempts >= TLS13_AUTO_BIND_MAX_RESYNC_RECORDS {
                        candidate.held = Some(held);
                        return Tls13SessionSecretCandidateProbe::ReleaseBuffered {
                            prefix_events,
                            trailing_events: Vec::new(),
                        };
                    }
                    candidate.advance_probe_offset(record_end_offset);
                    cursor += len;
                }
            }
        }
        candidate.held = Some(held);
        Tls13SessionSecretCandidateProbe::Buffered { prefix_events }
    }

    fn candidate_decrypts_at(
        &self,
        candidate: &Tls13SessionSecretBindingCandidate,
        ciphertext_offset: u64,
        record: &[u8],
    ) -> Option<Tls13SessionSecretFlowBinding> {
        let base_cursor = Tls13SessionSecretStreamCursor::resume_at(ciphertext_offset, 0, 0);
        let binding = self.binding_for_candidate(candidate, base_cursor)?;
        let decryptor =
            Tls13ApplicationDataDecryptor::from_application_traffic_secret(&binding.traffic_secret)
                .ok()?;
        let sequence_number = matching_sequence_number(&decryptor, record)?;
        let cursor =
            Tls13SessionSecretStreamCursor::resume_at(ciphertext_offset, 0, sequence_number);
        let binding = binding.with_cursor(cursor);
        Some(
            match Tls13SessionSecretMissingPlaintextPrefix::from_skipped_application_records(
                sequence_number,
            ) {
                Some(prefix) => binding.with_missing_plaintext_prefix(prefix),
                None => binding,
            },
        )
    }

    fn binding_for_candidate(
        &self,
        candidate: &Tls13SessionSecretBindingCandidate,
        cursor: Tls13SessionSecretStreamCursor,
    ) -> Option<Tls13SessionSecretFlowBinding> {
        binding_for_intent(self.store.as_ref(), &candidate.intent, cursor)
    }
}

fn matching_sequence_number(
    decryptor: &Tls13ApplicationDataDecryptor,
    record: &[u8],
) -> Option<u64> {
    (0..=TLS13_AUTO_BIND_MAX_SEQUENCE_NUMBER).find(|sequence_number| {
        decryptor
            .decrypt_record_at(*sequence_number, record)
            .is_ok()
    })
}

fn candidate_has_usable_material(
    store: Option<&TlsSessionSecretStore>,
    intent: &Tls13SessionSecretBindingIntent,
) -> bool {
    let Some(binding) = binding_for_intent(store, intent, Tls13SessionSecretStreamCursor::start())
    else {
        return false;
    };
    Tls13ApplicationDataDecryptor::from_application_traffic_secret(&binding.traffic_secret).is_ok()
}

fn binding_for_intent(
    store: Option<&TlsSessionSecretStore>,
    intent: &Tls13SessionSecretBindingIntent,
    cursor: Tls13SessionSecretStreamCursor,
) -> Option<Tls13SessionSecretFlowBinding> {
    let store = store?;
    let mut flow_candidate = Tls13SessionSecretFlowCandidate::resume_at(
        intent.flow.clone(),
        intent.direction,
        intent.client_random,
        intent.secret_kind,
        cursor,
    );
    if let Some(lookup_time) = intent.lookup_time {
        flow_candidate = flow_candidate.with_lookup_time(lookup_time);
    }
    if let Some(cipher_suite) = intent.observed_cipher_suite {
        flow_candidate = flow_candidate.with_observed_cipher_suite(cipher_suite);
    }
    Tls13SessionSecretFlowBindingPlanner::new(store)
        .plan(flow_candidate)
        .ok()
}

#[derive(Debug)]
pub(in crate::tls::session_secret::provider) enum Tls13SessionSecretAutomaticAction {
    PassThrough {
        events: Vec<CaptureEvent>,
    },
    BindAndProcess {
        released_events: Vec<CaptureEvent>,
        raw_prefix_events: Vec<CaptureEvent>,
        binding: Box<Tls13SessionSecretFlowBinding>,
        bytes: Box<CapturedBytes>,
    },
}

#[derive(Debug, Clone)]
pub(super) struct Tls13SessionSecretBindingIntent {
    flow: FlowContext,
    direction: Direction,
    client_random: TlsRandom,
    secret_kind: Tls13ApplicationTrafficSecretKind,
    next_probe_offset: u64,
    lookup_time: Option<TlsSessionSecretLookupTime>,
    observed_cipher_suite: Option<TlsCipherSuite>,
}

#[derive(Debug)]
pub(super) struct Tls13SessionSecretBindingCandidate {
    intent: Tls13SessionSecretBindingIntent,
    resync_attempts: u8,
    held: Option<Tls13SessionSecretBufferedBytes>,
}

impl Tls13SessionSecretBindingIntent {
    pub(super) fn new(
        flow: FlowContext,
        direction: Direction,
        client_random: TlsRandom,
        secret_kind: Tls13ApplicationTrafficSecretKind,
        next_probe_offset: u64,
        lookup_time: Option<TlsSessionSecretLookupTime>,
    ) -> Self {
        Self {
            flow,
            direction,
            client_random,
            secret_kind,
            next_probe_offset,
            lookup_time,
            observed_cipher_suite: None,
        }
    }

    pub(super) fn flow(&self) -> &FlowContext {
        &self.flow
    }

    fn set_observed_cipher_suite(&mut self, cipher_suite: TlsCipherSuite) {
        self.observed_cipher_suite = Some(cipher_suite);
    }
}

impl Tls13SessionSecretBindingCandidate {
    pub(super) fn from_intent(intent: Tls13SessionSecretBindingIntent) -> Self {
        Self {
            intent,
            resync_attempts: 0,
            held: None,
        }
    }

    pub(super) fn has_buffered_event(&self) -> bool {
        self.held.is_some()
    }

    pub(super) fn into_buffered_events(self) -> Vec<CaptureEvent> {
        self.held
            .map(Tls13SessionSecretBufferedBytes::into_events)
            .unwrap_or_default()
    }

    pub(super) fn intent(&self) -> &Tls13SessionSecretBindingIntent {
        &self.intent
    }

    pub(super) fn intent_mut(&mut self) -> &mut Tls13SessionSecretBindingIntent {
        &mut self.intent
    }

    fn advance_probe_offset(&mut self, offset: u64) {
        self.intent.next_probe_offset = self.intent.next_probe_offset.max(offset);
    }

    #[cfg(test)]
    pub(super) fn with_buffered_bytes(mut self, bytes: Tls13SessionSecretBufferedBytes) -> Self {
        self.held = Some(bytes);
        self
    }
}

enum Tls13SessionSecretCandidateAction {
    Process {
        event: Box<CaptureEvent>,
    },
    Queue {
        events: Vec<CaptureEvent>,
    },
    Bind {
        raw_prefix_events: Vec<CaptureEvent>,
        binding: Box<Tls13SessionSecretFlowBinding>,
        bytes: Box<CapturedBytes>,
    },
}

enum Tls13SessionSecretCandidateProbe {
    Continue {
        event: CaptureEvent,
    },
    Buffered {
        prefix_events: Vec<CaptureEvent>,
    },
    Terminal {
        prefix_events: Vec<CaptureEvent>,
    },
    Bind {
        raw_prefix_events: Vec<CaptureEvent>,
        bytes: CapturedBytes,
        binding: Box<Tls13SessionSecretFlowBinding>,
    },
    ReleaseBuffered {
        prefix_events: Vec<CaptureEvent>,
        trailing_events: Vec<CaptureEvent>,
    },
}

enum Tls13SessionSecretProbeRecord {
    Incomplete,
    Invalid,
    Complete { len: usize, content_type: u8 },
}

fn record_at(payload: &[u8], cursor: usize) -> Tls13SessionSecretProbeRecord {
    let suffix = &payload[cursor..];
    match Tls13RecordFrame::buffered(suffix) {
        Tls13BufferedRecord::Incomplete => Tls13SessionSecretProbeRecord::Incomplete,
        Tls13BufferedRecord::Invalid { .. } => Tls13SessionSecretProbeRecord::Invalid,
        Tls13BufferedRecord::Complete { len } => {
            let Some(header) = TlsRecordHeader::from_buffer(suffix) else {
                return Tls13SessionSecretProbeRecord::Incomplete;
            };
            Tls13SessionSecretProbeRecord::Complete {
                len,
                content_type: header.content_type(),
            }
        }
    }
}

fn opposite_direction(direction: Direction) -> Direction {
    match direction {
        Direction::Inbound => Direction::Outbound,
        Direction::Outbound => Direction::Inbound,
    }
}

#[derive(Debug)]
struct Tls13SessionSecretHandshakeFacts {
    by_flow: HashMap<FlowIdentity, TlsCipherSuite>,
    order: VecDeque<FlowIdentity>,
    max_flows: usize,
}

impl Tls13SessionSecretHandshakeFacts {
    fn new(max_flows: usize) -> Self {
        Self {
            by_flow: HashMap::new(),
            order: VecDeque::new(),
            max_flows,
        }
    }

    fn apply_to_intent(&self, intent: &mut Tls13SessionSecretBindingIntent) {
        if let Some(cipher_suite) = self.by_flow.get(&intent.flow.id).copied() {
            intent.set_observed_cipher_suite(cipher_suite);
        }
    }

    fn observe_server_hello(&mut self, flow: FlowIdentity, cipher_suite: TlsCipherSuite) {
        if self.max_flows == 0 {
            return;
        }
        if !self.by_flow.contains_key(&flow) {
            self.reserve_slot();
            self.order.push_back(flow.clone());
        }
        self.by_flow.insert(flow, cipher_suite);
    }

    fn remove_flow(&mut self, flow: &FlowIdentity) {
        self.by_flow.remove(flow);
        self.order.retain(|candidate| candidate != flow);
    }

    fn reserve_slot(&mut self) {
        while self.by_flow.len() >= self.max_flows {
            let Some(flow) = self.order.pop_front() else {
                self.by_flow.clear();
                return;
            };
            self.by_flow.remove(&flow);
        }
    }
}

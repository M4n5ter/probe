use std::collections::HashMap;

use probe_core::FlowIdentity;

use crate::CaptureEvent;

use super::super::Tls13SessionSecretDecryptingStreamKey;
use super::binder::{Tls13SessionSecretBindingCandidate, Tls13SessionSecretBindingIntent};

#[derive(Debug)]
pub(super) struct Tls13SessionSecretCandidateSet {
    candidates: HashMap<Tls13SessionSecretDecryptingStreamKey, Tls13SessionSecretCandidateSlot>,
    next_order: u64,
    max_candidates: usize,
}

#[derive(Debug)]
struct Tls13SessionSecretCandidateSlot {
    candidate: Tls13SessionSecretCandidate,
    order: u64,
}

#[derive(Debug)]
pub(super) struct Tls13SessionSecretTakenCandidate {
    pub(super) candidate: Tls13SessionSecretBindingCandidate,
    order: u64,
}

#[derive(Debug)]
pub(super) enum Tls13SessionSecretCandidate {
    WaitingForMaterial(Tls13SessionSecretBindingIntent),
    Probing(Tls13SessionSecretBindingCandidate),
}

impl Tls13SessionSecretCandidate {
    fn intent(&self) -> &Tls13SessionSecretBindingIntent {
        match self {
            Self::WaitingForMaterial(intent) => intent,
            Self::Probing(candidate) => candidate.intent(),
        }
    }

    fn intent_mut(&mut self) -> &mut Tls13SessionSecretBindingIntent {
        match self {
            Self::WaitingForMaterial(intent) => intent,
            Self::Probing(candidate) => candidate.intent_mut(),
        }
    }

    fn has_buffered_event(&self) -> bool {
        match self {
            Self::WaitingForMaterial(_) => false,
            Self::Probing(candidate) => candidate.has_buffered_event(),
        }
    }

    fn into_buffered_events(self) -> Vec<CaptureEvent> {
        match self {
            Self::WaitingForMaterial(_) => Vec::new(),
            Self::Probing(candidate) => candidate.into_buffered_events(),
        }
    }
}

impl From<Tls13SessionSecretBindingIntent> for Tls13SessionSecretCandidate {
    fn from(intent: Tls13SessionSecretBindingIntent) -> Self {
        Self::WaitingForMaterial(intent)
    }
}

impl From<Tls13SessionSecretBindingCandidate> for Tls13SessionSecretCandidate {
    fn from(candidate: Tls13SessionSecretBindingCandidate) -> Self {
        Self::Probing(candidate)
    }
}

impl Tls13SessionSecretCandidateSet {
    pub(super) fn new(max_candidates: usize) -> Self {
        Self {
            candidates: HashMap::new(),
            next_order: 0,
            max_candidates,
        }
    }

    pub(super) fn insert(
        &mut self,
        key: Tls13SessionSecretDecryptingStreamKey,
        candidate: impl Into<Tls13SessionSecretCandidate>,
    ) -> Vec<CaptureEvent> {
        let candidate = candidate.into();
        if self
            .candidates
            .get(&key)
            .is_some_and(|slot| slot.candidate.has_buffered_event())
        {
            return Vec::new();
        }
        let mut released_events = Vec::new();
        if !self.candidates.contains_key(&key) && !self.reserve_slot(&mut released_events) {
            return released_events;
        }
        let order = self
            .candidates
            .get(&key)
            .map(|slot| slot.order)
            .unwrap_or_else(|| self.allocate_order());
        self.candidates
            .insert(key, Tls13SessionSecretCandidateSlot { candidate, order });
        self.debug_assert_single_held_candidate();
        released_events
    }

    pub(super) fn take(
        &mut self,
        key: &Tls13SessionSecretDecryptingStreamKey,
    ) -> Option<Tls13SessionSecretTakenCandidate> {
        let slot = self.candidates.remove(key)?;
        match slot.candidate {
            Tls13SessionSecretCandidate::Probing(candidate) => {
                Some(Tls13SessionSecretTakenCandidate {
                    candidate,
                    order: slot.order,
                })
            }
            waiting @ Tls13SessionSecretCandidate::WaitingForMaterial(_) => {
                self.candidates.insert(
                    key.clone(),
                    Tls13SessionSecretCandidateSlot {
                        candidate: waiting,
                        order: slot.order,
                    },
                );
                None
            }
        }
    }

    pub(super) fn key_has_probing_candidate(
        &self,
        key: &Tls13SessionSecretDecryptingStreamKey,
    ) -> bool {
        self.candidates
            .get(key)
            .is_some_and(|slot| matches!(slot.candidate, Tls13SessionSecretCandidate::Probing(_)))
    }

    pub(super) fn restore(
        &mut self,
        key: Tls13SessionSecretDecryptingStreamKey,
        taken: Tls13SessionSecretTakenCandidate,
    ) {
        self.candidates.insert(
            key,
            Tls13SessionSecretCandidateSlot {
                candidate: Tls13SessionSecretCandidate::Probing(taken.candidate),
                order: taken.order,
            },
        );
        self.debug_assert_single_held_candidate();
    }

    pub(super) fn activate_waiting_candidates(
        &mut self,
        mut candidate_is_usable: impl FnMut(&Tls13SessionSecretBindingIntent) -> bool,
    ) {
        for slot in self.candidates.values_mut() {
            let Tls13SessionSecretCandidate::WaitingForMaterial(intent) = &slot.candidate else {
                continue;
            };
            if candidate_is_usable(intent) {
                slot.candidate = Tls13SessionSecretCandidate::Probing(
                    Tls13SessionSecretBindingCandidate::from_intent(intent.clone()),
                );
            }
        }
        self.debug_assert_single_held_candidate();
    }

    pub(super) fn update_flow_candidates(
        &mut self,
        flow: &FlowIdentity,
        mut update: impl FnMut(&mut Tls13SessionSecretBindingIntent),
    ) {
        for slot in self.candidates.values_mut() {
            if slot.candidate.intent().flow().id == *flow {
                update(slot.candidate.intent_mut());
            }
        }
    }

    pub(super) fn has_buffered_candidate(&self) -> bool {
        self.candidates
            .values()
            .any(|slot| slot.candidate.has_buffered_event())
    }

    pub(super) fn key_has_buffered_candidate(
        &self,
        key: &Tls13SessionSecretDecryptingStreamKey,
    ) -> bool {
        self.candidates
            .get(key)
            .is_some_and(|slot| slot.candidate.has_buffered_event())
    }

    pub(super) fn remove_flow_candidates(&mut self, flow: &FlowIdentity) -> Vec<CaptureEvent> {
        let keys = self
            .candidates
            .iter()
            .filter(|(key, _)| key.flow == *flow)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let slots = keys
            .into_iter()
            .filter_map(|key| self.candidates.remove(&key))
            .collect::<Vec<_>>();
        buffered_events_from_slots(slots)
    }

    pub(super) fn remove_candidate(
        &mut self,
        key: &Tls13SessionSecretDecryptingStreamKey,
    ) -> Vec<CaptureEvent> {
        self.candidates
            .remove(key)
            .map(|slot| buffered_events_from_slots(vec![slot]))
            .unwrap_or_default()
    }

    pub(super) fn release_buffered_events(&mut self) -> Vec<CaptureEvent> {
        buffered_events_from_slots(self.remove_all_buffered_candidate_slots())
    }

    fn reserve_slot(&mut self, released_events: &mut Vec<CaptureEvent>) -> bool {
        if self.max_candidates == 0 {
            return false;
        }
        while self.candidates.len() >= self.max_candidates {
            if !self.evict_oldest_candidate(released_events) {
                return false;
            }
        }
        true
    }

    fn evict_oldest_candidate(&mut self, released_events: &mut Vec<CaptureEvent>) -> bool {
        let Some(key) = self
            .candidates
            .iter()
            .min_by_key(|(_, slot)| slot.order)
            .map(|(key, _)| key.clone())
        else {
            return false;
        };
        let slot = self
            .candidates
            .remove(&key)
            .expect("oldest candidate key came from candidate map");
        if slot.candidate.has_buffered_event() {
            released_events.extend(buffered_events_from_slots(vec![slot]));
        }
        true
    }

    fn remove_all_buffered_candidate_slots(&mut self) -> Vec<Tls13SessionSecretCandidateSlot> {
        let keys = self
            .candidates
            .iter()
            .filter(|(_, slot)| slot.candidate.has_buffered_event())
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        keys.into_iter()
            .filter_map(|key| self.candidates.remove(&key))
            .collect()
    }

    fn debug_assert_single_held_candidate(&self) {
        debug_assert!(
            self.candidates
                .values()
                .filter(|slot| slot.candidate.has_buffered_event())
                .count()
                <= 1,
            "TLS auto-binding keeps at most one held candidate"
        );
    }

    fn allocate_order(&mut self) -> u64 {
        if self.next_order == u64::MAX {
            self.compact_order_indices();
        }
        let order = self.next_order;
        self.next_order = self.next_order.saturating_add(1);
        order
    }

    fn compact_order_indices(&mut self) {
        let mut slots = self.candidates.values_mut().collect::<Vec<_>>();
        slots.sort_by_key(|slot| slot.order);
        for (order, slot) in slots.into_iter().enumerate() {
            slot.order = order as u64;
        }
        self.next_order = self.candidates.len() as u64;
    }
}

fn buffered_events_from_slots(slots: Vec<Tls13SessionSecretCandidateSlot>) -> Vec<CaptureEvent> {
    debug_assert!(
        slots
            .iter()
            .filter(|slot| slot.candidate.has_buffered_event())
            .count()
            <= 1,
        "TLS auto-binding keeps at most one held candidate"
    );
    slots
        .into_iter()
        .flat_map(|slot| slot.candidate.into_buffered_events())
        .collect()
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EnforcementEvidence, FlowContext,
        FlowIdentity, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };

    use super::super::binder::Tls13SessionSecretBindingIntent;
    use super::super::buffered::Tls13SessionSecretBufferedBytes;
    use super::*;
    use crate::CapturedBytes;
    use crate::EnforcementEvidencePropagation;
    use crate::Tls13ApplicationTrafficSecretKind;
    use crate::tls::TlsRandom;

    const CLIENT_RANDOM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    #[test]
    fn replacing_candidate_keeps_single_accessible_candidate() {
        let flow = demo_flow(1);
        let key = Tls13SessionSecretDecryptingStreamKey::new(flow.id.clone(), Direction::Outbound);
        let mut candidates = Tls13SessionSecretCandidateSet::new(8);

        candidates.insert(
            key.clone(),
            binding_candidate(flow.clone(), Direction::Outbound),
        );
        candidates.insert(key.clone(), binding_candidate(flow, Direction::Outbound));

        assert!(candidates.take(&key).is_some());
        assert!(candidates.take(&key).is_none());
    }

    #[test]
    fn evicts_oldest_held_candidate_and_releases_raw_bytes() {
        let old_flow = demo_flow(1);
        let new_flow = demo_flow(2);
        let old_key =
            Tls13SessionSecretDecryptingStreamKey::new(old_flow.id.clone(), Direction::Outbound);
        let new_key =
            Tls13SessionSecretDecryptingStreamKey::new(new_flow.id.clone(), Direction::Outbound);
        let held_bytes = captured_bytes(old_flow, Direction::Outbound, b"abc");
        let held_candidate = binding_candidate(held_bytes.flow.clone(), Direction::Outbound)
            .with_buffered_bytes(
                Tls13SessionSecretBufferedBytes::from_slice(&held_bytes, 0, 3)
                    .expect("payload slice is within captured bytes"),
            );
        let mut candidates = Tls13SessionSecretCandidateSet::new(1);

        assert!(
            candidates
                .insert(old_key.clone(), held_candidate)
                .is_empty()
        );
        let released = candidates.insert(
            new_key.clone(),
            binding_candidate(new_flow, Direction::Outbound),
        );

        let [CaptureEvent::Bytes(bytes)] = released.as_slice() else {
            panic!("expected one released held bytes event: {released:?}");
        };
        assert_eq!(bytes.bytes.as_ref(), b"abc");
        assert!(candidates.take(&old_key).is_none());
        assert!(candidates.take(&new_key).is_some());
    }

    #[test]
    fn probing_candidate_does_not_refresh_fifo_eviction_age() {
        let old_flow = demo_flow(1);
        let middle_flow = demo_flow(2);
        let new_flow = demo_flow(3);
        let old_key =
            Tls13SessionSecretDecryptingStreamKey::new(old_flow.id.clone(), Direction::Outbound);
        let middle_key =
            Tls13SessionSecretDecryptingStreamKey::new(middle_flow.id.clone(), Direction::Outbound);
        let new_key =
            Tls13SessionSecretDecryptingStreamKey::new(new_flow.id.clone(), Direction::Outbound);
        let mut candidates = Tls13SessionSecretCandidateSet::new(2);

        assert!(
            candidates
                .insert(
                    old_key.clone(),
                    binding_candidate(old_flow, Direction::Outbound),
                )
                .is_empty()
        );
        assert!(
            candidates
                .insert(
                    middle_key.clone(),
                    binding_candidate(middle_flow, Direction::Outbound),
                )
                .is_empty()
        );
        let candidate = candidates
            .take(&old_key)
            .expect("old candidate remains accessible");
        candidates.restore(old_key.clone(), candidate);
        let released = candidates.insert(
            new_key.clone(),
            binding_candidate(new_flow, Direction::Outbound),
        );

        assert!(released.is_empty());
        assert!(candidates.take(&old_key).is_none());
        assert!(candidates.take(&middle_key).is_some());
        assert!(candidates.take(&new_key).is_some());
    }

    #[test]
    fn releasing_buffered_events_preserves_unheld_candidates() {
        let held_flow = demo_flow(1);
        let unheld_flow = demo_flow(2);
        let held_key =
            Tls13SessionSecretDecryptingStreamKey::new(held_flow.id.clone(), Direction::Outbound);
        let unheld_key =
            Tls13SessionSecretDecryptingStreamKey::new(unheld_flow.id.clone(), Direction::Outbound);
        let mut candidates = Tls13SessionSecretCandidateSet::new(8);

        assert!(
            candidates
                .insert(
                    held_key.clone(),
                    binding_candidate(held_flow.clone(), Direction::Outbound),
                )
                .is_empty()
        );
        assert!(
            candidates
                .insert(
                    unheld_key.clone(),
                    binding_candidate(unheld_flow, Direction::Outbound),
                )
                .is_empty()
        );
        let mut held = candidates.take(&held_key).expect("held candidate exists");
        held.candidate = held_candidate(held_flow, Direction::Outbound, b"held");
        candidates.restore(held_key.clone(), held);

        let released = candidates.release_buffered_events();

        let [CaptureEvent::Bytes(bytes)] = released.as_slice() else {
            panic!("expected one held byte release: {released:?}");
        };
        assert_eq!(bytes.bytes.as_ref(), b"held");
        assert!(candidates.take(&held_key).is_none());
        assert!(candidates.take(&unheld_key).is_some());
    }

    #[test]
    fn removing_flow_candidates_releases_held_candidate() {
        let flow = demo_flow(1);
        let outbound_key =
            Tls13SessionSecretDecryptingStreamKey::new(flow.id.clone(), Direction::Outbound);
        let inbound_key =
            Tls13SessionSecretDecryptingStreamKey::new(flow.id.clone(), Direction::Inbound);
        let mut candidates = Tls13SessionSecretCandidateSet::new(8);

        assert!(
            candidates
                .insert(
                    outbound_key.clone(),
                    binding_candidate(flow.clone(), Direction::Outbound),
                )
                .is_empty()
        );
        assert!(
            candidates
                .insert(
                    inbound_key.clone(),
                    binding_candidate(flow.clone(), Direction::Inbound),
                )
                .is_empty()
        );
        let mut outbound = candidates
            .take(&outbound_key)
            .expect("outbound candidate exists");
        outbound.candidate = held_candidate(flow.clone(), Direction::Outbound, b"held");
        candidates.restore(outbound_key.clone(), outbound);

        let released = candidates.remove_flow_candidates(&flow.id);

        let [CaptureEvent::Bytes(bytes)] = released.as_slice() else {
            panic!("expected one held byte release: {released:?}");
        };
        assert_eq!(bytes.bytes.as_ref(), b"held");
        assert!(candidates.take(&outbound_key).is_none());
        assert!(candidates.take(&inbound_key).is_none());
    }

    #[test]
    fn capacity_eviction_preserves_single_held_candidate_when_oldest_candidate_is_unheld() {
        let held_flow = demo_flow(1);
        let oldest_flow = demo_flow(2);
        let new_flow = demo_flow(3);
        let held_key =
            Tls13SessionSecretDecryptingStreamKey::new(held_flow.id.clone(), Direction::Outbound);
        let oldest_key =
            Tls13SessionSecretDecryptingStreamKey::new(oldest_flow.id.clone(), Direction::Outbound);
        let new_key =
            Tls13SessionSecretDecryptingStreamKey::new(new_flow.id.clone(), Direction::Outbound);
        let mut candidates = Tls13SessionSecretCandidateSet::new(2);

        assert!(
            candidates
                .insert(
                    oldest_key.clone(),
                    binding_candidate(oldest_flow, Direction::Outbound),
                )
                .is_empty()
        );
        assert!(
            candidates
                .insert(
                    held_key.clone(),
                    binding_candidate(held_flow.clone(), Direction::Outbound),
                )
                .is_empty()
        );
        let mut held = candidates.take(&held_key).expect("held candidate exists");
        held.candidate = held_candidate(held_flow, Direction::Outbound, b"held");
        candidates.restore(held_key.clone(), held);

        let released = candidates.insert(
            new_key.clone(),
            binding_candidate(new_flow, Direction::Outbound),
        );

        assert!(released.is_empty());
        assert!(candidates.take(&oldest_key).is_none());
        assert!(candidates.take(&held_key).is_some());
        assert!(candidates.take(&new_key).is_some());
    }

    fn binding_candidate(
        flow: FlowContext,
        direction: Direction,
    ) -> Tls13SessionSecretBindingCandidate {
        let intent = Tls13SessionSecretBindingIntent::new(
            flow,
            direction,
            TlsRandom::from_hex(CLIENT_RANDOM).expect("valid client random"),
            Tls13ApplicationTrafficSecretKind::Client,
            0,
            None,
        );
        Tls13SessionSecretBindingCandidate::from_intent(intent)
    }

    fn held_candidate(
        flow: FlowContext,
        direction: Direction,
        payload: &[u8],
    ) -> Tls13SessionSecretBindingCandidate {
        let bytes = captured_bytes(flow, direction, payload);
        binding_candidate(bytes.flow.clone(), direction).with_buffered_bytes(
            Tls13SessionSecretBufferedBytes::from_slice(&bytes, 0, payload.len())
                .expect("payload slice is within captured bytes"),
        )
    }

    fn captured_bytes(flow: FlowContext, direction: Direction, bytes: &[u8]) -> CapturedBytes {
        captured_bytes_at(flow, direction, 0, bytes)
    }

    fn captured_bytes_at(
        flow: FlowContext,
        direction: Direction,
        stream_offset: u64,
        bytes: &[u8],
    ) -> CapturedBytes {
        CapturedBytes {
            timestamp: Timestamp {
                monotonic_ns: 17,
                wall_time_unix_ns: 23,
            },
            flow,
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            direction,
            stream_offset,
            bytes: Bytes::copy_from_slice(bytes),
            attribution_confidence: 100,
            degraded: false,
            degradation_reason: None,
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }
    }

    fn demo_flow(socket_cookie: u64) -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 12345,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 443,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process,
                &local,
                &remote,
                TransportProtocol::Tcp,
                1,
                Some(socket_cookie),
            ),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(socket_cookie),
            attribution_confidence: 100,
        }
    }
}

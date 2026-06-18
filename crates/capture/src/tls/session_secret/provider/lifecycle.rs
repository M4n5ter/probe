use probe_core::{Direction, FlowIdentity, Timestamp};

use crate::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, PlaintextEvent, PlaintextEventKind,
};

use super::{
    Tls13SessionSecretCaptureDisposition, Tls13SessionSecretDecryptingEngine,
    Tls13SessionSecretDecryptingProviderError, Tls13SessionSecretDecryptingStreamKey,
    evidence::{
        Tls13SessionSecretEventEvidence, Tls13SessionSecretStreamObservation,
        apply_enforcement_evidence,
    },
};

impl Tls13SessionSecretDecryptingEngine {
    pub(super) fn poll_pending_or_inner(
        &mut self,
        provider_name: &'static str,
        inner: &mut dyn CaptureProvider,
    ) -> Result<CapturePoll, CaptureError> {
        if let Some(event) = self.pop_pending_event() {
            return Ok(CapturePoll::event(event));
        }
        match inner.poll_next()? {
            CapturePoll::Event(event) => self.handle_inner_event(provider_name, *event),
            CapturePoll::Finished => self.finish_bound_streams_before_inner_finished(),
            other => Ok(other),
        }
    }

    pub(super) fn pop_pending_event(&mut self) -> Option<CaptureEvent> {
        self.pending_events.pop_front()
    }

    fn handle_inner_event(
        &mut self,
        provider_name: &'static str,
        event: CaptureEvent,
    ) -> Result<CapturePoll, CaptureError> {
        self.handle_inner_events(provider_name, vec![event])
    }

    pub(super) fn handle_inner_events(
        &mut self,
        provider_name: &'static str,
        events: Vec<CaptureEvent>,
    ) -> Result<CapturePoll, CaptureError> {
        let mut ready_events = Vec::new();
        for event in events {
            ready_events.extend(self.materialize_inner_event(provider_name, event)?);
        }
        Ok(self.emit_ready_events(ready_events, CapturePoll::Progress))
    }

    pub(super) fn bind_and_handle_inner_event_after_raw_prefix(
        &mut self,
        provider_name: &'static str,
        preceding_inner_events: Vec<CaptureEvent>,
        raw_prefix_events: Vec<CaptureEvent>,
        binding: super::Tls13SessionSecretFlowBinding<'_>,
        event: CaptureEvent,
    ) -> Result<CapturePoll, CaptureError> {
        let mut ready_events = Vec::new();
        for event in preceding_inner_events {
            ready_events.extend(self.materialize_inner_event(provider_name, event)?);
        }
        self.bind(binding)
            .map_err(|error| CaptureError::provider(provider_name, error.to_string()))?;
        ready_events.extend(raw_prefix_events);
        ready_events.extend(self.materialize_inner_event(provider_name, event)?);
        Ok(self.emit_ready_events(ready_events, CapturePoll::Progress))
    }

    fn materialize_inner_event(
        &mut self,
        provider_name: &'static str,
        event: CaptureEvent,
    ) -> Result<Vec<CaptureEvent>, CaptureError> {
        let disposition = self.disposition(&event);
        self.record_observed_bound_timestamp(&event, &disposition);
        let bound_stream_was_active = self.bound_stream_was_active(&disposition);
        let mut plaintext_events =
            self.plaintext_events_from_inner_event(provider_name, &event, &disposition)?;
        self.flow_registry
            .record_plaintext_progress(&plaintext_events);
        self.ensure_plaintext_close_for_bound_capture_close(
            &event,
            &disposition,
            &mut plaintext_events,
        );
        let capture_events = self.capture_events_from_plaintext_events(plaintext_events);
        let buffered_streams = self.buffered_materialized_streams(&capture_events);
        self.flow_registry
            .record_plaintext_materialized(&capture_events, |flow, direction| {
                buffered_streams
                    .iter()
                    .any(|(buffered_flow, buffered_direction)| {
                        buffered_flow == flow && *buffered_direction == direction
                    })
            });
        self.record_consumed_ciphertext_without_plaintext(
            &disposition,
            bound_stream_was_active,
            &capture_events,
        );
        let mut ready_events = capture_events;
        self.record_observed_bound_close(&event, &disposition);

        if !disposition.suppress_ciphertext() {
            ready_events.push(event);
        }
        Ok(ready_events)
    }

    fn bound_stream_was_active(&self, disposition: &Tls13SessionSecretCaptureDisposition) -> bool {
        match disposition {
            Tls13SessionSecretCaptureDisposition::BoundStream(key) => {
                self.decryptor.stream_is_active(&key.flow, key.direction)
            }
            Tls13SessionSecretCaptureDisposition::ClosedFlow
            | Tls13SessionSecretCaptureDisposition::BoundFlow(_)
            | Tls13SessionSecretCaptureDisposition::Unbound => false,
        }
    }

    fn plaintext_events_from_inner_event(
        &mut self,
        provider_name: &'static str,
        event: &CaptureEvent,
        disposition: &Tls13SessionSecretCaptureDisposition,
    ) -> Result<Vec<PlaintextEvent>, CaptureError> {
        let events = match (event, disposition) {
            (
                CaptureEvent::ConnectionClosed {
                    timestamp, flow, ..
                },
                Tls13SessionSecretCaptureDisposition::BoundFlow(_),
            ) => Ok(self.decryptor.close_flow_observation(*timestamp, flow)),
            _ => self.decryptor.push_capture_event(event),
        };
        events
            .map_err(Tls13SessionSecretDecryptingProviderError::from)
            .map_err(|error| CaptureError::provider(provider_name, error.to_string()))
    }

    fn disposition(&self, event: &CaptureEvent) -> Tls13SessionSecretCaptureDisposition {
        match event {
            CaptureEvent::Bytes(bytes) => {
                let key = Tls13SessionSecretDecryptingStreamKey::new(
                    bytes.flow.id.clone(),
                    bytes.direction,
                );
                if self.flow_registry.contains(&key) {
                    Tls13SessionSecretCaptureDisposition::BoundStream(key)
                } else if self.flow_registry.flow_is_closed(&bytes.flow.id) {
                    Tls13SessionSecretCaptureDisposition::ClosedFlow
                } else {
                    Tls13SessionSecretCaptureDisposition::Unbound
                }
            }
            CaptureEvent::Gap(gap) => {
                let key = Tls13SessionSecretDecryptingStreamKey::new(
                    gap.flow.id.clone(),
                    gap.gap.direction,
                );
                if self.flow_registry.contains(&key) {
                    Tls13SessionSecretCaptureDisposition::BoundStream(key)
                } else if self.flow_registry.flow_is_closed(&gap.flow.id) {
                    Tls13SessionSecretCaptureDisposition::ClosedFlow
                } else {
                    Tls13SessionSecretCaptureDisposition::Unbound
                }
            }
            CaptureEvent::ConnectionClosed { flow, .. } => {
                if self.has_bound_flow(&flow.id) {
                    Tls13SessionSecretCaptureDisposition::BoundFlow(flow.id.clone())
                } else if self.flow_registry.flow_is_closed(&flow.id) {
                    Tls13SessionSecretCaptureDisposition::ClosedFlow
                } else {
                    Tls13SessionSecretCaptureDisposition::Unbound
                }
            }
            CaptureEvent::ConnectionOpened { .. } | CaptureEvent::Loss(_) => {
                Tls13SessionSecretCaptureDisposition::Unbound
            }
        }
    }

    fn has_bound_flow(&self, flow: &FlowIdentity) -> bool {
        self.flow_registry.has_flow(flow)
    }

    fn record_observed_bound_timestamp(
        &mut self,
        event: &CaptureEvent,
        disposition: &Tls13SessionSecretCaptureDisposition,
    ) {
        match (event, disposition) {
            (
                CaptureEvent::Bytes(bytes),
                Tls13SessionSecretCaptureDisposition::BoundStream(key),
            ) => self.record_bound_stream_observation(
                key,
                Tls13SessionSecretStreamObservation::from_capture_bytes(bytes),
            ),
            (CaptureEvent::Gap(gap), Tls13SessionSecretCaptureDisposition::BoundStream(key)) => {
                self.record_bound_stream_observation(
                    key,
                    Tls13SessionSecretStreamObservation::from_capture_gap(gap),
                );
            }
            (
                CaptureEvent::ConnectionClosed {
                    timestamp, flow, ..
                },
                Tls13SessionSecretCaptureDisposition::BoundFlow(_),
            ) => self.record_bound_flow_timestamp(&flow.id, *timestamp),
            _ => {}
        }
    }

    fn record_bound_stream_observation(
        &mut self,
        key: &Tls13SessionSecretDecryptingStreamKey,
        observation: Tls13SessionSecretStreamObservation,
    ) {
        self.flow_registry.observe_stream(key, observation);
    }

    fn record_bound_flow_timestamp(&mut self, flow: &FlowIdentity, timestamp: Timestamp) {
        self.flow_registry.observe_flow_timestamp(flow, timestamp);
    }

    fn record_observed_bound_close(
        &mut self,
        event: &CaptureEvent,
        disposition: &Tls13SessionSecretCaptureDisposition,
    ) {
        if let (
            CaptureEvent::ConnectionClosed { flow, .. },
            Tls13SessionSecretCaptureDisposition::BoundFlow(_),
        ) = (event, disposition)
        {
            self.flow_registry.record_flow_closed(&flow.id);
        }
    }

    fn remove_bound_flow(&mut self, flow: &FlowIdentity) {
        self.flow_registry.remove_flow(flow);
    }

    pub(super) fn finish_bound_streams_before_inner_finished(
        &mut self,
    ) -> Result<CapturePoll, CaptureError> {
        let mut ready_events = Vec::new();
        for (flow, timestamp) in self.flow_registry.bound_flow_finish_events() {
            let mut plaintext_events = self.decryptor.finish_flow_observation(timestamp, &flow);
            self.flow_registry
                .record_plaintext_progress(&plaintext_events);
            if let Some(timestamp) = timestamp {
                let carrying_gaps = self
                    .flow_registry
                    .observation_only_gaps_before_plaintext_finalization(
                        &flow,
                        timestamp,
                        &plaintext_events,
                    );
                plaintext_events.extend(carrying_gaps);
            }
            let capture_events = self.capture_events_from_plaintext_events(plaintext_events);
            let buffered_streams = self.buffered_materialized_streams(&capture_events);
            self.flow_registry
                .record_plaintext_materialized(&capture_events, |flow, direction| {
                    buffered_streams
                        .iter()
                        .any(|(buffered_flow, buffered_direction)| {
                            buffered_flow == flow && *buffered_direction == direction
                        })
                });
            ready_events.extend(capture_events);
            self.remove_bound_flow(&flow.id);
        }

        self.flow_registry.clear_streams();
        Ok(self.emit_ready_events(ready_events, CapturePoll::Finished))
    }

    fn emit_ready_events(
        &mut self,
        events: Vec<CaptureEvent>,
        empty_poll: CapturePoll,
    ) -> CapturePoll {
        let mut events = events.into_iter();
        let Some(event) = events.next() else {
            return empty_poll;
        };
        self.pending_events.extend(events);
        CapturePoll::event(event)
    }

    fn capture_events_from_plaintext_events(
        &self,
        events: Vec<PlaintextEvent>,
    ) -> Vec<CaptureEvent> {
        events
            .into_iter()
            .map(|event| self.capture_event_from_plaintext_event(event))
            .collect()
    }

    fn record_consumed_ciphertext_without_plaintext(
        &mut self,
        disposition: &Tls13SessionSecretCaptureDisposition,
        bound_stream_was_active: bool,
        capture_events: &[CaptureEvent],
    ) {
        if !bound_stream_was_active {
            return;
        }
        let Tls13SessionSecretCaptureDisposition::BoundStream(key) = disposition else {
            return;
        };
        if capture_events_cover_stream(capture_events, key)
            || self
                .decryptor
                .stream_has_buffered_ciphertext(&key.flow, key.direction)
        {
            return;
        }
        self.flow_registry.record_ciphertext_consumed(key);
    }

    fn buffered_materialized_streams(
        &self,
        events: &[CaptureEvent],
    ) -> Vec<(FlowIdentity, Direction)> {
        events
            .iter()
            .filter_map(capture_event_stream)
            .filter(|(flow, direction)| {
                self.decryptor
                    .stream_has_buffered_ciphertext(flow, *direction)
            })
            .collect()
    }

    fn capture_event_from_plaintext_event(&self, event: PlaintextEvent) -> CaptureEvent {
        let evidence = self
            .evidence_for_plaintext_event(&event)
            .unwrap_or_default();
        let mut event = CaptureEvent::from(event);
        apply_enforcement_evidence(&mut event, evidence);
        event
    }

    fn evidence_for_plaintext_event(
        &self,
        event: &PlaintextEvent,
    ) -> Option<Tls13SessionSecretEventEvidence> {
        match &event.kind {
            PlaintextEventKind::Bytes(bytes) => {
                self.stream_evidence(&bytes.flow.id, bytes.direction)
            }
            PlaintextEventKind::Gap(gap) => self.stream_evidence(&gap.flow.id, gap.gap.direction),
            PlaintextEventKind::ConnectionOpened(connection)
            | PlaintextEventKind::ConnectionClosed(connection) => {
                self.flow_evidence(&connection.flow.id)
            }
        }
    }

    fn stream_evidence(
        &self,
        flow: &FlowIdentity,
        direction: Direction,
    ) -> Option<Tls13SessionSecretEventEvidence> {
        self.flow_registry.stream_evidence(flow, direction)
    }

    fn flow_evidence(&self, flow: &FlowIdentity) -> Option<Tls13SessionSecretEventEvidence> {
        self.flow_registry.flow_evidence(flow)
    }
}

fn capture_events_cover_stream(
    events: &[CaptureEvent],
    key: &Tls13SessionSecretDecryptingStreamKey,
) -> bool {
    events
        .iter()
        .filter_map(capture_event_stream)
        .any(|(flow, direction)| flow == key.flow && direction == key.direction)
}

fn capture_event_stream(event: &CaptureEvent) -> Option<(FlowIdentity, Direction)> {
    match event {
        CaptureEvent::Bytes(bytes) => Some((bytes.flow.id.clone(), bytes.direction)),
        CaptureEvent::Gap(gap) => Some((gap.flow.id.clone(), gap.gap.direction)),
        CaptureEvent::ConnectionOpened { .. }
        | CaptureEvent::ConnectionClosed { .. }
        | CaptureEvent::Loss(_) => None,
    }
}

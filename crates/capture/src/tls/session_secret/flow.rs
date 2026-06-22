use std::collections::HashMap;

use probe_core::{Direction, FlowContext, FlowIdentity, Timestamp};
use thiserror::Error;

use crate::{
    CaptureEvent, CapturedBytes, CapturedGap, PlaintextConnection, PlaintextEvent,
    PlaintextEventKind, PlaintextSource,
};

use super::{
    binding::Tls13SessionSecretFlowBinding,
    stream::{Tls13SessionSecretStreamAdapter, Tls13SessionSecretStreamError},
};

#[derive(Debug, Default)]
pub struct Tls13SessionSecretFlowDecryptor {
    streams: HashMap<Tls13SessionSecretStreamKey, Tls13SessionSecretStreamAdapter>,
}

impl Tls13SessionSecretFlowDecryptor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(
        &mut self,
        binding: Tls13SessionSecretFlowBinding,
    ) -> Result<(), Tls13SessionSecretFlowDecryptError> {
        let Tls13SessionSecretFlowBinding {
            record,
            flow,
            direction,
            cursor,
            missing_plaintext_prefix,
        } = binding;
        let key = Tls13SessionSecretStreamKey::new(flow.id.clone(), direction);
        if self.streams.contains_key(&key) {
            return Err(Tls13SessionSecretFlowDecryptError::AlreadyBound {
                flow: flow.id,
                direction,
            });
        }
        let adapter = Tls13SessionSecretStreamAdapter::from_session_secret_record_with_cursor(
            &record, flow, direction, cursor,
        )?
        .with_degradation("TLS session-secret decrypt uses best-effort ciphertext capture");
        let adapter = match missing_plaintext_prefix {
            Some(prefix) => adapter.with_missing_plaintext_prefix(prefix),
            None => adapter,
        };
        self.streams.insert(key, adapter);
        Ok(())
    }

    pub fn push_capture_event(
        &mut self,
        event: &CaptureEvent,
    ) -> Result<Vec<PlaintextEvent>, Tls13SessionSecretFlowDecryptError> {
        match event {
            CaptureEvent::Bytes(bytes) => self.push_captured_bytes(bytes),
            CaptureEvent::Gap(gap) => self
                .push_captured_gap(gap)
                .map(|event| event.map(|event| vec![event]).unwrap_or_else(Vec::new)),
            CaptureEvent::ConnectionClosed {
                timestamp, flow, ..
            } => Ok(
                if let Some(mut events) = self.close_flow(*timestamp, flow) {
                    events.push(PlaintextEvent::connection_closed(
                        PlaintextSource::TlsSessionSecret,
                        PlaintextConnection::new(*timestamp, flow.clone()),
                    ));
                    events
                } else {
                    Vec::new()
                },
            ),
            CaptureEvent::Loss(_) | CaptureEvent::ConnectionOpened { .. } => Ok(Vec::new()),
        }
    }

    pub fn finish_flow_observation(
        &mut self,
        timestamp: Option<Timestamp>,
        flow: &FlowContext,
    ) -> Vec<PlaintextEvent> {
        let mut events = Vec::new();
        for direction in [Direction::Inbound, Direction::Outbound] {
            let key = Tls13SessionSecretStreamKey::new(flow.id.clone(), direction);
            if let Some(mut stream) = self.streams.remove(&key)
                && let Some(timestamp) = timestamp
                && let Some(event) = stream.close_with_incomplete_record_gap(timestamp)
            {
                events.push(event);
            }
        }
        events
    }

    pub(in crate::tls::session_secret) fn close_flow_observation(
        &mut self,
        timestamp: Timestamp,
        flow: &FlowContext,
    ) -> Vec<PlaintextEvent> {
        self.close_flow(timestamp, flow).unwrap_or_default()
    }

    pub(in crate::tls::session_secret) fn stream_has_buffered_ciphertext(
        &self,
        flow: &FlowIdentity,
        direction: Direction,
    ) -> bool {
        self.streams
            .get(&Tls13SessionSecretStreamKey::new(flow.clone(), direction))
            .is_some_and(|stream| stream.buffered_ciphertext_bytes() > 0)
    }

    pub(in crate::tls::session_secret) fn stream_is_active(
        &self,
        flow: &FlowIdentity,
        direction: Direction,
    ) -> bool {
        self.streams
            .contains_key(&Tls13SessionSecretStreamKey::new(flow.clone(), direction))
    }

    fn push_captured_bytes(
        &mut self,
        bytes: &CapturedBytes,
    ) -> Result<Vec<PlaintextEvent>, Tls13SessionSecretFlowDecryptError> {
        let key = Tls13SessionSecretStreamKey::new(bytes.flow.id.clone(), bytes.direction);
        let Some(stream) = self.streams.get_mut(&key) else {
            return Ok(Vec::new());
        };
        let outcome = stream.push_ciphertext_with_outcome(
            bytes.timestamp,
            bytes.stream_offset,
            bytes.bytes.as_ref(),
        )?;
        let terminal = outcome.is_terminal();
        if terminal {
            self.streams.remove(&key);
        }
        Ok(outcome
            .into_events()
            .into_iter()
            .map(|event| {
                degrade_plaintext_event(
                    event,
                    bytes
                        .degraded
                        .then_some(bytes.degradation_reason.as_deref())
                        .flatten(),
                    bytes.degraded,
                )
            })
            .collect())
    }

    fn push_captured_gap(
        &mut self,
        gap: &CapturedGap,
    ) -> Result<Option<PlaintextEvent>, Tls13SessionSecretFlowDecryptError> {
        let key = Tls13SessionSecretStreamKey::new(gap.flow.id.clone(), gap.gap.direction);
        let Some(stream) = self.streams.get_mut(&key) else {
            return Ok(None);
        };
        let event = stream.push_ciphertext_gap(gap.timestamp, &gap.gap)?;
        self.streams.remove(&key);
        Ok(Some(event))
    }

    fn close_flow(
        &mut self,
        timestamp: Timestamp,
        flow: &FlowContext,
    ) -> Option<Vec<PlaintextEvent>> {
        let mut removed_any = false;
        let mut events = Vec::new();
        for direction in [Direction::Inbound, Direction::Outbound] {
            let key = Tls13SessionSecretStreamKey::new(flow.id.clone(), direction);
            if let Some(mut stream) = self.streams.remove(&key) {
                removed_any = true;
                if let Some(event) = stream.close_with_incomplete_record_gap(timestamp) {
                    events.push(event);
                }
            }
        }
        removed_any.then_some(events)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Tls13SessionSecretStreamKey {
    flow: FlowIdentity,
    direction: Direction,
}

impl Tls13SessionSecretStreamKey {
    fn new(flow: FlowIdentity, direction: Direction) -> Self {
        Self { flow, direction }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Tls13SessionSecretFlowDecryptError {
    #[error("TLS session-secret stream is already bound for flow {flow:?} direction {direction:?}")]
    AlreadyBound {
        flow: FlowIdentity,
        direction: Direction,
    },
    #[error("{source}")]
    Stream {
        #[from]
        source: Tls13SessionSecretStreamError,
    },
}

fn degrade_plaintext_event(
    event: PlaintextEvent,
    reason: Option<&str>,
    degraded: bool,
) -> PlaintextEvent {
    if !degraded {
        return event;
    }
    let reason = reason.unwrap_or("upstream ciphertext capture is degraded");
    match event.kind {
        PlaintextEventKind::Bytes(chunk) => PlaintextEvent::bytes(
            event.source,
            chunk.with_degradation(format!(
                "TLS session-secret ciphertext capture degraded: {reason}"
            )),
        ),
        kind => PlaintextEvent::new(event.source, kind),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, EnforcementEvidence, FlowIdentity, Gap,
        ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };

    use super::super::{
        Tls13InnerContentType, Tls13SessionSecretStreamCursor, TlsSessionSecretStore,
        decrypt::protect_tls13_test_record, material::TlsSessionSecretRecord,
    };
    use super::*;
    use crate::{CapturedBytes, CapturedGap, EnforcementEvidencePropagation};

    const CLIENT_RANDOM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SHA256_TRAFFIC_SECRET: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn bound_direction_decrypts_captured_bytes_and_propagates_upstream_degradation()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let flow = demo_flow();
        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(Tls13SessionSecretFlowBinding::resume_at(
            record.clone(),
            flow.clone(),
            Direction::Outbound,
            Tls13SessionSecretStreamCursor::start(),
        ))?;
        let wire_record = protected_application_record(&record, 0, b"GET / HTTP/1.1\r\n\r\n")?;

        let events = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            wire_record,
            Some("libpcap stream assembler is best effort"),
        )))?;

        let [event] = events.as_slice() else {
            panic!("expected one plaintext event: {events:?}");
        };
        let bytes = bytes_event(event);
        assert_eq!(bytes.bytes.as_ref(), b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(bytes.stream_offset, 0);
        assert!(bytes.degraded);
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some(
                "TLS session-secret ciphertext capture degraded: libpcap stream assembler is best effort"
            )
        );
        Ok(())
    }

    #[test]
    fn explicit_cursor_aligns_nonzero_ciphertext_plaintext_and_sequence_offsets()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let flow = demo_flow();
        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(Tls13SessionSecretFlowBinding::resume_at(
            record.clone(),
            flow.clone(),
            Direction::Inbound,
            Tls13SessionSecretStreamCursor::resume_at(128, 7, 2),
        ))?;
        let wire_record = protected_application_record(&record, 2, b"ok")?;

        let events = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Inbound,
            128,
            wire_record,
            None,
        )))?;

        let [event] = events.as_slice() else {
            panic!("expected one plaintext event: {events:?}");
        };
        let bytes = bytes_event(event);
        assert_eq!(bytes.stream_offset, 7);
        assert_eq!(bytes.bytes.as_ref(), b"ok");
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some("TLS session-secret decrypt uses best-effort ciphertext capture")
        );
        Ok(())
    }

    #[test]
    fn unbound_capture_bytes_are_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let flow = demo_flow();
        let wire_record = protected_application_record(&record, 0, b"ignored")?;
        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();

        let events = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            wire_record,
            None,
        )))?;

        assert!(events.is_empty());
        Ok(())
    }

    #[test]
    fn captured_gap_emits_plaintext_gap_and_unbinds_direction()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let flow = demo_flow();
        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(Tls13SessionSecretFlowBinding::resume_at(
            record.clone(),
            flow.clone(),
            Direction::Outbound,
            Tls13SessionSecretStreamCursor::resume_at(0, 42, 0),
        ))?;

        let events = decryptor.push_capture_event(&CaptureEvent::Gap(captured_gap(
            flow.clone(),
            Direction::Outbound,
            100,
            Some(120),
        )))?;

        let [event] = events.as_slice() else {
            panic!("expected one plaintext gap event: {events:?}");
        };
        let PlaintextEventKind::Gap(gap) = &event.kind else {
            panic!("expected plaintext gap");
        };
        assert_eq!(gap.gap.expected_offset, 42);
        assert!(gap.gap.reason.contains("upstream gap"));
        let wire_record = protected_application_record(&record, 0, b"ignored after gap")?;
        let after_gap = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            wire_record,
            None,
        )))?;
        assert!(after_gap.is_empty());
        Ok(())
    }

    #[test]
    fn connection_closed_unbinds_flow_and_emits_plaintext_close()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let flow = demo_flow();
        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(Tls13SessionSecretFlowBinding::resume_at(
            record.clone(),
            flow.clone(),
            Direction::Outbound,
            Tls13SessionSecretStreamCursor::start(),
        ))?;

        let events = decryptor.push_capture_event(&CaptureEvent::ConnectionClosed {
            timestamp: timestamp(),
            flow: flow.clone(),
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
        })?;

        let [event] = events.as_slice() else {
            panic!("expected one plaintext close event: {events:?}");
        };
        assert!(matches!(
            event.kind,
            PlaintextEventKind::ConnectionClosed(_)
        ));
        let wire_record = protected_application_record(&record, 0, b"ignored after close")?;
        let after_close = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            wire_record,
            None,
        )))?;
        assert!(after_close.is_empty());
        Ok(())
    }

    #[test]
    fn connection_closed_emits_gap_before_close_for_incomplete_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let flow = demo_flow();
        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(Tls13SessionSecretFlowBinding::resume_at(
            record.clone(),
            flow.clone(),
            Direction::Outbound,
            Tls13SessionSecretStreamCursor::start(),
        ))?;
        let wire_record = protected_application_record(&record, 0, b"truncated")?;
        let split_at = 8;

        let partial = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            wire_record[..split_at].to_vec(),
            None,
        )))?;
        assert!(partial.is_empty());

        let events = decryptor.push_capture_event(&CaptureEvent::ConnectionClosed {
            timestamp: timestamp(),
            flow: flow.clone(),
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
        })?;

        let [gap, close] = events.as_slice() else {
            panic!("expected gap then close for incomplete record: {events:?}");
        };
        let PlaintextEventKind::Gap(gap) = &gap.kind else {
            panic!("expected plaintext gap before close");
        };
        assert_eq!(gap.gap.expected_offset, 0);
        assert!(
            gap.gap
                .reason
                .contains("closed with incomplete protected record")
        );
        assert!(matches!(
            close.kind,
            PlaintextEventKind::ConnectionClosed(_)
        ));

        let after_close = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            split_at as u64,
            wire_record[split_at..].to_vec(),
            None,
        )))?;
        assert!(after_close.is_empty());
        Ok(())
    }

    #[test]
    fn finish_flow_observation_emits_gap_without_inventing_close_for_incomplete_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let flow = demo_flow();
        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(Tls13SessionSecretFlowBinding::resume_at(
            record.clone(),
            flow.clone(),
            Direction::Outbound,
            Tls13SessionSecretStreamCursor::start(),
        ))?;
        let wire_record = protected_application_record(&record, 0, b"truncated")?;
        let split_at = 8;

        let partial = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            wire_record[..split_at].to_vec(),
            None,
        )))?;
        assert!(partial.is_empty());

        let events = decryptor.finish_flow_observation(Some(timestamp()), &flow);

        let [event] = events.as_slice() else {
            panic!("expected only a plaintext gap: {events:?}");
        };
        let PlaintextEventKind::Gap(gap) = &event.kind else {
            panic!("expected plaintext gap");
        };
        assert!(
            gap.gap
                .reason
                .contains("closed with incomplete protected record")
        );

        let after_finish = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            split_at as u64,
            wire_record[split_at..].to_vec(),
            None,
        )))?;
        assert!(after_finish.is_empty());
        Ok(())
    }

    fn session_secret_record() -> Result<TlsSessionSecretRecord, Box<dyn std::error::Error>> {
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}"#
        );
        let store = TlsSessionSecretStore::parse(material.as_bytes())?;
        Ok(store.records()[0].clone())
    }

    fn protected_application_record(
        record: &TlsSessionSecretRecord,
        sequence_number: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut inner_plaintext = plaintext.to_vec();
        inner_plaintext.push(Tls13InnerContentType::ApplicationData.as_u8());
        Ok(protect_tls13_test_record(
            record,
            sequence_number,
            &inner_plaintext,
        )?)
    }

    fn captured_bytes(
        flow: FlowContext,
        direction: Direction,
        stream_offset: u64,
        bytes: Vec<u8>,
        degradation_reason: Option<&str>,
    ) -> CapturedBytes {
        CapturedBytes {
            timestamp: timestamp(),
            flow,
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            direction,
            stream_offset,
            bytes: Bytes::from(bytes),
            attribution_confidence: 100,
            degraded: degradation_reason.is_some(),
            degradation_reason: degradation_reason.map(ToOwned::to_owned),
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }
    }

    fn captured_gap(
        flow: FlowContext,
        direction: Direction,
        expected_offset: u64,
        next_offset: Option<u64>,
    ) -> CapturedGap {
        CapturedGap {
            timestamp: timestamp(),
            flow,
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
            gap: Gap {
                direction,
                expected_offset,
                next_offset,
                reason: "upstream gap".to_string(),
            },
        }
    }

    fn bytes_event(event: &PlaintextEvent) -> crate::CapturedBytes {
        let crate::CaptureEvent::Bytes(bytes) = crate::CaptureEvent::from(event.clone()) else {
            panic!("expected plaintext bytes");
        };
        bytes
    }

    fn timestamp() -> Timestamp {
        Timestamp {
            monotonic_ns: 17,
            wall_time_unix_ns: 23,
        }
    }

    fn demo_flow() -> FlowContext {
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
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

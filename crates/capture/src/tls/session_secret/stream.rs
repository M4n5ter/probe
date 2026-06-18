use bytes::BytesMut;
use probe_core::{Direction, FlowContext, Gap, Timestamp};
use thiserror::Error;

use crate::{PlaintextEvent, PlaintextGap, PlaintextSource};

use super::{
    Tls13SessionSecretPlaintextAdapter, Tls13SessionSecretPlaintextError, TlsSessionSecretRecord,
    frame::{Tls13BufferedRecord, Tls13RecordFrame},
};

#[derive(Debug)]
pub struct Tls13SessionSecretStreamAdapter {
    plaintext: Tls13SessionSecretPlaintextAdapter,
    buffer: BytesMut,
    next_ciphertext_offset: u64,
    poisoned_reason: Option<String>,
}

impl Tls13SessionSecretStreamAdapter {
    pub fn from_session_secret_record(
        record: &TlsSessionSecretRecord,
        flow: FlowContext,
        direction: Direction,
    ) -> Result<Self, Tls13SessionSecretStreamError> {
        Ok(Self::new(
            Tls13SessionSecretPlaintextAdapter::from_session_secret_record(
                record, flow, direction,
            )?,
        ))
    }

    fn new(plaintext: Tls13SessionSecretPlaintextAdapter) -> Self {
        Self {
            plaintext,
            buffer: BytesMut::new(),
            next_ciphertext_offset: 0,
            poisoned_reason: None,
        }
    }

    pub fn sequence_number(&self) -> u64 {
        self.plaintext.sequence_number()
    }

    pub fn next_ciphertext_offset(&self) -> u64 {
        self.next_ciphertext_offset
    }

    pub fn next_plaintext_offset(&self) -> u64 {
        self.plaintext.next_stream_offset()
    }

    pub fn buffered_ciphertext_bytes(&self) -> usize {
        self.buffer.len()
    }

    #[cfg(test)]
    fn set_next_plaintext_offset(&mut self, next_plaintext_offset: u64) {
        self.plaintext.set_next_stream_offset(next_plaintext_offset);
    }

    #[cfg(test)]
    fn with_plaintext_offset(mut self, next_plaintext_offset: u64) -> Self {
        self.set_next_plaintext_offset(next_plaintext_offset);
        self
    }

    pub fn with_degradation(mut self, reason: impl Into<String>) -> Self {
        self.plaintext = self.plaintext.with_degradation(reason);
        self
    }

    pub fn push_ciphertext(
        &mut self,
        timestamp: Timestamp,
        stream_offset: u64,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Vec<PlaintextEvent>, Tls13SessionSecretStreamError> {
        self.ensure_not_poisoned()?;
        let bytes = bytes.as_ref();
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        if stream_offset != self.next_ciphertext_offset {
            return Ok(vec![self.poison_with_plaintext_gap(
                timestamp,
                format!(
                    "TLS session-secret ciphertext stream offset mismatch: expected {}, got {}",
                    self.next_ciphertext_offset, stream_offset
                ),
            )]);
        }
        self.next_ciphertext_offset = self
            .next_ciphertext_offset
            .checked_add(bytes.len() as u64)
            .ok_or(Tls13SessionSecretStreamError::CiphertextOffsetExhausted)?;
        self.buffer.extend_from_slice(bytes);
        Ok(self.drain_records(timestamp))
    }

    pub fn push_ciphertext_gap(
        &mut self,
        timestamp: Timestamp,
        gap: &Gap,
    ) -> Result<PlaintextEvent, Tls13SessionSecretStreamError> {
        self.ensure_not_poisoned()?;
        Ok(self.poison_with_plaintext_gap(
            timestamp,
            format!(
                "TLS session-secret ciphertext stream has gap: expected_offset={}, next_offset={:?}, reason={}",
                gap.expected_offset, gap.next_offset, gap.reason
            ),
        ))
    }

    fn drain_records(&mut self, timestamp: Timestamp) -> Vec<PlaintextEvent> {
        let mut events = Vec::new();
        loop {
            match Tls13RecordFrame::buffered(self.buffer.as_ref()) {
                Tls13BufferedRecord::Incomplete => break,
                Tls13BufferedRecord::Invalid { error } => {
                    let reason = format!("TLS session-secret protected record is invalid: {error}");
                    events.push(self.poison_with_plaintext_gap(timestamp, reason));
                    break;
                }
                Tls13BufferedRecord::Complete { len } => {
                    let record = self.buffer.split_to(len).freeze();
                    match self
                        .plaintext
                        .decrypt_next_record(timestamp, record.as_ref())
                    {
                        Ok(Some(event)) => events.push(event),
                        Ok(None) => {}
                        Err(error) => {
                            events.push(self.poison_with_plaintext_gap(
                                timestamp,
                                format!(
                                    "TLS session-secret protected record decrypt failed: {error}"
                                ),
                            ));
                            break;
                        }
                    }
                }
            }
        }
        events
    }

    fn poison_with_plaintext_gap(
        &mut self,
        timestamp: Timestamp,
        reason: String,
    ) -> PlaintextEvent {
        self.buffer.clear();
        self.poisoned_reason = Some(reason.clone());
        PlaintextEvent::gap(
            PlaintextSource::TlsSessionSecret,
            PlaintextGap::new(
                timestamp,
                self.plaintext.flow().clone(),
                Gap {
                    direction: self.plaintext.direction(),
                    expected_offset: self.plaintext.next_stream_offset(),
                    next_offset: None,
                    reason,
                },
            ),
        )
    }

    fn ensure_not_poisoned(&self) -> Result<(), Tls13SessionSecretStreamError> {
        match &self.poisoned_reason {
            Some(reason) => Err(Tls13SessionSecretStreamError::Poisoned {
                reason: reason.clone(),
            }),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Tls13SessionSecretStreamError {
    #[error("{source}")]
    Plaintext {
        #[from]
        source: Tls13SessionSecretPlaintextError,
    },
    #[error("TLS session-secret ciphertext stream is poisoned: {reason}")]
    Poisoned { reason: String },
    #[error("TLS session-secret ciphertext stream offset is exhausted")]
    CiphertextOffsetExhausted,
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureProviderKind, CaptureSource, FlowIdentity, ProcessContext,
        ProcessIdentity, TransportProtocol,
    };

    use super::super::{
        Tls13InnerContentType, TlsSessionSecretStore, decrypt::protect_tls13_test_record,
        frame::TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES,
    };
    use super::*;
    use crate::{CaptureEvent, tls::decode_hex};

    const CLIENT_RANDOM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SHA256_TRAFFIC_SECRET: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const OPENSSL_AES_128_GCM_RECORD: &str = concat!(
        "1703030035",
        "624db31e844203eed70ed895907c1dba83b7983bed37e448fef63e37",
        "a1918fb3d23e8ec8696562f3744f95453557cff5fec855a1fe"
    );
    const PLAINTEXT: &[u8] = b"GET /tls13 HTTP/1.1\r\nhost: e2e\r\n\r\n";

    #[test]
    fn split_ciphertext_record_emits_plaintext_after_record_completes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut adapter = stream_adapter()?;
        let timestamp = timestamp();
        let record = hex(OPENSSL_AES_128_GCM_RECORD);
        let split_at = 9;

        let events = adapter.push_ciphertext(timestamp, 0, &record[..split_at])?;

        assert!(events.is_empty());
        assert_eq!(adapter.buffered_ciphertext_bytes(), split_at);
        assert_eq!(adapter.next_ciphertext_offset(), split_at as u64);
        assert_eq!(adapter.sequence_number(), 0);

        let events = adapter.push_ciphertext(timestamp, split_at as u64, &record[split_at..])?;

        let [event] = events.as_slice() else {
            panic!("expected one plaintext event: {events:?}");
        };
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(event.clone()) else {
            panic!("expected plaintext bytes");
        };
        assert_eq!(bytes.origin.source(), CaptureSource::TlsSessionSecret);
        assert_eq!(bytes.origin.provider(), CaptureProviderKind::Plaintext);
        assert_eq!(bytes.stream_offset, 0);
        assert_eq!(bytes.bytes.as_ref(), PLAINTEXT);
        assert_eq!(adapter.buffered_ciphertext_bytes(), 0);
        assert_eq!(adapter.next_ciphertext_offset(), record.len() as u64);
        assert_eq!(adapter.sequence_number(), 1);
        assert_eq!(adapter.next_plaintext_offset(), PLAINTEXT.len() as u64);
        Ok(())
    }

    #[test]
    fn multiple_records_in_one_ciphertext_chunk_preserve_plaintext_offsets()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let mut adapter = Tls13SessionSecretStreamAdapter::from_session_secret_record(
            &record,
            demo_flow(),
            Direction::Inbound,
        )?;
        let first = protected_application_record(&record, 0, b"one")?;
        let second = protected_application_record(&record, 1, b"two")?;
        let mut chunk = first.clone();
        chunk.extend_from_slice(&second);

        let events = adapter.push_ciphertext(timestamp(), 0, chunk)?;

        assert_eq!(events.len(), 2);
        let first = bytes_event(&events[0]);
        let second = bytes_event(&events[1]);
        assert_eq!(first.stream_offset, 0);
        assert_eq!(first.bytes.as_ref(), b"one");
        assert_eq!(second.stream_offset, 3);
        assert_eq!(second.bytes.as_ref(), b"two");
        assert_eq!(adapter.sequence_number(), 2);
        assert_eq!(adapter.next_plaintext_offset(), 6);
        Ok(())
    }

    #[test]
    fn ciphertext_offset_mismatch_emits_plaintext_gap_and_poisons_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut adapter = stream_adapter()?;
        let timestamp = timestamp();

        let events = adapter.push_ciphertext(timestamp, 5, b"abc")?;

        let [event] = events.as_slice() else {
            panic!("expected one gap event: {events:?}");
        };
        let CaptureEvent::Gap(gap) = CaptureEvent::from(event.clone()) else {
            panic!("expected plaintext gap");
        };
        assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 0);
        assert!(gap.gap.next_offset.is_none());
        assert!(gap.gap.reason.contains("offset mismatch"));
        let error = adapter
            .push_ciphertext(timestamp, 0, b"ignored")
            .expect_err("poisoned stream must not accept more ciphertext");
        assert!(matches!(
            error,
            Tls13SessionSecretStreamError::Poisoned { .. }
        ));
        Ok(())
    }

    #[test]
    fn upstream_ciphertext_gap_emits_plaintext_gap_and_poisons_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut adapter = stream_adapter()?.with_plaintext_offset(42);
        let timestamp = timestamp();

        let event = adapter.push_ciphertext_gap(
            timestamp,
            &Gap {
                direction: Direction::Outbound,
                expected_offset: 10,
                next_offset: Some(20),
                reason: "upstream gap".to_string(),
            },
        )?;

        let CaptureEvent::Gap(gap) = CaptureEvent::from(event) else {
            panic!("expected plaintext gap");
        };
        assert_eq!(gap.gap.expected_offset, 42);
        assert!(gap.gap.next_offset.is_none());
        assert!(gap.gap.reason.contains("upstream gap"));
        let error = adapter
            .push_ciphertext(timestamp, 0, b"ignored")
            .expect_err("poisoned stream must not accept more ciphertext");
        assert!(matches!(
            error,
            Tls13SessionSecretStreamError::Poisoned { .. }
        ));
        Ok(())
    }

    #[test]
    fn stream_degradation_reason_propagates_to_plaintext_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let mut adapter = Tls13SessionSecretStreamAdapter::from_session_secret_record(
            &record,
            demo_flow(),
            Direction::Outbound,
        )?
        .with_degradation("ciphertext stream is degraded upstream");
        let wire_record = protected_application_record(&record, 0, b"ok")?;

        let events = adapter.push_ciphertext(timestamp(), 0, wire_record)?;

        let bytes = bytes_event(&events[0]);
        assert!(bytes.degraded);
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some("ciphertext stream is degraded upstream")
        );
        Ok(())
    }

    #[test]
    fn oversized_ciphertext_record_emits_plaintext_gap_and_poisons_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut adapter = stream_adapter()?;
        let payload_len = TLS13_MAX_CIPHERTEXT_FRAGMENT_BYTES + 1;
        let record_header = [
            0x17,
            0x03,
            0x03,
            (payload_len >> 8) as u8,
            payload_len as u8,
        ];

        let events = adapter.push_ciphertext(timestamp(), 0, record_header)?;

        let [event] = events.as_slice() else {
            panic!("expected one gap event: {events:?}");
        };
        let CaptureEvent::Gap(gap) = CaptureEvent::from(event.clone()) else {
            panic!("expected plaintext gap");
        };
        assert_eq!(gap.gap.expected_offset, 0);
        assert!(gap.gap.reason.contains("exceeds"));
        assert_eq!(adapter.buffered_ciphertext_bytes(), 0);
        let error = adapter
            .push_ciphertext(timestamp(), record_header.len() as u64, b"ignored")
            .expect_err("poisoned stream must not accept more ciphertext");
        assert!(matches!(
            error,
            Tls13SessionSecretStreamError::Poisoned { .. }
        ));
        Ok(())
    }

    #[test]
    fn decrypt_failure_emits_gap_after_prior_events_and_poisons_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record()?;
        let mut adapter = Tls13SessionSecretStreamAdapter::from_session_secret_record(
            &record,
            demo_flow(),
            Direction::Outbound,
        )?;
        let good = protected_application_record(&record, 0, b"ok")?;
        let mut bad = protected_application_record(&record, 1, b"bad")?;
        *bad.last_mut().expect("record has tag") ^= 0x01;
        let mut chunk = good;
        chunk.extend_from_slice(&bad);

        let events = adapter.push_ciphertext(timestamp(), 0, chunk)?;

        assert_eq!(events.len(), 2);
        assert_eq!(bytes_event(&events[0]).bytes.as_ref(), b"ok");
        let CaptureEvent::Gap(gap) = CaptureEvent::from(events[1].clone()) else {
            panic!("expected plaintext gap");
        };
        assert_eq!(gap.gap.expected_offset, 2);
        assert!(gap.gap.reason.contains("decrypt failed"));
        assert_eq!(adapter.sequence_number(), 1);
        Ok(())
    }

    fn stream_adapter() -> Result<Tls13SessionSecretStreamAdapter, Box<dyn std::error::Error>> {
        Ok(Tls13SessionSecretStreamAdapter::from_session_secret_record(
            &session_secret_record()?,
            demo_flow(),
            Direction::Outbound,
        )?)
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

    fn bytes_event(event: &PlaintextEvent) -> crate::CapturedBytes {
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(event.clone()) else {
            panic!("expected plaintext bytes");
        };
        bytes
    }

    fn hex(value: &str) -> Vec<u8> {
        decode_hex(value).expect("test vector must be hex")
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

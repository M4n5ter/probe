use probe_core::{Direction, FlowContext, Timestamp};
use thiserror::Error;

use crate::{PlaintextChunk, PlaintextEvent, PlaintextSource};

use super::{Tls13ApplicationDataDecryptor, Tls13DecryptError, TlsSessionSecretRecord};

#[derive(Debug)]
pub struct Tls13SessionSecretPlaintextAdapter {
    decryptor: Tls13ApplicationDataDecryptor,
    flow: FlowContext,
    direction: Direction,
    next_stream_offset: u64,
    degradation_reason: Option<String>,
}

impl Tls13SessionSecretPlaintextAdapter {
    pub fn from_session_secret_record(
        record: &TlsSessionSecretRecord,
        flow: FlowContext,
        direction: Direction,
    ) -> Result<Self, Tls13SessionSecretPlaintextError> {
        Ok(Self {
            decryptor: Tls13ApplicationDataDecryptor::from_session_secret_record(record)?,
            flow,
            direction,
            next_stream_offset: 0,
            degradation_reason: None,
        })
    }

    pub fn sequence_number(&self) -> u64 {
        self.decryptor.sequence_number()
    }

    pub fn next_stream_offset(&self) -> u64 {
        self.next_stream_offset
    }

    pub(in crate::tls::session_secret) fn flow(&self) -> &FlowContext {
        &self.flow
    }

    pub(in crate::tls::session_secret) fn direction(&self) -> Direction {
        self.direction
    }

    pub(in crate::tls::session_secret) fn set_sequence_number(&mut self, sequence_number: u64) {
        self.decryptor.set_sequence_number(sequence_number);
    }

    pub(in crate::tls::session_secret) fn set_next_stream_offset(
        &mut self,
        next_stream_offset: u64,
    ) {
        self.next_stream_offset = next_stream_offset;
    }

    #[cfg(test)]
    fn with_stream_offset(mut self, next_stream_offset: u64) -> Self {
        self.set_next_stream_offset(next_stream_offset);
        self
    }

    pub fn with_degradation(mut self, reason: impl Into<String>) -> Self {
        self.degradation_reason = Some(reason.into());
        self
    }

    pub fn decrypt_next_record(
        &mut self,
        timestamp: Timestamp,
        wire_record: &[u8],
    ) -> Result<Option<PlaintextEvent>, Tls13SessionSecretPlaintextError> {
        let decrypted = self.decryptor.decrypt_next_record(wire_record)?;
        if !decrypted.content_type().is_application_data() || decrypted.plaintext().is_empty() {
            return Ok(None);
        }
        let plaintext_len = decrypted.plaintext().len() as u64;
        let mut chunk = PlaintextChunk::new(
            timestamp,
            self.flow.clone(),
            self.direction,
            decrypted.plaintext(),
        )
        .with_stream_offset(self.next_stream_offset);
        if let Some(reason) = &self.degradation_reason {
            chunk = chunk.with_degradation(reason.clone());
        }
        self.next_stream_offset = self.next_stream_offset.saturating_add(plaintext_len);
        Ok(Some(PlaintextEvent::bytes(
            PlaintextSource::TlsSessionSecret,
            chunk,
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Tls13SessionSecretPlaintextError {
    #[error(
        "TLS 1.3 session secret plaintext adapter failed to decrypt protected record: {source}"
    )]
    Decrypt {
        #[from]
        source: Tls13DecryptError,
    },
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureProviderKind, CaptureSource, FlowIdentity, ProcessContext,
        ProcessIdentity, TransportProtocol,
    };

    use super::super::{
        Tls13InnerContentType, TlsSessionSecretKind, TlsSessionSecretProtocol,
        TlsSessionSecretStore, decrypt::protect_tls13_test_record,
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
    fn tls13_application_record_becomes_plaintext_event() -> Result<(), Box<dyn std::error::Error>>
    {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            "0x1301",
            SHA256_TRAFFIC_SECRET,
        )?;
        let timestamp = Timestamp {
            monotonic_ns: 17,
            wall_time_unix_ns: 23,
        };
        let mut adapter = Tls13SessionSecretPlaintextAdapter::from_session_secret_record(
            &record,
            demo_flow(),
            Direction::Outbound,
        )?
        .with_stream_offset(9)
        .with_degradation("TLS record stream is degraded upstream");

        let Some(event) =
            adapter.decrypt_next_record(timestamp, &hex(OPENSSL_AES_128_GCM_RECORD))?
        else {
            panic!("application data record should emit plaintext bytes");
        };

        assert_eq!(event.source, PlaintextSource::TlsSessionSecret);
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(event) else {
            panic!("expected plaintext bytes");
        };
        assert_eq!(bytes.origin.source(), CaptureSource::TlsSessionSecret);
        assert_eq!(bytes.origin.provider(), CaptureProviderKind::Plaintext);
        assert_eq!(bytes.timestamp, timestamp);
        assert_eq!(bytes.direction, Direction::Outbound);
        assert_eq!(bytes.stream_offset, 9);
        assert_eq!(bytes.bytes.as_ref(), PLAINTEXT);
        assert!(bytes.degraded);
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some("TLS record stream is degraded upstream")
        );
        assert_eq!(adapter.sequence_number(), 1);
        assert_eq!(adapter.next_stream_offset(), 9 + PLAINTEXT.len() as u64);
        Ok(())
    }

    #[test]
    fn authentication_failure_does_not_advance_plaintext_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            "0x1301",
            SHA256_TRAFFIC_SECRET,
        )?;
        let mut adapter = Tls13SessionSecretPlaintextAdapter::from_session_secret_record(
            &record,
            demo_flow(),
            Direction::Outbound,
        )?
        .with_stream_offset(99);
        let timestamp = Timestamp {
            monotonic_ns: 17,
            wall_time_unix_ns: 23,
        };
        let mut wire_record = hex(OPENSSL_AES_128_GCM_RECORD);
        *wire_record.last_mut().expect("record has tag") ^= 0x01;

        let error = adapter
            .decrypt_next_record(timestamp, &wire_record)
            .expect_err("tag corruption must fail authentication");

        assert_eq!(
            error,
            Tls13SessionSecretPlaintextError::Decrypt {
                source: Tls13DecryptError::AeadOpenFailed,
            }
        );
        assert_eq!(adapter.sequence_number(), 0);
        assert_eq!(adapter.next_stream_offset(), 99);
        Ok(())
    }

    #[test]
    fn successful_records_without_application_payload_do_not_emit_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = session_secret_record(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            "0x1301",
            SHA256_TRAFFIC_SECRET,
        )?;
        let mut adapter = Tls13SessionSecretPlaintextAdapter::from_session_secret_record(
            &record,
            demo_flow(),
            Direction::Inbound,
        )?
        .with_stream_offset(99);
        let timestamp = Timestamp {
            monotonic_ns: 17,
            wall_time_unix_ns: 23,
        };
        let alert_record = protect_tls13_test_record(
            &record,
            0,
            &[0x01, 0x00, Tls13InnerContentType::Alert.as_u8()],
        )?;

        let event = adapter.decrypt_next_record(timestamp, &alert_record)?;

        assert!(event.is_none());
        assert_eq!(adapter.sequence_number(), 1);
        assert_eq!(adapter.next_stream_offset(), 99);

        let empty_application_data_record = protect_tls13_test_record(
            &record,
            1,
            &[Tls13InnerContentType::ApplicationData.as_u8()],
        )?;

        let event = adapter.decrypt_next_record(timestamp, &empty_application_data_record)?;

        assert!(event.is_none());
        assert_eq!(adapter.sequence_number(), 2);
        assert_eq!(adapter.next_stream_offset(), 99);
        Ok(())
    }

    fn session_secret_record(
        protocol: TlsSessionSecretProtocol,
        secret_kind: TlsSessionSecretKind,
        cipher_suite: &str,
        secret: &str,
    ) -> Result<TlsSessionSecretRecord, Box<dyn std::error::Error>> {
        let protocol = match protocol {
            TlsSessionSecretProtocol::Tls12 => "tls12",
            TlsSessionSecretProtocol::Tls13 => "tls13",
        };
        let secret_kind = match secret_kind {
            TlsSessionSecretKind::Master => "master_secret",
            TlsSessionSecretKind::ClientHandshakeTraffic => "client_handshake_traffic_secret",
            TlsSessionSecretKind::ServerHandshakeTraffic => "server_handshake_traffic_secret",
            TlsSessionSecretKind::ClientApplicationTraffic => "client_application_traffic_secret",
            TlsSessionSecretKind::ServerApplicationTraffic => "server_application_traffic_secret",
            TlsSessionSecretKind::Exporter => "exporter_secret",
        };
        let material = format!(
            r#"{{"protocol":"{protocol}","secret_kind":"{secret_kind}","client_random":"{CLIENT_RANDOM}","secret":"{secret}","cipher_suite":"{cipher_suite}"}}"#
        );
        let store = TlsSessionSecretStore::parse(material.as_bytes())?;
        Ok(store.records()[0].clone())
    }

    fn hex(value: &str) -> Vec<u8> {
        decode_hex(value).expect("test vector must be hex")
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

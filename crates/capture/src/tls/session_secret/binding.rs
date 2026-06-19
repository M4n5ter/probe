use probe_core::{Direction, FlowContext, Timestamp};
use thiserror::Error;

use super::super::{TlsMaterialLookup, TlsRandom};
use super::{
    material::{
        TlsSessionSecretKind, TlsSessionSecretProtocol, TlsSessionSecretRecord,
        TlsSessionSecretStore,
    },
    stream::Tls13SessionSecretStreamCursor,
};

#[derive(Debug, Clone)]
pub struct Tls13SessionSecretFlowBinding {
    pub(in crate::tls::session_secret) record: TlsSessionSecretRecord,
    pub(in crate::tls::session_secret) flow: FlowContext,
    pub(in crate::tls::session_secret) direction: Direction,
    pub(in crate::tls::session_secret) cursor: Tls13SessionSecretStreamCursor,
}

impl Tls13SessionSecretFlowBinding {
    pub(in crate::tls::session_secret) fn resume_at(
        record: TlsSessionSecretRecord,
        flow: FlowContext,
        direction: Direction,
        cursor: Tls13SessionSecretStreamCursor,
    ) -> Self {
        Self {
            record,
            flow,
            direction,
            cursor,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tls13SessionSecretFlowCandidate {
    flow: FlowContext,
    direction: Direction,
    client_random: TlsRandom,
    secret_kind: Tls13ApplicationTrafficSecretKind,
    lookup_time: Option<TlsSessionSecretLookupTime>,
    cursor: Tls13SessionSecretStreamCursor,
}

impl Tls13SessionSecretFlowCandidate {
    pub fn start(
        flow: FlowContext,
        direction: Direction,
        client_random: TlsRandom,
        secret_kind: Tls13ApplicationTrafficSecretKind,
    ) -> Self {
        Self::resume_at(
            flow,
            direction,
            client_random,
            secret_kind,
            Tls13SessionSecretStreamCursor::start(),
        )
    }

    pub fn resume_at(
        flow: FlowContext,
        direction: Direction,
        client_random: TlsRandom,
        secret_kind: Tls13ApplicationTrafficSecretKind,
        cursor: Tls13SessionSecretStreamCursor,
    ) -> Self {
        Self {
            flow,
            direction,
            client_random,
            secret_kind,
            lookup_time: None,
            cursor,
        }
    }

    pub fn with_lookup_time(mut self, lookup_time: TlsSessionSecretLookupTime) -> Self {
        self.lookup_time = Some(lookup_time);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13ApplicationTrafficSecretKind {
    Client,
    Server,
}

impl Tls13ApplicationTrafficSecretKind {
    fn session_secret_kind(self) -> TlsSessionSecretKind {
        match self {
            Self::Client => TlsSessionSecretKind::ClientApplicationTraffic,
            Self::Server => TlsSessionSecretKind::ServerApplicationTraffic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlsSessionSecretLookupTime {
    wall_time_unix_ns: u64,
}

impl TlsSessionSecretLookupTime {
    pub fn from_wall_time_unix_ns(wall_time_unix_ns: u64) -> Self {
        Self { wall_time_unix_ns }
    }

    pub fn from_timestamp(timestamp: Timestamp) -> Result<Self, TlsSessionSecretLookupTimeError> {
        let wall_time_unix_ns = u64::try_from(timestamp.wall_time_unix_ns).map_err(|_| {
            TlsSessionSecretLookupTimeError::NegativeWallTime {
                wall_time_unix_ns: timestamp.wall_time_unix_ns,
            }
        })?;
        Ok(Self::from_wall_time_unix_ns(wall_time_unix_ns))
    }

    pub fn wall_time_unix_ns(self) -> u64 {
        self.wall_time_unix_ns
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TlsSessionSecretLookupTimeError {
    #[error(
        "TLS session secret lookup requires non-negative wall_time_unix_ns, got {wall_time_unix_ns}"
    )]
    NegativeWallTime { wall_time_unix_ns: i64 },
}

#[derive(Debug, Clone, Copy)]
pub struct Tls13SessionSecretFlowBindingPlanner<'a> {
    store: &'a TlsSessionSecretStore,
}

impl<'a> Tls13SessionSecretFlowBindingPlanner<'a> {
    pub fn new(store: &'a TlsSessionSecretStore) -> Self {
        Self { store }
    }

    pub fn plan(
        &self,
        candidate: Tls13SessionSecretFlowCandidate,
    ) -> Result<Tls13SessionSecretFlowBinding, Tls13SessionSecretFlowBindingPlanError> {
        let secret_kind = candidate.secret_kind.session_secret_kind();
        let at_wall_time_unix_ns = candidate
            .lookup_time
            .map(TlsSessionSecretLookupTime::wall_time_unix_ns);
        match self.store.lookup(
            TlsSessionSecretProtocol::Tls13,
            secret_kind,
            &candidate.client_random,
            at_wall_time_unix_ns,
        ) {
            TlsMaterialLookup::Found(record) => Ok(Tls13SessionSecretFlowBinding::resume_at(
                record.clone(),
                candidate.flow,
                candidate.direction,
                candidate.cursor,
            )),
            TlsMaterialLookup::Missing => {
                Err(Tls13SessionSecretFlowBindingPlanError::MissingSecret {
                    client_random: candidate.client_random,
                    secret_kind,
                    at_wall_time_unix_ns,
                })
            }
            TlsMaterialLookup::Ambiguous { matches } => {
                Err(Tls13SessionSecretFlowBindingPlanError::AmbiguousSecret {
                    client_random: candidate.client_random,
                    secret_kind,
                    at_wall_time_unix_ns,
                    matches,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Tls13SessionSecretFlowBindingPlanError {
    #[error(
        "missing TLS 1.3 session secret for client_random {client_random:?} secret_kind {secret_kind:?} at {at_wall_time_unix_ns:?}"
    )]
    MissingSecret {
        client_random: TlsRandom,
        secret_kind: TlsSessionSecretKind,
        at_wall_time_unix_ns: Option<u64>,
    },
    #[error(
        "ambiguous TLS 1.3 session secret for client_random {client_random:?} secret_kind {secret_kind:?} at {at_wall_time_unix_ns:?}: {matches} matches"
    )]
    AmbiguousSecret {
        client_random: TlsRandom,
        secret_kind: TlsSessionSecretKind,
        at_wall_time_unix_ns: Option<u64>,
        matches: usize,
    },
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, EnforcementEvidence, FlowIdentity,
        ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };

    use super::super::{
        Tls13InnerContentType, Tls13SessionSecretFlowDecryptor, decrypt::protect_tls13_test_record,
    };
    use super::*;
    use crate::{CaptureEvent, CapturedBytes, EnforcementEvidencePropagation};

    const CLIENT_RANDOM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const OTHER_CLIENT_RANDOM: &str =
        "101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f";
    const SHA256_TRAFFIC_SECRET: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn planner_binds_found_material_and_decryptor_emits_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = session_secret_store(session_secret_record_json(
            CLIENT_RANDOM,
            TlsSessionSecretKind::ClientApplicationTraffic,
            SHA256_TRAFFIC_SECRET,
            Some((10, 20)),
        ))?;
        let client_random = TlsRandom::from_hex(CLIENT_RANDOM).expect("valid client random");
        let record = store.records()[0].clone();
        let flow = demo_flow();
        let binding = Tls13SessionSecretFlowBindingPlanner::new(&store).plan(
            Tls13SessionSecretFlowCandidate::resume_at(
                flow.clone(),
                Direction::Outbound,
                client_random,
                Tls13ApplicationTrafficSecretKind::Client,
                Tls13SessionSecretStreamCursor::resume_at(5, 7, 2),
            )
            .with_lookup_time(
                TlsSessionSecretLookupTime::from_timestamp(Timestamp {
                    monotonic_ns: 99,
                    wall_time_unix_ns: 15,
                })
                .expect("non-negative wall time"),
            ),
        )?;
        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(binding)?;
        let wire_record = protected_application_record(&record, 2, b"ok")?;

        let events = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            5,
            wire_record,
        )))?;

        let [event] = events.as_slice() else {
            panic!("expected one plaintext event: {events:?}");
        };
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(event.clone()) else {
            panic!("expected plaintext bytes");
        };
        assert_eq!(bytes.stream_offset, 7);
        assert_eq!(bytes.bytes.as_ref(), b"ok");
        Ok(())
    }

    #[test]
    fn planner_reports_missing_material() -> Result<(), Box<dyn std::error::Error>> {
        let store = session_secret_store(session_secret_record_json(
            CLIENT_RANDOM,
            TlsSessionSecretKind::ClientApplicationTraffic,
            SHA256_TRAFFIC_SECRET,
            None,
        ))?;
        let other_random = TlsRandom::from_hex(OTHER_CLIENT_RANDOM).expect("valid client random");

        let error = Tls13SessionSecretFlowBindingPlanner::new(&store)
            .plan(Tls13SessionSecretFlowCandidate::start(
                demo_flow(),
                Direction::Outbound,
                other_random,
                Tls13ApplicationTrafficSecretKind::Client,
            ))
            .expect_err("lookup should miss");

        assert!(matches!(
            error,
            Tls13SessionSecretFlowBindingPlanError::MissingSecret { .. }
        ));
        Ok(())
    }

    #[test]
    fn planner_reports_ambiguous_material() -> Result<(), Box<dyn std::error::Error>> {
        let material = format!(
            "{}\n{}",
            session_secret_record_json(
                CLIENT_RANDOM,
                TlsSessionSecretKind::ClientApplicationTraffic,
                SHA256_TRAFFIC_SECRET,
                None,
            ),
            session_secret_record_json(
                CLIENT_RANDOM,
                TlsSessionSecretKind::ClientApplicationTraffic,
                SHA256_TRAFFIC_SECRET,
                None,
            )
        );
        let store = session_secret_store(material)?;
        let client_random = TlsRandom::from_hex(CLIENT_RANDOM).expect("valid client random");

        let error = Tls13SessionSecretFlowBindingPlanner::new(&store)
            .plan(Tls13SessionSecretFlowCandidate::start(
                demo_flow(),
                Direction::Outbound,
                client_random,
                Tls13ApplicationTrafficSecretKind::Client,
            ))
            .expect_err("lookup should be ambiguous");

        assert_eq!(
            error,
            Tls13SessionSecretFlowBindingPlanError::AmbiguousSecret {
                client_random,
                secret_kind: TlsSessionSecretKind::ClientApplicationTraffic,
                at_wall_time_unix_ns: None,
                matches: 2,
            }
        );
        Ok(())
    }

    #[test]
    fn planner_uses_lookup_time_to_select_valid_material() -> Result<(), Box<dyn std::error::Error>>
    {
        let early_secret = "11".repeat(32);
        let late_secret = "22".repeat(32);
        let material = format!(
            "{}\n{}",
            session_secret_record_json(
                CLIENT_RANDOM,
                TlsSessionSecretKind::ClientApplicationTraffic,
                &early_secret,
                Some((10, 20)),
            ),
            session_secret_record_json(
                CLIENT_RANDOM,
                TlsSessionSecretKind::ClientApplicationTraffic,
                &late_secret,
                Some((30, 40)),
            )
        );
        let store = session_secret_store(material)?;
        let client_random = TlsRandom::from_hex(CLIENT_RANDOM).expect("valid client random");
        let late_record = store.records()[1].clone();
        let flow = demo_flow();

        let binding = Tls13SessionSecretFlowBindingPlanner::new(&store).plan(
            Tls13SessionSecretFlowCandidate::start(
                flow.clone(),
                Direction::Outbound,
                client_random,
                Tls13ApplicationTrafficSecretKind::Client,
            )
            .with_lookup_time(TlsSessionSecretLookupTime::from_wall_time_unix_ns(35)),
        )?;

        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(binding)?;
        let wire_record = protected_application_record(&late_record, 0, b"late")?;
        let events = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Outbound,
            0,
            wire_record,
        )))?;

        let [event] = events.as_slice() else {
            panic!("expected one plaintext event: {events:?}");
        };
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(event.clone()) else {
            panic!("expected plaintext bytes");
        };
        assert_eq!(bytes.bytes.as_ref(), b"late");
        Ok(())
    }

    #[test]
    fn planner_binds_server_application_secret_kind() -> Result<(), Box<dyn std::error::Error>> {
        let store = session_secret_store(session_secret_record_json(
            CLIENT_RANDOM,
            TlsSessionSecretKind::ServerApplicationTraffic,
            SHA256_TRAFFIC_SECRET,
            None,
        ))?;
        let client_random = TlsRandom::from_hex(CLIENT_RANDOM).expect("valid client random");
        let record = store.records()[0].clone();
        let flow = demo_flow();

        let binding = Tls13SessionSecretFlowBindingPlanner::new(&store).plan(
            Tls13SessionSecretFlowCandidate::start(
                flow.clone(),
                Direction::Inbound,
                client_random,
                Tls13ApplicationTrafficSecretKind::Server,
            ),
        )?;

        let mut decryptor = Tls13SessionSecretFlowDecryptor::new();
        decryptor.bind(binding)?;
        let wire_record = protected_application_record(&record, 0, b"server")?;
        let events = decryptor.push_capture_event(&CaptureEvent::Bytes(captured_bytes(
            flow,
            Direction::Inbound,
            0,
            wire_record,
        )))?;

        let [event] = events.as_slice() else {
            panic!("expected one plaintext event: {events:?}");
        };
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(event.clone()) else {
            panic!("expected plaintext bytes");
        };
        assert_eq!(bytes.bytes.as_ref(), b"server");
        Ok(())
    }

    #[test]
    fn lookup_time_from_timestamp_rejects_negative_wall_time() {
        let error = TlsSessionSecretLookupTime::from_timestamp(Timestamp {
            monotonic_ns: 99,
            wall_time_unix_ns: -1,
        })
        .expect_err("negative wall time is not valid lookup time");

        assert_eq!(
            error,
            TlsSessionSecretLookupTimeError::NegativeWallTime {
                wall_time_unix_ns: -1,
            }
        );
    }

    fn session_secret_store(
        material: String,
    ) -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>> {
        Ok(TlsSessionSecretStore::parse(material.as_bytes())?)
    }

    fn session_secret_record_json(
        client_random: &str,
        secret_kind: TlsSessionSecretKind,
        secret: &str,
        validity: Option<(u64, u64)>,
    ) -> String {
        let kind = match secret_kind {
            TlsSessionSecretKind::ClientApplicationTraffic => "client_application_traffic_secret",
            TlsSessionSecretKind::ServerApplicationTraffic => "server_application_traffic_secret",
            TlsSessionSecretKind::ClientHandshakeTraffic => "client_handshake_traffic_secret",
            TlsSessionSecretKind::ServerHandshakeTraffic => "server_handshake_traffic_secret",
            TlsSessionSecretKind::Exporter => "exporter_secret",
            TlsSessionSecretKind::Master => "master_secret",
        };
        let validity = validity
            .map(|(not_before, not_after)| {
                format!(r#","not_before_unix_ns":{not_before},"not_after_unix_ns":{not_after}"#)
            })
            .unwrap_or_default();
        format!(
            r#"{{"protocol":"tls13","secret_kind":"{kind}","client_random":"{client_random}","secret":"{secret}","cipher_suite":"0x1301"{validity}}}"#
        )
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
    ) -> CapturedBytes {
        CapturedBytes {
            timestamp: timestamp(),
            flow,
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            direction,
            stream_offset,
            bytes: Bytes::from(bytes),
            attribution_confidence: 100,
            degraded: false,
            degradation_reason: None,
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }
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

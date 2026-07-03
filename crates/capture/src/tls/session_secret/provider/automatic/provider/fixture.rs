use std::collections::VecDeque;

use bytes::Bytes;
use probe_core::{
    AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource, Direction,
    EnforcementEvidence, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, Timestamp,
    TransportProtocol,
};

use super::super::super::super::{
    Tls13InnerContentType, TlsSessionSecretRecord, TlsSessionSecretStore,
    decrypt::protect_tls13_test_record,
};
use super::Tls13SessionSecretAutoBindingProvider;
use crate::tls::decode_hex;
use crate::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CapturedBytes,
    EnforcementEvidencePropagation,
};

pub(super) const CLIENT_RANDOM: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
pub(super) const OTHER_CLIENT_RANDOM: &str =
    "101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f";
pub(super) const SHA256_TRAFFIC_SECRET: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SERVER_RANDOM: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

pub(super) struct AutoBindingFixture {
    pub(super) store: TlsSessionSecretStore,
    pub(super) flow: FlowContext,
    pub(super) client_hello: Vec<u8>,
    pub(super) application_record: Vec<u8>,
}

pub(super) struct BidirectionalAutoBindingFixture {
    pub(super) store: TlsSessionSecretStore,
    pub(super) flow: FlowContext,
    pub(super) client_hello: Vec<u8>,
    pub(super) server_application_record: Vec<u8>,
}

pub(super) fn auto_binding_fixture() -> Result<AutoBindingFixture, Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let application_record =
        protected_application_record(&store.records()[0], 0, b"GET / HTTP/1.1\r\n\r\n")?;
    Ok(AutoBindingFixture {
        store,
        flow: demo_flow(1),
        client_hello: tls_client_hello_record(),
        application_record,
    })
}

pub(super) fn bidirectional_auto_binding_fixture()
-> Result<BidirectionalAutoBindingFixture, Box<dyn std::error::Error>> {
    let store = bidirectional_session_secret_store()?;
    let server_application_record =
        protected_application_record(&store.records()[1], 0, b"server")?;
    Ok(BidirectionalAutoBindingFixture {
        store,
        flow: demo_flow(1),
        client_hello: tls_client_hello_record(),
        server_application_record,
    })
}

pub(super) fn auto_provider(
    store: impl Into<Option<TlsSessionSecretStore>>,
    events: impl IntoIterator<Item = CaptureEvent>,
) -> Tls13SessionSecretAutoBindingProvider {
    match store.into() {
        Some(store) => {
            Tls13SessionSecretAutoBindingProvider::new(Box::new(VecProvider::new(events)), store)
        }
        None => {
            Tls13SessionSecretAutoBindingProvider::new_pending(Box::new(VecProvider::new(events)))
        }
    }
}

pub(super) fn assert_terminal_outbound_candidate_releases_held_raw(
    outbound_bytes: &[u8],
    second_chunk_offset_gap: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let AutoBindingFixture {
        store,
        flow,
        client_hello,
        ..
    } = auto_binding_fixture()?;
    let split_at = 4;
    let first = outbound_captured_bytes(
        &flow,
        client_hello.len() as u64,
        outbound_bytes[..split_at].to_vec(),
    );
    let second = outbound_captured_bytes(
        &flow,
        (client_hello.len() + split_at) as u64 + second_chunk_offset_gap,
        outbound_bytes[split_at..].to_vec(),
    );
    let mut provider = auto_provider(
        store,
        [
            outbound_bytes_event(&flow, 0, client_hello.clone()),
            CaptureEvent::Bytes(first.clone()),
            CaptureEvent::Bytes(second.clone()),
        ],
    );

    assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
    assert_next_captured_bytes(&mut provider, &first)?;
    assert_next_captured_bytes(&mut provider, &second)?;
    assert!(provider.next()?.is_none());
    Ok(())
}

pub(super) fn assert_next_libpcap_bytes(
    provider: &mut Tls13SessionSecretAutoBindingProvider,
    expected: &[u8],
) -> Result<CapturedBytes, Box<dyn std::error::Error>> {
    assert_next_auto_provider_bytes(provider, CaptureSource::Libpcap, expected)
}

pub(super) fn assert_next_tls_session_secret_bytes(
    provider: &mut Tls13SessionSecretAutoBindingProvider,
    expected: &[u8],
) -> Result<CapturedBytes, Box<dyn std::error::Error>> {
    assert_next_auto_provider_bytes(provider, CaptureSource::TlsSessionSecret, expected)
}

fn assert_next_auto_provider_bytes(
    provider: &mut Tls13SessionSecretAutoBindingProvider,
    source: CaptureSource,
    expected: &[u8],
) -> Result<CapturedBytes, Box<dyn std::error::Error>> {
    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected bytes event from auto-binding provider");
    };
    assert_eq!(bytes.origin.source(), source);
    assert_eq!(bytes.bytes.as_ref(), expected);
    Ok(bytes)
}

pub(super) fn assert_next_captured_bytes(
    provider: &mut Tls13SessionSecretAutoBindingProvider,
    expected: &CapturedBytes,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected exact bytes event from auto-binding provider");
    };
    assert_eq!(&bytes, expected);
    Ok(())
}

fn session_secret_store() -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>> {
    session_secret_store_for_client_random(CLIENT_RANDOM)
}

pub(super) fn session_secret_store_for_client_random(
    client_random: &str,
) -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>> {
    session_secret_store_with_secret(client_random, SHA256_TRAFFIC_SECRET)
}

pub(super) fn session_secret_store_with_secret(
    client_random: &str,
    secret: &str,
) -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>> {
    let material = format!(
        r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"{secret}","cipher_suite":"0x1301"}}"#
    );
    Ok(TlsSessionSecretStore::parse(material.as_bytes())?)
}

fn bidirectional_session_secret_store() -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>>
{
    let material = format!(
        r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}
{{"protocol":"tls13","secret_kind":"server_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}"#
    );
    Ok(TlsSessionSecretStore::parse(material.as_bytes())?)
}

pub(super) fn ambiguous_session_secret_store()
-> Result<TlsSessionSecretStore, Box<dyn std::error::Error>> {
    let material = format!(
        r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}"#
    );
    Ok(TlsSessionSecretStore::parse(material.as_bytes())?)
}

pub(super) fn protected_application_record(
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

fn tls_client_hello_record() -> Vec<u8> {
    tls_handshake_record(1, tls_client_hello_body())
}

pub(super) fn tls_server_hello_record() -> Vec<u8> {
    tls_handshake_record(2, tls_server_hello_body())
}

fn tls_client_hello_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&decode_hex(CLIENT_RANDOM).expect("valid client random"));
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    let supported_versions = vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
    body.extend_from_slice(&(supported_versions.len() as u16).to_be_bytes());
    body.extend_from_slice(&supported_versions);
    body
}

fn tls_server_hello_body() -> Vec<u8> {
    let supported_versions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&decode_hex(SERVER_RANDOM).expect("valid server random"));
    body.push(0);
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(0);
    body.extend_from_slice(&(supported_versions.len() as u16).to_be_bytes());
    body.extend_from_slice(&supported_versions);
    body
}

fn tls_handshake_record(handshake_type: u8, body: Vec<u8>) -> Vec<u8> {
    let mut payload = vec![
        handshake_type,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    payload.extend_from_slice(&body);
    tls_record(22, payload)
}

pub(super) fn tls_outer_application_data_record(payload: Vec<u8>) -> Vec<u8> {
    tls_record(23, payload)
}

pub(super) fn non_application_records(count: usize) -> Vec<u8> {
    (0..count)
        .flat_map(|index| tls_record(22, vec![index as u8]))
        .collect()
}

pub(super) fn unauthenticated_application_records(count: usize) -> Vec<u8> {
    (0..count)
        .flat_map(|index| tls_outer_application_data_record(vec![index as u8; 17]))
        .collect()
}

fn tls_record(content_type: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut record = vec![
        content_type,
        0x03,
        0x03,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ];
    record.extend_from_slice(&payload);
    record
}

fn captured_bytes(
    flow: FlowContext,
    direction: Direction,
    stream_offset: u64,
    bytes: Vec<u8>,
) -> CapturedBytes {
    captured_bytes_with_timestamp(timestamp(), flow, direction, stream_offset, bytes)
}

pub(super) fn outbound_bytes_event(
    flow: &FlowContext,
    stream_offset: u64,
    bytes: Vec<u8>,
) -> CaptureEvent {
    CaptureEvent::Bytes(outbound_captured_bytes(flow, stream_offset, bytes))
}

pub(super) fn outbound_captured_bytes(
    flow: &FlowContext,
    stream_offset: u64,
    bytes: Vec<u8>,
) -> CapturedBytes {
    captured_bytes(flow.clone(), Direction::Outbound, stream_offset, bytes)
}

pub(super) fn inbound_captured_bytes(
    flow: &FlowContext,
    stream_offset: u64,
    bytes: Vec<u8>,
) -> CapturedBytes {
    captured_bytes(flow.clone(), Direction::Inbound, stream_offset, bytes)
}

pub(super) fn captured_bytes_with_timestamp(
    timestamp: Timestamp,
    flow: FlowContext,
    direction: Direction,
    stream_offset: u64,
    bytes: Vec<u8>,
) -> CapturedBytes {
    CapturedBytes {
        timestamp,
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

pub(super) fn captured_gap(
    flow: FlowContext,
    direction: Direction,
    expected_offset: u64,
    next_offset: Option<u64>,
    reason: &str,
) -> crate::CapturedGap {
    crate::CapturedGap {
        timestamp: timestamp(),
        flow,
        origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
        enforcement_evidence: EnforcementEvidence::default(),
        enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        gap: probe_core::Gap {
            direction,
            expected_offset,
            next_offset,
            reason: reason.to_string(),
        },
    }
}

pub(super) fn timestamp() -> Timestamp {
    Timestamp {
        monotonic_ns: 17,
        wall_time_unix_ns: 23,
    }
}

pub(super) fn demo_flow(socket_cookie: u64) -> FlowContext {
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

#[derive(Debug)]
struct VecProvider {
    events: VecDeque<CaptureEvent>,
}

impl VecProvider {
    fn new(events: impl IntoIterator<Item = CaptureEvent>) -> Self {
        Self {
            events: events.into_iter().collect(),
        }
    }
}

impl CaptureProvider for VecProvider {
    fn name(&self) -> &'static str {
        "vec"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(CapabilityKind::Libpcap)]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        Ok(self
            .events
            .pop_front()
            .map(CapturePoll::event)
            .unwrap_or(CapturePoll::Finished))
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_next()
    }
}

#[derive(Debug)]
pub(super) struct IdleAfterEventsProvider {
    events: VecDeque<CaptureEvent>,
}

impl IdleAfterEventsProvider {
    pub(super) fn new(events: impl IntoIterator<Item = CaptureEvent>) -> Self {
        Self {
            events: events.into_iter().collect(),
        }
    }
}

impl CaptureProvider for IdleAfterEventsProvider {
    fn name(&self) -> &'static str {
        "idle_after_events"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(CapabilityKind::Libpcap)]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        Ok(self
            .events
            .pop_front()
            .map(CapturePoll::event)
            .unwrap_or(CapturePoll::Idle))
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_next()
    }
}

#[derive(Debug)]
pub(super) struct StrictFinishedProvider {
    events: VecDeque<CaptureEvent>,
    finished_returned: bool,
}

impl StrictFinishedProvider {
    pub(super) fn new(events: impl IntoIterator<Item = CaptureEvent>) -> Self {
        Self {
            events: events.into_iter().collect(),
            finished_returned: false,
        }
    }
}

impl CaptureProvider for StrictFinishedProvider {
    fn name(&self) -> &'static str {
        "strict_finished"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(CapabilityKind::Libpcap)]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        if let Some(event) = self.events.pop_front() {
            return Ok(CapturePoll::event(event));
        }
        if self.finished_returned {
            return Err(CaptureError::provider(
                self.name(),
                "inner provider was polled after finish",
            ));
        }
        self.finished_returned = true;
        Ok(CapturePoll::Finished)
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_next()
    }
}

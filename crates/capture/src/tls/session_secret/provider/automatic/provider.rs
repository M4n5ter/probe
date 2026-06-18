use probe_core::{CapabilityKind, CapabilityState};

use crate::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider};

use super::super::super::TlsSessionSecretStore;
use super::super::Tls13SessionSecretDecryptingEngine;
use super::{Tls13SessionSecretAutomaticAction, Tls13SessionSecretAutomaticBinder};

const TLS13_SESSION_SECRET_AUTO_BINDING_PROVIDER_NAME: &str = "tls_session_secret_auto_binding";

pub struct Tls13SessionSecretAutoBindingProvider {
    inner: Box<dyn CaptureProvider>,
    binder: Tls13SessionSecretAutomaticBinder,
    engine: Tls13SessionSecretDecryptingEngine,
    inner_finished: bool,
}

impl Tls13SessionSecretAutoBindingProvider {
    pub fn new(inner: Box<dyn CaptureProvider>, store: TlsSessionSecretStore) -> Self {
        Self {
            inner,
            binder: Tls13SessionSecretAutomaticBinder::new(store),
            engine: Tls13SessionSecretDecryptingEngine::new(),
            inner_finished: false,
        }
    }

    fn handle_inner_event(&mut self, event: CaptureEvent) -> Result<CapturePoll, CaptureError> {
        match self.binder.observe_and_bind(event) {
            Tls13SessionSecretAutomaticAction::PassThrough { events } => self
                .engine
                .handle_inner_events(TLS13_SESSION_SECRET_AUTO_BINDING_PROVIDER_NAME, events),
            Tls13SessionSecretAutomaticAction::BindAndProcess {
                released_events,
                raw_prefix_events,
                binding,
                bytes,
            } => self.engine.bind_and_handle_inner_event_after_raw_prefix(
                TLS13_SESSION_SECRET_AUTO_BINDING_PROVIDER_NAME,
                released_events,
                raw_prefix_events,
                *binding,
                CaptureEvent::Bytes(*bytes),
            ),
        }
    }

    fn finish_after_inner_finished(&mut self) -> Result<CapturePoll, CaptureError> {
        let released_events = self.binder.release_buffered_events();
        if !released_events.is_empty() {
            return self.engine.handle_inner_events(
                TLS13_SESSION_SECRET_AUTO_BINDING_PROVIDER_NAME,
                released_events,
            );
        }
        self.engine.finish_bound_streams_before_inner_finished()
    }
}

impl CaptureProvider for Tls13SessionSecretAutoBindingProvider {
    fn name(&self) -> &'static str {
        TLS13_SESSION_SECRET_AUTO_BINDING_PROVIDER_NAME
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        let mut capabilities = self.inner.capabilities();
        capabilities.push(CapabilityState::degraded(
            CapabilityKind::TlsSessionSecretRecordDecrypt,
            "TLS session-secret auto-binding provider can automatically bind TLS 1.3 application traffic secrets from observed ClientHello and bounded record resync; ciphertext capture remains best effort",
        ));
        capabilities
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        if let Some(event) = self.engine.pop_pending_event() {
            return Ok(CapturePoll::event(event));
        }
        if self.inner_finished {
            return self.finish_after_inner_finished();
        }
        match self.inner.poll_next()? {
            CapturePoll::Event(event) => self.handle_inner_event(*event),
            CapturePoll::Finished => {
                self.inner_finished = true;
                self.finish_after_inner_finished()
            }
            other => Ok(other),
        }
    }
}

#[cfg(test)]
mod tests {
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
    use super::*;
    use crate::tls::decode_hex;
    use crate::{CapturedBytes, EnforcementEvidencePropagation};

    const CLIENT_RANDOM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const OTHER_CLIENT_RANDOM: &str =
        "101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f";
    const SHA256_TRAFFIC_SECRET: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    struct AutoBindingFixture {
        store: TlsSessionSecretStore,
        flow: FlowContext,
        client_hello: Vec<u8>,
        application_record: Vec<u8>,
    }

    struct BidirectionalAutoBindingFixture {
        store: TlsSessionSecretStore,
        flow: FlowContext,
        client_hello: Vec<u8>,
        server_application_record: Vec<u8>,
    }

    #[test]
    fn auto_binding_provider_binds_after_authenticated_application_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let encrypted_handshake_like_record = tls_outer_application_data_record(vec![0; 17]);
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(
                    &flow,
                    client_hello.len() as u64,
                    encrypted_handshake_like_record.clone(),
                ),
                outbound_bytes_event(
                    &flow,
                    (client_hello.len() + encrypted_handshake_like_record.len()) as u64,
                    application_record,
                ),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_libpcap_bytes(&mut provider, encrypted_handshake_like_record.as_slice())?;
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"GET / HTTP/1.1\r\n\r\n")?;
        assert!(bytes.degraded);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_splits_current_chunk_when_binding_starts_mid_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let mut combined_record = client_hello.clone();
        combined_record.extend_from_slice(&application_record);
        let mut provider = auto_provider(store, [outbound_bytes_event(&flow, 0, combined_record)]);

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"GET / HTTP/1.1\r\n\r\n")?;
        assert!(bytes.degraded);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_buffers_split_application_record_before_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let split_at = 8;
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(
                    &flow,
                    client_hello.len() as u64,
                    application_record[..split_at].to_vec(),
                ),
                outbound_bytes_event(
                    &flow,
                    (client_hello.len() + split_at) as u64,
                    application_record[split_at..].to_vec(),
                ),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"GET / HTTP/1.1\r\n\r\n")?;
        assert!(bytes.degraded);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_releases_held_raw_bytes_before_close()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let first_split = 4;
        let held = outbound_captured_bytes(
            &flow,
            client_hello.len() as u64,
            application_record[..first_split].to_vec(),
        );
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                CaptureEvent::Bytes(held.clone()),
                CaptureEvent::ConnectionClosed {
                    timestamp: timestamp(),
                    flow: flow.clone(),
                    origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
                },
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_captured_bytes(&mut provider, &held)?;
        let Some(CaptureEvent::ConnectionClosed { origin, .. }) = provider.next()? else {
            panic!("expected original close after released held raw bytes");
        };
        assert_eq!(origin.source(), CaptureSource::Libpcap);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_releases_held_raw_bytes_before_directional_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let first_split = 4;
        let held = outbound_captured_bytes(
            &flow,
            client_hello.len() as u64,
            application_record[..first_split].to_vec(),
        );
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                CaptureEvent::Bytes(held.clone()),
                CaptureEvent::Gap(captured_gap(
                    flow.clone(),
                    Direction::Outbound,
                    (client_hello.len() + first_split) as u64,
                    None,
                    "outbound capture gap",
                )),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_captured_bytes(&mut provider, &held)?;
        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
            panic!("expected original gap after released held raw bytes");
        };
        assert_eq!(gap.origin.source(), CaptureSource::Libpcap);
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_keeps_opposite_direction_candidate_after_directional_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let BidirectionalAutoBindingFixture {
            store,
            flow,
            client_hello,
            server_application_record,
            ..
        } = bidirectional_auto_binding_fixture()?;
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                CaptureEvent::Gap(captured_gap(
                    flow.clone(),
                    Direction::Outbound,
                    client_hello.len() as u64,
                    None,
                    "outbound capture gap",
                )),
                CaptureEvent::Bytes(inbound_captured_bytes(&flow, 0, server_application_record)),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
            panic!("expected original outbound gap before server plaintext");
        };
        assert_eq!(gap.gap.direction, Direction::Outbound);
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"server")?;
        assert!(bytes.degraded);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_releases_held_raw_bytes_before_later_pass_through_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let unrelated_flow = demo_flow(2);
        let unrelated_payload = b"later flow".to_vec();
        let split_at = 4;
        let held_first = outbound_captured_bytes(
            &flow,
            client_hello.len() as u64,
            application_record[..split_at].to_vec(),
        );
        let unrelated = outbound_captured_bytes(&unrelated_flow, 0, unrelated_payload.clone());
        let held_second = outbound_captured_bytes(
            &flow,
            (client_hello.len() + split_at) as u64,
            application_record[split_at..].to_vec(),
        );
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                CaptureEvent::Bytes(held_first.clone()),
                CaptureEvent::Bytes(unrelated.clone()),
                CaptureEvent::Bytes(held_second.clone()),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_captured_bytes(&mut provider, &held_first)?;
        assert_next_captured_bytes(&mut provider, &unrelated)?;
        assert_next_captured_bytes(&mut provider, &held_second)?;
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_releases_held_raw_bytes_after_bounded_non_application_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            ..
        } = auto_binding_fixture()?;
        let records = non_application_records(32);
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(&flow, client_hello.len() as u64, records.clone()),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_libpcap_bytes(&mut provider, &records)?;
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_preserves_prefix_before_terminal_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            ..
        } = auto_binding_fixture()?;
        let split_at = 7;
        let invalid_record = [0x17, 0x03, 0x03, 0xff, 0xff];
        let mut second_chunk = client_hello[split_at..].to_vec();
        second_chunk.extend_from_slice(&invalid_record);
        let expected_prefix =
            outbound_captured_bytes(&flow, split_at as u64, client_hello[split_at..].to_vec());
        let expected_invalid =
            outbound_captured_bytes(&flow, client_hello.len() as u64, invalid_record.to_vec());
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello[..split_at].to_vec()),
                outbound_bytes_event(&flow, split_at as u64, second_chunk),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, &client_hello[..split_at])?;
        assert_next_captured_bytes(&mut provider, &expected_prefix)?;
        assert_next_captured_bytes(&mut provider, &expected_invalid)?;
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_releases_held_raw_bytes_when_append_mismatches()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            application_record, ..
        } = auto_binding_fixture()?;
        assert_terminal_outbound_candidate_releases_held_raw(&application_record[..8], 1)
    }

    #[test]
    fn auto_binding_provider_releases_held_raw_bytes_when_record_is_invalid()
    -> Result<(), Box<dyn std::error::Error>> {
        let invalid_record = [0x17, 0x03, 0x03, 0xff, 0xff];
        assert_terminal_outbound_candidate_releases_held_raw(&invalid_record, 0)
    }

    #[test]
    fn auto_binding_provider_releases_held_raw_bytes_when_authentication_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let unauthenticated_records = unauthenticated_application_records(32);
        assert_terminal_outbound_candidate_releases_held_raw(&unauthenticated_records, 0)
    }

    #[test]
    fn auto_binding_provider_does_not_poll_inner_after_releasing_buffered_bytes_on_finish()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let split_at = 4;
        let mut provider = Tls13SessionSecretAutoBindingProvider::new(
            Box::new(StrictFinishedProvider::new([
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(
                    &flow,
                    client_hello.len() as u64,
                    application_record[..split_at].to_vec(),
                ),
            ])),
            store,
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_libpcap_bytes(&mut provider, &application_record[..split_at])?;
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_skips_completed_client_hello_tail_before_probing_current_chunk()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let split_at = 7;
        let mut second_chunk = client_hello[split_at..].to_vec();
        second_chunk.extend_from_slice(&application_record);
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello[..split_at].to_vec()),
                outbound_bytes_event(&flow, split_at as u64, second_chunk),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, &client_hello[..split_at])?;
        assert_next_libpcap_bytes(&mut provider, &client_hello[split_at..])?;
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"GET / HTTP/1.1\r\n\r\n")?;
        assert!(bytes.degraded);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_fails_closed_when_observation_time_is_invalid()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let mut provider = auto_provider(
            store,
            [
                CaptureEvent::Bytes(captured_bytes_with_timestamp(
                    Timestamp {
                        monotonic_ns: 17,
                        wall_time_unix_ns: -1,
                    },
                    flow.clone(),
                    Direction::Outbound,
                    0,
                    client_hello.clone(),
                )),
                outbound_bytes_event(&flow, client_hello.len() as u64, application_record.clone()),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_libpcap_bytes(&mut provider, application_record.as_slice())?;
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_does_not_buffer_split_record_without_matching_material()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_split_record_passes_through_without_binding(session_secret_store_for_client_random(
            OTHER_CLIENT_RANDOM,
        )?)
    }

    #[test]
    fn auto_binding_provider_does_not_buffer_split_record_with_ambiguous_material()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_split_record_passes_through_without_binding(ambiguous_session_secret_store()?)
    }

    fn assert_split_record_passes_through_without_binding(
        store: TlsSessionSecretStore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            flow,
            client_hello,
            application_record,
            ..
        } = auto_binding_fixture()?;
        let split_at = 8;
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(
                    &flow,
                    client_hello.len() as u64,
                    application_record[..split_at].to_vec(),
                ),
                outbound_bytes_event(
                    &flow,
                    (client_hello.len() + split_at) as u64,
                    application_record[split_at..].to_vec(),
                ),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_libpcap_bytes(&mut provider, &application_record[..split_at])?;
        assert_next_libpcap_bytes(&mut provider, &application_record[split_at..])?;
        assert!(provider.next()?.is_none());
        Ok(())
    }

    fn auto_binding_fixture() -> Result<AutoBindingFixture, Box<dyn std::error::Error>> {
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

    fn bidirectional_auto_binding_fixture()
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

    fn auto_provider(
        store: TlsSessionSecretStore,
        events: impl IntoIterator<Item = CaptureEvent>,
    ) -> Tls13SessionSecretAutoBindingProvider {
        Tls13SessionSecretAutoBindingProvider::new(Box::new(VecProvider::new(events)), store)
    }

    fn assert_terminal_outbound_candidate_releases_held_raw(
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

    fn assert_next_libpcap_bytes(
        provider: &mut Tls13SessionSecretAutoBindingProvider,
        expected: &[u8],
    ) -> Result<CapturedBytes, Box<dyn std::error::Error>> {
        assert_next_auto_provider_bytes(provider, CaptureSource::Libpcap, expected)
    }

    fn assert_next_tls_session_secret_bytes(
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

    fn assert_next_captured_bytes(
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

    fn session_secret_store_for_client_random(
        client_random: &str,
    ) -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>> {
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}"#
        );
        Ok(TlsSessionSecretStore::parse(material.as_bytes())?)
    }

    fn bidirectional_session_secret_store()
    -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>> {
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}
{{"protocol":"tls13","secret_kind":"server_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}"#
        );
        Ok(TlsSessionSecretStore::parse(material.as_bytes())?)
    }

    fn ambiguous_session_secret_store() -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>>
    {
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}"#
        );
        Ok(TlsSessionSecretStore::parse(material.as_bytes())?)
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

    fn tls_client_hello_record() -> Vec<u8> {
        tls_handshake_record(1, tls_client_hello_body())
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

    fn tls_outer_application_data_record(payload: Vec<u8>) -> Vec<u8> {
        tls_record(23, payload)
    }

    fn non_application_records(count: usize) -> Vec<u8> {
        (0..count)
            .flat_map(|index| tls_record(22, vec![index as u8]))
            .collect()
    }

    fn unauthenticated_application_records(count: usize) -> Vec<u8> {
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

    fn outbound_bytes_event(
        flow: &FlowContext,
        stream_offset: u64,
        bytes: Vec<u8>,
    ) -> CaptureEvent {
        CaptureEvent::Bytes(outbound_captured_bytes(flow, stream_offset, bytes))
    }

    fn outbound_captured_bytes(
        flow: &FlowContext,
        stream_offset: u64,
        bytes: Vec<u8>,
    ) -> CapturedBytes {
        captured_bytes(flow.clone(), Direction::Outbound, stream_offset, bytes)
    }

    fn inbound_captured_bytes(
        flow: &FlowContext,
        stream_offset: u64,
        bytes: Vec<u8>,
    ) -> CapturedBytes {
        captured_bytes(flow.clone(), Direction::Inbound, stream_offset, bytes)
    }

    fn captured_bytes_with_timestamp(
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

    fn captured_gap(
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

    fn timestamp() -> Timestamp {
        Timestamp {
            monotonic_ns: 17,
            wall_time_unix_ns: 23,
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
    }

    #[derive(Debug)]
    struct StrictFinishedProvider {
        events: VecDeque<CaptureEvent>,
        finished_returned: bool,
    }

    impl StrictFinishedProvider {
        fn new(events: impl IntoIterator<Item = CaptureEvent>) -> Self {
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
    }
}

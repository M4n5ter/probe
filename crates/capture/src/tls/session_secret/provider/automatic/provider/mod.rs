use probe_core::{CapabilityKind, CapabilityState};

use crate::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider};

use super::super::super::TlsSessionSecretStore;
use super::super::Tls13SessionSecretDecryptingEngine;
use super::{Tls13SessionSecretAutomaticAction, Tls13SessionSecretAutomaticBinder};

#[cfg(test)]
mod fixture;

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
            binder: Tls13SessionSecretAutomaticBinder::new(Some(store)),
            engine: Tls13SessionSecretDecryptingEngine::new(),
            inner_finished: false,
        }
    }

    pub fn new_pending(inner: Box<dyn CaptureProvider>) -> Self {
        Self {
            inner,
            binder: Tls13SessionSecretAutomaticBinder::new(None),
            engine: Tls13SessionSecretDecryptingEngine::new(),
            inner_finished: false,
        }
    }

    pub fn replace_store(&mut self, store: TlsSessionSecretStore) {
        self.binder.replace_store(store);
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
    use probe_core::{CaptureOrigin, CaptureSource, Direction, Timestamp};

    use super::super::super::super::TlsSessionSecretStore;
    use super::fixture::*;
    use super::*;

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
    fn auto_binding_provider_binds_when_store_arrives_after_client_hello()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let mut provider = auto_provider(
            None,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(&flow, client_hello.len() as u64, application_record),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        provider.replace_store(store);
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"GET / HTTP/1.1\r\n\r\n")?;
        assert!(bytes.degraded);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_binds_later_record_when_store_arrives_after_first_application_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let second_application_record =
            protected_application_record(&store.records()[0], 1, b"second")?;
        let mut provider = auto_provider(
            None,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(&flow, client_hello.len() as u64, application_record.clone()),
                outbound_bytes_event(
                    &flow,
                    (client_hello.len() + application_record.len()) as u64,
                    second_application_record,
                ),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_libpcap_bytes(&mut provider, application_record.as_slice())?;
        provider.replace_store(store);

        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
            panic!("late binding should expose skipped plaintext as a gap");
        };
        assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 0);
        assert_eq!(gap.gap.next_offset, None);
        assert!(gap.gap.reason.contains("earlier plaintext is unavailable"));

        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"second")?;
        assert_eq!(bytes.stream_offset, 0);
        assert!(bytes.degraded);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_binds_at_sequence_window_boundary_after_material_arrives_late()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_late_material_sequence_window_boundary(true)
    }

    #[test]
    fn auto_binding_provider_passes_through_after_sequence_window_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_late_material_sequence_window_boundary(false)
    }

    #[test]
    fn auto_binding_provider_pre_auth_candidate_uses_refreshed_material_before_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let stale_store = session_secret_store_with_secret(
            CLIENT_RANDOM,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )?;
        let mut provider = auto_provider(
            stale_store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(&flow, client_hello.len() as u64, application_record),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        provider.replace_store(store);
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"GET / HTTP/1.1\r\n\r\n")?;
        assert!(bytes.degraded);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn auto_binding_provider_bound_stream_keeps_admitted_material_after_refresh()
    -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let second_application_record =
            protected_application_record(&store.records()[0], 1, b"second")?;
        let second_application_record_offset =
            (client_hello.len() + application_record.len()) as u64;
        let replacement_store = session_secret_store_with_secret(
            CLIENT_RANDOM,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )?;
        let mut provider = auto_provider(
            store,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(&flow, client_hello.len() as u64, application_record),
                outbound_bytes_event(
                    &flow,
                    second_application_record_offset,
                    second_application_record,
                ),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"GET / HTTP/1.1\r\n\r\n")?;
        assert!(bytes.degraded);
        provider.replace_store(replacement_store);
        let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"second")?;
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

    fn assert_late_material_sequence_window_boundary(
        within_window: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let AutoBindingFixture {
            store,
            flow,
            client_hello,
            application_record,
        } = auto_binding_fixture()?;
        let sequence_number = if within_window {
            super::super::TLS13_AUTO_BIND_MAX_SEQUENCE_NUMBER
        } else {
            super::super::TLS13_AUTO_BIND_MAX_SEQUENCE_NUMBER + 1
        };
        let boundary_record =
            protected_application_record(&store.records()[0], sequence_number, b"boundary")?;
        let mut provider = auto_provider(
            None,
            [
                outbound_bytes_event(&flow, 0, client_hello.clone()),
                outbound_bytes_event(&flow, client_hello.len() as u64, application_record.clone()),
                outbound_bytes_event(
                    &flow,
                    (client_hello.len() + application_record.len()) as u64,
                    boundary_record.clone(),
                ),
            ],
        );

        assert_next_libpcap_bytes(&mut provider, client_hello.as_slice())?;
        assert_next_libpcap_bytes(&mut provider, application_record.as_slice())?;
        provider.replace_store(store);

        if within_window {
            let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
                panic!("late boundary binding should expose skipped plaintext as a gap");
            };
            assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
            assert!(
                gap.gap
                    .reason
                    .contains(&format!("after {sequence_number} earlier"))
            );
            let bytes = assert_next_tls_session_secret_bytes(&mut provider, b"boundary")?;
            assert!(bytes.degraded);
        } else {
            assert_next_libpcap_bytes(&mut provider, boundary_record.as_slice())?;
        }

        assert!(provider.next()?.is_none());
        Ok(())
    }
}

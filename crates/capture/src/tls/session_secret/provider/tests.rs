use std::collections::VecDeque;

use bytes::Bytes;
use probe_core::{
    AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource, Direction,
    EnforcementEvidence, FlowContext, FlowIdentity, ObservationOnlyReason, ProcessContext,
    ProcessIdentity, Timestamp, TransportProtocol,
};

use super::super::{
    Tls13ApplicationTrafficSecretKind, Tls13InnerContentType, Tls13SessionSecretFlowBinding,
    Tls13SessionSecretFlowBindingPlanner, Tls13SessionSecretFlowCandidate,
    Tls13SessionSecretFlowDecryptError, TlsSessionSecretRecord, TlsSessionSecretStore,
    decrypt::protect_tls13_test_record,
};
use super::{Tls13SessionSecretDecryptingProvider, Tls13SessionSecretDecryptingProviderError};
use crate::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CapturedBytes,
    EnforcementEvidencePropagation, TlsRandom,
};

const CLIENT_RANDOM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SHA256_TRAFFIC_SECRET: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn decrypting_provider_suppresses_bound_ciphertext_and_emits_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let wire_record = protected_application_record(&record, 0, b"GET / HTTP/1.1\r\n\r\n")?;
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [CaptureEvent::Bytes(captured_bytes(
            flow.clone(),
            Direction::Outbound,
            0,
            wire_record,
        ))],
    )?;

    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected decrypted plaintext bytes");
    };

    assert_eq!(bytes.origin.source(), CaptureSource::TlsSessionSecret);
    assert_eq!(bytes.bytes.as_ref(), b"GET / HTTP/1.1\r\n\r\n");
    assert!(bytes.degraded);
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_keeps_unbound_capture_events() -> Result<(), Box<dyn std::error::Error>> {
    let flow = demo_flow(1);
    let inner = VecProvider::new([CaptureEvent::Bytes(captured_bytes(
        flow,
        Direction::Outbound,
        0,
        b"raw".to_vec(),
    ))]);
    let mut provider = Tls13SessionSecretDecryptingProvider::new(Box::new(inner));

    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected original bytes");
    };

    assert_eq!(bytes.origin.source(), CaptureSource::Libpcap);
    assert_eq!(bytes.bytes.as_ref(), b"raw");
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_buffers_partial_bound_ciphertext_without_leaking_raw_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let wire_record = protected_application_record(&record, 0, b"ok")?;
    let split_at = 8;
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [
            CaptureEvent::Bytes(captured_bytes(
                flow.clone(),
                Direction::Outbound,
                0,
                wire_record[..split_at].to_vec(),
            )),
            CaptureEvent::Bytes(captured_bytes(
                flow.clone(),
                Direction::Outbound,
                split_at as u64,
                wire_record[split_at..].to_vec(),
            )),
        ],
    )?;

    assert_eq!(provider.poll_next()?, CapturePoll::Progress);
    let CapturePoll::Event(event) = provider.poll_next()? else {
        panic!("expected plaintext event after second ciphertext chunk");
    };
    let CaptureEvent::Bytes(bytes) = *event else {
        panic!("expected plaintext bytes");
    };
    assert_eq!(bytes.origin.source(), CaptureSource::TlsSessionSecret);
    assert_eq!(bytes.bytes.as_ref(), b"ok");
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_carries_upstream_enforcement_evidence_to_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let wire_record = protected_application_record(&record, 0, b"GET /private HTTP/1.1\r\n\r\n")?;
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "bounded syscall payload snapshot",
    );
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [CaptureEvent::Bytes(captured_bytes_with_evidence(
            flow.clone(),
            Direction::Outbound,
            0,
            wire_record,
            evidence.clone(),
            EnforcementEvidencePropagation::Flow,
        ))],
    )?;

    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected decrypted plaintext bytes");
    };

    assert_eq!(bytes.origin.source(), CaptureSource::TlsSessionSecret);
    assert_eq!(bytes.enforcement_evidence, evidence);
    assert_eq!(
        bytes.enforcement_evidence_propagation,
        EnforcementEvidencePropagation::Flow
    );
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_carries_upstream_enforcement_evidence_to_finish_gap()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let wire_record = protected_application_record(&record, 0, b"truncated")?;
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "bounded syscall payload snapshot",
    );
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [CaptureEvent::Bytes(captured_bytes_with_evidence(
            flow.clone(),
            Direction::Outbound,
            0,
            wire_record[..8].to_vec(),
            evidence.clone(),
            EnforcementEvidencePropagation::Flow,
        ))],
    )?;

    assert_eq!(provider.poll_next()?, CapturePoll::Progress);
    let CapturePoll::Event(event) = provider.poll_next()? else {
        panic!("expected plaintext gap after inner finish");
    };
    let CaptureEvent::Gap(gap) = *event else {
        panic!("expected plaintext gap after inner finish");
    };
    assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
    assert!(
        gap.gap
            .reason
            .contains("closed with incomplete protected record")
    );
    assert_eq!(gap.enforcement_evidence, evidence);
    assert_eq!(
        gap.enforcement_evidence_propagation,
        EnforcementEvidencePropagation::Flow
    );
    assert_eq!(provider.poll_next()?, CapturePoll::Finished);
    Ok(())
}

#[test]
fn decrypting_provider_keeps_suppressing_bound_ciphertext_after_upstream_gap()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let later_wire_record = protected_application_record(&record, 0, b"must not leak")?;
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "suppressed bounded syscall payload snapshot",
    );
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [
            CaptureEvent::Gap(captured_gap(
                flow.clone(),
                Direction::Outbound,
                0,
                Some(64),
                "upstream gap",
            )),
            CaptureEvent::Bytes(captured_bytes_with_evidence(
                flow.clone(),
                Direction::Outbound,
                64,
                later_wire_record,
                evidence.clone(),
                EnforcementEvidencePropagation::Flow,
            )),
            CaptureEvent::ConnectionClosed {
                timestamp: timestamp(),
                flow: flow.clone(),
                origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            },
        ],
    )?;

    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected plaintext gap");
    };
    assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
    assert!(gap.gap.reason.contains("upstream gap"));
    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected evidence-carrying plaintext gap before close");
    };
    assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
    assert_eq!(gap.enforcement_evidence, evidence);
    assert_eq!(
        gap.enforcement_evidence_propagation,
        EnforcementEvidencePropagation::Flow
    );
    let Some(CaptureEvent::ConnectionClosed { origin, .. }) = provider.next()? else {
        panic!("expected plaintext close after suppressed ciphertext");
    };
    assert_eq!(origin.source(), CaptureSource::TlsSessionSecret);
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_carries_terminal_suppressed_evidence_before_close_from_other_active_direction()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let later_wire_record = protected_application_record(&record, 0, b"must not leak")?;
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "suppressed bounded syscall payload snapshot",
    );
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [
            CaptureEvent::Gap(captured_gap(
                flow.clone(),
                Direction::Outbound,
                0,
                Some(64),
                "upstream gap",
            )),
            CaptureEvent::Bytes(captured_bytes_with_evidence(
                flow.clone(),
                Direction::Outbound,
                64,
                later_wire_record,
                evidence.clone(),
                EnforcementEvidencePropagation::Flow,
            )),
            CaptureEvent::ConnectionClosed {
                timestamp: timestamp(),
                flow: flow.clone(),
                origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            },
        ],
    )?;
    provider.bind(binding(
        &store,
        flow.clone(),
        Direction::Inbound,
        Tls13ApplicationTrafficSecretKind::Client,
    )?)?;

    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected plaintext gap");
    };
    assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
    assert!(gap.gap.reason.contains("upstream gap"));
    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected evidence-carrying plaintext gap before close");
    };
    assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
    assert_eq!(gap.gap.direction, Direction::Outbound);
    assert_eq!(gap.enforcement_evidence, evidence);
    assert_eq!(
        gap.enforcement_evidence_propagation,
        EnforcementEvidencePropagation::Flow
    );
    let Some(CaptureEvent::ConnectionClosed { origin, .. }) = provider.next()? else {
        panic!("expected plaintext close after carrying gap");
    };
    assert_eq!(origin.source(), CaptureSource::TlsSessionSecret);
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_carries_terminal_suppressed_evidence_before_observation_finish()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let later_wire_record = protected_application_record(&record, 0, b"must not leak")?;
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "suppressed bounded syscall payload snapshot",
    );
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [
            CaptureEvent::Gap(captured_gap(
                flow.clone(),
                Direction::Outbound,
                0,
                Some(64),
                "upstream gap",
            )),
            CaptureEvent::Bytes(captured_bytes_with_evidence(
                flow.clone(),
                Direction::Outbound,
                64,
                later_wire_record,
                evidence.clone(),
                EnforcementEvidencePropagation::Flow,
            )),
        ],
    )?;

    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected plaintext gap");
    };
    assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
    assert!(gap.gap.reason.contains("upstream gap"));
    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected evidence-carrying plaintext gap before finish");
    };
    assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
    assert_eq!(gap.gap.direction, Direction::Outbound);
    assert_eq!(gap.enforcement_evidence, evidence);
    assert_eq!(
        gap.enforcement_evidence_propagation,
        EnforcementEvidencePropagation::Flow
    );
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_preserves_partial_tail_evidence_after_plaintext_from_same_chunk_on_finish()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "bounded syscall payload snapshot with partial TLS tail",
    );
    let wire_chunk = protected_application_records_with_partial_tail(&record, b"ok", b"tail")?;
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [CaptureEvent::Bytes(captured_bytes_with_evidence(
            flow.clone(),
            Direction::Outbound,
            0,
            wire_chunk,
            evidence.clone(),
            EnforcementEvidencePropagation::Flow,
        ))],
    )?;

    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected decrypted plaintext bytes");
    };
    assert_eq!(bytes.bytes.as_ref(), b"ok");
    assert_eq!(bytes.enforcement_evidence, evidence);
    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected incomplete-record gap at observation finish");
    };
    assert!(
        gap.gap
            .reason
            .contains("closed with incomplete protected record")
    );
    assert_eq!(gap.enforcement_evidence, evidence);
    assert_eq!(
        gap.enforcement_evidence_propagation,
        EnforcementEvidencePropagation::Flow
    );
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_preserves_partial_tail_evidence_after_plaintext_from_same_chunk_on_close()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "bounded syscall payload snapshot with partial TLS tail",
    );
    let wire_chunk = protected_application_records_with_partial_tail(&record, b"ok", b"tail")?;
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [
            CaptureEvent::Bytes(captured_bytes_with_evidence(
                flow.clone(),
                Direction::Outbound,
                0,
                wire_chunk,
                evidence.clone(),
                EnforcementEvidencePropagation::Flow,
            )),
            CaptureEvent::ConnectionClosed {
                timestamp: timestamp(),
                flow: flow.clone(),
                origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            },
        ],
    )?;

    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected decrypted plaintext bytes");
    };
    assert_eq!(bytes.bytes.as_ref(), b"ok");
    assert_eq!(bytes.enforcement_evidence, evidence);
    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected incomplete-record gap before close");
    };
    assert!(
        gap.gap
            .reason
            .contains("closed with incomplete protected record")
    );
    assert_eq!(gap.enforcement_evidence, evidence);
    assert_eq!(
        gap.enforcement_evidence_propagation,
        EnforcementEvidencePropagation::Flow
    );
    let Some(CaptureEvent::ConnectionClosed { origin, .. }) = provider.next()? else {
        panic!("expected plaintext close");
    };
    assert_eq!(origin.source(), CaptureSource::TlsSessionSecret);
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_rejects_rebinding_after_bound_close_is_observed()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let wire_chunk = protected_application_records_with_partial_tail(&record, b"ok", b"tail")?;
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [
            CaptureEvent::Bytes(captured_bytes(
                flow.clone(),
                Direction::Outbound,
                0,
                wire_chunk,
            )),
            CaptureEvent::ConnectionClosed {
                timestamp: timestamp(),
                flow: flow.clone(),
                origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            },
        ],
    )?;

    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected decrypted plaintext bytes");
    };
    assert_eq!(bytes.bytes.as_ref(), b"ok");
    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected incomplete-record gap before pending close");
    };
    assert!(
        gap.gap
            .reason
            .contains("closed with incomplete protected record")
    );
    let error = provider
        .bind(binding(
            &store,
            flow.clone(),
            Direction::Outbound,
            Tls13ApplicationTrafficSecretKind::Client,
        )?)
        .expect_err("provider has already observed close");
    assert!(matches!(
        error,
        Tls13SessionSecretDecryptingProviderError::ClosedFlow { .. }
    ));

    let Some(CaptureEvent::ConnectionClosed { origin, .. }) = provider.next()? else {
        panic!("expected pending plaintext close");
    };
    assert_eq!(origin.source(), CaptureSource::TlsSessionSecret);
    let error = provider
        .bind(binding(
            &store,
            flow,
            Direction::Outbound,
            Tls13ApplicationTrafficSecretKind::Client,
        )?)
        .expect_err("closed flow must not be rebound");
    assert!(matches!(
        error,
        Tls13SessionSecretDecryptingProviderError::ClosedFlow { .. }
    ));
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_suppresses_late_capture_events_after_bound_close()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let wire_record = protected_application_record(&record, 0, b"ok")?;
    let late_wire_record = protected_application_record(&record, 1, b"must not leak")?;
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [
            CaptureEvent::Bytes(captured_bytes(
                flow.clone(),
                Direction::Outbound,
                0,
                wire_record,
            )),
            CaptureEvent::ConnectionClosed {
                timestamp: timestamp(),
                flow: flow.clone(),
                origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            },
            CaptureEvent::Bytes(captured_bytes(
                flow.clone(),
                Direction::Outbound,
                29,
                late_wire_record,
            )),
            CaptureEvent::Gap(captured_gap(
                flow.clone(),
                Direction::Outbound,
                64,
                None,
                "late upstream gap",
            )),
            CaptureEvent::ConnectionClosed {
                timestamp: timestamp(),
                flow,
                origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            },
        ],
    )?;

    let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
        panic!("expected decrypted plaintext bytes");
    };
    assert_eq!(bytes.origin.source(), CaptureSource::TlsSessionSecret);
    assert_eq!(bytes.bytes.as_ref(), b"ok");
    let Some(CaptureEvent::ConnectionClosed { origin, .. }) = provider.next()? else {
        panic!("expected plaintext close");
    };
    assert_eq!(origin.source(), CaptureSource::TlsSessionSecret);
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_does_not_emit_finish_gap_for_consumed_record_without_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let alert_record =
        protected_inner_record(&record, 0, b"\x01\x00", Tls13InnerContentType::Alert)?;
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "bounded syscall payload snapshot for encrypted alert",
    );
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [CaptureEvent::Bytes(captured_bytes_with_evidence(
            flow,
            Direction::Outbound,
            0,
            alert_record,
            evidence,
            EnforcementEvidencePropagation::Flow,
        ))],
    )?;

    assert_eq!(provider.poll_next()?, CapturePoll::Progress);
    assert_eq!(provider.poll_next()?, CapturePoll::Finished);
    Ok(())
}

#[test]
fn decrypting_provider_does_not_emit_close_gap_for_consumed_record_without_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let record = store.records()[0].clone();
    let flow = demo_flow(1);
    let alert_record =
        protected_inner_record(&record, 0, b"\x01\x00", Tls13InnerContentType::Alert)?;
    let evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        "bounded syscall payload snapshot for encrypted alert",
    );
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [
            CaptureEvent::Bytes(captured_bytes_with_evidence(
                flow.clone(),
                Direction::Outbound,
                0,
                alert_record,
                evidence,
                EnforcementEvidencePropagation::Flow,
            )),
            CaptureEvent::ConnectionClosed {
                timestamp: timestamp(),
                flow: flow.clone(),
                origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            },
        ],
    )?;

    assert_eq!(provider.poll_next()?, CapturePoll::Progress);
    let Some(CaptureEvent::ConnectionClosed { origin, .. }) = provider.next()? else {
        panic!("expected plaintext close without preceding gap");
    };
    assert_eq!(origin.source(), CaptureSource::TlsSessionSecret);
    assert!(provider.next()?.is_none());
    Ok(())
}

#[test]
fn decrypting_provider_finishes_unobserved_binding_without_stale_decryptor_state()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let flow = demo_flow(1);
    let mut provider =
        outbound_client_provider(&store, flow.clone(), std::iter::empty::<CaptureEvent>())?;

    assert!(provider.next()?.is_none());
    provider.bind(binding(
        &store,
        flow,
        Direction::Outbound,
        Tls13ApplicationTrafficSecretKind::Client,
    )?)?;
    Ok(())
}

#[test]
fn decrypting_provider_rejects_rebinding_suppressed_terminal_stream()
-> Result<(), Box<dyn std::error::Error>> {
    let store = session_secret_store()?;
    let flow = demo_flow(1);
    let mut provider = outbound_client_provider(
        &store,
        flow.clone(),
        [CaptureEvent::Gap(captured_gap(
            flow.clone(),
            Direction::Outbound,
            0,
            None,
            "upstream gap",
        ))],
    )?;

    let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
        panic!("expected plaintext gap");
    };
    assert_eq!(gap.origin.source(), CaptureSource::TlsSessionSecret);
    let error = provider
        .bind(binding(
            &store,
            flow,
            Direction::Outbound,
            Tls13ApplicationTrafficSecretKind::Client,
        )?)
        .expect_err("terminal suppression should remain bound until close or finish");
    assert!(matches!(
        error,
        Tls13SessionSecretDecryptingProviderError::FlowDecrypt {
            source: Tls13SessionSecretFlowDecryptError::AlreadyBound { .. }
        }
    ));
    Ok(())
}

fn outbound_client_provider(
    store: &TlsSessionSecretStore,
    flow: FlowContext,
    events: impl IntoIterator<Item = CaptureEvent>,
) -> Result<Tls13SessionSecretDecryptingProvider, Box<dyn std::error::Error>> {
    Ok(Tls13SessionSecretDecryptingProvider::with_bindings(
        Box::new(VecProvider::new(events)),
        [binding(
            store,
            flow,
            Direction::Outbound,
            Tls13ApplicationTrafficSecretKind::Client,
        )?],
    )?)
}

fn binding(
    store: &TlsSessionSecretStore,
    flow: FlowContext,
    direction: Direction,
    secret_kind: Tls13ApplicationTrafficSecretKind,
) -> Result<Tls13SessionSecretFlowBinding, Box<dyn std::error::Error>> {
    let client_random = TlsRandom::from_hex(CLIENT_RANDOM).expect("valid client random");
    Ok(Tls13SessionSecretFlowBindingPlanner::new(store).plan(
        Tls13SessionSecretFlowCandidate::start(flow, direction, client_random, secret_kind),
    )?)
}

fn session_secret_store() -> Result<TlsSessionSecretStore, Box<dyn std::error::Error>> {
    let material = format!(
        r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{CLIENT_RANDOM}","secret":"{SHA256_TRAFFIC_SECRET}","cipher_suite":"0x1301"}}"#
    );
    Ok(TlsSessionSecretStore::parse(material.as_bytes())?)
}

fn protected_application_record(
    record: &TlsSessionSecretRecord,
    sequence_number: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    protected_inner_record(
        record,
        sequence_number,
        plaintext,
        Tls13InnerContentType::ApplicationData,
    )
}

fn protected_inner_record(
    record: &TlsSessionSecretRecord,
    sequence_number: u64,
    plaintext: &[u8],
    content_type: Tls13InnerContentType,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut inner_plaintext = plaintext.to_vec();
    inner_plaintext.push(content_type.as_u8());
    Ok(protect_tls13_test_record(
        record,
        sequence_number,
        &inner_plaintext,
    )?)
}

fn protected_application_records_with_partial_tail(
    record: &TlsSessionSecretRecord,
    first_plaintext: &[u8],
    partial_plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut first_record = protected_application_record(record, 0, first_plaintext)?;
    let partial_record = protected_application_record(record, 1, partial_plaintext)?;
    first_record.extend_from_slice(&partial_record[..8]);
    Ok(first_record)
}

fn captured_bytes(
    flow: FlowContext,
    direction: Direction,
    stream_offset: u64,
    bytes: Vec<u8>,
) -> CapturedBytes {
    captured_bytes_with_timestamp(timestamp(), flow, direction, stream_offset, bytes)
}

fn captured_bytes_with_timestamp(
    timestamp: Timestamp,
    flow: FlowContext,
    direction: Direction,
    stream_offset: u64,
    bytes: Vec<u8>,
) -> CapturedBytes {
    captured_bytes_with_timestamp_and_evidence(
        timestamp,
        flow,
        direction,
        stream_offset,
        bytes,
        EnforcementEvidence::default(),
        EnforcementEvidencePropagation::Event,
    )
}

fn captured_bytes_with_evidence(
    flow: FlowContext,
    direction: Direction,
    stream_offset: u64,
    bytes: Vec<u8>,
    enforcement_evidence: EnforcementEvidence,
    enforcement_evidence_propagation: EnforcementEvidencePropagation,
) -> CapturedBytes {
    captured_bytes_with_timestamp_and_evidence(
        timestamp(),
        flow,
        direction,
        stream_offset,
        bytes,
        enforcement_evidence,
        enforcement_evidence_propagation,
    )
}

fn captured_bytes_with_timestamp_and_evidence(
    timestamp: Timestamp,
    flow: FlowContext,
    direction: Direction,
    stream_offset: u64,
    bytes: Vec<u8>,
    enforcement_evidence: EnforcementEvidence,
    enforcement_evidence_propagation: EnforcementEvidencePropagation,
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
        enforcement_evidence,
        enforcement_evidence_propagation,
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

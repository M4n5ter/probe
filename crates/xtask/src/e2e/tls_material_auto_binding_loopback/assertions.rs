use std::collections::{BTreeSet, HashMap};

use capture::CaptureEvent;
use probe_core::{CaptureProviderKind, CaptureSource, Direction, EventEnvelope, EventKind};
use storage::{FjallSpool, StoredEvent};

use super::super::{
    harness::{decode_capture_event, decode_envelope, e2e_error},
    loopback::assert_no_policy_runtime_errors,
};
use super::{
    POLICY_ID, POLICY_VERSION,
    fixture::{EXPECTED_METHOD, SyntheticTls13AutoBindingFixture},
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-tls-material";

pub(super) fn assert_spool_outputs(
    spool_path: &std::path::Path,
    fixture: SyntheticTls13AutoBindingFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 256)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected TLS material ingress records, got none").into());
    }
    assert_ingress_contains_ciphertext_and_plaintext(&ingress, fixture)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_request(&envelopes)?;
    assert_expected_policy_alert(&envelopes)?;

    println!(
        "e2e TLS material auto-binding observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_ingress_contains_ciphertext_and_plaintext(
    events: &[StoredEvent],
    fixture: SyntheticTls13AutoBindingFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    assert_libpcap_ciphertext_boundary(&capture_events, fixture)?;
    let has_tls_plaintext = capture_events
        .iter()
        .any(|event| is_expected_tls_session_secret_plaintext(event, fixture));
    if !has_tls_plaintext {
        return Err(e2e_error(format!(
            "missing decrypted TLS material plaintext; observed {}",
            ingress_summary(&capture_events)
        ))
        .into());
    }
    Ok(())
}

fn assert_libpcap_ciphertext_boundary(
    events: &[CaptureEvent],
    fixture: SyntheticTls13AutoBindingFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let outbound_by_flow = libpcap_payload_spans_by_flow(events, Direction::Outbound);
    if outbound_by_flow.is_empty() {
        return Err(e2e_error("missing live libpcap ciphertext ingress").into());
    }

    let client_hello = fixture.client_hello_record();
    let server_hello = fixture.server_hello_record();
    let inbound_by_flow = libpcap_payload_spans_by_flow(events, Direction::Inbound);
    let same_flow_handshake = outbound_by_flow.iter().any(|(flow_id, outbound_spans)| {
        let has_client_hello = outbound_spans
            .iter()
            .any(|span| span.as_slice() == client_hello.as_slice());
        let has_server_hello = inbound_by_flow.get(flow_id).is_some_and(|inbound_spans| {
            inbound_spans
                .iter()
                .any(|span| span.as_slice() == server_hello.as_slice())
        });
        has_client_hello && has_server_hello
    });
    if !same_flow_handshake {
        return Err(e2e_error(format!(
            "missing same-flow TLS ClientHello/ServerHello in live libpcap ingress; observed {}",
            ingress_summary(events)
        ))
        .into());
    }

    let unexpected = outbound_by_flow
        .values()
        .flatten()
        .filter(|span| span.as_slice() != client_hello.as_slice())
        .map(Vec::len)
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(e2e_error(format!(
            "unexpected outbound libpcap payload after TLS material binding; non-ClientHello span lengths: {unexpected:?}",
        ))
        .into());
    }
    Ok(())
}

fn is_expected_tls_session_secret_plaintext(
    event: &CaptureEvent,
    fixture: SyntheticTls13AutoBindingFixture,
) -> bool {
    let CaptureEvent::Bytes(bytes) = event else {
        return false;
    };
    bytes.origin.source() == CaptureSource::TlsSessionSecret
        && bytes.origin.provider() == CaptureProviderKind::Plaintext
        && bytes.direction == Direction::Outbound
        && bytes.degraded
        && {
            let expected = fixture.expected_plaintext();
            bytes
                .bytes
                .as_ref()
                .windows(expected.len())
                .any(|window| window == expected.as_slice())
        }
}

fn assert_expected_request(envelopes: &[EventEnvelope]) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = SyntheticTls13AutoBindingFixture;
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::HttpRequestHeaders(headers)
                if envelope.origin().source() == CaptureSource::TlsSessionSecret
                    && envelope.origin().provider() == CaptureProviderKind::Plaintext
                    && envelope.degraded()
                    && headers.direction == Direction::Outbound
                    && headers.method.as_deref() == Some(EXPECTED_METHOD) =>
            {
                headers.target.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if observed.contains(fixture.target()) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing TLS material HTTP request target {}; observed {observed:?}",
        fixture.target()
    ))
    .into())
}

fn assert_expected_policy_alert(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = SyntheticTls13AutoBindingFixture;
    let expected_policy_version = format!("{POLICY_ID}@{POLICY_VERSION}");
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert)
                if envelope.origin().source() == CaptureSource::TlsSessionSecret
                    && envelope.origin().provider() == CaptureProviderKind::Plaintext
                    && envelope.degraded()
                    && envelope.policy_version() == Some(expected_policy_version.as_str()) =>
            {
                Some(alert.message.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = fixture.policy_alert();
    if observed.contains(expected.as_str()) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing TLS material policy alert {expected}; observed {observed:?}"
    ))
    .into())
}

fn libpcap_payload_spans_by_flow(
    events: &[CaptureEvent],
    direction: Direction,
) -> HashMap<String, Vec<Vec<u8>>> {
    let mut chunks_by_flow = HashMap::<String, Vec<(u64, &[u8])>>::new();
    for event in events {
        let CaptureEvent::Bytes(bytes) = event else {
            continue;
        };
        if bytes.origin.source() == CaptureSource::Libpcap
            && bytes.origin.provider() == CaptureProviderKind::Libpcap
            && bytes.direction == direction
        {
            chunks_by_flow
                .entry(bytes.flow.id.0.clone())
                .or_default()
                .push((bytes.stream_offset, bytes.bytes.as_ref()));
        }
    }

    chunks_by_flow
        .into_iter()
        .map(|(flow_id, chunks)| (flow_id, contiguous_payload_spans(chunks)))
        .collect()
}

fn contiguous_payload_spans(mut chunks: Vec<(u64, &[u8])>) -> Vec<Vec<u8>> {
    chunks.sort_by_key(|(offset, _)| *offset);
    let mut spans = Vec::new();
    let mut current = Vec::new();
    let mut next_offset = None::<u64>;
    for (offset, bytes) in chunks {
        let end_offset = offset.saturating_add(bytes.len() as u64);
        match next_offset {
            None => {
                current.extend_from_slice(bytes);
                next_offset = Some(end_offset);
            }
            Some(next) if offset > next => {
                if !current.is_empty() {
                    spans.push(std::mem::take(&mut current));
                }
                current.extend_from_slice(bytes);
                next_offset = Some(end_offset);
            }
            Some(next) if offset < next => {
                let overlap = (next - offset) as usize;
                if overlap < bytes.len() {
                    current.extend_from_slice(&bytes[overlap..]);
                    next_offset = Some(end_offset);
                }
            }
            Some(_) => {
                current.extend_from_slice(bytes);
                next_offset = Some(end_offset);
            }
        }
    }
    if !current.is_empty() {
        spans.push(current);
    }
    spans
}

fn ingress_summary(events: &[CaptureEvent]) -> String {
    let summaries = events
        .iter()
        .filter_map(event_summary)
        .take(16)
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        "no relevant ingress events".to_string()
    } else {
        summaries.join("; ")
    }
}

fn event_summary(event: &CaptureEvent) -> Option<String> {
    match event {
        CaptureEvent::Bytes(bytes)
            if matches!(
                bytes.origin.source(),
                CaptureSource::Libpcap | CaptureSource::TlsSessionSecret
            ) =>
        {
            Some(format!(
                "bytes source={:?} provider={:?} flow={} direction={:?} len={} degraded={}",
                bytes.origin.source(),
                bytes.origin.provider(),
                bytes.flow.id.0,
                bytes.direction,
                bytes.bytes.len(),
                bytes.degraded
            ))
        }
        CaptureEvent::Gap(gap)
            if matches!(
                gap.origin.source(),
                CaptureSource::Libpcap | CaptureSource::TlsSessionSecret
            ) =>
        {
            Some(format!(
                "gap source={:?} provider={:?} direction={:?} reason={}",
                gap.origin.source(),
                gap.origin.provider(),
                gap.gap.direction,
                gap.gap.reason
            ))
        }
        _ => None,
    }
}

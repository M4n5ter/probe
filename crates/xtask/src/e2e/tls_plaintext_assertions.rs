use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use capture::{CaptureEvent, CaptureProviderKind};
use probe_core::{CaptureSource, Direction, EventEnvelope, EventKind};
use storage::{FjallSpool, StoredEvent};

use super::{
    agent_admin::assert_no_policy_runtime_errors,
    harness::{decode_capture_event, decode_envelope, e2e_error},
    loopback::is_fixture_process,
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-tls-plaintext";
const EXPECTED_POLICY_VERSION: &str = "tls-plaintext-e2e-policy@e2e";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TlsPlaintextExpectations {
    request_count: usize,
}

impl TlsPlaintextExpectations {
    pub(super) fn new(request_count: usize) -> Self {
        Self { request_count }
    }

    pub(super) fn policy_alert_count_for_runs(self, runs: usize) -> u64 {
        (self.policy_alert_messages().len() * runs) as u64
    }

    fn targets(self) -> BTreeSet<String> {
        (0..self.request_count)
            .map(|request| format!("/traffic-probe-e2e/{request}"))
            .collect()
    }

    fn policy_alert_messages(self) -> BTreeSet<String> {
        self.targets()
            .into_iter()
            .map(expected_policy_alert_message)
            .collect()
    }
}

pub(super) fn assert_spool_outputs(
    spool_path: &Path,
    listen_port: u16,
    expectations: TlsPlaintextExpectations,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 256)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected TLS plaintext ingress records, got none").into());
    }
    assert_tls_plaintext_ingress(&ingress, listen_port, expectations)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_requests(&envelopes, expectations)?;
    assert_expected_policy_alerts(&envelopes, expectations)?;

    println!(
        "e2e TLS plaintext loopback observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

pub(super) fn assert_spool_outputs_for_pid(
    spool_path: &Path,
    listen_port: u16,
    expectations: TlsPlaintextExpectations,
    expected_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_spool_outputs_for_pids(
        spool_path,
        listen_port,
        expectations,
        [expected_pid],
        1,
        "dynamic libssl loopback",
    )
}

pub(super) fn assert_target_lifecycle_spool_outputs(
    spool_path: &Path,
    listen_port: u16,
    expectations: TlsPlaintextExpectations,
    old_pid: u32,
    new_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_spool_outputs_for_pids(
        spool_path,
        listen_port,
        expectations,
        [old_pid, new_pid],
        2,
        "target lifecycle loopback",
    )
}

fn assert_spool_outputs_for_pids(
    spool_path: &Path,
    listen_port: u16,
    expectations: TlsPlaintextExpectations,
    expected_pids: impl IntoIterator<Item = u32>,
    expected_runs: usize,
    scenario: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_pids = expected_pids.into_iter().collect::<BTreeSet<_>>();
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 512)?;
    if ingress.is_empty() {
        return Err(e2e_error(format!(
            "expected {scenario} TLS plaintext ingress records, got none"
        ))
        .into());
    }
    assert_tls_plaintext_ingress_for_pids(
        &ingress,
        listen_port,
        expectations,
        expected_pids.iter().copied(),
    )?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 1024)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_requests(&envelopes, expectations)?;
    assert_expected_request_pids(&envelopes, expectations, expected_pids.iter().copied())?;
    assert_expected_policy_alerts(&envelopes, expectations)?;
    assert_expected_policy_alert_pids(&envelopes, expectations, expected_pids.iter().copied())?;
    assert_expected_policy_alert_count(&envelopes, expectations, expected_runs)?;

    println!(
        "e2e TLS plaintext {scenario} observed {} ingress records and {} export records for pids {:?}",
        ingress.len(),
        envelopes.len(),
        expected_pids
    );
    Ok(())
}

fn assert_tls_plaintext_ingress(
    events: &[StoredEvent],
    listen_port: u16,
    expectations: TlsPlaintextExpectations,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    let unresolved = capture_events
        .iter()
        .filter(|event| is_unresolved_tls_plaintext_bytes(event))
        .count();
    if unresolved > 0 {
        return Err(e2e_error(format!(
            "observed {unresolved} unresolved libssl plaintext byte event(s) under a remote-port scoped selector; observed {}",
            ingress_summary(&capture_events, listen_port)
        ))
        .into());
    }

    let expected_targets = expectations.targets();
    let observed_targets = capture_events
        .iter()
        .filter_map(|event| {
            expected_tls_plaintext_request_fact(event, listen_port, &expected_targets)
        })
        .map(|fact| fact.target)
        .collect::<BTreeSet<_>>();
    if observed_targets.is_superset(&expected_targets) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing outbound libssl uprobe plaintext request bytes for targets {:?}; observed targets {:?}; observed {}",
        expected_targets,
        observed_targets,
        ingress_summary(&capture_events, listen_port),
    ))
    .into())
}

fn assert_tls_plaintext_ingress_for_pids(
    events: &[StoredEvent],
    listen_port: u16,
    expectations: TlsPlaintextExpectations,
    expected_pids: impl IntoIterator<Item = u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    let unresolved = capture_events
        .iter()
        .filter(|event| is_unresolved_tls_plaintext_bytes(event))
        .count();
    if unresolved > 0 {
        return Err(e2e_error(format!(
            "observed {unresolved} unresolved libssl plaintext byte event(s) under a remote-port scoped target lifecycle selector; observed {}",
            ingress_summary(&capture_events, listen_port)
        ))
        .into());
    }

    let expected = expected_pids.into_iter().collect::<BTreeSet<_>>();
    let expected_targets = expectations.targets();
    let mut observed = BTreeMap::<u32, BTreeSet<String>>::new();
    for fact in capture_events.iter().filter_map(|event| {
        expected_tls_plaintext_request_fact(event, listen_port, &expected_targets)
    }) {
        observed.entry(fact.pid).or_default().insert(fact.target);
    }

    let missing = expected
        .iter()
        .copied()
        .filter(|pid| {
            !observed
                .get(pid)
                .is_some_and(|targets| targets.is_superset(&expected_targets))
        })
        .collect::<BTreeSet<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing target lifecycle TLS plaintext request bytes for pids {:?}; observed {:?}; observed {}",
        missing,
        observed,
        ingress_summary(&capture_events, listen_port)
    ))
    .into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsPlaintextRequestFact {
    pid: u32,
    target: String,
}

fn expected_tls_plaintext_request_fact(
    event: &CaptureEvent,
    listen_port: u16,
    expected_targets: &BTreeSet<String>,
) -> Option<TlsPlaintextRequestFact> {
    let CaptureEvent::Bytes(bytes) = event else {
        return None;
    };
    if bytes.origin.source() == CaptureSource::LibsslUprobe
        && bytes.origin.provider() == CaptureProviderKind::Plaintext
        && bytes.direction == Direction::Outbound
        && bytes.flow.remote.port == listen_port
        && bytes.flow.attribution_confidence > 0
        && is_fixture_process(&bytes.flow.process)
        && bytes.degraded
        && bytes
            .degradation_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("libssl uprobe"))
    {
        let target = request_target_in_bytes(bytes.bytes.as_ref(), expected_targets)?;
        Some(TlsPlaintextRequestFact {
            pid: bytes.flow.process.identity.pid,
            target,
        })
    } else {
        None
    }
}

fn request_target_in_bytes(payload: &[u8], expected_targets: &BTreeSet<String>) -> Option<String> {
    expected_targets
        .iter()
        .find(|target| {
            let needle = format!("POST {target}");
            payload
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
        })
        .cloned()
}

fn is_unresolved_tls_plaintext_bytes(event: &CaptureEvent) -> bool {
    let CaptureEvent::Bytes(bytes) = event else {
        return false;
    };
    bytes.origin.source() == CaptureSource::LibsslUprobe
        && bytes.origin.provider() == CaptureProviderKind::Plaintext
        && bytes.flow.attribution_confidence == 0
        && bytes.flow.local.port == 0
        && bytes.flow.remote.port == 0
}

fn ingress_summary(events: &[CaptureEvent], listen_port: u16) -> String {
    let summaries = events
        .iter()
        .filter_map(|event| event_summary(event, listen_port))
        .take(16)
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        return format!("no TLS plaintext ingress events near port {listen_port}");
    }
    summaries.join("; ")
}

fn event_summary(event: &CaptureEvent, listen_port: u16) -> Option<String> {
    match event {
        CaptureEvent::Bytes(bytes) if is_summary_relevant_bytes(bytes, listen_port) => {
            Some(format!(
                "bytes source={:?} provider={:?} direction={:?} local={}:{} remote={}:{} pid={} name={} confidence={} len={} degraded={} fixture={}",
                bytes.origin.source(),
                bytes.origin.provider(),
                bytes.direction,
                bytes.flow.local.address,
                bytes.flow.local.port,
                bytes.flow.remote.address,
                bytes.flow.remote.port,
                bytes.flow.process.identity.pid,
                bytes.flow.process.name,
                bytes.flow.attribution_confidence,
                bytes.bytes.len(),
                bytes.degraded,
                is_fixture_process(&bytes.flow.process)
            ))
        }
        CaptureEvent::Gap(gap) if is_summary_relevant_gap(gap, listen_port) => Some(format!(
            "gap source={:?} provider={:?} direction={:?} local={}:{} remote={}:{} pid={} name={} confidence={} reason={}",
            gap.origin.source(),
            gap.origin.provider(),
            gap.gap.direction,
            gap.flow.local.address,
            gap.flow.local.port,
            gap.flow.remote.address,
            gap.flow.remote.port,
            gap.flow.process.identity.pid,
            gap.flow.process.name,
            gap.flow.attribution_confidence,
            gap.gap.reason
        )),
        _ => None,
    }
}

fn is_summary_relevant_bytes(bytes: &capture::CapturedBytes, listen_port: u16) -> bool {
    bytes.origin.source() == CaptureSource::LibsslUprobe
        || bytes.flow.local.port == listen_port
        || bytes.flow.remote.port == listen_port
}

fn is_summary_relevant_gap(gap: &capture::CapturedGap, listen_port: u16) -> bool {
    gap.origin.source() == CaptureSource::LibsslUprobe
        || gap.flow.local.port == listen_port
        || gap.flow.remote.port == listen_port
}

fn assert_expected_requests(
    envelopes: &[EventEnvelope],
    expectations: TlsPlaintextExpectations,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(tls_plaintext_http_request_target)
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = expectations.targets();
    if observed.is_superset(&expected) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing TLS plaintext HTTP request targets; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn assert_expected_request_pids(
    envelopes: &[EventEnvelope],
    expectations: TlsPlaintextExpectations,
    expected_pids: impl IntoIterator<Item = u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = expected_pids.into_iter().collect::<BTreeSet<_>>();
    let expected_targets = expectations.targets();
    let mut observed = BTreeMap::<u32, BTreeSet<String>>::new();
    for fact in envelopes
        .iter()
        .filter_map(|envelope| tls_plaintext_http_request_fact(envelope, &expected_targets))
    {
        observed.entry(fact.pid).or_default().insert(fact.target);
    }

    let missing = expected
        .iter()
        .copied()
        .filter(|pid| {
            !observed
                .get(pid)
                .is_some_and(|targets| targets.is_superset(&expected_targets))
        })
        .collect::<BTreeSet<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing TLS plaintext HTTP request headers for pids {:?}, observed {:?}",
        missing, observed
    ))
    .into())
}

fn assert_expected_policy_alerts(
    envelopes: &[EventEnvelope],
    expectations: TlsPlaintextExpectations,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(tls_plaintext_policy_alert_message)
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = expectations.policy_alert_messages();
    if observed.is_superset(&expected) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing TLS plaintext policy alerts; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn assert_expected_policy_alert_pids(
    envelopes: &[EventEnvelope],
    expectations: TlsPlaintextExpectations,
    expected_pids: impl IntoIterator<Item = u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_pids = expected_pids.into_iter().collect::<BTreeSet<_>>();
    let expected_messages = expectations.policy_alert_messages();
    let mut observed = BTreeMap::<u32, BTreeSet<String>>::new();
    for envelope in envelopes {
        let Some(message) = tls_plaintext_policy_alert_message(envelope) else {
            continue;
        };
        if !expected_messages.contains(message) {
            continue;
        }
        if let Some(flow) = envelope.flow() {
            observed
                .entry(flow.process.identity.pid)
                .or_default()
                .insert(message.clone());
        }
    }

    let missing = expected_pids
        .iter()
        .copied()
        .filter(|pid| {
            !observed
                .get(pid)
                .is_some_and(|messages| messages.is_superset(&expected_messages))
        })
        .collect::<BTreeSet<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing TLS plaintext policy alerts for pids {:?}; observed {:?}",
        missing, observed
    ))
    .into())
}

fn assert_expected_policy_alert_count(
    envelopes: &[EventEnvelope],
    expectations: TlsPlaintextExpectations,
    expected_runs: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_messages = expectations.policy_alert_messages();
    let expected_count = expected_messages.len() * expected_runs;
    let observed_count = envelopes
        .iter()
        .filter_map(tls_plaintext_policy_alert_message)
        .filter(|message| expected_messages.contains(*message))
        .count();
    if observed_count >= expected_count {
        return Ok(());
    }

    Err(e2e_error(format!(
        "expected at least {expected_count} TLS plaintext policy alerts, observed {observed_count}"
    ))
    .into())
}

fn tls_plaintext_http_request_target(envelope: &EventEnvelope) -> Option<&String> {
    let EventKind::HttpRequestHeaders(headers) = envelope.kind() else {
        return None;
    };
    if is_tls_plaintext_envelope(envelope)
        && headers.direction == Direction::Outbound
        && headers.method.as_deref() == Some("POST")
    {
        headers.target.as_ref()
    } else {
        None
    }
}

fn tls_plaintext_http_request_fact(
    envelope: &EventEnvelope,
    expected_targets: &BTreeSet<String>,
) -> Option<TlsPlaintextRequestFact> {
    let target = tls_plaintext_http_request_target(envelope)?;
    if expected_targets.contains(target) {
        envelope.flow().map(|flow| TlsPlaintextRequestFact {
            pid: flow.process.identity.pid,
            target: target.clone(),
        })
    } else {
        None
    }
}

fn tls_plaintext_policy_alert_message(envelope: &EventEnvelope) -> Option<&String> {
    let EventKind::PolicyAlert(alert) = envelope.kind() else {
        return None;
    };
    if is_tls_plaintext_envelope(envelope)
        && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
    {
        Some(&alert.message)
    } else {
        None
    }
}

fn is_tls_plaintext_envelope(envelope: &EventEnvelope) -> bool {
    envelope.origin().source() == CaptureSource::LibsslUprobe
        && envelope.origin().provider() == CaptureProviderKind::Plaintext
        && envelope.degraded()
}

fn expected_policy_alert_message(target: String) -> String {
    format!("tls plaintext policy observed {target}")
}

use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use capture::CaptureEvent;
use e2e_support::mitm_bridge;
use probe_config::TransparentInterceptionStrategyConfig;
use probe_core::{
    Action, CaptureProviderKind, CaptureSource, Direction, EnforcementExecutionEvidence,
    EnforcementMode, EnforcementOutcome, EventEnvelope, EventKind, L7MitmAuditEvent,
    L7MitmAuditPhase, L7MitmExternalBackendAudit, L7MitmManagedProcessBackendAudit,
    ProxySideEnforcementSurface, VerdictScope,
};
use serde_json::json;
use storage::{FjallSpool, StoredEvent};

use super::{
    backend::{
        MitmBackendConfig, MitmBackendKind, MitmBridgeCase, MitmBridgeDirection,
        PreparedMitmBackend, wait_for_managed_backend_pid,
    },
    feed::{
        E2E_EXPORT_CURSOR_OWNER, ENFORCEMENT_MANIFEST_ID, ENFORCEMENT_MANIFEST_VERSION,
        EXPECTED_POLICY_VERSION, POLICY_HOOK_REASON_PREFIX, POLICY_HOOK_RESPONSE_REASON,
        expected_bridge_policy_alert_message, expected_libpcap_targets,
        expected_policy_alert_message, is_bridge_flow, is_bridge_ingress_bytes,
        is_product_proxy_deny_response_bytes, product_proxy_deny_response_bytes,
    },
};
use crate::e2e::{
    harness::{decode_capture_event, decode_envelope, e2e_error},
    loopback::{assert_no_policy_runtime_errors, send_admin_request},
};

const HEALTH_TRANSITION_TIMEOUT: Duration = Duration::from_secs(5);
const OUTBOUND_REDIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MANAGED_DATA_PLANE_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn assert_mitm_backend_runtime(
    case: MitmBridgeCase,
    admin_socket_path: &Path,
    backend: &PreparedMitmBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(pid_file) = backend.managed_pid_file() {
        let pid = wait_for_managed_backend_pid(pid_file)?;
        if !PathBuf::from(format!("/proc/{pid}")).try_exists()? {
            return Err(e2e_error(format!(
                "managed MITM backend pid {pid} was reported but is not visible in procfs"
            ))
            .into());
        }
    }

    let response = send_admin_request(admin_socket_path, json!({"command": "status"}))?;
    assert_backend_status(case, backend, &response)?;
    assert_l7_mitm_runtime_status(case, &response)?;
    assert_policy_hook_enforcement_manifest_status(case, &response)
}

pub(super) fn exercise_l7_mitm_health_transition(
    case: MitmBridgeCase,
    backend: &mut PreparedMitmBackend,
    admin_socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if case.backend() != MitmBackendKind::External {
        return Ok(());
    }
    wait_for_l7_mitm_backend_health(admin_socket_path, "healthy")?;
    backend.pause_external_listener()?;
    wait_for_l7_mitm_backend_health(admin_socket_path, "unhealthy")?;
    backend.resume_external_listener()?;
    wait_for_l7_mitm_backend_health(admin_socket_path, "healthy")
}

pub(super) fn assert_outbound_redirect_reaches_mitm_backend(
    case: MitmBridgeCase,
    intercept_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    if case.direction() != MitmBridgeDirection::Outbound {
        return Ok(());
    }
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, intercept_port));
    TcpStream::connect_timeout(&target, OUTBOUND_REDIRECT_CONNECT_TIMEOUT).map_err(|error| {
        e2e_error(format!(
            "{} outbound MITM redirect did not connect through selector port {intercept_port}: {error}",
            case.case_name()
        ))
    })?;
    Ok(())
}

pub(super) fn exercise_managed_mitm_data_plane(
    case: MitmBridgeCase,
    backend: &PreparedMitmBackend,
    intercept_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    if case.backend() != MitmBackendKind::ManagedProcess {
        return Ok(());
    }
    let target = managed_data_plane_target(case, backend, intercept_port)?;
    let mut stream =
        TcpStream::connect_timeout(&target, MANAGED_DATA_PLANE_TIMEOUT).map_err(|error| {
            e2e_error(format!(
                "{} managed MITM data-plane canary could not connect to {target}: {error}",
                case.case_name()
            ))
        })?;
    stream.set_read_timeout(Some(MANAGED_DATA_PLANE_TIMEOUT))?;
    stream.set_write_timeout(Some(MANAGED_DATA_PLANE_TIMEOUT))?;
    stream.write_all(mitm_bridge::REQUEST_BYTES)?;
    stream.shutdown(Shutdown::Write)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let expected = if case.product_proxy_backend() {
        product_proxy_deny_response_bytes()
    } else if case.backend_owned_policy_hook_enabled() {
        mitm_bridge::DENY_RESPONSE_BYTES.to_vec()
    } else {
        mitm_bridge::PASSTHROUGH_RESPONSE_BYTES.to_vec()
    };
    if response == expected.as_slice() {
        return Ok(());
    }
    Err(e2e_error(format!(
        "{} managed MITM data-plane response mismatch: expected {:?}, got {:?}",
        case.case_name(),
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(&response)
    ))
    .into())
}

fn managed_data_plane_target(
    case: MitmBridgeCase,
    backend: &PreparedMitmBackend,
    intercept_port: u16,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    match case.direction() {
        MitmBridgeDirection::Inbound => match &backend.config {
            MitmBackendConfig::ManagedProcess { target, .. } => {
                target.parse::<SocketAddr>().map_err(Into::into)
            }
            MitmBackendConfig::External { .. } => {
                Err(e2e_error("managed data-plane canary received an external backend").into())
            }
        },
        MitmBridgeDirection::Outbound => {
            Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, intercept_port)))
        }
    }
}

pub(super) fn assert_spool_outputs(
    case: MitmBridgeCase,
    backend: &PreparedMitmBackend,
    spool_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 512)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected MITM bridge ingress records, got none").into());
    }
    assert_livestream_ingress(case, &ingress)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_bridge_export(case, &envelopes)?;
    assert_expected_libpcap_export(&envelopes)?;
    assert_expected_libpcap_policy_alerts(&envelopes)?;
    assert_expected_policy_hook_decision(case, &envelopes)?;
    assert_expected_l7_mitm_audit(case, backend, &envelopes)?;

    println!(
        "e2e MITM plaintext bridge live sidecar observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

pub(super) fn assert_backend_owned_policy_hook_execution(
    case: MitmBridgeCase,
    backend: &PreparedMitmBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    if !case.fixture_action_report_enabled() {
        return Ok(());
    }
    let Some(action_report_file) = backend.action_report_file.as_ref() else {
        return Err(
            e2e_error("backend-owned MITM policy hook case omitted action report file").into(),
        );
    };
    let content = fs::read_to_string(action_report_file)?;
    let reports = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let [report] = reports.as_slice() else {
        return Err(e2e_error(format!(
            "expected exactly one managed MITM action report, got {}: {reports:?}",
            reports.len()
        ))
        .into());
    };
    let expected = [
        ("flow_id", json!(mitm_bridge::FLOW_ID)),
        ("target", json!(mitm_bridge::REQUEST_TARGET)),
        ("requested_action", json!("deny")),
        ("executed_action", json!("deny")),
        ("reason", json!(POLICY_HOOK_RESPONSE_REASON)),
    ];
    for (field, expected) in expected {
        if report[field] != expected {
            return Err(e2e_error(format!(
                "managed MITM action report {field} mismatch: expected {expected}, got {}; report={report}",
                report[field]
            ))
            .into());
        }
    }
    Ok(())
}

fn wait_for_l7_mitm_backend_health(
    admin_socket_path: &Path,
    expected_mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + HEALTH_TRANSITION_TIMEOUT;
    loop {
        let response = send_admin_request(admin_socket_path, json!({"command": "status"}))?;
        let runtime =
            response["snapshot"]["enforcement"]["interception"]["runtime_l7_mitm"].clone();
        if runtime["backend_health"]["mode"] == json!(expected_mode) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for L7 MITM backend health mode {expected_mode}, last runtime: {runtime}"
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn assert_backend_status(
    case: MitmBridgeCase,
    backend: &PreparedMitmBackend,
    response: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let status_backend = &response["snapshot"]["enforcement"]["interception"]["mitm"]["backend"];
    let expected_mode = match case.backend() {
        MitmBackendKind::External => "external",
        MitmBackendKind::ManagedProcess => "managed_process",
    };
    if status_backend["mode"] != json!(expected_mode) {
        return Err(e2e_error(format!(
            "MITM backend status mode mismatch: expected {expected_mode}, got {status_backend}"
        ))
        .into());
    }

    match &backend.config {
        MitmBackendConfig::External { target }
        | MitmBackendConfig::ManagedProcess { target, .. } => {
            if status_backend["readiness_probe"]["target"] != json!(target) {
                return Err(e2e_error(format!(
                    "MITM backend readiness target mismatch: expected {target}, got {status_backend}"
                ))
                .into());
            }
        }
    }

    Ok(())
}

fn assert_l7_mitm_runtime_status(
    case: MitmBridgeCase,
    response: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let status_strategy = &response["snapshot"]["enforcement"]["interception"]["strategy"];
    let expected_strategy = match case.direction() {
        MitmBridgeDirection::Inbound => TransparentInterceptionStrategyConfig::InboundTproxyMitm,
        MitmBridgeDirection::Outbound => {
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm
        }
    };
    if *status_strategy != json!(expected_strategy) {
        return Err(e2e_error(format!(
            "{} expected L7 MITM strategy {:?}, got {status_strategy}",
            case.case_name(),
            expected_strategy
        ))
        .into());
    }
    let runtime = &response["snapshot"]["enforcement"]["interception"]["runtime_l7_mitm"];
    if runtime["backend_health"]["mode"] != json!("healthy") {
        return Err(e2e_error(format!(
            "{} expected healthy L7 MITM backend runtime, got {runtime}",
            case.case_name()
        ))
        .into());
    }
    if runtime["plaintext_bridge"]["mode"] != json!("active") {
        return Err(e2e_error(format!(
            "{} expected active L7 MITM plaintext bridge, got {runtime}",
            case.case_name()
        ))
        .into());
    }
    Ok(())
}

fn assert_policy_hook_enforcement_manifest_status(
    case: MitmBridgeCase,
    response: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if !case.policy_hook_enabled() {
        return Ok(());
    }
    let enforcement = &response["snapshot"]["enforcement"];
    let source = &enforcement["policy"]["source"];
    let manifest = &source["manifest"];
    if source["mode"] == json!("loaded")
        && source["source"]["kind"] == json!("local")
        && manifest["id"] == json!(ENFORCEMENT_MANIFEST_ID)
        && manifest["version"] == json!(ENFORCEMENT_MANIFEST_VERSION)
        && manifest["selector_configured"] == json!(false)
        && manifest["protective_actions"] == json!(["deny"])
        && enforcement["manifest_selector_configured"] == json!(false)
    {
        return Ok(());
    }
    Err(e2e_error(format!(
        "unexpected MITM policy hook enforcement manifest status: {enforcement}"
    ))
    .into())
}

fn assert_livestream_ingress(
    case: MitmBridgeCase,
    events: &[StoredEvent],
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    if !capture_events
        .iter()
        .any(|event| is_bridge_ingress_bytes(case, event))
    {
        return Err(e2e_error("missing MITM bridge capture-event feed ingress bytes").into());
    }
    if case.product_proxy_backend()
        && !capture_events
            .iter()
            .any(is_product_proxy_deny_response_bytes)
    {
        return Err(
            e2e_error("missing product MITM proxy deny response plaintext feed bytes").into(),
        );
    }
    if !capture_events.iter().any(|event| {
        matches!(
            event,
            CaptureEvent::Bytes(bytes)
                if bytes.origin.source() == CaptureSource::Libpcap
                    && bytes.origin.provider() == CaptureProviderKind::Libpcap
                    && bytes.degraded
        )
    }) {
        return Err(e2e_error("missing required libpcap primary ingress bytes").into());
    }
    Ok(())
}

fn assert_expected_bridge_export(
    case: MitmBridgeCase,
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let request_found = envelopes.iter().any(|envelope| {
        is_bridge_flow(case, envelope)
            && matches!(
                envelope.kind(),
                EventKind::HttpRequestHeaders(headers)
                    if headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(mitm_bridge::REQUEST_TARGET)
            )
    });
    if !request_found {
        return Err(e2e_error("missing MITM bridge parsed HTTP request").into());
    }

    let bridge_alert = expected_bridge_policy_alert_message();
    let alert_found = envelopes.iter().any(|envelope| {
        is_bridge_flow(case, envelope)
            && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
            && matches!(
                envelope.kind(),
                EventKind::PolicyAlert(alert) if alert.message == bridge_alert
            )
    });
    if !alert_found {
        return Err(e2e_error("missing MITM bridge policy alert").into());
    }
    Ok(())
}

fn assert_expected_libpcap_export(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::HttpRequestHeaders(headers)
                if envelope.origin().source() == CaptureSource::Libpcap
                    && envelope.origin().provider() == CaptureProviderKind::Libpcap
                    && headers.direction == Direction::Outbound
                    && headers.method.as_deref() == Some("POST") =>
            {
                headers.target.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_libpcap_targets();
    if observed.is_superset(&expected) {
        return Ok(());
    }
    Err(e2e_error(format!(
        "missing libpcap primary HTTP request targets; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn assert_expected_libpcap_policy_alerts(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert)
                if envelope.origin().source() == CaptureSource::Libpcap
                    && envelope.origin().provider() == CaptureProviderKind::Libpcap
                    && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION) =>
            {
                Some(alert.message.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_libpcap_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .collect::<BTreeSet<_>>();
    if observed.is_superset(&expected) {
        return Ok(());
    }
    Err(e2e_error(format!(
        "missing libpcap primary policy alerts; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn assert_expected_policy_hook_decision(
    case: MitmBridgeCase,
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    if !case.policy_hook_enabled() {
        return Ok(());
    }
    assert_expected_policy_hook_verdict(case, envelopes)?;
    assert_expected_delegated_policy_hook_decision(case, envelopes)
}

fn assert_expected_policy_hook_verdict(
    case: MitmBridgeCase,
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let matches = envelopes
        .iter()
        .filter(|envelope| {
            is_bridge_flow(case, envelope)
                && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
                && matches!(
                    envelope.kind(),
                    EventKind::PolicyVerdict(verdict)
                        if verdict.action == Action::Deny
                            && verdict.scope == VerdictScope::Request
                            && verdict.reason == expected_policy_hook_reason()
                            && verdict.confidence == 100
                )
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        return Ok(());
    }
    Err(e2e_error(format!(
        "expected exactly one MITM policy hook verdict, got {}",
        matches.len()
    ))
    .into())
}

fn assert_expected_delegated_policy_hook_decision(
    case: MitmBridgeCase,
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_execution_reason = case.policy_hook_execution_reason();
    let observed = envelopes
        .iter()
        .filter_map(|envelope| {
            if !is_bridge_flow(case, envelope)
                || envelope.policy_version() != Some(EXPECTED_POLICY_VERSION)
            {
                return None;
            }
            match envelope.kind() {
                EventKind::EnforcementDecision(decision) => Some(format!("{decision:?}")),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    let matches = envelopes
        .iter()
        .filter(|envelope| {
            is_bridge_flow(case, envelope)
                && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
                && matches!(
                    envelope.kind(),
                    EventKind::EnforcementDecision(decision)
                        if decision.mode == EnforcementMode::Enforce
                            && decision.outcome == EnforcementOutcome::Delegated
                            && decision.requested_action == Action::Deny
                            && decision.effective_action == Action::Deny
                            && decision.scope == VerdictScope::Request
                            && decision.selector_matched
                            && decision.execution == Some(
                                EnforcementExecutionEvidence::ProxySideHook {
                                    surface: ProxySideEnforcementSurface::L7Mitm,
                                    executed_action: Action::Deny,
                                    reason: expected_execution_reason.to_string(),
                                }
                            )
                            && decision.reason.contains("accepted delegated enforcement action")
                            && decision.reason.contains(expected_execution_reason)
                )
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        return Ok(());
    }
    Err(e2e_error(format!(
        "expected exactly one delegated MITM policy hook enforcement decision, got {}; observed bridge decisions: {observed:?}",
        matches.len(),
    ))
    .into())
}

fn expected_policy_hook_reason() -> String {
    format!("{POLICY_HOOK_REASON_PREFIX}{}", mitm_bridge::REQUEST_TARGET)
}

fn assert_expected_l7_mitm_audit(
    case: MitmBridgeCase,
    backend: &PreparedMitmBackend,
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let audit_envelopes = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind(), EventKind::L7MitmAudit(_)))
        .collect::<Vec<_>>();
    if audit_envelopes.is_empty() {
        return Err(e2e_error("missing durable L7 MITM audit events").into());
    }
    if !audit_envelopes.iter().all(|envelope| {
        envelope.origin().source() == CaptureSource::L7MitmControlPlane
            && envelope.origin().provider() == CaptureProviderKind::Interception
    }) {
        return Err(e2e_error("L7 MITM audit events used the wrong provider origin").into());
    }

    let events = audit_envelopes
        .iter()
        .map(|envelope| match envelope.kind() {
            EventKind::L7MitmAudit(event) => event,
            _ => unreachable!("audit_envelopes only contains L7 MITM audit events"),
        })
        .collect::<Vec<_>>();
    let phases = events
        .iter()
        .map(|event| event.phase())
        .collect::<BTreeSet<_>>();
    let mut required = BTreeSet::from([
        L7MitmAuditPhase::BackendStarting,
        L7MitmAuditPhase::BackendStopping,
        L7MitmAuditPhase::BackendStopped,
    ]);
    if case.backend() == MitmBackendKind::External {
        required.insert(L7MitmAuditPhase::BackendUnhealthy);
        required.insert(L7MitmAuditPhase::BackendRecovered);
    }
    if !phases.is_superset(&required) {
        return Err(e2e_error(format!(
            "missing L7 MITM lifecycle audit phases; expected at least {:?}, observed {:?}",
            required, phases
        ))
        .into());
    }
    match (case.backend(), &backend.config) {
        (MitmBackendKind::External, MitmBackendConfig::External { target }) => {
            assert_expected_external_l7_mitm_audit(&events, target)?;
        }
        (MitmBackendKind::ManagedProcess, MitmBackendConfig::ManagedProcess { target, .. }) => {
            assert_expected_managed_l7_mitm_audit(&events, target)?;
        }
        (backend_kind, config) => {
            return Err(e2e_error(format!(
                "MITM backend case/config mismatch: backend={backend_kind:?}, config={config:?}"
            ))
            .into());
        }
    }
    Ok(())
}

fn assert_expected_external_l7_mitm_audit(
    events: &[&L7MitmAuditEvent],
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let has_health_probe_started = events.iter().any(|event| {
        matches!(
            event,
            L7MitmAuditEvent::External {
                event: L7MitmExternalBackendAudit::BackendHealthProbeStarted { readiness_probe },
            } if readiness_probe.target == target
        )
    });
    let has_unhealthy = events.iter().any(|event| {
        matches!(
            event,
            L7MitmAuditEvent::External {
                event:
                    L7MitmExternalBackendAudit::BackendUnhealthy {
                        readiness_probe,
                        consecutive_failures,
                        reason,
                    },
            } if readiness_probe.target == target
                && *consecutive_failures > 0
                && !reason.is_empty()
        )
    });
    let has_recovered = events.iter().any(|event| {
        matches!(
            event,
            L7MitmAuditEvent::External {
                event: L7MitmExternalBackendAudit::BackendRecovered { readiness_probe },
            } if readiness_probe.target == target
        )
    });
    if has_health_probe_started && has_unhealthy && has_recovered {
        return Ok(());
    }
    Err(e2e_error(format!(
        "missing external L7 MITM audit payload for target {target}: \
         health_probe_started={has_health_probe_started}, unhealthy={has_unhealthy}, \
         recovered={has_recovered}"
    ))
    .into())
}

fn assert_expected_managed_l7_mitm_audit(
    events: &[&L7MitmAuditEvent],
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let has_ready = events.iter().any(|event| {
        matches!(
            event,
            L7MitmAuditEvent::ManagedProcess {
                event: L7MitmManagedProcessBackendAudit::BackendReady {
                    readiness_probe,
                    process,
                },
            } if readiness_probe.target == target && process.process_group.is_some()
        )
    });
    if has_ready {
        return Ok(());
    }
    Err(e2e_error(format!(
        "missing managed-process L7 MITM backend_ready audit with process group for target {target}"
    ))
    .into())
}

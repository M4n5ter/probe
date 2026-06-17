use capture::CaptureEvent;
use enforcement::{
    EnforcementBackend, EnforcementBackendDecision, EnforcementBackendRequest, EnforcementError,
    ScopedEnforcementPlanner,
};
use parsers::Http1ParserFactory;
use pipeline::{
    CapturePipeline, PARSER_INGRESS_CURSOR_OWNER, PipelinePolicy, PipelineRuntimeMetrics,
    PipelineRuntimeMetricsSnapshot,
};
use policy::{PolicyHook, PolicyManifest, PolicyRuntime};
use probe_core::{
    Action, Direction, EnforcementEvidence, EnforcementOutcome, EventEnvelope, EventKind,
    ObservationOnlyReason, ProtectiveActionProfile,
};
use tempfile::tempdir;

use super::fixture::{
    SequenceProvider, connection_closed, demo_flow_with_ports,
    event_local_observation_only_ebpf_unresolved_gap, exported_envelopes,
    flow_carried_observation_only_ebpf_syscall_gap,
    observation_only_ebpf_syscall_bytes_with_direction,
};

#[test]
fn observation_only_ebpf_syscall_bytes_cannot_apply_connection_enforcement()
-> Result<(), Box<dyn std::error::Error>> {
    let (envelopes, metrics) = run_reset_policy(
        vec![observation_only_ebpf_syscall_bytes_with_direction(
            demo_flow_with_ports(50_000, 80, 41),
            Direction::Outbound,
            b"GET /blocked HTTP/1.1\r\nHost: test\r\n\r\n",
        )],
        PolicyHook::HttpRequestHeaders,
        r#"
function on_http_request_headers(_)
  return probe.verdict({
action = "reset",
scope = "flow",
reason = "matched observation-only eBPF syscall sample",
confidence = 100,
  })
end
"#,
    )?;

    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::HttpRequestHeaders(headers)
                if envelope.degraded
                    && envelope
                        .enforcement_evidence
                        .destructive_enforcement_rejection_reason()
                        .is_some_and(|reason| reason.contains("eBPF syscall payload snapshot"))
                    && headers.target.as_deref() == Some("/blocked")
        )
    }));
    assert_unsupported_reset(&envelopes, "eBPF syscall payload snapshot");
    assert_no_apply(metrics);
    Ok(())
}

#[test]
fn observation_detail_does_not_change_enforcement_decision_event_id()
-> Result<(), Box<dyn std::error::Error>> {
    let first = unsupported_reset_decision_id_for_observation_detail("first diagnostic detail")?;
    let second = unsupported_reset_decision_id_for_observation_detail("second diagnostic detail")?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn observation_only_ebpf_syscall_gap_cannot_apply_connection_enforcement()
-> Result<(), Box<dyn std::error::Error>> {
    let (envelopes, metrics) = run_reset_policy(
        vec![flow_carried_observation_only_ebpf_syscall_gap(
            demo_flow_with_ports(50_000, 80, 42),
        )],
        PolicyHook::Gap,
        r#"
function on_gap(_)
  return probe.verdict({
action = "reset",
scope = "flow",
reason = "matched observation-only eBPF syscall gap",
confidence = 100,
  })
end
"#,
    )?;

    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::Gap(gap)
                if envelope
                    .enforcement_evidence
                    .destructive_enforcement_rejection_reason()
                    .is_some_and(|reason| reason.contains("eBPF syscall payload snapshot"))
                    && gap.reason.contains("eBPF syscall gap")
        )
    }));
    assert_unsupported_reset(&envelopes, "eBPF syscall payload snapshot");
    assert_no_apply(metrics);
    Ok(())
}

#[test]
fn close_flushed_events_inherit_observation_only_evidence() -> Result<(), Box<dyn std::error::Error>>
{
    let flow = demo_flow_with_ports(50_000, 80, 43);
    let (envelopes, metrics) = run_reset_policy(
        vec![
            observation_only_ebpf_syscall_bytes_with_direction(
                flow.clone(),
                Direction::Inbound,
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe",
            ),
            connection_closed(flow),
        ],
        PolicyHook::ProtocolError,
        r#"
function on_protocol_error(_)
  return probe.verdict({
action = "reset",
scope = "flow",
reason = "matched close-flushed observation-only protocol error",
confidence = 100,
  })
end
"#,
    )?;

    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::ProtocolError(error)
                if error.reason.contains("connection closed before fixed HTTP body completed")
                    && envelope
                    .enforcement_evidence
                    .destructive_enforcement_rejection_reason()
                    .is_some_and(|reason| reason.contains("eBPF syscall payload snapshot"))
        )
    }));
    assert_unsupported_reset(&envelopes, "eBPF syscall payload snapshot");
    assert_no_apply(metrics);
    Ok(())
}

#[test]
fn observation_only_flow_evidence_blocks_parser_cursor_until_close()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let flow = demo_flow_with_ports(50_000, 80, 44);
    run_without_policy(
        &spool,
        vec![flow_carried_observation_only_ebpf_syscall_gap(flow.clone())],
    )?;
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 0);

    let mut parser_factory = Http1ParserFactory::default();
    let mut recovery = CapturePipeline::new(&spool, &mut parser_factory, Vec::new(), "test");
    let summary = recovery.recover_ingress_journal_until_idle(16)?;
    assert_eq!(summary.ingress_records_recovered, 1);
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 0);

    let mut close_provider = SequenceProvider::new(vec![connection_closed(flow)]);
    let close_summary = recovery.run_provider(&mut close_provider)?;
    assert_eq!(close_summary.ingress_records_journaled, 1);
    assert_eq!(close_summary.ingress_records_processed, 1);
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 2);
    Ok(())
}

#[test]
fn event_local_observation_only_gap_does_not_block_parser_cursor_without_close()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    run_without_policy(
        &spool,
        vec![event_local_observation_only_ebpf_unresolved_gap(
            demo_flow_with_ports(50_000, 80, 45),
        )],
    )?;

    let envelopes = exported_envelopes(&spool)?;
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::Gap(gap)
                if gap.reason.contains("eBPF unresolved flow")
                    && envelope
                        .enforcement_evidence
                        .destructive_enforcement_rejection_reason()
                        .is_some_and(|reason| reason.contains("strong flow identity"))
        )
    }));
    assert_eq!(spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?, 1);
    Ok(())
}

fn run_reset_policy(
    events: Vec<CaptureEvent>,
    hook: PolicyHook,
    lua: &str,
) -> Result<(Vec<EventEnvelope>, PipelineRuntimeMetricsSnapshot), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "deny-policy".to_string(),
            version: "test-version".to_string(),
            hooks: vec![hook],
        },
        lua,
    )?;
    let mut enforcement_planner = ScopedEnforcementPlanner::with_backend(
        None,
        ProtectiveActionProfile::default(),
        ApplyingBackend,
    )?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(events);
    let metrics = PipelineRuntimeMetrics::default();
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        vec![PipelinePolicy::unscoped(policy)],
        "test",
    )
    .with_runtime_metrics(metrics.clone())
    .with_enforcement_planner(&mut enforcement_planner);

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(
        summary.ingress_records_journaled, summary.ingress_records_processed,
        "all supplied events should be journaled and processed"
    );
    Ok((exported_envelopes(&spool)?, metrics.snapshot()))
}

fn unsupported_reset_decision_id_for_observation_detail(
    detail: &str,
) -> Result<probe_core::EventId, Box<dyn std::error::Error>> {
    let mut event = observation_only_ebpf_syscall_bytes_with_direction(
        demo_flow_with_ports(50_000, 80, 46),
        Direction::Outbound,
        b"GET /blocked HTTP/1.1\r\nHost: test\r\n\r\n",
    );
    let CaptureEvent::Bytes(chunk) = &mut event else {
        panic!("observation helper must produce bytes");
    };
    chunk.degradation_reason = Some(detail.to_string());
    chunk.enforcement_evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
        detail,
    );

    let (envelopes, _metrics) = run_reset_policy(
        vec![event],
        PolicyHook::HttpRequestHeaders,
        r#"
function on_http_request_headers(_)
  return probe.verdict({
action = "reset",
scope = "flow",
reason = "matched observation-only eBPF syscall sample",
confidence = 100,
  })
end
"#,
    )?;
    let decision = envelopes
        .iter()
        .find(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::EnforcementDecision(decision)
                    if decision.outcome == EnforcementOutcome::Unsupported
            )
        })
        .expect("observation-only reset must emit an unsupported enforcement decision");
    assert!(!matches!(
        &decision.kind,
        EventKind::EnforcementDecision(value) if value.reason.contains(detail)
    ));
    Ok(decision.id.clone())
}

fn run_without_policy(
    spool: &storage::FjallSpool,
    events: Vec<CaptureEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(events);
    let mut pipeline = CapturePipeline::new(spool, &mut parser_factory, Vec::new(), "test");
    pipeline.run_provider(&mut provider)?;
    Ok(())
}

fn assert_unsupported_reset(envelopes: &[EventEnvelope], expected_reason: &str) {
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::PolicyVerdict(verdict) if verdict.action == Action::Reset
        )
    }));
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::EnforcementDecision(decision)
                if decision.outcome == EnforcementOutcome::Unsupported
                    && decision.requested_action == Action::Reset
                    && decision.effective_action == Action::Observe
                    && decision.reason.contains(expected_reason)
        )
    }));
}

fn assert_no_apply(metrics: PipelineRuntimeMetricsSnapshot) {
    assert_eq!(metrics.policy.verdicts, 1);
    assert_eq!(metrics.enforcement.decisions, 1);
    assert_eq!(metrics.enforcement.unsupported, 1);
    assert_eq!(metrics.enforcement.applied, 0);
}

struct ApplyingBackend;

impl EnforcementBackend for ApplyingBackend {
    fn apply(
        &mut self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<EnforcementBackendDecision, EnforcementError> {
        Ok(EnforcementBackendDecision::applied(format!(
            "planned apply {:?}",
            request.verdict.action
        )))
    }
}

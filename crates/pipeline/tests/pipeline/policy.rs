use enforcement::ScopedEnforcementPlanner;
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelinePolicy, PipelineRuntimeMetrics};
use policy::{PolicyHook, PolicyManifest, PolicyRuntime};
use probe_core::{
    Action, EnforcementMode, EnforcementOutcome, EventKind, ProcessSelector, Selector,
    TrafficSelector,
};
use tempfile::tempdir;

use super::fixture::{SequenceProvider, captured_bytes, demo_flow_with_ports, exported_envelopes};

#[test]
fn policy_verdicts_are_evaluated_by_scoped_enforcement_planner()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "deny-policy".to_string(),
            version: "test-version".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  return probe.verdict({
action = "deny",
scope = "request",
reason = "blocked in test",
confidence = 100,
  })
end
"#,
    )?;
    let mut enforcement_planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, None)?;
    let mut parser_factory = Http1ParserFactory::default();
    let flow = demo_flow_with_ports(50_000, 80, 4);
    let mut provider = SequenceProvider::new(vec![captured_bytes(
        flow,
        b"GET /blocked HTTP/1.1\r\nHost: test\r\n\r\n",
    )]);
    let metrics = PipelineRuntimeMetrics::default();
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        Some(PipelinePolicy::unscoped(&policy)),
        "test",
    )
    .with_runtime_metrics(metrics.clone())
    .with_enforcement_planner(&mut enforcement_planner);

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    let envelopes = exported_envelopes(&spool)?;
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::PolicyVerdict(verdict) if verdict.action == Action::Deny
        )
    }));
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            &envelope.kind,
            EventKind::EnforcementDecision(decision)
                if decision.outcome == EnforcementOutcome::DryRun
                    && decision.requested_action == Action::Deny
                    && decision.effective_action == Action::Observe
            && decision.selector_matched
        )
    }));
    let metrics = metrics.snapshot();
    assert_eq!(metrics.capture_events_read, summary.capture_events_read);
    assert_eq!(
        metrics.ingress_records_journaled,
        summary.ingress_records_journaled
    );
    assert_eq!(
        metrics.ingress_records_processed,
        summary.ingress_records_processed
    );
    assert_eq!(metrics.export_events_written, summary.export_events_written);
    assert_eq!(metrics.policy.evaluations, 1);
    assert_eq!(metrics.policy.verdicts, 1);
    assert_eq!(metrics.enforcement.decisions, 1);
    assert_eq!(metrics.enforcement.dry_run, 1);
    Ok(())
}

#[test]
fn policy_selector_scopes_policy_execution() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "scoped-policy".to_string(),
            version: "test-version".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  return probe.emit_alert("matched " .. event.kind.target)
end
"#,
    )?;
    let selector = Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            remote_ports: vec![443],
            ..TrafficSelector::default()
        },
    )
    .compile()?;
    let mut parser_factory = Http1ParserFactory::default();
    let metrics = PipelineRuntimeMetrics::default();
    let mut provider = SequenceProvider::new(vec![
        captured_bytes(
            demo_flow_with_ports(50_000, 80, 20),
            b"GET /miss HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_001, 443, 21),
            b"GET /hit HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
    ]);
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        Some(PipelinePolicy::new(&policy, Some(&selector))),
        "test",
    )
    .with_runtime_metrics(metrics.clone());

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 2);
    assert_eq!(summary.ingress_records_processed, 2);
    let envelopes = exported_envelopes(&spool)?;
    let alerts = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind, EventKind::PolicyAlert(_)))
        .collect::<Vec<_>>();
    assert_eq!(alerts.len(), 1);
    assert!(matches!(
        &alerts[0].kind,
        EventKind::PolicyAlert(alert) if alert.message == "matched /hit"
    ));
    let metrics = metrics.snapshot();
    assert_eq!(metrics.policy.evaluations, 1);
    assert_eq!(metrics.policy.selector_misses, 1);
    assert_eq!(metrics.policy.alerts, 1);
    assert_eq!(metrics.policy.verdicts, 0);
    assert_eq!(metrics.enforcement.decisions, 0);
    Ok(())
}

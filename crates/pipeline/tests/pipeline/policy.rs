use std::cell::Cell;

use enforcement::{
    EnforcementBackend, EnforcementBackendDecision, EnforcementBackendRequest, EnforcementError,
    ScopedEnforcementPlanner,
};
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelinePolicy, PipelinePolicySet, PipelineRuntimeMetrics};
use policy::{PolicyHook, PolicyManifest, PolicyRuntime};
use probe_core::{
    Action, EnforcementMode, EnforcementOutcome, EventEmission, EventKind, EventType,
    PolicyEmissionStage, ProcessSelector, ProtectiveActionProfile, Selector, TrafficSelector,
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
        vec![PipelinePolicy::unscoped(policy)],
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
            envelope.kind(),
            EventKind::PolicyVerdict(verdict) if verdict.action == Action::Deny
        )
    }));
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::EnforcementDecision(decision)
                if decision.outcome == EnforcementOutcome::DryRun
                    && decision.requested_action == Action::Deny
                    && decision.effective_action == Action::Observe
            && decision.selector_matched
        )
    }));
    let policy_coordinates = envelopes
        .iter()
        .filter_map(|envelope| match (envelope.kind(), envelope.provenance()) {
            (EventKind::PolicyVerdict(_) | EventKind::EnforcementDecision(_), Some(provenance)) => {
                match provenance.emission {
                    EventEmission::Policy {
                        trigger_index,
                        policy_index,
                        output_index,
                        stage,
                    } => Some((trigger_index, policy_index, output_index, stage)),
                    EventEmission::Primary { .. } => None,
                }
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        policy_coordinates,
        vec![
            (0, 0, 0, PolicyEmissionStage::Output),
            (0, 0, 0, PolicyEmissionStage::EnforcementDecision),
        ]
    );
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
        vec![PipelinePolicy::new(policy, Some(selector))],
        "test",
    )
    .with_runtime_metrics(metrics.clone());

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 2);
    assert_eq!(summary.ingress_records_processed, 2);
    let envelopes = exported_envelopes(&spool)?;
    let alerts = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind(), EventKind::PolicyAlert(_)))
        .collect::<Vec<_>>();
    assert_eq!(alerts.len(), 1);
    assert!(matches!(
        alerts[0].kind(),
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

#[test]
fn policy_outputs_do_not_shift_later_primary_event_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "multi-output-policy".to_string(),
            version: "test-version".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  if event.kind.target == "/first" then
    return {
      probe.emit_alert("first one"),
      probe.emit_alert("first two"),
    }
  end
end
"#,
    )?;
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(vec![captured_bytes(
        demo_flow_with_ports(50_000, 80, 22),
        b"GET /first HTTP/1.1\r\nHost: test\r\n\r\nGET /second HTTP/1.1\r\nHost: test\r\n\r\n",
    )]);
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        vec![PipelinePolicy::unscoped(policy)],
        "test",
    );

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    assert_eq!(summary.export_events_written, 4);
    let envelopes = exported_envelopes(&spool)?;
    let policy_alerts = envelopes
        .iter()
        .filter_map(|envelope| match (envelope.kind(), envelope.provenance()) {
            (EventKind::PolicyAlert(alert), Some(provenance)) => match provenance.emission {
                EventEmission::Policy {
                    trigger_index,
                    policy_index,
                    output_index,
                    stage,
                } => Some((
                    alert.message.clone(),
                    trigger_index,
                    policy_index,
                    output_index,
                    stage,
                )),
                EventEmission::Primary { .. } => None,
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let primary_targets = envelopes
        .into_iter()
        .filter_map(|envelope| match (envelope.kind(), envelope.provenance()) {
            (EventKind::HttpRequestHeaders(headers), Some(provenance)) => match provenance.emission
            {
                EventEmission::Primary { index } => Some((headers.target.clone(), index)),
                EventEmission::Policy { .. } => None,
            },
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(
        policy_alerts,
        vec![
            (
                "first one".to_string(),
                0,
                0,
                0,
                PolicyEmissionStage::Output
            ),
            (
                "first two".to_string(),
                0,
                0,
                1,
                PolicyEmissionStage::Output
            ),
        ]
    );
    assert_eq!(
        primary_targets,
        vec![
            (Some("/first".to_string()), 0),
            (Some("/second".to_string()), 1)
        ]
    );
    Ok(())
}

#[test]
fn multiple_policies_apply_selectors_and_verdicts_in_order()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let first = PolicyRuntime::from_source(
        PolicyManifest {
            id: "first-policy".to_string(),
            version: "one".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  return probe.emit_alert("first " .. event.kind.target)
end
"#,
    )?;
    let second = PolicyRuntime::from_source(
        PolicyManifest {
            id: "miss-policy".to_string(),
            version: "two".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  return probe.emit_alert("miss " .. event.kind.target)
end
"#,
    )?;
    let verdict = PolicyRuntime::from_source(
        PolicyManifest {
            id: "verdict-policy".to_string(),
            version: "three".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(_)
  return probe.verdict({
action = "deny",
scope = "request",
reason = "blocked by multi-policy test",
confidence = 100,
  })
end
"#,
    )?;
    let matching_selector = Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            remote_ports: vec![80],
            ..TrafficSelector::default()
        },
    )
    .compile()?;
    let missing_selector = Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            remote_ports: vec![443],
            ..TrafficSelector::default()
        },
    )
    .compile()?;
    let mut enforcement_planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, None)?;
    let mut parser_factory = Http1ParserFactory::default();
    let metrics = PipelineRuntimeMetrics::default();
    let mut provider = SequenceProvider::new(vec![captured_bytes(
        demo_flow_with_ports(50_000, 80, 30),
        b"GET /both HTTP/1.1\r\nHost: test\r\n\r\n",
    )]);
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        vec![
            PipelinePolicy::new(first, Some(matching_selector)),
            PipelinePolicy::new(second, Some(missing_selector)),
            PipelinePolicy::unscoped(verdict),
        ],
        "test",
    )
    .with_runtime_metrics(metrics.clone())
    .with_enforcement_planner(&mut enforcement_planner);

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.ingress_records_journaled, 1);
    assert_eq!(summary.ingress_records_processed, 1);
    let envelopes = exported_envelopes(&spool)?;
    let outcome_policy_versions = envelopes
        .iter()
        .filter(|envelope| {
            matches!(
                envelope.kind(),
                EventKind::PolicyAlert(_)
                    | EventKind::PolicyVerdict(_)
                    | EventKind::EnforcementDecision(_)
            )
        })
        .filter_map(|envelope| envelope.policy_version())
        .collect::<Vec<_>>();
    assert_eq!(
        outcome_policy_versions,
        vec![
            "first-policy@one",
            "verdict-policy@three",
            "verdict-policy@three"
        ]
    );
    assert!(envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::EnforcementDecision(decision)
                if decision.outcome == EnforcementOutcome::DryRun
                    && decision.requested_action == Action::Deny
        )
    }));
    let metrics = metrics.snapshot();
    assert_eq!(metrics.policy.evaluations, 2);
    assert_eq!(metrics.policy.alerts, 1);
    assert_eq!(metrics.policy.verdicts, 1);
    assert_eq!(metrics.policy.selector_misses, 1);
    assert_eq!(metrics.enforcement.decisions, 1);
    assert_eq!(metrics.enforcement.dry_run, 1);
    Ok(())
}

#[test]
fn policy_runtime_error_does_not_suppress_prior_verdict_or_later_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let verdict = PolicyRuntime::from_source(
        PolicyManifest {
            id: "verdict-policy".to_string(),
            version: "one".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(_)
  return probe.verdict({
action = "deny",
scope = "request",
reason = "blocked before invalid policy",
confidence = 100,
  })
end
"#,
    )?;
    let invalid = PolicyRuntime::from_source(
        PolicyManifest {
            id: "invalid-policy".to_string(),
            version: "two".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(_)
  return "not a policy outcome"
end
"#,
    )?;
    let later = PolicyRuntime::from_source(
        PolicyManifest {
            id: "later-policy".to_string(),
            version: "three".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  return probe.emit_alert("later " .. event.kind.target)
end
"#,
    )?;
    let mut enforcement_planner = ScopedEnforcementPlanner::new(EnforcementMode::DryRun, None)?;
    let metrics = PipelineRuntimeMetrics::default();
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(vec![captured_bytes(
        demo_flow_with_ports(50_000, 80, 31),
        b"GET /bad HTTP/1.1\r\nHost: test\r\n\r\n",
    )]);
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        vec![
            PipelinePolicy::unscoped(verdict),
            PipelinePolicy::unscoped(invalid),
            PipelinePolicy::unscoped(later),
        ],
        "test",
    )
    .with_runtime_metrics(metrics.clone())
    .with_enforcement_planner(&mut enforcement_planner);

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.export_events_written, 5);
    let envelopes = exported_envelopes(&spool)?;
    let policy_outputs = envelopes
        .iter()
        .filter(|envelope| {
            matches!(
                envelope.kind(),
                EventKind::PolicyAlert(_)
                    | EventKind::PolicyVerdict(_)
                    | EventKind::PolicyRuntimeError(_)
                    | EventKind::EnforcementDecision(_)
            )
        })
        .collect::<Vec<_>>();
    let policy_versions = policy_outputs
        .iter()
        .filter_map(|envelope| envelope.policy_version())
        .collect::<Vec<_>>();
    assert_eq!(
        policy_versions,
        vec![
            "verdict-policy@one",
            "verdict-policy@one",
            "invalid-policy@two",
            "later-policy@three"
        ]
    );
    assert!(matches!(
        policy_outputs[0].kind(),
        EventKind::PolicyVerdict(verdict) if verdict.action == Action::Deny
    ));
    assert!(matches!(
        policy_outputs[1].kind(),
        EventKind::EnforcementDecision(decision)
            if decision.outcome == EnforcementOutcome::DryRun
                && decision.requested_action == Action::Deny
    ));
    assert!(matches!(
        policy_outputs[2].kind(),
        EventKind::PolicyRuntimeError(error)
            if error.event_type == EventType::HttpRequestHeaders
                && error.reason.contains("invalid outcome")
    ));
    assert!(matches!(
        policy_outputs[3].kind(),
        EventKind::PolicyAlert(alert) if alert.message == "later /bad"
    ));
    let metrics = metrics.snapshot();
    assert_eq!(metrics.policy.evaluations, 3);
    assert_eq!(metrics.policy.alerts, 1);
    assert_eq!(metrics.policy.verdicts, 1);
    assert_eq!(metrics.policy.errors, 1);
    assert_eq!(metrics.enforcement.decisions, 1);
    assert_eq!(metrics.enforcement.dry_run, 1);
    Ok(())
}

#[test]
fn policy_error_metric_counts_only_persisted_runtime_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = ExportFailureAfterFirstSpool::new(storage::FjallSpool::open(temp.path())?);
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "invalid-policy".to_string(),
            version: "one".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(_)
  return "not a policy outcome"
end
"#,
    )?;
    let later = PolicyRuntime::from_source(
        PolicyManifest {
            id: "later-policy".to_string(),
            version: "two".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  return probe.emit_alert("later " .. event.kind.target)
end
"#,
    )?;
    let metrics = PipelineRuntimeMetrics::default();
    let mut parser_factory = Http1ParserFactory::default();
    let policy_set = PipelinePolicySet::new(vec![
        PipelinePolicy::unscoped(policy),
        PipelinePolicy::unscoped(later),
    ]);
    let mut provider = SequenceProvider::new(vec![captured_bytes(
        demo_flow_with_ports(50_000, 80, 33),
        b"GET /bad-metric HTTP/1.1\r\nHost: test\r\n\r\n",
    )]);
    let mut pipeline =
        CapturePipeline::new(&spool, &mut parser_factory, policy_set.clone(), "test")
            .with_runtime_metrics(metrics.clone());

    let error = pipeline
        .run_provider(&mut provider)
        .expect_err("policy runtime error append should fail");

    assert!(matches!(
        error,
        pipeline::PipelineError::Storage(storage::StorageError::Io(_))
    ));
    let metrics = metrics.snapshot();
    assert_eq!(metrics.policy.evaluations, 1);
    assert_eq!(metrics.policy.errors, 0);
    let policy_runtime = policy_set.runtime_snapshot();
    assert_eq!(policy_runtime[0].runtime_errors.consecutive_errors, 0);
    assert_eq!(policy_runtime[0].runtime_errors.disabled_reason, None);
    Ok(())
}

#[test]
fn policy_runtime_errors_disable_policy_after_consecutive_threshold()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "flaky-policy".to_string(),
            version: "one".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(event)
  if event.kind.target == "/ok" then
    return probe.emit_alert("ok reset")
  end
  return "not a policy outcome"
end
"#,
    )?;
    let metrics = PipelineRuntimeMetrics::default();
    let mut parser_factory = Http1ParserFactory::default();
    let policy_set =
        PipelinePolicySet::new(vec![PipelinePolicy::with_runtime_error_disable_threshold(
            policy, None, 2,
        )]);
    let mut provider = SequenceProvider::new(vec![
        captured_bytes(
            demo_flow_with_ports(50_001, 80, 41),
            b"GET /bad-1 HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_002, 80, 42),
            b"GET /ok HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_003, 80, 43),
            b"GET /bad-2 HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_004, 80, 44),
            b"GET /bad-3 HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_005, 80, 45),
            b"GET /bad-4 HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
    ]);
    let mut pipeline =
        CapturePipeline::new(&spool, &mut parser_factory, policy_set.clone(), "test")
            .with_runtime_metrics(metrics.clone());

    pipeline.run_provider(&mut provider)?;

    let envelopes = exported_envelopes(&spool)?;
    let runtime_errors = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyRuntimeError(error) => Some(error),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(runtime_errors.len(), 3);
    assert!(
        !runtime_errors[0].reason.contains("policy disabled"),
        "{}",
        runtime_errors[0].reason
    );
    assert!(
        runtime_errors[2]
            .reason
            .contains("policy disabled after 2 consecutive runtime errors"),
        "{}",
        runtime_errors[2].reason
    );
    assert!(envelopes.iter().any(|envelope| {
        matches!(envelope.kind(), EventKind::PolicyAlert(alert) if alert.message == "ok reset")
    }));
    let metrics = metrics.snapshot();
    assert_eq!(metrics.policy.evaluations, 4);
    assert_eq!(metrics.policy.alerts, 1);
    assert_eq!(metrics.policy.errors, 3);
    assert_eq!(metrics.policy.disabled, 1);
    let policy_runtime = policy_set.runtime_snapshot();
    assert_eq!(policy_runtime.len(), 1);
    assert_eq!(policy_runtime[0].policy_version, "flaky-policy@one");
    assert_eq!(policy_runtime[0].runtime_errors.disable_threshold, 2);
    assert_eq!(policy_runtime[0].runtime_errors.consecutive_errors, 2);
    assert!(
        policy_runtime[0]
            .runtime_errors
            .disabled_reason
            .as_deref()
            .is_some_and(
                |reason| reason.contains("policy disabled after 2 consecutive runtime errors")
            )
    );
    Ok(())
}

#[test]
fn zero_policy_runtime_error_threshold_keeps_policy_active()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = invalid_outcome_policy("always-invalid")?;
    let metrics = PipelineRuntimeMetrics::default();
    let mut parser_factory = Http1ParserFactory::default();
    let policy_set =
        PipelinePolicySet::new(vec![PipelinePolicy::with_runtime_error_disable_threshold(
            policy, None, 0,
        )]);
    let mut provider = SequenceProvider::new(vec![
        captured_bytes(
            demo_flow_with_ports(50_011, 80, 51),
            b"GET /bad-1 HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_012, 80, 52),
            b"GET /bad-2 HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
        captured_bytes(
            demo_flow_with_ports(50_013, 80, 53),
            b"GET /bad-3 HTTP/1.1\r\nHost: test\r\n\r\n",
        ),
    ]);
    let mut pipeline =
        CapturePipeline::new(&spool, &mut parser_factory, policy_set.clone(), "test")
            .with_runtime_metrics(metrics.clone());

    pipeline.run_provider(&mut provider)?;

    let runtime_error_count = exported_envelopes(&spool)?
        .iter()
        .filter(|envelope| matches!(envelope.kind(), EventKind::PolicyRuntimeError(_)))
        .count();
    assert_eq!(runtime_error_count, 3);
    let metrics = metrics.snapshot();
    assert_eq!(metrics.policy.evaluations, 3);
    assert_eq!(metrics.policy.errors, 3);
    assert_eq!(metrics.policy.disabled, 0);
    let policy_runtime = policy_set.runtime_snapshot();
    assert_eq!(policy_runtime[0].runtime_errors.disable_threshold, 0);
    assert_eq!(policy_runtime[0].runtime_errors.consecutive_errors, 3);
    assert_eq!(policy_runtime[0].runtime_errors.disabled_reason, None);
    Ok(())
}

#[test]
fn enforcement_error_is_exported_after_verdict_audit() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let spool = storage::FjallSpool::open(temp.path())?;
    let policy = PolicyRuntime::from_source(
        PolicyManifest {
            id: "verdict-policy".to_string(),
            version: "one".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(_)
  return probe.verdict({
action = "deny",
scope = "request",
reason = "blocked before append",
confidence = 100,
  })
end
"#,
    )?;
    let metrics = PipelineRuntimeMetrics::default();
    let mut parser_factory = Http1ParserFactory::default();
    let mut provider = SequenceProvider::new(vec![captured_bytes(
        demo_flow_with_ports(50_000, 80, 32),
        b"GET /enforce-fail HTTP/1.1\r\nHost: test\r\n\r\n",
    )]);
    let mut enforcement_planner = ScopedEnforcementPlanner::with_backend(
        None,
        ProtectiveActionProfile::default(),
        FailingBackend,
    )?;
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        vec![PipelinePolicy::unscoped(policy)],
        "test",
    )
    .with_runtime_metrics(metrics.clone())
    .with_enforcement_planner(&mut enforcement_planner);

    let summary = pipeline.run_provider(&mut provider)?;

    assert_eq!(summary.export_events_written, 3);
    let envelopes = exported_envelopes(&spool)?;
    let policy_outputs = envelopes
        .iter()
        .filter(|envelope| {
            matches!(
                envelope.kind(),
                EventKind::PolicyVerdict(_) | EventKind::EnforcementDecision(_)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(policy_outputs.len(), 2);
    assert!(matches!(
        policy_outputs[0].kind(),
        EventKind::PolicyVerdict(verdict) if verdict.action == Action::Deny
    ));
    assert!(matches!(
        policy_outputs[1].kind(),
        EventKind::EnforcementDecision(decision)
            if decision.outcome == EnforcementOutcome::Failed
                && decision.effective_action == Action::Observe
                && decision.reason.contains("planned failure")
    ));
    let metrics = metrics.snapshot();
    assert_eq!(metrics.policy.verdicts, 1);
    assert_eq!(metrics.enforcement.decisions, 1);
    assert_eq!(metrics.enforcement.failed, 1);
    Ok(())
}

fn invalid_outcome_policy(id: &str) -> Result<PolicyRuntime, policy::PolicyError> {
    PolicyRuntime::from_source(
        PolicyManifest {
            id: id.to_string(),
            version: "one".to_string(),
            hooks: vec![PolicyHook::HttpRequestHeaders],
        },
        r#"
function on_http_request_headers(_)
  return "not a policy outcome"
end
"#,
    )
}

struct FailingBackend;

impl EnforcementBackend for FailingBackend {
    fn apply(
        &mut self,
        _request: EnforcementBackendRequest<'_>,
    ) -> Result<EnforcementBackendDecision, EnforcementError> {
        Err(EnforcementError::Backend("planned failure".to_string()))
    }
}

struct ExportFailureAfterFirstSpool {
    inner: storage::FjallSpool,
    successful_export_appends: Cell<usize>,
}

impl ExportFailureAfterFirstSpool {
    fn new(inner: storage::FjallSpool) -> Self {
        Self {
            inner,
            successful_export_appends: Cell::new(1),
        }
    }
}

impl storage::ExportSpool for ExportFailureAfterFirstSpool {
    fn read_export_batch(
        &self,
        sink: &str,
        limit: usize,
    ) -> Result<Vec<storage::StoredEvent>, storage::StorageError> {
        self.inner.read_export_batch(sink, limit)
    }

    fn ack_export(&self, sink: &str, sequence: u64) -> Result<(), storage::StorageError> {
        self.inner.ack_export(sink, sequence)
    }

    fn export_cursor(&self, sink: &str) -> Result<u64, storage::StorageError> {
        self.inner.export_cursor(sink)
    }

    fn prune_export_through(
        &self,
        sequence: u64,
        limit: usize,
    ) -> Result<u64, storage::StorageError> {
        self.inner.prune_export_through(sequence, limit)
    }

    fn prune_expired_export_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<storage::RetentionPrune, storage::StorageError> {
        self.inner
            .prune_expired_export_prefix(cutoff_unix_ns, limit, cursor_owners)
    }

    fn prune_export_to_max_records(
        &self,
        max_records: u64,
        limit: usize,
        cursor_owners: &[&str],
    ) -> Result<storage::RetentionPrune, storage::StorageError> {
        self.inner
            .prune_export_to_max_records(max_records, limit, cursor_owners)
    }
}

impl storage::DurableSpool for ExportFailureAfterFirstSpool {
    fn append_ingress(
        &self,
        payload: storage::SpoolPayload,
    ) -> Result<storage::StoredEvent, storage::StorageError> {
        self.inner.append_ingress(payload)
    }

    fn read_ingress_batch(
        &self,
        consumer: storage::IngressCursorOwner,
        limit: usize,
    ) -> Result<Vec<storage::StoredEvent>, storage::StorageError> {
        self.inner.read_ingress_batch(consumer, limit)
    }

    fn read_ingress_batch_after(
        &self,
        sequence: u64,
        limit: usize,
    ) -> Result<Vec<storage::StoredEvent>, storage::StorageError> {
        self.inner.read_ingress_batch_after(sequence, limit)
    }

    fn ack_ingress(
        &self,
        consumer: storage::IngressCursorOwner,
        sequence: u64,
    ) -> Result<(), storage::StorageError> {
        self.inner.ack_ingress(consumer, sequence)
    }

    fn ingress_cursor(
        &self,
        consumer: storage::IngressCursorOwner,
    ) -> Result<u64, storage::StorageError> {
        self.inner.ingress_cursor(consumer)
    }

    fn append_export(
        &self,
        payload: storage::SpoolPayload,
    ) -> Result<storage::StoredEvent, storage::StorageError> {
        self.append_export_with_failure(|| self.inner.append_export(payload))
    }

    fn append_export_once(
        &self,
        dedup_key: &str,
        payload: storage::SpoolPayload,
    ) -> Result<storage::AppendOutcome, storage::StorageError> {
        self.append_export_with_failure(|| self.inner.append_export_once(dedup_key, payload))
    }

    fn prune_expired_ingress_prefix(
        &self,
        cutoff_unix_ns: u64,
        limit: usize,
        consumers: &[storage::IngressCursorOwner],
    ) -> Result<storage::RetentionPrune, storage::StorageError> {
        self.inner
            .prune_expired_ingress_prefix(cutoff_unix_ns, limit, consumers)
    }

    fn prune_ingress_to_max_records(
        &self,
        max_records: u64,
        limit: usize,
        consumers: &[storage::IngressCursorOwner],
    ) -> Result<storage::RetentionPrune, storage::StorageError> {
        self.inner
            .prune_ingress_to_max_records(max_records, limit, consumers)
    }
}

impl ExportFailureAfterFirstSpool {
    fn append_export_with_failure<T>(
        &self,
        append: impl FnOnce() -> Result<T, storage::StorageError>,
    ) -> Result<T, storage::StorageError> {
        let remaining = self.successful_export_appends.get();
        if remaining == 0 {
            return Err(storage::StorageError::Io(std::io::Error::other(
                "planned export failure",
            )));
        }
        self.successful_export_appends.set(remaining - 1);
        append()
    }
}

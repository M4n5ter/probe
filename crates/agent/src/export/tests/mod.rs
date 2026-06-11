use std::{
    collections::BTreeMap,
    fs,
    sync::Arc,
    time::{Duration, Instant},
};

use probe_config::{
    AgentConfig, CompressionCodecName, ExportWorkerScheduleConfig, ExporterConfig,
    ExporterTransport,
};
use runtime::{ExportPlan, ExportSinkPlan, ExportWorkerPlan};
use storage::FjallSpool;

use super::*;

mod support;
use support::*;

#[test]
fn acked_event_ids_advance_only_contiguous_cursor_prefix() {
    let batch = batch_with_events(["one", "two", "three"]);

    assert_eq!(
        contiguous_cursor_from_event_ids(&batch, &["one".to_string(), "two".to_string()]),
        Some(2)
    );
    assert_eq!(
        contiguous_cursor_from_event_ids(&batch, &["two".to_string(), "three".to_string()]),
        None
    );
}

#[test]
fn export_worker_backoff_counts_from_failure_completion() {
    let tick_started_at = Instant::now();
    let failure_completed_at = tick_started_at + Duration::from_millis(750);
    let mut backoff = ExportWorkerBackoff::new(Duration::from_millis(1_000));

    backoff.record_failure_at("slow", failure_completed_at);

    assert!(backoff.should_skip("slow", failure_completed_at + Duration::from_millis(999)));
    assert!(!backoff.should_skip("slow", failure_completed_at + Duration::from_millis(1_000)));
}

#[tokio::test]
async fn planned_export_sinks_use_independent_cursors_and_attempt_all()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("planned-export-sinks");
    let spool = FjallSpool::open(&temp)?;
    append_export_event(&spool, 1)?;
    let failing = TestWebhookServer::spawn(false)?;
    let successful = TestWebhookServer::spawn(true)?;
    let config = AgentConfig {
        agent_id: "agent-1".to_string(),
        exporters: vec![
            ExporterConfig {
                id: "failing".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: failing.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
            },
            ExporterConfig {
                id: "successful".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: successful.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
            },
        ],
        ..AgentConfig::default()
    };
    config.validate_basic()?;
    let plan = runtime_plan(config)?;

    let result = drain_planned_sinks(&spool, &plan.config.agent_id, &plan.export).await;

    assert!(matches!(
        result,
        Err(ExportDrainError::MultipleSinksFailed { .. })
    ));
    assert_eq!(spool.export_cursor("failing")?, 0);
    assert_eq!(spool.export_cursor("successful")?, 1);

    let request = successful.join()?;
    assert_eq!(
        request_header(&request, "x-probe-node").as_deref(),
        Some("node-a")
    );
    assert_eq!(
        request_header(&request, "x-sssa-codec").as_deref(),
        Some("none")
    );
    assert_eq!(
        request_header(&request, "idempotency-key").as_deref(),
        Some("agent-1:successful:1")
    );
    let _ = failing.join()?;
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[tokio::test]
async fn export_worker_drains_until_stopped() -> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("planned-export-worker");
    let spool = Arc::new(FjallSpool::open(&temp)?);
    append_export_event(spool.as_ref(), 1)?;
    let server = TestWebhookServer::spawn_accepting(true, 2)?;
    let mut config = AgentConfig {
        agent_id: "agent-1".to_string(),
        exporters: vec![ExporterConfig {
            id: "worker".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: server.endpoint(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
        }],
        ..AgentConfig::default()
    };
    config.export.worker.schedule = ExportWorkerScheduleConfig::FixedIntervalBounded {
        interval_ms: 10,
        batches_per_sink_per_tick: 1,
        sink_timeout_ms: 5_000,
        failure_backoff_ms: 30_000,
    };
    config.validate_basic()?;
    let plan = runtime_plan(config)?;
    let config = ExportWorkerConfig::from_export_plan(plan.config.agent_id.clone(), &plan.export)
        .expect("worker should be enabled for planned webhook sink");

    let worker = spawn_export_worker(Arc::clone(&spool), config);
    wait_for_export_cursor(spool.as_ref(), "worker", 1).await?;
    append_export_event(spool.as_ref(), 2)?;
    wait_for_export_cursor(spool.as_ref(), "worker", 2).await?;
    worker.stop().await;

    let requests = server.join_requests()?;
    assert_eq!(requests.len(), 2);
    assert_eq!(
        request_header(&requests[0], "x-sssa-codec").as_deref(),
        Some("none")
    );
    assert_eq!(
        request_header(&requests[0], "idempotency-key").as_deref(),
        Some("agent-1:worker:1")
    );
    assert_eq!(
        request_header(&requests[1], "idempotency-key").as_deref(),
        Some("agent-1:worker:2")
    );
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[tokio::test]
async fn export_worker_uses_configured_per_tick_batch_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let spool = Arc::new(SingleEventBatchSpool::with_export_events(2)?);
    let server = TestWebhookServer::spawn_accepting(true, 2)?;
    let plan = ExportPlan {
        worker: ExportWorkerPlan::FixedIntervalBounded {
            interval_ms: 60_000,
            batches_per_sink_per_tick: 2,
            sink_timeout_ms: 5_000,
            failure_backoff_ms: 30_000,
        },
        sinks: vec![ExportSinkPlan {
            id: "budget".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: server.endpoint(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
        }],
    };
    let config = ExportWorkerConfig::from_export_plan("agent-1".to_string(), &plan)
        .expect("worker should be enabled");

    let worker = spawn_export_worker(Arc::clone(&spool), config);
    wait_for_memory_export_cursor(spool.as_ref(), "budget", 2).await?;
    worker.stop().await;

    let requests = server.join_requests()?;
    assert_eq!(requests.len(), 2);
    assert_eq!(
        request_header(&requests[0], "idempotency-key").as_deref(),
        Some("agent-1:budget:1")
    );
    assert_eq!(
        request_header(&requests[1], "idempotency-key").as_deref(),
        Some("agent-1:budget:2")
    );
    Ok(())
}

#[tokio::test]
async fn export_worker_backs_off_failing_sink_without_blocking_healthy_sink()
-> Result<(), Box<dyn std::error::Error>> {
    let spool = Arc::new(SingleEventBatchSpool::with_export_events(2)?);
    let failing = TestWebhookServer::spawn_recording(false)?;
    let successful = TestWebhookServer::spawn_accepting(true, 2)?;
    let plan = ExportPlan {
        worker: ExportWorkerPlan::FixedIntervalBounded {
            interval_ms: 10,
            batches_per_sink_per_tick: 1,
            sink_timeout_ms: 5_000,
            failure_backoff_ms: 60_000,
        },
        sinks: vec![
            ExportSinkPlan {
                id: "failing".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: failing.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
            },
            ExportSinkPlan {
                id: "successful".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: successful.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
            },
        ],
    };
    let config = ExportWorkerConfig::from_export_plan("agent-1".to_string(), &plan)
        .expect("worker should be enabled");

    let worker = spawn_export_worker(Arc::clone(&spool), config);
    wait_for_memory_export_cursor(spool.as_ref(), "successful", 2).await?;
    worker.stop().await;

    let successful_requests = successful.join_requests()?;
    assert_eq!(successful_requests.len(), 2);
    let failing_requests = failing.join_requests()?;
    assert_eq!(failing_requests.len(), 1);
    assert_eq!(
        request_header(&failing_requests[0], "idempotency-key").as_deref(),
        Some("agent-1:failing:1")
    );
    Ok(())
}

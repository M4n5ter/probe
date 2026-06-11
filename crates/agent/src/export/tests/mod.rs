use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use probe_config::{
    AgentConfig, CompressionCodecName, ExportWorkerScheduleConfig, ExporterConfig,
    ExporterTransport, TlsMaterialKind,
};
use runtime::{
    ExportPlan, ExportSinkPlan, ExportSinkTlsPlan, ExportTlsMaterialPlan, ExportWorkerPlan,
};
use storage::{FjallSpool, SpoolPayload};

use super::*;
use crate::tls_material::MAX_TLS_MATERIAL_BYTES;

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

#[test]
fn webhook_tls_config_loads_export_materials() -> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("webhook-tls-config");
    fs::create_dir_all(&temp)?;
    let trust_anchor = temp.join("ca.pem");
    let client_certificate = temp.join("client.pem");
    let client_private_key = temp.join("client.key");
    fs::write(&trust_anchor, b"ca-pem")?;
    fs::write(&client_certificate, b"cert-pem")?;
    fs::write(&client_private_key, b"key-pem")?;
    let plan = ExportSinkTlsPlan {
        trust_anchors: vec![tls_material(
            "collector-ca",
            TlsMaterialKind::TrustAnchor,
            trust_anchor,
        )],
        client_certificates: vec![tls_material(
            "client-cert",
            TlsMaterialKind::ClientCertificate,
            client_certificate,
        )],
        client_private_key: Some(tls_material(
            "client-key",
            TlsMaterialKind::ClientPrivateKey,
            client_private_key,
        )),
    };

    let tls = webhook_tls_config_from_plan(&plan)?;

    assert_eq!(tls.trust_anchor_pems, vec![b"ca-pem".to_vec()]);
    assert_eq!(tls.identity_pem.as_deref(), Some(&b"cert-pem\nkey-pem"[..]));
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[test]
fn export_worker_config_does_not_read_tls_materials_without_webhook_sinks()
-> Result<(), Box<dyn std::error::Error>> {
    let tls = ExportSinkTlsPlan {
        trust_anchors: vec![tls_material(
            "collector-ca",
            TlsMaterialKind::TrustAnchor,
            PathBuf::from("/missing/ca.pem"),
        )],
        client_certificates: vec![tls_material(
            "client-cert",
            TlsMaterialKind::ClientCertificate,
            PathBuf::from("/missing/client.pem"),
        )],
        client_private_key: Some(tls_material(
            "client-key",
            TlsMaterialKind::ClientPrivateKey,
            PathBuf::from("/missing/client.key"),
        )),
    };
    let disabled = ExportPlan {
        worker: ExportWorkerPlan::Disabled {
            reason: "test".to_string(),
        },
        sinks: Vec::new(),
    };
    assert!(ExportWorkerConfig::from_export_plan("agent-1".to_string(), &disabled).is_none());
    let non_webhook = ExportPlan {
        worker: ExportWorkerPlan::FixedIntervalBounded {
            interval_ms: 10,
            batches_per_sink_per_tick: 1,
            sink_timeout_ms: 5_000,
            failure_backoff_ms: 30_000,
        },
        sinks: vec![ExportSinkPlan {
            id: "grpc".to_string(),
            transport: ExporterTransport::Grpc,
            endpoint: "https://collector.example".to_string(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
            tls,
        }],
    };

    assert!(ExportWorkerConfig::from_export_plan("agent-1".to_string(), &non_webhook).is_some());
    Ok(())
}

#[tokio::test]
async fn planned_drain_does_not_read_tls_materials_without_sinks()
-> Result<(), Box<dyn std::error::Error>> {
    let spool = SingleEventBatchSpool::with_export_events(0)?;
    let plan = ExportPlan {
        worker: ExportWorkerPlan::Disabled {
            reason: "test".to_string(),
        },
        sinks: Vec::new(),
    };

    drain_planned_sinks(&spool, "agent-1", &plan).await?;
    Ok(())
}

#[tokio::test]
async fn planned_webhook_drain_fails_when_tls_material_is_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let spool = SingleEventBatchSpool::with_export_events(1)?;
    let plan = ExportPlan {
        worker: ExportWorkerPlan::Disabled {
            reason: "test".to_string(),
        },
        sinks: vec![ExportSinkPlan {
            id: "secure".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: "https://collector.example/batches".to_string(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
            tls: ExportSinkTlsPlan {
                trust_anchors: vec![tls_material(
                    "collector-ca",
                    TlsMaterialKind::TrustAnchor,
                    PathBuf::from("/missing/collector-ca.pem"),
                )],
                ..Default::default()
            },
        }],
    };

    let error = drain_planned_sinks(&spool, "agent-1", &plan)
        .await
        .expect_err("missing TLS material must fail the planned webhook drain");

    let rendered = error.to_string();
    assert!(rendered.contains("TLS material collector-ca"));
    assert!(rendered.contains("TrustAnchor"));
    assert!(rendered.contains("/missing/collector-ca.pem"));
    Ok(())
}

#[tokio::test]
async fn planned_webhook_drain_skips_tls_materials_without_pending_events()
-> Result<(), Box<dyn std::error::Error>> {
    let spool = SingleEventBatchSpool::with_export_events(0)?;
    let plan = ExportPlan {
        worker: ExportWorkerPlan::Disabled {
            reason: "test".to_string(),
        },
        sinks: vec![ExportSinkPlan {
            id: "secure".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: "https://collector.example/batches".to_string(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
            tls: ExportSinkTlsPlan {
                trust_anchors: vec![tls_material(
                    "collector-ca",
                    TlsMaterialKind::TrustAnchor,
                    PathBuf::from("/missing/collector-ca.pem"),
                )],
                ..Default::default()
            },
        }],
    };

    drain_planned_sinks(&spool, "agent-1", &plan).await?;
    Ok(())
}

#[tokio::test]
async fn planned_webhook_drain_rejects_unsafe_tls_material_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = test_dir("unsafe-tls-materials");
    fs::create_dir_all(&temp)?;
    let oversized = temp.join("oversized-ca.pem");
    fs::File::create(&oversized)?.set_len(MAX_TLS_MATERIAL_BYTES + 1)?;
    let oversized_error = drain_planned_sinks(
        &SingleEventBatchSpool::with_export_events(1)?,
        "agent-1",
        &export_plan_with_trust_anchor(oversized),
    )
    .await
    .expect_err("oversized TLS material must fail before unbounded read");
    assert!(oversized_error.to_string().contains("too large"));

    let directory_error = drain_planned_sinks(
        &SingleEventBatchSpool::with_export_events(1)?,
        "agent-1",
        &export_plan_with_trust_anchor(temp.clone()),
    )
    .await
    .expect_err("directory TLS material must be rejected");
    assert!(directory_error.to_string().contains("directory"));
    fs::remove_dir_all(temp)?;
    Ok(())
}

#[tokio::test]
async fn planned_webhook_drain_validates_batch_before_reading_tls_materials()
-> Result<(), Box<dyn std::error::Error>> {
    let spool = SingleEventBatchSpool::with_export_payload(SpoolPayload::new(
        SpoolPayloadSchema::from_wire("bad.schema"),
        b"bad payload",
    ));
    let plan = export_plan_with_trust_anchor(PathBuf::from("/missing/collector-ca.pem"));

    let error = drain_planned_sinks(&spool, "agent-1", &plan)
        .await
        .expect_err("bad local batch must fail before TLS material is read");
    let rendered = error.to_string();

    assert!(rendered.contains("unsupported spooled payload schema"));
    assert!(!rendered.contains("TLS material"));
    Ok(())
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
                tls: Default::default(),
            },
            ExporterConfig {
                id: "successful".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: successful.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
                tls: Default::default(),
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
            tls: Default::default(),
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
            tls: ExportSinkTlsPlan::default(),
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
                tls: ExportSinkTlsPlan::default(),
            },
            ExportSinkPlan {
                id: "successful".to_string(),
                transport: ExporterTransport::Webhook,
                endpoint: successful.endpoint(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: ExportSinkTlsPlan::default(),
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

fn export_plan_with_trust_anchor(path: PathBuf) -> ExportPlan {
    ExportPlan {
        worker: ExportWorkerPlan::Disabled {
            reason: "test".to_string(),
        },
        sinks: vec![ExportSinkPlan {
            id: "secure".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: "https://collector.example/batches".to_string(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
            tls: ExportSinkTlsPlan {
                trust_anchors: vec![tls_material(
                    "collector-ca",
                    TlsMaterialKind::TrustAnchor,
                    path,
                )],
                ..Default::default()
            },
        }],
    }
}

fn tls_material(
    id: &str,
    kind: TlsMaterialKind,
    path: impl Into<PathBuf>,
) -> ExportTlsMaterialPlan {
    ExportTlsMaterialPlan {
        id: id.to_string(),
        kind,
        path: path.into(),
    }
}

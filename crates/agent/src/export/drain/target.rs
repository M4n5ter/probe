use exporter::{CompressionCodec, WebhookExporter, WebhookTlsConfig};
use probe_config::CompressionCodecName;
use runtime::{
    ExportPlan, ExportSinkPlan, ExportSinkTlsPlan, ExportTlsMaterialPlan, WebhookExportSinkPlan,
};
use storage::ExportSpool;

use super::{
    ExportDrainError,
    batch::{EXPORT_BATCH_LIMIT, drain_export_sink_from_batch, export_batch_from_events},
    cleanup::prune_export_acknowledged_prefix_for_sinks,
    mode::{SinkDrainMode, duration_millis},
};
use crate::tls_material::{FilesystemTlsMaterialStore, TlsMaterialFileStore};

const REPLAY_WEBHOOK_SINK: &str = "replay-webhook";

pub async fn drain_planned_sinks(
    spool: &impl ExportSpool,
    agent_id: &str,
    export: &ExportPlan,
) -> Result<(), ExportDrainError> {
    let result =
        drain_export_sinks_with_mode(spool, agent_id, &export.sinks, SinkDrainMode::UntilEmpty)
            .await;
    finish_export_sink_drain(
        result,
        prune_export_acknowledged_prefix_for_sinks(spool, &export.sinks),
    )
}

pub async fn drain_replay_webhook(
    spool: &impl ExportSpool,
    agent_id: &str,
    endpoint: String,
    codec: CompressionCodec,
) -> Result<(), ExportDrainError> {
    drain_webhook_sink(
        spool,
        agent_id,
        WebhookExportTarget::replay(endpoint, codec),
        SinkDrainMode::UntilEmpty,
    )
    .await
}

pub(super) async fn drain_export_sinks_with_mode(
    spool: &impl ExportSpool,
    agent_id: &str,
    sinks: &[ExportSinkPlan],
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let mut failures = Vec::new();
    for sink in sinks {
        let result = drain_export_sink_with_mode(spool, agent_id, sink, mode).await;
        if let Err(error) = result {
            eprintln!("exporter sink {} failed: {error}", sink.id());
            failures.push(format!("{}: {error}", sink.id()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ExportDrainError::MultipleSinksFailed {
            failures: failures.join("; "),
        })
    }
}

pub(super) fn finish_export_sink_drain(
    drain_result: Result<(), ExportDrainError>,
    cleanup_result: Result<(), ExportDrainError>,
) -> Result<(), ExportDrainError> {
    match (drain_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(drain_error), Ok(())) => Err(drain_error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(drain_error), Err(cleanup_error)) => Err(ExportDrainError::MultipleSinksFailed {
            failures: format!("{drain_error}; export queue cleanup: {cleanup_error}"),
        }),
    }
}

pub(super) async fn drain_export_sink_with_mode(
    spool: &impl ExportSpool,
    agent_id: &str,
    sink: &ExportSinkPlan,
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    match sink {
        ExportSinkPlan::Webhook(sink) => {
            drain_webhook_sink_with_mode(
                spool,
                agent_id,
                webhook_export_target_from_plan_sink(sink),
                mode,
            )
            .await
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookExportTarget {
    sink: String,
    endpoint: String,
    codec: CompressionCodec,
    headers: Vec<(String, String)>,
    tls: ExportSinkTlsPlan,
}

impl WebhookExportTarget {
    fn replay(endpoint: String, codec: CompressionCodec) -> Self {
        Self {
            sink: REPLAY_WEBHOOK_SINK.to_string(),
            endpoint,
            codec,
            headers: Vec::new(),
            tls: ExportSinkTlsPlan::default(),
        }
    }
}

fn webhook_export_target_from_plan_sink(sink: &WebhookExportSinkPlan) -> WebhookExportTarget {
    WebhookExportTarget {
        sink: sink.id.clone(),
        endpoint: sink.endpoint.clone(),
        codec: compression_codec_from_config(sink.codec),
        headers: sink
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        tls: sink.tls.clone(),
    }
}

fn compression_codec_from_config(codec: CompressionCodecName) -> CompressionCodec {
    match codec {
        CompressionCodecName::None => CompressionCodec::None,
        CompressionCodecName::Zstd => CompressionCodec::Zstd,
        CompressionCodecName::Gzip => CompressionCodec::Gzip,
        CompressionCodecName::Deflate => CompressionCodec::Deflate,
    }
}

async fn drain_webhook_sink_with_mode(
    spool: &impl ExportSpool,
    agent_id: &str,
    target: WebhookExportTarget,
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let sink = target.sink.clone();
    match mode.sink_timeout() {
        Some(timeout) => {
            match tokio::time::timeout(timeout, drain_webhook_sink(spool, agent_id, target, mode))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(ExportDrainError::SinkTimedOut {
                    sink,
                    timeout_ms: duration_millis(timeout),
                }),
            }
        }
        None => drain_webhook_sink(spool, agent_id, target, mode).await,
    }
}

async fn drain_webhook_sink(
    spool: &impl ExportSpool,
    agent_id: &str,
    target: WebhookExportTarget,
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let WebhookExportTarget {
        sink,
        endpoint,
        codec,
        headers,
        tls,
    } = target;
    let first_events = spool.read_export_batch(&sink, EXPORT_BATCH_LIMIT)?;
    if first_events.is_empty() {
        return Ok(());
    }
    let Some(first_batch) = export_batch_from_events(agent_id, &sink, codec, first_events)? else {
        return Ok(());
    };
    let tls = webhook_tls_config_from_plan(&tls)?;
    let exporter = WebhookExporter::with_tls_config(endpoint, codec, headers, tls)?;
    drain_export_sink_from_batch(spool, agent_id, &sink, codec, mode, &exporter, first_batch)
        .await
        .map(|_| ())
}

fn webhook_tls_config_from_plan(
    plan: &ExportSinkTlsPlan,
) -> Result<WebhookTlsConfig, ExportDrainError> {
    webhook_tls_config_from_plan_with_file_store(plan, &FilesystemTlsMaterialStore)
}

fn webhook_tls_config_from_plan_with_file_store(
    plan: &ExportSinkTlsPlan,
    file_store: &impl TlsMaterialFileStore,
) -> Result<WebhookTlsConfig, ExportDrainError> {
    let trust_anchor_pems = plan
        .trust_anchors
        .iter()
        .map(|material| read_tls_material_for_export(material, file_store))
        .collect::<Result<Vec<_>, _>>()?;
    let identity_pem = match (
        plan.client_certificates.is_empty(),
        plan.client_private_key.as_ref(),
    ) {
        (true, None) => None,
        (false, Some(private_key)) => {
            let mut pem = Vec::new();
            for certificate in &plan.client_certificates {
                pem.extend(read_tls_material_for_export(certificate, file_store)?);
                pem.push(b'\n');
            }
            pem.extend(read_tls_material_for_export(private_key, file_store)?);
            Some(pem)
        }
        (true, Some(_)) | (false, None) => {
            return Err(ExportDrainError::IncompleteClientTlsIdentity);
        }
    };
    Ok(WebhookTlsConfig {
        trust_anchor_pems,
        identity_pem,
    })
}

fn read_tls_material_for_export(
    material: &ExportTlsMaterialPlan,
    file_store: &impl TlsMaterialFileStore,
) -> Result<Vec<u8>, ExportDrainError> {
    file_store
        .read_tls_material(&material.path)
        .map_err(|source| ExportDrainError::TlsMaterial {
            id: material.id.clone(),
            kind: material.kind,
            path: material.path.clone(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        num::NonZeroU64,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use probe_config::{
        AgentConfig, CompressionCodecName, ExporterConfig, ExporterTransport, TlsMaterialKind,
    };
    use probe_core::{CapabilityKind, CapabilityState, SpoolPayloadSchema};
    use runtime::{
        self, ExportFailureBackoffPlan, ExportPlan, ExportSinkTlsPlan, ExportSinkWorkerPlan,
        ExportTlsMaterialPlan, ExportWorkerPlan, ProviderRegistry, RuntimePlan,
        WebhookExportSinkPlan,
    };
    use storage::{FjallSpool, SpoolPayload};

    use super::*;
    use crate::export::drain::{
        batch::export_batch_id,
        spooled_event::append_export_events,
        webhook_server::{WebhookAckServer, request_header},
    };

    const OVERSIZED_TEST_FILE_BYTES: u64 = 10 * 1024 * 1024;

    #[test]
    fn webhook_tls_config_loads_export_materials() -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("webhook-tls-config");
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

    #[tokio::test]
    async fn planned_drain_does_not_read_tls_materials_without_sinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("planned-drain-without-sinks");
        let spool = FjallSpool::open(&temp)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: Vec::new(),
        };

        drain_planned_sinks(&spool, "agent-1", &plan).await?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn planned_webhook_drain_fails_when_tls_material_is_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("missing-webhook-tls-material");
        let spool = FjallSpool::open(&temp)?;
        append_export_events(&spool, 1)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: vec![
                WebhookExportSinkPlan {
                    id: "secure".to_string(),
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
                    worker: inherited_worker_quota(1),
                }
                .into(),
            ],
        };

        let error = drain_planned_sinks(&spool, "agent-1", &plan)
            .await
            .expect_err("missing TLS material must fail the planned webhook drain");

        let rendered = error.to_string();
        assert!(rendered.contains("TLS material collector-ca"));
        assert!(rendered.contains("TrustAnchor"));
        assert!(rendered.contains("/missing/collector-ca.pem"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn planned_webhook_drain_skips_tls_materials_without_pending_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("skip-webhook-tls-material");
        let spool = FjallSpool::open(&temp)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: vec![
                WebhookExportSinkPlan {
                    id: "secure".to_string(),
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
                    worker: inherited_worker_quota(1),
                }
                .into(),
            ],
        };

        drain_planned_sinks(&spool, "agent-1", &plan).await?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn planned_webhook_drain_rejects_unsafe_tls_material_sources()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("unsafe-tls-materials");
        fs::create_dir_all(&temp)?;
        let spool_temp = temp_path("unsafe-tls-material-spool");
        let spool = FjallSpool::open(&spool_temp)?;
        append_export_events(&spool, 1)?;
        let oversized = temp.join("oversized-ca.pem");
        fs::File::create(&oversized)?.set_len(OVERSIZED_TEST_FILE_BYTES)?;
        let oversized_error =
            drain_planned_sinks(&spool, "agent-1", &export_plan_with_trust_anchor(oversized))
                .await
                .expect_err("oversized TLS material must fail before unbounded read");
        assert!(oversized_error.to_string().contains("too large"));

        let directory_error = drain_planned_sinks(
            &spool,
            "agent-1",
            &export_plan_with_trust_anchor(temp.clone()),
        )
        .await
        .expect_err("directory TLS material must be rejected");
        assert!(directory_error.to_string().contains("directory"));
        fs::remove_dir_all(temp)?;
        fs::remove_dir_all(spool_temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn planned_webhook_drain_validates_batch_before_reading_tls_materials()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("bad-webhook-batch");
        let spool = FjallSpool::open(&temp)?;
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            b"bad payload",
        ))?;
        let plan = export_plan_with_trust_anchor(PathBuf::from("/missing/collector-ca.pem"));

        let error = drain_planned_sinks(&spool, "agent-1", &plan)
            .await
            .expect_err("bad local batch must fail before TLS material is read");
        let rendered = error.to_string();

        assert!(rendered.contains("unsupported spooled payload schema"));
        assert!(!rendered.contains("TLS material"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn planned_export_sinks_use_independent_cursors_and_attempt_all()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("planned-export-sinks");
        let spool = FjallSpool::open(&temp)?;
        append_export_events(&spool, 1)?;
        let failing = WebhookAckServer::rejecting(1)?;
        let successful = WebhookAckServer::accepting(1)?;
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
                    worker: Default::default(),
                },
                ExporterConfig {
                    id: "successful".to_string(),
                    transport: ExporterTransport::Webhook,
                    endpoint: successful.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
                    tls: Default::default(),
                    worker: Default::default(),
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
        assert_eq!(
            spool
                .read_export_batch("failing", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1]
        );

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
            request_header(&request, "idempotency-key"),
            Some(export_batch_id("agent-1", "successful", 1, 1))
        );
        let _ = failing.join()?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn planned_tail_drain_ignores_worker_batch_quota_and_runs_bounded_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("planned-tail-drain");
        let spool = FjallSpool::open(&temp)?;
        let event_count = (EXPORT_BATCH_LIMIT + 1) as u64;
        append_export_events(&spool, event_count)?;
        let server = WebhookAckServer::accepting(2)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 60_000,
                batches_per_sink_per_tick: 1,
                sink_timeout_ms: 5_000,
                failure_backoff: fixed_failure_backoff(30_000),
            },
            sinks: vec![
                WebhookExportSinkPlan {
                    id: "tail".to_string(),
                    endpoint: server.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::new(),
                    tls: ExportSinkTlsPlan::default(),
                    worker: overridden_worker_quota(1),
                }
                .into(),
            ],
        };

        drain_planned_sinks(&spool, "agent-1", &plan).await?;

        assert_eq!(spool.export_cursor("tail")?, event_count);
        assert_eq!(
            spool
                .read_export_batch("late", 10)?
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![event_count]
        );
        let requests = server.join_requests()?;
        assert_eq!(requests.len(), 2);
        assert_eq!(
            request_header(&requests[0], "idempotency-key"),
            Some(export_batch_id(
                "agent-1",
                "tail",
                1,
                EXPORT_BATCH_LIMIT as u64
            ))
        );
        assert_eq!(
            request_header(&requests[1], "idempotency-key"),
            Some(export_batch_id(
                "agent-1",
                "tail",
                EXPORT_BATCH_LIMIT as u64 + 1,
                event_count,
            ))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("sssa-probe-{name}-{}-{nanos}", std::process::id()))
    }

    fn export_plan_with_trust_anchor(path: PathBuf) -> ExportPlan {
        ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: vec![
                WebhookExportSinkPlan {
                    id: "secure".to_string(),
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
                    worker: inherited_worker_quota(1),
                }
                .into(),
            ],
        }
    }

    fn inherited_worker_quota(effective_batches_per_tick: u64) -> ExportSinkWorkerPlan {
        ExportSinkWorkerPlan {
            batches_per_tick_override: None,
            effective_batches_per_tick: NonZeroU64::new(effective_batches_per_tick)
                .expect("positive batch quota"),
        }
    }

    fn overridden_worker_quota(effective_batches_per_tick: u64) -> ExportSinkWorkerPlan {
        ExportSinkWorkerPlan {
            batches_per_tick_override: Some(effective_batches_per_tick),
            effective_batches_per_tick: NonZeroU64::new(effective_batches_per_tick)
                .expect("positive batch quota"),
        }
    }

    fn fixed_failure_backoff(backoff_ms: u64) -> ExportFailureBackoffPlan {
        ExportFailureBackoffPlan {
            initial_ms: backoff_ms,
            max_ms: backoff_ms,
            multiplier: 1,
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

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(
            config,
            &ProviderRegistry::new(Vec::new(), test_capabilities()),
        )
    }

    fn test_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
        ]
    }
}

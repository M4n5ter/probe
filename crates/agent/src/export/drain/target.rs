use std::{future::Future, time::Duration};

use exporter::{
    CompressionCodec, FileExporter, UnixHttpExporter, WebhookConnectionOptions, WebhookExporter,
    WebhookTlsConfig,
};
use probe_config::CompressionCodecName;
use runtime::{
    ExportPlan, ExportSinkPlan, ExportSinkTlsPlan, ExportTlsMaterialPlan, FileExportSinkPlan,
    TlsMaterialStorePlan, UnixHttpExportSinkPlan, WebhookExportSinkPlan,
};
use storage::ExportSpool;

use super::{
    ExportDrainError,
    batch::{EXPORT_BATCH_LIMIT, drain_export_sink_from_batch, export_batch_from_events},
    mode::{SinkDrainMode, duration_millis},
};
use crate::tls_material::{FilesystemTlsMaterialStore, TlsMaterialFileStore};

const REPLAY_WEBHOOK_SINK: &str = "replay-webhook";

#[cfg(test)]
pub async fn drain_planned_sinks(
    spool: &impl ExportSpool,
    agent_id: &str,
    export: &ExportPlan,
) -> Result<(), ExportDrainError> {
    drain_planned_sinks_with_webhook_connection(
        spool,
        agent_id,
        export,
        &TlsMaterialStorePlan::default(),
        WebhookConnectionOptions::default(),
    )
    .await
}

pub(crate) async fn drain_planned_sinks_with_webhook_connection(
    spool: &impl ExportSpool,
    agent_id: &str,
    export: &ExportPlan,
    tls_material_store: &TlsMaterialStorePlan,
    webhook_connection: WebhookConnectionOptions,
) -> Result<(), ExportDrainError> {
    drain_export_sinks_with_mode(
        spool,
        agent_id,
        &export.sinks,
        &FilesystemTlsMaterialStore::from_plan(tls_material_store),
        SinkDrainMode::UntilEmpty,
        webhook_connection,
    )
    .await
}

pub async fn drain_replay_webhook(
    spool: &impl ExportSpool,
    agent_id: &str,
    endpoint: String,
    codec: CompressionCodec,
) -> Result<(), ExportDrainError> {
    let target = WebhookExportTarget::replay(endpoint, codec);
    let sink = target.sink.clone();
    let file_store = FilesystemTlsMaterialStore::default();
    with_sink_timeout(
        sink,
        SinkDrainMode::UntilEmpty.sink_timeout(),
        drain_webhook_sink(
            spool,
            agent_id,
            target,
            SinkDrainMode::UntilEmpty,
            &file_store,
        ),
    )
    .await
}

async fn with_sink_timeout<F>(
    sink: String,
    timeout: Option<Duration>,
    future: F,
) -> Result<(), ExportDrainError>
where
    F: Future<Output = Result<(), ExportDrainError>>,
{
    match timeout {
        Some(timeout) => match tokio::time::timeout(timeout, future).await {
            Ok(result) => result,
            Err(_) => Err(ExportDrainError::SinkTimedOut {
                sink,
                timeout_ms: duration_millis(timeout),
            }),
        },
        None => future.await,
    }
}

pub(super) async fn drain_export_sinks_with_mode(
    spool: &impl ExportSpool,
    agent_id: &str,
    sinks: &[ExportSinkPlan],
    file_store: &FilesystemTlsMaterialStore,
    mode: SinkDrainMode,
    webhook_connection: WebhookConnectionOptions,
) -> Result<(), ExportDrainError> {
    let mut failures = Vec::new();
    for sink in sinks {
        let result = drain_export_sink_with_mode(
            spool,
            agent_id,
            sink,
            file_store,
            mode,
            webhook_connection,
        )
        .await;
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

pub(super) async fn drain_export_sink_with_mode(
    spool: &impl ExportSpool,
    agent_id: &str,
    sink: &ExportSinkPlan,
    file_store: &FilesystemTlsMaterialStore,
    mode: SinkDrainMode,
    webhook_connection: WebhookConnectionOptions,
) -> Result<(), ExportDrainError> {
    match sink {
        ExportSinkPlan::Webhook(sink) => {
            let target = webhook_export_target_from_plan_sink(sink, webhook_connection);
            let sink = target.sink.clone();
            with_sink_timeout(
                sink,
                mode.sink_timeout(),
                drain_webhook_sink(spool, agent_id, target, mode, file_store),
            )
            .await
        }
        ExportSinkPlan::File(sink) => {
            let target = file_export_target_from_plan_sink(sink);
            let sink = target.sink.clone();
            with_sink_timeout(
                sink,
                mode.sink_timeout(),
                drain_file_sink(spool, agent_id, target, mode),
            )
            .await
        }
        ExportSinkPlan::UnixHttp(sink) => {
            let target = unix_http_export_target_from_plan_sink(sink);
            let sink = target.sink.clone();
            with_sink_timeout(
                sink,
                mode.sink_timeout(),
                drain_unix_http_sink(spool, agent_id, target, mode),
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
    webhook_connection: WebhookConnectionOptions,
}

impl WebhookExportTarget {
    fn replay(endpoint: String, codec: CompressionCodec) -> Self {
        Self {
            sink: REPLAY_WEBHOOK_SINK.to_string(),
            endpoint,
            codec,
            headers: Vec::new(),
            tls: ExportSinkTlsPlan::default(),
            webhook_connection: WebhookConnectionOptions::default(),
        }
    }
}

fn webhook_export_target_from_plan_sink(
    sink: &WebhookExportSinkPlan,
    webhook_connection: WebhookConnectionOptions,
) -> WebhookExportTarget {
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
        webhook_connection,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileExportTarget {
    sink: String,
    path: std::path::PathBuf,
    codec: CompressionCodec,
}

fn file_export_target_from_plan_sink(sink: &FileExportSinkPlan) -> FileExportTarget {
    FileExportTarget {
        sink: sink.id.clone(),
        path: sink.path.clone(),
        codec: compression_codec_from_config(sink.codec),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnixHttpExportTarget {
    sink: String,
    socket_path: std::path::PathBuf,
    endpoint: String,
    codec: CompressionCodec,
    headers: Vec<(String, String)>,
}

fn unix_http_export_target_from_plan_sink(sink: &UnixHttpExportSinkPlan) -> UnixHttpExportTarget {
    UnixHttpExportTarget {
        sink: sink.id.clone(),
        socket_path: sink.socket_path.clone(),
        endpoint: sink.endpoint.clone(),
        codec: compression_codec_from_config(sink.codec),
        headers: sink
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
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

async fn drain_webhook_sink(
    spool: &impl ExportSpool,
    agent_id: &str,
    target: WebhookExportTarget,
    mode: SinkDrainMode,
    file_store: &FilesystemTlsMaterialStore,
) -> Result<(), ExportDrainError> {
    let WebhookExportTarget {
        sink,
        endpoint,
        codec,
        headers,
        tls,
        webhook_connection,
    } = target;
    let first_events = spool.read_export_batch(&sink, EXPORT_BATCH_LIMIT)?;
    if first_events.is_empty() {
        return Ok(());
    }
    let Some(first_batch) = export_batch_from_events(agent_id, &sink, codec, first_events)? else {
        return Ok(());
    };
    let tls = webhook_tls_config_from_plan(&tls, file_store)?;
    let exporter = WebhookExporter::with_connection_options(
        endpoint,
        codec,
        headers,
        tls,
        webhook_connection,
    )?;
    drain_export_sink_from_batch(spool, agent_id, &sink, codec, mode, &exporter, first_batch)
        .await
        .map(|_| ())
}

async fn drain_file_sink(
    spool: &impl ExportSpool,
    agent_id: &str,
    target: FileExportTarget,
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let FileExportTarget { sink, path, codec } = target;
    let first_events = spool.read_export_batch(&sink, EXPORT_BATCH_LIMIT)?;
    if first_events.is_empty() {
        return Ok(());
    }
    let Some(first_batch) = export_batch_from_events(agent_id, &sink, codec, first_events)? else {
        return Ok(());
    };
    let exporter = FileExporter::new(path, codec);
    drain_export_sink_from_batch(spool, agent_id, &sink, codec, mode, &exporter, first_batch)
        .await
        .map(|_| ())
}

async fn drain_unix_http_sink(
    spool: &impl ExportSpool,
    agent_id: &str,
    target: UnixHttpExportTarget,
    mode: SinkDrainMode,
) -> Result<(), ExportDrainError> {
    let UnixHttpExportTarget {
        sink,
        socket_path,
        endpoint,
        codec,
        headers,
    } = target;
    let first_events = spool.read_export_batch(&sink, EXPORT_BATCH_LIMIT)?;
    if first_events.is_empty() {
        return Ok(());
    }
    let Some(first_batch) = export_batch_from_events(agent_id, &sink, codec, first_events)? else {
        return Ok(());
    };
    let exporter = UnixHttpExporter::with_headers(socket_path, endpoint, codec, headers)?;
    drain_export_sink_from_batch(spool, agent_id, &sink, codec, mode, &exporter, first_batch)
        .await
        .map(|_| ())
}

fn webhook_tls_config_from_plan(
    plan: &ExportSinkTlsPlan,
    file_store: &impl TlsMaterialFileStore,
) -> Result<WebhookTlsConfig, ExportDrainError> {
    webhook_tls_config_from_plan_with_file_store(plan, file_store)
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
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use probe_config::{
        AgentConfig, CompressionCodecName, ExporterConfig, ExporterTransportConfig, TlsMaterialKind,
    };
    use probe_core::{CapabilityKind, CapabilityState, SpoolPayloadSchema};
    use runtime::{
        self, ExportFailureBackoffPlan, ExportPlan, ExportSinkTlsPlan, ExportSinkWorkerPlan,
        ExportTlsMaterialPlan, ExportWorkerPlan, FileExportSinkPlan, ProviderRegistry, RuntimePlan,
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
        write_private_file(&trust_anchor, b"ca-pem")?;
        write_private_file(&client_certificate, b"cert-pem")?;
        write_private_file(&client_private_key, b"key-pem")?;
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

        let store = FilesystemTlsMaterialStore::default();
        let tls = webhook_tls_config_from_plan(&plan, &store)?;

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
    async fn planned_webhook_drain_enforces_tls_material_allowed_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("webhook-tls-material-roots");
        fs::create_dir_all(&temp)?;
        let root = temp.join("allowed");
        let outside = temp.join("outside");
        fs::create_dir(&root)?;
        fs::create_dir(&outside)?;
        let outside_material = outside.join("collector-ca.pem");
        write_private_file(&outside_material, b"ca-pem")?;
        let spool_temp = temp_path("webhook-tls-material-roots-spool");
        let spool = FjallSpool::open(&spool_temp)?;
        append_export_events(&spool, 1)?;
        let plan = export_plan_with_trust_anchor(outside_material);
        let tls_material_store = TlsMaterialStorePlan::FilesystemRoots {
            allowed_roots: vec![root],
        };

        let error = drain_planned_sinks_with_webhook_connection(
            &spool,
            "agent-1",
            &plan,
            &tls_material_store,
            WebhookConnectionOptions::default(),
        )
        .await
        .expect_err("TLS material outside allowed roots must fail drain");

        assert!(
            error
                .to_string()
                .contains("outside configured filesystem roots")
        );
        fs::remove_dir_all(temp)?;
        fs::remove_dir_all(spool_temp)?;
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
                    transport: ExporterTransportConfig::Webhook {
                        endpoint: failing.endpoint(),
                        headers: BTreeMap::new(),
                        tls: Default::default(),
                    },
                    codec: CompressionCodecName::None,
                    worker: Default::default(),
                },
                ExporterConfig {
                    id: "successful".to_string(),
                    transport: ExporterTransportConfig::Webhook {
                        endpoint: successful.endpoint(),
                        headers: BTreeMap::from([(
                            "x-probe-node".to_string(),
                            "node-a".to_string(),
                        )]),
                        tls: Default::default(),
                    },
                    codec: CompressionCodecName::None,
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
            request_header(&request, "x-traffic-probe-codec").as_deref(),
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
    async fn planned_file_drain_writes_json_lines_and_advances_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = temp_path("planned-file-export-sink");
        fs::create_dir_all(&temp)?;
        let spool_path = temp.join("spool");
        let export_path = temp.join("export.jsonl");
        let spool = FjallSpool::open(&spool_path)?;
        append_export_events(&spool, 2)?;
        let plan = ExportPlan {
            worker: ExportWorkerPlan::Disabled {
                reason: "test".to_string(),
            },
            sinks: vec![
                FileExportSinkPlan {
                    id: "local-file".to_string(),
                    path: export_path.clone(),
                    codec: CompressionCodecName::None,
                    worker: inherited_worker_quota(1),
                }
                .into(),
            ],
        };

        drain_planned_sinks(&spool, "agent-1", &plan).await?;

        assert_eq!(spool.export_cursor("local-file")?, 2);
        let contents = fs::read_to_string(&export_path)?;
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let record = serde_json::from_str::<exporter::FileBatchRecord>(lines[0])?;
        assert_eq!(record.kind, exporter::FileBatchRecordKind::ProtobufBatch);
        assert_eq!(record.batch_id, "agent-1:local-file:1-2");
        assert_eq!(record.agent_id, "agent-1");
        assert_eq!(record.codec, CompressionCodec::None);
        assert_eq!(record.first_sequence, 1);
        assert_eq!(record.last_sequence, 2);
        assert_eq!(record.event_count, 2);
        let payload = record.decode_payload()?;
        let batch = proto::BatchEnvelope::decode_from_slice(&payload)?;
        assert_eq!(batch.batch_id, "agent-1:local-file:1-2");
        assert_eq!(batch.events.len(), 2);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn planned_tail_drain_ignores_worker_batch_quota_without_pruning_queue()
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
            (1..=10).collect::<Vec<_>>()
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
        std::env::temp_dir().join(format!(
            "traffic-probe-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), std::io::Error> {
        fs::write(path, contents)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
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

use std::{collections::BTreeMap, num::NonZeroU64, path::PathBuf};

use probe_config::{
    AgentConfig, CompressionCodecName, ExportFailureBackoffConfig, ExportWorkerScheduleConfig,
    ExporterTlsConfig, ExporterTransportConfig,
};
use serde::{Deserialize, Serialize};

use super::tls::{ExportTlsMaterialPlan, export_tls_materials_by_id};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPlan {
    pub worker: ExportWorkerPlan,
    pub sinks: Vec<ExportSinkPlan>,
}

impl ExportPlan {
    pub(super) fn resolve(config: &AgentConfig) -> Self {
        let materials_by_id = export_tls_materials_by_id(&config.tls.materials);
        let default_sink_batches_per_tick =
            export_worker_default_sink_batches_per_tick(config.export.worker.schedule);
        let sinks = config
            .exporters
            .iter()
            .map(|exporter| match &exporter.transport {
                ExporterTransportConfig::Webhook {
                    endpoint,
                    headers,
                    tls,
                } => ExportSinkPlan::Webhook(WebhookExportSinkPlan {
                    id: exporter.id.clone(),
                    endpoint: endpoint.clone(),
                    codec: exporter.codec,
                    headers: headers.clone(),
                    tls: ExportSinkTlsPlan::from_config(tls, &materials_by_id),
                    worker: ExportSinkWorkerPlan::from_config(
                        exporter.worker.batches_per_tick,
                        default_sink_batches_per_tick,
                    ),
                }),
                ExporterTransportConfig::File { path } => {
                    ExportSinkPlan::File(FileExportSinkPlan {
                        id: exporter.id.clone(),
                        path: path.clone(),
                        codec: exporter.codec,
                        worker: ExportSinkWorkerPlan::from_config(
                            exporter.worker.batches_per_tick,
                            default_sink_batches_per_tick,
                        ),
                    })
                }
                ExporterTransportConfig::UnixHttp {
                    socket_path,
                    endpoint,
                    headers,
                } => ExportSinkPlan::UnixHttp(UnixHttpExportSinkPlan {
                    id: exporter.id.clone(),
                    socket_path: socket_path.clone(),
                    endpoint: endpoint.clone(),
                    codec: exporter.codec,
                    headers: headers.clone(),
                    worker: ExportSinkWorkerPlan::from_config(
                        exporter.worker.batches_per_tick,
                        default_sink_batches_per_tick,
                    ),
                }),
            })
            .collect::<Vec<_>>();
        let worker = match (config.export.worker.enabled, sinks.is_empty()) {
            (false, _) => ExportWorkerPlan::Disabled {
                reason: "export worker disabled by config".to_string(),
            },
            (true, true) => ExportWorkerPlan::Disabled {
                reason: "export worker has no planned sinks".to_string(),
            },
            (true, false) => ExportWorkerPlan::from(config.export.worker.schedule),
        };
        Self { worker, sinks }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ExportWorkerPlan {
    Disabled {
        reason: String,
    },
    FixedIntervalBounded {
        interval_ms: u64,
        batches_per_sink_per_tick: u64,
        sink_timeout_ms: u64,
        failure_backoff: ExportFailureBackoffPlan,
    },
}

impl ExportWorkerPlan {
    pub fn disabled_reason(&self) -> Option<&str> {
        match self {
            Self::Disabled { reason } => Some(reason),
            Self::FixedIntervalBounded { .. } => None,
        }
    }
}

impl From<ExportWorkerScheduleConfig> for ExportWorkerPlan {
    fn from(value: ExportWorkerScheduleConfig) -> Self {
        match value {
            ExportWorkerScheduleConfig::FixedIntervalBounded {
                interval_ms,
                batches_per_sink_per_tick,
                sink_timeout_ms,
                failure_backoff,
            } => Self::FixedIntervalBounded {
                interval_ms,
                batches_per_sink_per_tick,
                sink_timeout_ms,
                failure_backoff: failure_backoff.into(),
            },
        }
    }
}

fn export_worker_default_sink_batches_per_tick(schedule: ExportWorkerScheduleConfig) -> u64 {
    match schedule {
        ExportWorkerScheduleConfig::FixedIntervalBounded {
            batches_per_sink_per_tick,
            ..
        } => batches_per_sink_per_tick.max(1),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportFailureBackoffPlan {
    pub initial_ms: u64,
    pub max_ms: u64,
    pub multiplier: u32,
}

impl Default for ExportFailureBackoffPlan {
    fn default() -> Self {
        ExportFailureBackoffConfig::default().into()
    }
}

impl From<ExportFailureBackoffConfig> for ExportFailureBackoffPlan {
    fn from(value: ExportFailureBackoffConfig) -> Self {
        Self {
            initial_ms: value.initial_ms,
            max_ms: value.max_ms,
            multiplier: value.multiplier,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "transport")]
pub enum ExportSinkPlan {
    Webhook(WebhookExportSinkPlan),
    File(FileExportSinkPlan),
    UnixHttp(UnixHttpExportSinkPlan),
}

impl ExportSinkPlan {
    pub fn id(&self) -> &str {
        match self {
            Self::Webhook(sink) => &sink.id,
            Self::File(sink) => &sink.id,
            Self::UnixHttp(sink) => &sink.id,
        }
    }

    pub fn worker(&self) -> &ExportSinkWorkerPlan {
        match self {
            Self::Webhook(sink) => &sink.worker,
            Self::File(sink) => &sink.worker,
            Self::UnixHttp(sink) => &sink.worker,
        }
    }
}

impl From<WebhookExportSinkPlan> for ExportSinkPlan {
    fn from(value: WebhookExportSinkPlan) -> Self {
        Self::Webhook(value)
    }
}

impl From<FileExportSinkPlan> for ExportSinkPlan {
    fn from(value: FileExportSinkPlan) -> Self {
        Self::File(value)
    }
}

impl From<UnixHttpExportSinkPlan> for ExportSinkPlan {
    fn from(value: UnixHttpExportSinkPlan) -> Self {
        Self::UnixHttp(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookExportSinkPlan {
    pub id: String,
    pub endpoint: String,
    pub codec: CompressionCodecName,
    pub headers: BTreeMap<String, String>,
    pub tls: ExportSinkTlsPlan,
    pub worker: ExportSinkWorkerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileExportSinkPlan {
    pub id: String,
    pub path: PathBuf,
    pub codec: CompressionCodecName,
    pub worker: ExportSinkWorkerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixHttpExportSinkPlan {
    pub id: String,
    pub socket_path: PathBuf,
    pub endpoint: String,
    pub codec: CompressionCodecName,
    pub headers: BTreeMap<String, String>,
    pub worker: ExportSinkWorkerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSinkWorkerPlan {
    pub batches_per_tick_override: Option<u64>,
    pub effective_batches_per_tick: NonZeroU64,
}

impl ExportSinkWorkerPlan {
    fn from_config(batches_per_tick_override: Option<u64>, default_batches_per_tick: u64) -> Self {
        let sanitized_override =
            batches_per_tick_override.filter(|batches_per_tick| *batches_per_tick > 0);
        let effective_batches_per_tick =
            NonZeroU64::new(sanitized_override.unwrap_or(default_batches_per_tick))
                .unwrap_or(NonZeroU64::MIN);
        Self {
            batches_per_tick_override: sanitized_override,
            effective_batches_per_tick,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSinkTlsPlan {
    pub trust_anchors: Vec<ExportTlsMaterialPlan>,
    pub client_certificates: Vec<ExportTlsMaterialPlan>,
    pub client_private_key: Option<ExportTlsMaterialPlan>,
}

impl ExportSinkTlsPlan {
    fn from_config(
        config: &ExporterTlsConfig,
        materials_by_id: &BTreeMap<&str, ExportTlsMaterialPlan>,
    ) -> Self {
        Self {
            trust_anchors: config
                .trust_anchor_refs
                .iter()
                .filter_map(|reference| materials_by_id.get(reference.as_str()))
                .cloned()
                .collect(),
            client_certificates: config
                .client_certificate_refs
                .iter()
                .filter_map(|reference| materials_by_id.get(reference.as_str()))
                .cloned()
                .collect(),
            client_private_key: config
                .client_private_key_ref
                .as_deref()
                .and_then(|reference| materials_by_id.get(reference))
                .cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use probe_config::{
        ExporterConfig, ExporterTransportConfig, ExporterWorkerConfig, TlsMaterialConfig,
        TlsMaterialKind,
    };

    use super::*;

    #[test]
    fn export_plan_disables_worker_without_sinks() {
        let plan = ExportPlan::resolve(&AgentConfig::default());

        assert_eq!(
            plan.worker,
            ExportWorkerPlan::Disabled {
                reason: "export worker has no planned sinks".to_string(),
            }
        );
        assert_eq!(plan.sinks, Vec::<ExportSinkPlan>::new());
    }

    #[test]
    fn export_plan_normalizes_worker_plan_and_sinks() {
        let mut config = AgentConfig::default();
        config.export.worker.schedule = ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 250,
            batches_per_sink_per_tick: 3,
            sink_timeout_ms: 2_000,
            failure_backoff: ExportFailureBackoffConfig {
                initial_ms: 5_000,
                max_ms: 20_000,
                multiplier: 3,
            },
        };
        config.exporters = vec![ExporterConfig {
            id: "primary".to_string(),
            transport: ExporterTransportConfig::Webhook {
                endpoint: "https://collector.example/batches".to_string(),
                headers: Default::default(),
                tls: ExporterTlsConfig {
                    trust_anchor_refs: vec!["collector-ca".to_string()],
                    client_certificate_refs: vec!["client-cert".to_string()],
                    client_private_key_ref: Some("client-key".to_string()),
                },
            },
            codec: CompressionCodecName::None,
            worker: ExporterWorkerConfig {
                batches_per_tick: Some(2),
            },
        }];
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("collector-ca".to_string()),
                kind: TlsMaterialKind::TrustAnchor,
                path: PathBuf::from("/etc/ssl/private/collector-ca.pem"),
            },
            TlsMaterialConfig {
                id: Some("client-cert".to_string()),
                kind: TlsMaterialKind::ClientCertificate,
                path: PathBuf::from("/etc/traffic-probe/client.pem"),
            },
            TlsMaterialConfig {
                id: Some("client-key".to_string()),
                kind: TlsMaterialKind::ClientPrivateKey,
                path: PathBuf::from("/etc/traffic-probe/client.key"),
            },
            TlsMaterialConfig {
                id: Some("keylog".to_string()),
                kind: TlsMaterialKind::KeyLogFile,
                path: PathBuf::from("/tmp/ssl-keylog.log"),
            },
        ];

        let plan = ExportPlan::resolve(&config);

        assert_eq!(
            plan.worker,
            ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 250,
                batches_per_sink_per_tick: 3,
                sink_timeout_ms: 2_000,
                failure_backoff: ExportFailureBackoffPlan {
                    initial_ms: 5_000,
                    max_ms: 20_000,
                    multiplier: 3,
                },
            }
        );
        assert_eq!(
            plan.sinks,
            vec![ExportSinkPlan::Webhook(WebhookExportSinkPlan {
                id: "primary".to_string(),
                endpoint: "https://collector.example/batches".to_string(),
                codec: CompressionCodecName::None,
                headers: Default::default(),
                tls: ExportSinkTlsPlan {
                    trust_anchors: vec![export_tls_material(
                        "collector-ca",
                        TlsMaterialKind::TrustAnchor,
                        "/etc/ssl/private/collector-ca.pem",
                    )],
                    client_certificates: vec![export_tls_material(
                        "client-cert",
                        TlsMaterialKind::ClientCertificate,
                        "/etc/traffic-probe/client.pem",
                    )],
                    client_private_key: Some(export_tls_material(
                        "client-key",
                        TlsMaterialKind::ClientPrivateKey,
                        "/etc/traffic-probe/client.key",
                    )),
                },
                worker: ExportSinkWorkerPlan {
                    batches_per_tick_override: Some(2),
                    effective_batches_per_tick: NonZeroU64::new(2).expect("positive batch quota"),
                },
            })]
        );
    }

    #[test]
    fn export_plan_builds_file_sink() {
        let config = AgentConfig {
            exporters: vec![ExporterConfig {
                id: "local-file".to_string(),
                transport: ExporterTransportConfig::File {
                    path: PathBuf::from("/var/lib/traffic-probe/export.jsonl"),
                },
                codec: CompressionCodecName::Gzip,
                worker: ExporterWorkerConfig {
                    batches_per_tick: Some(4),
                },
            }],
            ..AgentConfig::default()
        };

        let plan = ExportPlan::resolve(&config);

        assert_eq!(
            plan.sinks,
            vec![ExportSinkPlan::File(FileExportSinkPlan {
                id: "local-file".to_string(),
                path: PathBuf::from("/var/lib/traffic-probe/export.jsonl"),
                codec: CompressionCodecName::Gzip,
                worker: ExportSinkWorkerPlan {
                    batches_per_tick_override: Some(4),
                    effective_batches_per_tick: NonZeroU64::new(4).expect("positive batch quota"),
                },
            })]
        );
    }

    #[test]
    fn export_plan_builds_unix_http_sink() {
        let config = AgentConfig {
            exporters: vec![ExporterConfig {
                id: "local-sidecar".to_string(),
                transport: ExporterTransportConfig::UnixHttp {
                    socket_path: PathBuf::from("/run/probe/collector.sock"),
                    endpoint: "/probe/batches".to_string(),
                    headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
                },
                codec: CompressionCodecName::Deflate,
                worker: ExporterWorkerConfig {
                    batches_per_tick: Some(5),
                },
            }],
            ..AgentConfig::default()
        };

        let plan = ExportPlan::resolve(&config);

        assert_eq!(
            plan.sinks,
            vec![ExportSinkPlan::UnixHttp(UnixHttpExportSinkPlan {
                id: "local-sidecar".to_string(),
                socket_path: PathBuf::from("/run/probe/collector.sock"),
                endpoint: "/probe/batches".to_string(),
                codec: CompressionCodecName::Deflate,
                headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
                worker: ExportSinkWorkerPlan {
                    batches_per_tick_override: Some(5),
                    effective_batches_per_tick: NonZeroU64::new(5).expect("positive batch quota"),
                },
            })]
        );
    }

    fn export_tls_material(
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
}

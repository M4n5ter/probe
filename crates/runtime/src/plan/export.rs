use std::{collections::BTreeMap, num::NonZeroU64};

use probe_config::{
    AgentConfig, CompressionCodecName, ExportFailureBackoffConfig, ExportWorkerScheduleConfig,
    ExporterTlsConfig, ExporterTransport,
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
            .map(|exporter| ExportSinkPlan {
                id: exporter.id.clone(),
                transport: exporter.transport,
                endpoint: exporter.endpoint.clone(),
                codec: exporter.codec,
                headers: exporter.headers.clone(),
                tls: ExportSinkTlsPlan::from_config(&exporter.tls, &materials_by_id),
                worker: ExportSinkWorkerPlan::from_config(
                    exporter.worker.batches_per_tick,
                    default_sink_batches_per_tick,
                ),
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
pub struct ExportSinkPlan {
    pub id: String,
    pub transport: ExporterTransport,
    pub endpoint: String,
    pub codec: CompressionCodecName,
    pub headers: BTreeMap<String, String>,
    pub tls: ExportSinkTlsPlan,
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
    use std::path::PathBuf;

    use probe_config::{ExporterConfig, ExporterWorkerConfig, TlsMaterialConfig, TlsMaterialKind};

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
            transport: ExporterTransport::Webhook,
            endpoint: "https://collector.example/batches".to_string(),
            codec: CompressionCodecName::None,
            headers: Default::default(),
            tls: ExporterTlsConfig {
                trust_anchor_refs: vec!["collector-ca".to_string()],
                client_certificate_refs: vec!["client-cert".to_string()],
                client_private_key_ref: Some("client-key".to_string()),
            },
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
                path: PathBuf::from("/etc/sssa/client.pem"),
            },
            TlsMaterialConfig {
                id: Some("client-key".to_string()),
                kind: TlsMaterialKind::ClientPrivateKey,
                path: PathBuf::from("/etc/sssa/client.key"),
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
            vec![ExportSinkPlan {
                id: "primary".to_string(),
                transport: ExporterTransport::Webhook,
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
                        "/etc/sssa/client.pem",
                    )],
                    client_private_key: Some(export_tls_material(
                        "client-key",
                        TlsMaterialKind::ClientPrivateKey,
                        "/etc/sssa/client.key",
                    )),
                },
                worker: ExportSinkWorkerPlan {
                    batches_per_tick_override: Some(2),
                    effective_batches_per_tick: NonZeroU64::new(2).expect("positive batch quota"),
                },
            }]
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

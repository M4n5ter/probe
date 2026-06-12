use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const DEFAULT_EXPORT_WORKER_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_EXPORT_BATCHES_PER_SINK_PER_TICK: u64 = 1;
pub const DEFAULT_EXPORT_SINK_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_EXPORT_FAILURE_BACKOFF_MS: u64 = 30_000;

fn default_export_worker_interval_ms() -> u64 {
    DEFAULT_EXPORT_WORKER_INTERVAL_MS
}

fn default_export_batches_per_sink_per_tick() -> u64 {
    DEFAULT_EXPORT_BATCHES_PER_SINK_PER_TICK
}

fn default_export_sink_timeout_ms() -> u64 {
    DEFAULT_EXPORT_SINK_TIMEOUT_MS
}

fn default_export_failure_backoff_ms() -> u64 {
    DEFAULT_EXPORT_FAILURE_BACKOFF_MS
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExportRuntimeConfig {
    pub worker: ExportWorkerRuntimeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExportWorkerRuntimeConfig {
    pub enabled: bool,
    pub schedule: ExportWorkerScheduleConfig,
}

impl Default for ExportWorkerRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            schedule: ExportWorkerScheduleConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", deny_unknown_fields)]
pub enum ExportWorkerScheduleConfig {
    FixedIntervalBounded {
        #[serde(default = "default_export_worker_interval_ms")]
        interval_ms: u64,
        #[serde(default = "default_export_batches_per_sink_per_tick")]
        batches_per_sink_per_tick: u64,
        #[serde(default = "default_export_sink_timeout_ms")]
        sink_timeout_ms: u64,
        #[serde(default = "default_export_failure_backoff_ms")]
        failure_backoff_ms: u64,
    },
}

impl Default for ExportWorkerScheduleConfig {
    fn default() -> Self {
        Self::FixedIntervalBounded {
            interval_ms: DEFAULT_EXPORT_WORKER_INTERVAL_MS,
            batches_per_sink_per_tick: DEFAULT_EXPORT_BATCHES_PER_SINK_PER_TICK,
            sink_timeout_ms: DEFAULT_EXPORT_SINK_TIMEOUT_MS,
            failure_backoff_ms: DEFAULT_EXPORT_FAILURE_BACKOFF_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExporterConfig {
    pub id: String,
    pub transport: ExporterTransport,
    pub endpoint: String,
    pub codec: CompressionCodecName,
    pub headers: BTreeMap<String, String>,
    pub tls: ExporterTlsConfig,
    pub worker: ExporterWorkerConfig,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: String::new(),
            codec: CompressionCodecName::Zstd,
            headers: BTreeMap::new(),
            tls: ExporterTlsConfig::default(),
            worker: ExporterWorkerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExporterWorkerConfig {
    pub batches_per_tick: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExporterTlsConfig {
    pub trust_anchor_refs: Vec<String>,
    pub client_certificate_refs: Vec<String>,
    pub client_private_key_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExporterTransport {
    Webhook,
    Grpc,
    Kafka,
    Otlp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodecName {
    None,
    Zstd,
    Gzip,
    Deflate,
}

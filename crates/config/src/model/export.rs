use std::{collections::BTreeMap, path::PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};

pub const DEFAULT_EXPORT_WORKER_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_EXPORT_BATCHES_PER_SINK_PER_TICK: u64 = 1;
pub const DEFAULT_EXPORT_SINK_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_EXPORT_FAILURE_BACKOFF_INITIAL_MS: u64 = 30_000;
pub const DEFAULT_EXPORT_FAILURE_BACKOFF_MAX_MS: u64 = 300_000;
pub const DEFAULT_EXPORT_FAILURE_BACKOFF_MULTIPLIER: u32 = 2;

fn default_export_worker_interval_ms() -> u64 {
    DEFAULT_EXPORT_WORKER_INTERVAL_MS
}

fn default_export_batches_per_sink_per_tick() -> u64 {
    DEFAULT_EXPORT_BATCHES_PER_SINK_PER_TICK
}

fn default_export_sink_timeout_ms() -> u64 {
    DEFAULT_EXPORT_SINK_TIMEOUT_MS
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
        #[serde(default)]
        failure_backoff: ExportFailureBackoffConfig,
    },
}

impl Default for ExportWorkerScheduleConfig {
    fn default() -> Self {
        Self::FixedIntervalBounded {
            interval_ms: DEFAULT_EXPORT_WORKER_INTERVAL_MS,
            batches_per_sink_per_tick: DEFAULT_EXPORT_BATCHES_PER_SINK_PER_TICK,
            sink_timeout_ms: DEFAULT_EXPORT_SINK_TIMEOUT_MS,
            failure_backoff: ExportFailureBackoffConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExportFailureBackoffConfig {
    pub initial_ms: u64,
    pub max_ms: u64,
    pub multiplier: u32,
}

impl Default for ExportFailureBackoffConfig {
    fn default() -> Self {
        Self {
            initial_ms: DEFAULT_EXPORT_FAILURE_BACKOFF_INITIAL_MS,
            max_ms: DEFAULT_EXPORT_FAILURE_BACKOFF_MAX_MS,
            multiplier: DEFAULT_EXPORT_FAILURE_BACKOFF_MULTIPLIER,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExporterConfig {
    pub id: String,
    pub transport: ExporterTransportConfig,
    pub codec: CompressionCodecName,
    pub worker: ExporterWorkerConfig,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            transport: ExporterTransportConfig::default(),
            codec: CompressionCodecName::Zstd,
            worker: ExporterWorkerConfig::default(),
        }
    }
}

impl Serialize for ExporterConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.transport {
            ExporterTransportConfig::Webhook {
                endpoint,
                headers,
                tls,
            } => {
                let mut state = serializer.serialize_struct("ExporterConfig", 7)?;
                state.serialize_field("id", &self.id)?;
                state.serialize_field("transport", &ExporterTransportKind::Webhook)?;
                state.serialize_field("endpoint", endpoint)?;
                state.serialize_field("codec", &self.codec)?;
                state.serialize_field("headers", headers)?;
                state.serialize_field("tls", tls)?;
                state.serialize_field("worker", &self.worker)?;
                state.end()
            }
            ExporterTransportConfig::File { path } => {
                let mut state = serializer.serialize_struct("ExporterConfig", 5)?;
                state.serialize_field("id", &self.id)?;
                state.serialize_field("transport", &ExporterTransportKind::File)?;
                state.serialize_field("path", path)?;
                state.serialize_field("codec", &self.codec)?;
                state.serialize_field("worker", &self.worker)?;
                state.end()
            }
            ExporterTransportConfig::UnixHttp {
                socket_path,
                endpoint,
                headers,
            } => {
                let mut state = serializer.serialize_struct("ExporterConfig", 7)?;
                state.serialize_field("id", &self.id)?;
                state.serialize_field("transport", &ExporterTransportKind::UnixHttp)?;
                state.serialize_field("socket_path", socket_path)?;
                state.serialize_field("endpoint", endpoint)?;
                state.serialize_field("codec", &self.codec)?;
                state.serialize_field("headers", headers)?;
                state.serialize_field("worker", &self.worker)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ExporterConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ExporterWireConfig::deserialize(deserializer)?;
        let transport = match wire.transport {
            ExporterTransportKind::Webhook => {
                if wire.path.is_some() {
                    return Err(de::Error::custom(
                        "field `path` is only valid for file exporters",
                    ));
                }
                if wire.socket_path.is_some() {
                    return Err(de::Error::custom(
                        "field `socket_path` is only valid for unix_http exporters",
                    ));
                }
                ExporterTransportConfig::Webhook {
                    endpoint: wire.endpoint.unwrap_or_default(),
                    headers: wire.headers.unwrap_or_default(),
                    tls: wire.tls.unwrap_or_default(),
                }
            }
            ExporterTransportKind::File => {
                if wire.endpoint.is_some() {
                    return Err(de::Error::custom(
                        "field `endpoint` is only valid for webhook exporters",
                    ));
                }
                if wire.headers.is_some() {
                    return Err(de::Error::custom(
                        "field `headers` is only valid for webhook exporters",
                    ));
                }
                if wire.tls.is_some() {
                    return Err(de::Error::custom(
                        "field `tls` is only valid for webhook exporters",
                    ));
                }
                if wire.socket_path.is_some() {
                    return Err(de::Error::custom(
                        "field `socket_path` is only valid for unix_http exporters",
                    ));
                }
                ExporterTransportConfig::File {
                    path: wire.path.unwrap_or_default(),
                }
            }
            ExporterTransportKind::UnixHttp => {
                if wire.path.is_some() {
                    return Err(de::Error::custom(
                        "field `path` is only valid for file exporters",
                    ));
                }
                if wire.tls.is_some() {
                    return Err(de::Error::custom(
                        "field `tls` is only valid for webhook exporters",
                    ));
                }
                ExporterTransportConfig::UnixHttp {
                    socket_path: wire.socket_path.unwrap_or_default(),
                    endpoint: wire.endpoint.unwrap_or_default(),
                    headers: wire.headers.unwrap_or_default(),
                }
            }
        };

        Ok(Self {
            id: wire.id,
            transport,
            codec: wire.codec,
            worker: wire.worker,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ExporterWireConfig {
    id: String,
    transport: ExporterTransportKind,
    endpoint: Option<String>,
    headers: Option<BTreeMap<String, String>>,
    tls: Option<ExporterTlsConfig>,
    path: Option<PathBuf>,
    socket_path: Option<PathBuf>,
    codec: CompressionCodecName,
    worker: ExporterWorkerConfig,
}

impl Default for ExporterWireConfig {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            transport: ExporterTransportKind::Webhook,
            endpoint: None,
            headers: None,
            tls: None,
            path: None,
            socket_path: None,
            codec: CompressionCodecName::default(),
            worker: ExporterWorkerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExporterTransportKind {
    #[default]
    Webhook,
    File,
    UnixHttp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExporterTransportConfig {
    Webhook {
        endpoint: String,
        headers: BTreeMap<String, String>,
        tls: ExporterTlsConfig,
    },
    File {
        path: PathBuf,
    },
    UnixHttp {
        socket_path: PathBuf,
        endpoint: String,
        headers: BTreeMap<String, String>,
    },
}

impl Default for ExporterTransportConfig {
    fn default() -> Self {
        Self::Webhook {
            endpoint: String::new(),
            headers: BTreeMap::new(),
            tls: ExporterTlsConfig::default(),
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodecName {
    None,
    #[default]
    Zstd,
    Gzip,
    Deflate,
}

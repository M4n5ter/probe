mod error;
mod model;
mod tls;
mod validation;

pub use error::{ConfigError, ConfigValidationError, ConfigViolation};
pub use model::{
    AdminConfig, AgentConfig, CaptureBackend, CaptureConfig, CaptureSelection,
    CompressionCodecName, ConnectionEnforcementBackendConfig,
    DEFAULT_EXPORT_BATCHES_PER_SINK_PER_TICK, DEFAULT_EXPORT_FAILURE_BACKOFF_INITIAL_MS,
    DEFAULT_EXPORT_FAILURE_BACKOFF_MAX_MS, DEFAULT_EXPORT_FAILURE_BACKOFF_MULTIPLIER,
    DEFAULT_EXPORT_RETENTION_PRUNE_BATCH_LIMIT, DEFAULT_EXPORT_RETENTION_SWEEP_INTERVAL_MS,
    DEFAULT_EXPORT_SINK_TIMEOUT_MS, DEFAULT_EXPORT_WORKER_INTERVAL_MS,
    DEFAULT_INGRESS_RETENTION_PRUNE_BATCH_LIMIT, DEFAULT_INGRESS_RETENTION_SWEEP_INTERVAL_MS,
    DEFAULT_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS, EbpfCaptureConfig, EnforcementConfig,
    EnforcementPolicyConfig, EnforcementPolicyManifest, EnforcementPolicySourceConfig,
    ExportFailureBackoffConfig, ExportQueueRetentionConfig, ExportRuntimeConfig,
    ExportWorkerRuntimeConfig, ExportWorkerScheduleConfig, ExporterConfig, ExporterTlsConfig,
    ExporterTransport, ExporterWorkerConfig, IngressJournalRetentionConfig, LibpcapCaptureConfig,
    LiveCaptureBackend, MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS, PlaintextFeedCaptureConfig,
    PlaintextTlsConfig, PolicyConfig, StorageConfig, StorageRetentionConfig, TlsConfig,
    TlsMaterialConfig, TlsMaterialKind, TlsPlaintextDecryptHintConfig,
    TlsPlaintextInstrumentationConfig,
};

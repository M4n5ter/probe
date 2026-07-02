use thiserror::Error;

use crate::{
    capture_event_feed::CaptureEventFeedLoadError, check::CheckError,
    configured_enforcement::ConfiguredEnforcementError, configured_policy::ConfiguredPolicyError,
    enforcement_reload::EnforcementReloadError,
    enforcement_reload_watcher::EnforcementReloadWatcherError, export::ExportDrainError,
    plaintext_feed::PlaintextFeedLoadError, policy_reload_watcher::PolicyReloadWatcherError,
    tls_plaintext::TlsDecryptHintError, transparent_interception::TransparentInterceptionError,
};

#[derive(Debug, Error)]
pub(crate) enum AgentError {
    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to signal readiness through {target}: {source}")]
    SignalReadiness {
        target: String,
        source: std::io::Error,
    },
    #[error("invalid readiness socket in {name}: {value}")]
    InvalidReadinessSocket { name: &'static str, value: String },
    #[error("invalid replay policy file: {0}")]
    ReplayPolicyFile(#[from] probe_io::BoundedFileError),
    #[error("config error: {0}")]
    Config(#[from] probe_config::ConfigError),
    #[error("artifact error: {0}")]
    Artifact(#[from] crate::artifacts::ArtifactError),
    #[error("runtime error: {0}")]
    Runtime(#[from] runtime::RuntimeError),
    #[error("failed to serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("pipeline error: {0}")]
    Pipeline(#[from] pipeline::PipelineError),
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("policy error: {0}")]
    Policy(#[from] policy::PolicyError),
    #[error("{0}")]
    ConfiguredPolicy(#[from] ConfiguredPolicyError),
    #[error("enforcement error: {0}")]
    Enforcement(#[from] enforcement::EnforcementError),
    #[error("{0}")]
    ConfiguredEnforcement(#[source] Box<ConfiguredEnforcementError>),
    #[error("{0}")]
    TransparentInterception(#[from] TransparentInterceptionError),
    #[error("proto error: {0}")]
    Proto(#[from] proto::ProtoError),
    #[error("export error: {0}")]
    Export(#[from] ExportDrainError),
    #[error("capture provider error: {0}")]
    Capture(#[from] capture::CaptureError),
    #[error("capture task failed to join: {0}")]
    CaptureTaskJoin(String),
    #[error("attribution error: {0}")]
    Attribution(#[from] attribution::AttributionError),
    #[error("plaintext feed error: {0}")]
    PlaintextFeed(#[from] PlaintextFeedLoadError),
    #[error("capture event feed error: {0}")]
    CaptureEventFeed(#[from] CaptureEventFeedLoadError),
    #[error("TLS decrypt hint error: {0}")]
    TlsDecryptHints(#[from] TlsDecryptHintError),
    #[error("L7 MITM runtime error: {0}")]
    L7MitmRuntime(String),
    #[error("MITM proxy error: {0}")]
    MitmProxy(#[from] mitm_proxy::MitmProxyError),
    #[error("policy reload watcher error: {0}")]
    PolicyReloadWatcher(#[from] PolicyReloadWatcherError),
    #[error("enforcement policy reload watcher error: {0}")]
    EnforcementReloadWatcher(#[from] EnforcementReloadWatcherError),
    #[error("enforcement policy reload poller error: {0}")]
    EnforcementReloadPoller(#[from] EnforcementReloadError),
    #[error("admin error: {0}")]
    Admin(#[from] crate::admin::AdminError),
    #[error("admin client error: {0}")]
    AdminClient(#[from] crate::admin::AdminClientError),
    #[error("admin command failed: {0}")]
    AdminCommand(String),
    #[error("TUI error: {0}")]
    Tui(#[from] crate::tui::TuiError),
    #[error("{0}")]
    Check(#[source] Box<CheckError>),
    #[error("unsupported run config: {0}")]
    UnsupportedRunConfig(String),
}

impl From<CheckError> for AgentError {
    fn from(error: CheckError) -> Self {
        Self::Check(Box::new(error))
    }
}

impl From<ConfiguredEnforcementError> for AgentError {
    fn from(error: ConfiguredEnforcementError) -> Self {
        Self::ConfiguredEnforcement(Box::new(error))
    }
}

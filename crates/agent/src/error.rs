use thiserror::Error;

use crate::{
    check::CheckError, configured_enforcement::ConfiguredEnforcementError,
    configured_policy::ConfiguredPolicyError, export::ExportDrainError,
    plaintext_feed::PlaintextFeedLoadError, transparent_interception::TransparentInterceptionError,
};

#[derive(Debug, Error)]
pub(crate) enum AgentError {
    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid replay policy file: {0}")]
    ReplayPolicyFile(#[from] probe_io::BoundedFileError),
    #[error("config error: {0}")]
    Config(#[from] probe_config::ConfigError),
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
    ConfiguredEnforcement(#[from] ConfiguredEnforcementError),
    #[error("{0}")]
    TransparentInterception(#[from] TransparentInterceptionError),
    #[error("proto error: {0}")]
    Proto(#[from] proto::ProtoError),
    #[error("export error: {0}")]
    Export(#[from] ExportDrainError),
    #[error("capture provider error: {0}")]
    Capture(#[from] capture::CaptureError),
    #[error("attribution error: {0}")]
    Attribution(#[from] attribution::AttributionError),
    #[error("plaintext feed error: {0}")]
    PlaintextFeed(#[from] PlaintextFeedLoadError),
    #[error("admin error: {0}")]
    Admin(#[from] crate::admin::AdminError),
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

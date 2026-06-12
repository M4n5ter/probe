use probe_config::{ConfigError, ConfigValidationError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("runtime config validation failed: {0}")]
    Validation(#[from] ConfigValidationError),
    #[error("no live capture provider is available: {reason}")]
    NoLiveCapture { reason: String },
}

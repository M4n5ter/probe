use std::{io, net::AddrParseError};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MitmProxyError {
    #[error("invalid MITM proxy config: {0}")]
    InvalidConfig(String),
    #[error("MITM proxy I/O failed while trying to {action}: {source}")]
    Io {
        action: &'static str,
        source: io::Error,
    },
    #[error("MITM proxy address parse failed: {0}")]
    AddressParse(#[from] AddrParseError),
    #[error("MITM proxy JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid MITM proxy HTTP message: {0}")]
    Http(String),
    #[error("MITM proxy worker thread panicked")]
    ThreadPanic,
}

pub(crate) fn io_error(action: &'static str) -> impl FnOnce(io::Error) -> MitmProxyError {
    move |source| MitmProxyError::Io { action, source }
}

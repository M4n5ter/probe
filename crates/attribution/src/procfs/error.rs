use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttributionError {
    #[error("failed to read {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("failed to read symlink {path}: {source}")]
    ReadLink { path: String, source: io::Error },
    #[error("invalid proc stat for pid {pid}: {reason}")]
    InvalidStat { pid: u32, reason: String },
    #[error("invalid proc status for pid {pid}: {reason}")]
    InvalidStatus { pid: u32, reason: String },
    #[error("invalid proc net tcp entry in {path}: {reason}")]
    InvalidNetTcp { path: String, reason: String },
    #[error("incomplete procfs socket owner scan: {reason}")]
    IncompleteSocketOwnerScan { reason: String },
}

impl Clone for AttributionError {
    fn clone(&self) -> Self {
        match self {
            Self::Read { path, source } => Self::Read {
                path: path.clone(),
                source: clone_io_error(source),
            },
            Self::ReadLink { path, source } => Self::ReadLink {
                path: path.clone(),
                source: clone_io_error(source),
            },
            Self::InvalidStat { pid, reason } => Self::InvalidStat {
                pid: *pid,
                reason: reason.clone(),
            },
            Self::InvalidStatus { pid, reason } => Self::InvalidStatus {
                pid: *pid,
                reason: reason.clone(),
            },
            Self::InvalidNetTcp { path, reason } => Self::InvalidNetTcp {
                path: path.clone(),
                reason: reason.clone(),
            },
            Self::IncompleteSocketOwnerScan { reason } => Self::IncompleteSocketOwnerScan {
                reason: reason.clone(),
            },
        }
    }
}

fn clone_io_error(source: &io::Error) -> io::Error {
    io::Error::new(source.kind(), source.to_string())
}

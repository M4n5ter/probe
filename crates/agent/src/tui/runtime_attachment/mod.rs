use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeAttachment {
    Detached {
        message: String,
    },
    Starting {
        message: String,
    },
    Existing {
        socket_path: PathBuf,
    },
    Managed {
        socket_path: PathBuf,
        pid: Option<u32>,
        log_path: PathBuf,
    },
    Lost {
        message: String,
    },
    LostManaged {
        message: String,
        log_path: PathBuf,
    },
}

impl Default for RuntimeAttachment {
    fn default() -> Self {
        Self::detached()
    }
}

impl RuntimeAttachment {
    pub(crate) fn detached() -> Self {
        Self::Detached {
            message: "No agent runtime attached".to_string(),
        }
    }

    pub(crate) fn starting() -> Self {
        Self::Starting {
            message: "Starting or attaching TUI managed agent".to_string(),
        }
    }

    pub(crate) fn existing(socket_path: PathBuf) -> Self {
        Self::Existing { socket_path }
    }

    pub(crate) fn managed(socket_path: PathBuf, pid: Option<u32>, log_path: PathBuf) -> Self {
        Self::Managed {
            socket_path,
            pid,
            log_path,
        }
    }

    pub(crate) fn lost(message: impl Into<String>) -> Self {
        Self::Lost {
            message: message.into(),
        }
    }

    pub(crate) fn lost_managed(message: impl Into<String>, log_path: PathBuf) -> Self {
        Self::LostManaged {
            message: message.into(),
            log_path,
        }
    }

    pub(crate) fn is_starting(&self) -> bool {
        matches!(self, Self::Starting { .. })
    }

    pub(crate) fn active_socket_path(&self) -> Option<&Path> {
        match self {
            Self::Existing { socket_path } | Self::Managed { socket_path, .. } => Some(socket_path),
            Self::Detached { .. }
            | Self::Starting { .. }
            | Self::Lost { .. }
            | Self::LostManaged { .. } => None,
        }
    }

    pub(crate) fn managed_log_path(&self) -> Option<&Path> {
        match self {
            Self::Managed { log_path, .. } | Self::LostManaged { log_path, .. } => Some(log_path),
            Self::Detached { .. }
            | Self::Starting { .. }
            | Self::Existing { .. }
            | Self::Lost { .. } => None,
        }
    }

    pub(crate) fn status_text(&self) -> String {
        match self {
            Self::Detached { message }
            | Self::Starting { message }
            | Self::Lost { message }
            | Self::LostManaged { message, .. } => message.clone(),
            Self::Existing { socket_path } => {
                format!("Using running agent at {}", socket_path.display())
            }
            Self::Managed {
                socket_path,
                pid,
                log_path,
            } => match pid {
                Some(pid) => format!(
                    "TUI managed agent pid {pid} at {}; log {}",
                    socket_path.display(),
                    log_path.display()
                ),
                None => format!(
                    "TUI managed agent at {}; log {}",
                    socket_path.display(),
                    log_path.display()
                ),
            },
        }
    }
}

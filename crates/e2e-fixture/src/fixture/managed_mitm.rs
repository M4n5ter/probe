use std::{
    error::Error,
    fmt,
    fs::OpenOptions,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use e2e_support::mitm_bridge;

use super::loopback::{LoopbackError, bind_loopback_listener};

const SCENARIO: &str = "managed-mitm-backend";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedMitmBackendConfig {
    pub listen_addr: SocketAddr,
    pub pid_file: PathBuf,
    pub bridge_feed_file: PathBuf,
}

#[derive(Debug)]
pub(crate) enum ManagedMitmBackendError {
    Invalid(String),
    Loopback(LoopbackError),
    Feed(Box<dyn Error>),
    Io {
        action: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for ManagedMitmBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "{reason}"),
            Self::Loopback(error) => write!(formatter, "{error}"),
            Self::Feed(error) => write!(formatter, "failed to write capture event feed: {error}"),
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
        }
    }
}

impl Error for ManagedMitmBackendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Loopback(error) => Some(error),
            Self::Feed(error) => Some(error.as_ref()),
            Self::Io { source, .. } => Some(source),
        }
    }
}

impl From<LoopbackError> for ManagedMitmBackendError {
    fn from(error: LoopbackError) -> Self {
        Self::Loopback(error)
    }
}

pub(crate) fn run_managed_mitm_backend(
    config: ManagedMitmBackendConfig,
) -> Result<(), ManagedMitmBackendError> {
    validate_listen_addr(config.listen_addr)?;
    mitm_bridge::create_empty_capture_event_feed(&config.bridge_feed_file)
        .map_err(|source| io_error("create managed MITM bridge feed", source))?;
    let listener = bind_loopback_listener(config.listen_addr.port())?;
    write_pid_file(&config.pid_file)?;

    let mut feed_appended = false;
    loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                drop(stream);
                if !feed_appended {
                    mitm_bridge::append_capture_event_feed(&config.bridge_feed_file)
                        .map_err(ManagedMitmBackendError::Feed)?;
                    feed_appended = true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(io_error("accept managed MITM readiness connection", source));
            }
        }
    }
}

fn write_pid_file(path: &Path) -> Result<(), ManagedMitmBackendError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create managed MITM pid file", source))?;
    file.write_all(std::process::id().to_string().as_bytes())
        .map_err(|source| io_error("write managed MITM pid file", source))
}

fn validate_listen_addr(listen_addr: SocketAddr) -> Result<(), ManagedMitmBackendError> {
    match listen_addr {
        SocketAddr::V4(addr) if *addr.ip() == Ipv4Addr::LOCALHOST && addr.port() != 0 => Ok(()),
        _ => Err(ManagedMitmBackendError::Invalid(format!(
            "{SCENARIO} requires a fixed 127.0.0.1 listen address, got {listen_addr}"
        ))),
    }
}

fn io_error(action: &'static str, source: io::Error) -> ManagedMitmBackendError {
    ManagedMitmBackendError::Io { action, source }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs};

    use super::*;

    #[test]
    fn pid_file_creation_does_not_truncate_existing_feed_file() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let shared_path = root.path().join("managed-mitm");
        fs::write(&shared_path, "feed")?;

        let error = write_pid_file(&shared_path)
            .expect_err("pid file creation must reject an existing feed path");

        assert!(error.to_string().contains("create managed MITM pid file"));
        assert_eq!(fs::read_to_string(shared_path)?, "feed");
        Ok(())
    }
}

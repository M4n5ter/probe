use std::{error::Error, fmt, path::PathBuf};

use crate::dynssl::{DynSslClient, DynSslError};

use super::{args, coordination, http};

const SCENARIO: &str = "dynssl-client";

pub(crate) fn run(
    args: impl IntoIterator<Item = String>,
) -> Result<DynSslFixtureReport, DynSslFixtureError> {
    let args = args::parse(args).map_err(DynSslFixtureError::Usage)?;
    let process_nonce = coordination::coordination_nonce();
    coordination::publish_ready_file(
        &args.process_ready_file,
        format!("pid={}\nstart_nonce={process_nonce}\n", std::process::id()).as_bytes(),
    )
    .map_err(|source| io_error("publish process ready file", source))?;
    coordination::wait_for_start_file(&args.load_start_file, &process_nonce)
        .map_err(|source| io_error("wait for libssl load start file", source))?;

    let client = DynSslClient::load(&args.libssl_path)?;
    let exchange_nonce = coordination::coordination_nonce();
    coordination::publish_ready_file(
        &args.library_ready_file,
        format!(
            "pid={}\nlibssl_path={}\nstart_nonce={exchange_nonce}\n",
            std::process::id(),
            client.libssl_path().display()
        )
        .as_bytes(),
    )
    .map_err(|source| io_error("publish library ready file", source))?;
    coordination::wait_for_start_file(&args.exchange_start_file, &exchange_nonce)
        .map_err(|source| io_error("wait for exchange start file", source))?;

    let request = http::request(args.request_index, args.request_body_bytes);
    let exchange = client.exchange(args.server_addr, &request, args.post_write_delay)?;
    Ok(DynSslFixtureReport {
        pid: std::process::id(),
        libssl_path: exchange.libssl_path,
        request_bytes: exchange.request_bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynSslFixtureReport {
    pid: u32,
    libssl_path: PathBuf,
    request_bytes: usize,
}

impl fmt::Display for DynSslFixtureReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "scenario={SCENARIO}")?;
        writeln!(formatter, "pid={}", self.pid)?;
        writeln!(formatter, "libssl_path={}", self.libssl_path.display())?;
        writeln!(formatter, "request_bytes={}", self.request_bytes)?;
        writeln!(formatter, "result=ok")
    }
}

#[derive(Debug)]
pub(crate) enum DynSslFixtureError {
    Usage(String),
    DynamicSsl(DynSslError),
    Io {
        action: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for DynSslFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::DynamicSsl(error) => write!(formatter, "{error}"),
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
        }
    }
}

impl Error for DynSslFixtureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Usage(_) => None,
            Self::DynamicSsl(error) => Some(error),
            Self::Io { source, .. } => Some(source),
        }
    }
}

impl From<DynSslError> for DynSslFixtureError {
    fn from(error: DynSslError) -> Self {
        Self::DynamicSsl(error)
    }
}

fn io_error(action: &'static str, source: std::io::Error) -> DynSslFixtureError {
    DynSslFixtureError::Io { action, source }
}

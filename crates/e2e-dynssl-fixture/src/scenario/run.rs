use std::{error::Error, fmt, path::Path};

use crate::dynssl::{DynSslClient, DynSslError};

use super::{
    args::{self, LibsslPhaseArgs, ScenarioArgs},
    coordination, http,
};

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
    let mut exchanges = Vec::with_capacity(args.phases.len());
    let mut previous_client = None;
    let mut next_load_nonce = process_nonce;
    for (phase_index, phase) in args.phases.iter().enumerate() {
        let phase = run_phase(&args, phase, phase_index, previous_client, &next_load_nonce)?;
        exchanges.push(phase.exchange);
        previous_client = Some(phase.client);
        next_load_nonce = phase.next_load_nonce;
    }
    drop(previous_client);

    Ok(DynSslFixtureReport {
        pid: std::process::id(),
        exchanges,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynSslFixtureReport {
    pid: u32,
    exchanges: Vec<DynSslFixtureExchangeReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynSslFixtureExchangeReport {
    libssl_path: std::path::PathBuf,
    request_bytes: usize,
}

impl fmt::Display for DynSslFixtureReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "scenario={SCENARIO}")?;
        writeln!(formatter, "pid={}", self.pid)?;
        for (index, exchange) in self.exchanges.iter().enumerate() {
            writeln!(
                formatter,
                "exchange.{index}.libssl_path={}",
                exchange.libssl_path.display()
            )?;
            writeln!(
                formatter,
                "exchange.{index}.request_bytes={}",
                exchange.request_bytes
            )?;
        }
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

struct CompletedLibsslPhase {
    client: DynSslClient,
    exchange: DynSslFixtureExchangeReport,
    next_load_nonce: String,
}

fn run_phase(
    args: &ScenarioArgs,
    phase: &LibsslPhaseArgs,
    phase_index: usize,
    previous_client: Option<DynSslClient>,
    load_nonce: &str,
) -> Result<CompletedLibsslPhase, DynSslFixtureError> {
    coordination::wait_for_start_file(&phase.load_start_file, load_nonce)
        .map_err(|source| io_error("wait for libssl phase load start file", source))?;
    drop(previous_client);
    let client = DynSslClient::load(&phase.libssl_path)?;
    let exchange_nonce = coordination::coordination_nonce();
    publish_library_ready_file(&phase.library_ready_file, &client, &exchange_nonce)?;
    coordination::wait_for_start_file(&phase.exchange_start_file, &exchange_nonce)
        .map_err(|source| io_error("wait for libssl phase exchange start file", source))?;
    let exchange = run_exchange(args, &client, args.request_index + phase_index)?;
    Ok(CompletedLibsslPhase {
        client,
        exchange,
        next_load_nonce: exchange_nonce,
    })
}

fn publish_library_ready_file(
    path: &Path,
    client: &DynSslClient,
    exchange_nonce: &str,
) -> Result<(), DynSslFixtureError> {
    coordination::publish_ready_file(
        path,
        format!(
            "pid={}\nlibssl_path={}\nstart_nonce={exchange_nonce}\n",
            std::process::id(),
            client.libssl_path().display()
        )
        .as_bytes(),
    )
    .map_err(|source| io_error("publish library ready file", source))
}

fn run_exchange(
    args: &ScenarioArgs,
    client: &DynSslClient,
    request_index: usize,
) -> Result<DynSslFixtureExchangeReport, DynSslFixtureError> {
    let request = http::request(request_index, args.request_body_bytes);
    let exchange = client.exchange(args.server_addr, &request, args.post_write_delay)?;
    Ok(DynSslFixtureExchangeReport {
        libssl_path: exchange.libssl_path,
        request_bytes: exchange.request_bytes,
    })
}

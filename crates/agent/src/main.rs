use std::{
    collections::HashSet,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use capture::ReplayProvider;
use clap::{Parser, Subcommand, ValueEnum};
use exporter::{CompressionCodec, ReliableExporter, WebhookExporter};
use parsers::Http1Parser;
use pipeline::CapturePipeline;
use policy::{POLICY_HOOKS, PolicyManifest, PolicyRuntime};
use probe_config::AgentConfig;
use probe_core::{
    AddressPort, Direction, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, Timestamp,
    TransportProtocol,
};
use proto::{BatchEnvelope, EVENT_ENVELOPE_JSON_SCHEMA};
use runtime::{ProviderRegistry, RuntimePlan};
use storage::{DurableSpool, FjallSpool};
use thiserror::Error;

#[derive(Debug, Error)]
enum AgentError {
    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
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
    #[error("proto error: {0}")]
    Proto(#[from] proto::ProtoError),
    #[error("export error: {0}")]
    Export(#[from] exporter::ExportError),
    #[error("unsupported spooled payload schema at sequence {sequence}: {schema}")]
    UnsupportedSpoolPayloadSchema { sequence: u64, schema: String },
}

#[derive(Debug, Parser)]
#[command(name = "sssa-probe")]
#[command(about = "Process-level traffic probe agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    Capabilities,
    Replay {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        spool: PathBuf,
        #[arg(long, default_value = "outbound")]
        direction: CliDirection,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        webhook: Option<String>,
        #[arg(long, default_value = "zstd")]
        codec: CliCompressionCodec,
        #[arg(long, default_value = "replay-agent")]
        agent_id: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliDirection {
    Inbound,
    Outbound,
}

impl From<CliDirection> for Direction {
    fn from(value: CliDirection) -> Self {
        match value {
            CliDirection::Inbound => Self::Inbound,
            CliDirection::Outbound => Self::Outbound,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliCompressionCodec {
    None,
    Zstd,
    Gzip,
    Deflate,
}

impl From<CliCompressionCodec> for CompressionCodec {
    fn from(value: CliCompressionCodec) -> Self {
        match value {
            CliCompressionCodec::None => Self::None,
            CliCompressionCodec::Zstd => Self::Zstd,
            CliCompressionCodec::Gzip => Self::Gzip,
            CliCompressionCodec::Deflate => Self::Deflate,
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), AgentError> {
    match cli.command {
        Command::Run { config } => {
            let plan = read_runtime_plan_or_default(config.as_ref())?;
            plan.require_live_capture()?;
            println!(
                "agent {} planned config {} capture {:?} selected {:?}",
                plan.config.agent_id,
                plan.config.config_version,
                plan.capture.mode,
                plan.capture.selected_backend
            );
        }
        Command::Check { config } => {
            let plan = read_runtime_plan(&config)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        Command::Capabilities => {
            let matrix = ProviderRegistry::discover().capability_matrix();
            println!("{}", serde_json::to_string_pretty(&matrix)?);
        }
        Command::Replay {
            input,
            spool,
            direction,
            policy,
            webhook,
            codec,
            agent_id,
        } => {
            replay(
                input,
                spool,
                direction.into(),
                policy,
                webhook,
                codec.into(),
                agent_id,
            )
            .await?;
        }
    }
    Ok(())
}

fn read_runtime_plan_or_default(path: Option<&PathBuf>) -> Result<RuntimePlan, AgentError> {
    let config = read_config_or_default(path)?;
    build_runtime_plan(config)
}

fn read_runtime_plan(path: &PathBuf) -> Result<RuntimePlan, AgentError> {
    let config = read_config(path)?;
    build_runtime_plan(config)
}

fn build_runtime_plan(config: AgentConfig) -> Result<RuntimePlan, AgentError> {
    let registry = ProviderRegistry::discover();
    RuntimePlan::build(config, &registry).map_err(AgentError::Runtime)
}

fn read_config_or_default(path: Option<&PathBuf>) -> Result<AgentConfig, AgentError> {
    match path {
        Some(path) => read_config(path),
        None => Ok(AgentConfig::default()),
    }
}

fn read_config(path: &PathBuf) -> Result<AgentConfig, AgentError> {
    let content = std::fs::read_to_string(path).map_err(|source| AgentError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    AgentConfig::from_toml_str(&content).map_err(AgentError::Config)
}

async fn replay(
    input: PathBuf,
    spool: PathBuf,
    direction: Direction,
    policy: Option<PathBuf>,
    webhook: Option<String>,
    codec: CompressionCodec,
    agent_id: String,
) -> Result<(), AgentError> {
    let bytes = std::fs::read(&input).map_err(|source| AgentError::ReadFile {
        path: input.display().to_string(),
        source,
    })?;
    let policy = policy.as_ref().map(read_policy).transpose()?;
    let mut http_parser = Http1Parser::default();
    let spool = FjallSpool::open(spool)?;
    let flow = replay_flow();
    let mut replay_provider =
        ReplayProvider::new(flow.clone(), direction, bytes, current_timestamp(1));
    let mut pipeline = CapturePipeline::new(&spool, &mut http_parser, policy.as_ref(), "replay");
    let summary = pipeline.run_provider(&mut replay_provider)?;
    println!(
        "replay pipeline journaled {} capture chunks and stored {} export events",
        summary.ingress_chunks, summary.export_events
    );

    if let Some(endpoint) = webhook {
        export_once(&spool, &agent_id, endpoint, codec).await?;
    }

    Ok(())
}

fn read_policy(path: &PathBuf) -> Result<PolicyRuntime, AgentError> {
    let source = std::fs::read_to_string(path).map_err(|source| AgentError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("replay-policy")
        .to_string();
    PolicyRuntime::from_source(
        PolicyManifest {
            id,
            version: "replay".to_string(),
            hooks: POLICY_HOOKS
                .iter()
                .map(|hook| (*hook).to_string())
                .collect(),
        },
        &source,
    )
    .map_err(AgentError::Policy)
}

async fn export_once(
    spool: &impl DurableSpool,
    agent_id: &str,
    endpoint: String,
    codec: CompressionCodec,
) -> Result<(), AgentError> {
    let sink = "replay-webhook";
    let events = spool.read_export_batch(sink, 1024)?;
    let Some(last_sequence) = events.last().map(|event| event.sequence) else {
        println!("no spooled events to export");
        return Ok(());
    };
    for event in &events {
        if event.payload.schema() != EVENT_ENVELOPE_JSON_SCHEMA {
            return Err(AgentError::UnsupportedSpoolPayloadSchema {
                sequence: event.sequence,
                schema: event.payload.schema().to_string(),
            });
        }
    }

    let batch = BatchEnvelope::from_json_payloads(
        format!("{agent_id}:{last_sequence}"),
        agent_id,
        codec.wire_name(),
        events
            .iter()
            .map(|event| (event.sequence, event.payload.bytes())),
    )?;
    let exporter = WebhookExporter::new(endpoint, codec);
    let ack = exporter.send(&batch).await?;
    let committed_cursor = ack
        .committed_cursor
        .or_else(|| contiguous_cursor_from_event_ids(&batch, &ack.acked_event_ids));
    if let Some(cursor) = committed_cursor {
        spool.ack_export(sink, cursor)?;
        println!(
            "exported batch {} and committed cursor {cursor}",
            ack.batch_id
        );
    } else {
        println!(
            "exported batch {} without committed cursor; spool cursor unchanged",
            ack.batch_id
        );
    }
    Ok(())
}

fn contiguous_cursor_from_event_ids(
    batch: &BatchEnvelope,
    acked_event_ids: &[String],
) -> Option<u64> {
    let acked_event_ids = acked_event_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut cursor = None;
    for event in &batch.events {
        if acked_event_ids.contains(event.event_id.as_str()) {
            cursor = Some(event.sequence);
        } else {
            break;
        }
    }
    cursor
}

fn current_timestamp(monotonic_ns: u64) -> Timestamp {
    Timestamp {
        monotonic_ns,
        wall_time_unix_ns: wall_time_unix_ns(),
    }
}

fn wall_time_unix_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as i128)
}

fn replay_flow() -> FlowContext {
    let process = synthetic_replay_process();
    let local = AddressPort {
        address: "127.0.0.1".to_string(),
        port: 50_000,
    };
    let remote = AddressPort {
        address: "127.0.0.1".to_string(),
        port: 80,
    };
    FlowContext {
        id: FlowIdentity::stable(
            &process.identity,
            &local,
            &remote,
            TransportProtocol::Tcp,
            0,
            None,
        ),
        process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: 0,
        socket_cookie: None,
        attribution_confidence: 0,
    }
}

fn synthetic_replay_process() -> ProcessContext {
    let identity = ProcessIdentity {
        pid: 0,
        tgid: 0,
        start_time_ticks: 0,
        boot_id: "replay".to_string(),
        exe_path: "replay".to_string(),
        cmdline_hash: "replay".to_string(),
        uid: 0,
        gid: 0,
        cgroup: None,
        systemd_service: None,
        container_id: None,
        runtime_hint: None,
    };
    ProcessContext {
        identity,
        name: "replay".to_string(),
        cmdline: vec!["replay".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use proto::{BATCH_SCHEMA_VERSION, EventRecord, PayloadFormat};

    use super::*;

    #[test]
    fn acked_event_ids_advance_only_contiguous_cursor_prefix() {
        let batch = batch_with_events(["one", "two", "three"]);

        assert_eq!(
            contiguous_cursor_from_event_ids(&batch, &["one".to_string(), "two".to_string()]),
            Some(2)
        );
        assert_eq!(
            contiguous_cursor_from_event_ids(&batch, &["two".to_string(), "three".to_string()]),
            None
        );
    }

    #[test]
    fn replay_flow_uses_synthetic_process_identity() {
        let flow = replay_flow();

        assert_eq!(flow.process.identity.pid, 0);
        assert_eq!(flow.process.identity.tgid, 0);
        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(flow.process.identity.boot_id, "replay");
    }

    fn batch_with_events<const N: usize>(event_ids: [&str; N]) -> BatchEnvelope {
        BatchEnvelope {
            batch_id: "batch-1".to_string(),
            agent_id: "agent-1".to_string(),
            codec: "none".to_string(),
            events: event_ids
                .into_iter()
                .enumerate()
                .map(|(index, event_id)| EventRecord {
                    event_id: event_id.to_string(),
                    sequence: (index + 1) as u64,
                    payload_format: PayloadFormat::Json as i32,
                    payload: Vec::new(),
                    payload_schema: "test.schema".to_string(),
                })
                .collect(),
            schema_version: BATCH_SCHEMA_VERSION,
        }
    }
}

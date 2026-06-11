use std::{
    collections::HashSet,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use attribution::ProcfsSocketResolver;
use capture::{
    CaptureError, CaptureProvider, LibpcapConfig, LibpcapProvider, ProcessResolver, ReplayProvider,
    ResolvedProcess,
};
use clap::{Parser, Subcommand, ValueEnum};
use enforcement::ScopedEnforcementPlanner;
use exporter::{CompressionCodec, ReliableExporter, WebhookExporter};
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelineRunOptions};
use policy::{POLICY_HOOKS, PolicyManifest, PolicyRuntime};
use probe_config::{
    AgentConfig, CaptureBackend, CompressionCodecName, ExporterConfig, ExporterTransport,
};
use probe_core::{
    AddressPort, CapabilityKind, Direction, EnforcementMode, FlowContext, FlowIdentity,
    ProcessContext, ProcessIdentity, RuntimeMode, TcpConnection, Timestamp, TransportProtocol,
};
use proto::{BatchEnvelope, EVENT_ENVELOPE_JSON_SCHEMA};
use runtime::{
    CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimeError, RuntimePlan,
};
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
    #[error("enforcement error: {0}")]
    Enforcement(#[from] enforcement::EnforcementError),
    #[error("proto error: {0}")]
    Proto(#[from] proto::ProtoError),
    #[error("export error: {0}")]
    Export(#[from] exporter::ExportError),
    #[error("capture provider error: {0}")]
    Capture(#[from] CaptureError),
    #[error("unsupported run config: {0}")]
    UnsupportedRunConfig(String),
    #[error("one or more exporters failed: {failures}")]
    ExportDrainFailed { failures: String },
    #[error("unsupported spooled payload schema at sequence {sequence}: {schema}")]
    UnsupportedSpoolPayloadSchema { sequence: u64, schema: String },
}

const EXPORT_BATCH_LIMIT: usize = 1024;

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
        #[arg(long)]
        max_events: Option<u64>,
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
        #[arg(long, default_value = "audit-only")]
        enforcement_mode: CliEnforcementMode,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliEnforcementMode {
    Disabled,
    AuditOnly,
    DryRun,
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

impl From<CliEnforcementMode> for EnforcementMode {
    fn from(value: CliEnforcementMode) -> Self {
        match value {
            CliEnforcementMode::Disabled => Self::Disabled,
            CliEnforcementMode::AuditOnly => Self::AuditOnly,
            CliEnforcementMode::DryRun => Self::DryRun,
        }
    }
}

struct ReplayCommand {
    input: PathBuf,
    spool: PathBuf,
    direction: Direction,
    policy: Option<PathBuf>,
    webhook: Option<String>,
    codec: CompressionCodec,
    agent_id: String,
    enforcement_mode: EnforcementMode,
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
        Command::Run { config, max_events } => {
            let plan = read_runtime_plan_or_default(config.as_ref())?;
            let mut provider = build_live_capture_provider(&plan)?;
            let mut parser_factory = Http1ParserFactory::default();
            let spool = FjallSpool::open(&plan.config.storage.path)?;
            let policy = read_configured_policy(&plan.config)?;
            let mut enforcement_planner = build_configured_enforcement_planner(&plan.config)?;
            let mut pipeline = CapturePipeline::new(
                &spool,
                &mut parser_factory,
                policy.as_ref(),
                plan.config.config_version.clone(),
            );
            if let Some(enforcement_planner) = enforcement_planner.as_mut() {
                pipeline = pipeline.with_enforcement_planner(enforcement_planner);
            }
            println!(
                "agent {} running config {} capture {:?} selected {:?}",
                plan.config.agent_id,
                plan.config.config_version,
                plan.capture.mode,
                plan.capture.selected_backend
            );
            let summary = pipeline
                .run_provider_with_options(provider.as_mut(), PipelineRunOptions { max_events })?;
            println!(
                "agent stopped after reading {} capture events, journaling {} capture chunks, and storing {} export events",
                summary.capture_events, summary.ingress_chunks, summary.export_events
            );
            export_configured_sinks(&spool, &plan.config).await?;
        }
        Command::Check { config } => {
            let plan = read_runtime_plan(&config)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        Command::Capabilities => {
            let matrix = default_provider_registry(&AgentConfig::default()).capability_matrix();
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
            enforcement_mode,
        } => {
            replay(ReplayCommand {
                input,
                spool,
                direction: direction.into(),
                policy,
                webhook,
                codec: codec.into(),
                agent_id,
                enforcement_mode: enforcement_mode.into(),
            })
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
    let registry = default_provider_registry(&config);
    RuntimePlan::build(config, &registry).map_err(AgentError::Runtime)
}

fn default_provider_registry(config: &AgentConfig) -> ProviderRegistry {
    ProviderRegistry::with_default_platform(default_capture_provider_descriptors(config))
}

fn default_capture_provider_descriptors(config: &AgentConfig) -> Vec<CaptureProviderDescriptor> {
    vec![
        CaptureProviderDescriptor::available(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
        ),
        CaptureProviderDescriptor::unavailable(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Unimplemented,
            "provider not implemented in this build",
        ),
        libpcap_provider_descriptor(&libpcap_config_from_agent(config)),
    ]
}

fn libpcap_provider_descriptor(config: &LibpcapConfig) -> CaptureProviderDescriptor {
    match LibpcapProvider::probe(config) {
        Ok(()) => CaptureProviderDescriptor::available(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
        ),
        Err(error) => CaptureProviderDescriptor::unavailable(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
            error.to_string(),
        ),
    }
}

fn build_live_capture_provider(plan: &RuntimePlan) -> Result<Box<dyn CaptureProvider>, AgentError> {
    plan.require_live_capture()?;
    match plan.capture.selected_backend {
        Some(CaptureBackend::Libpcap) => Ok(Box::new(LibpcapProvider::open_with_process_resolver(
            libpcap_config_from_agent(&plan.config),
            procfs_tcp_process_resolver_for_plan(plan),
        )?)),
        Some(backend) => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
            reason: format!("{backend:?} capture provider is selected but has no agent builder"),
        })),
        None => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
            reason: plan
                .capture
                .reason
                .clone()
                .unwrap_or_else(|| "capture plan did not select a live backend".to_string()),
        })),
    }
}

fn procfs_tcp_process_resolver_for_plan(plan: &RuntimePlan) -> Option<Box<dyn ProcessResolver>> {
    (plan
        .capabilities
        .mode(CapabilityKind::ProcfsSocketAttribution)
        != RuntimeMode::Unavailable)
        .then(|| Box::<ProcfsTcpProcessResolver>::default() as Box<dyn ProcessResolver>)
}

fn libpcap_config_from_agent(config: &AgentConfig) -> LibpcapConfig {
    LibpcapConfig {
        interface: config.capture.libpcap.interface.clone(),
        bpf_filter: config.capture.libpcap.bpf_filter.clone(),
        snaplen: config.capture.libpcap.snaplen,
        promisc: config.capture.libpcap.promisc,
        immediate_mode: config.capture.libpcap.immediate_mode,
        read_timeout_ms: config.capture.libpcap.read_timeout_ms,
        buffer_size: config.capture.libpcap.buffer_size,
    }
}

struct ProcfsTcpProcessResolver {
    resolver: ProcfsSocketResolver,
}

impl Default for ProcfsTcpProcessResolver {
    fn default() -> Self {
        Self {
            resolver: ProcfsSocketResolver::new(),
        }
    }
}

impl ProcessResolver for ProcfsTcpProcessResolver {
    fn resolve_tcp_process(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<ResolvedProcess>, CaptureError> {
        self.resolver
            .resolve_tcp_connection(connection)
            .map(|resolved| {
                resolved.map(|resolved| ResolvedProcess {
                    process: resolved.process,
                    confidence: resolved.confidence,
                })
            })
            .map_err(|error| CaptureError::provider("procfs_socket_attribution", error.to_string()))
    }

    fn invalidate_cached_resolution(&mut self) {
        self.resolver.invalidate_snapshot();
    }
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

async fn replay(command: ReplayCommand) -> Result<(), AgentError> {
    let bytes = std::fs::read(&command.input).map_err(|source| AgentError::ReadFile {
        path: command.input.display().to_string(),
        source,
    })?;
    let policy = command.policy.as_ref().map(read_policy).transpose()?;
    let mut parser_factory = Http1ParserFactory::default();
    let spool = FjallSpool::open(command.spool)?;
    let flow = replay_flow();
    let mut replay_provider =
        ReplayProvider::new(flow.clone(), command.direction, bytes, current_timestamp(1));
    let mut enforcement_planner = ScopedEnforcementPlanner::new(command.enforcement_mode, None)?;
    let mut pipeline = CapturePipeline::new(&spool, &mut parser_factory, policy.as_ref(), "replay")
        .with_enforcement_planner(&mut enforcement_planner);
    let summary = pipeline.run_provider(&mut replay_provider)?;
    println!(
        "replay pipeline journaled {} capture chunks and stored {} export events",
        summary.ingress_chunks, summary.export_events
    );

    if let Some(endpoint) = command.webhook {
        drain_webhook_sink(
            &spool,
            &command.agent_id,
            WebhookExportTarget::replay(endpoint, command.codec),
        )
        .await?;
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
                .map(|hook| hook.as_str().to_string())
                .collect(),
        },
        &source,
    )
    .map_err(AgentError::Policy)
}

fn read_configured_policy(config: &AgentConfig) -> Result<Option<PolicyRuntime>, AgentError> {
    let enabled = config
        .policies
        .iter()
        .filter(|policy| policy.enabled)
        .collect::<Vec<_>>();
    match enabled.as_slice() {
        [] => Ok(None),
        [policy] => read_policy(&policy.path).map(Some),
        _ => Err(AgentError::UnsupportedRunConfig(
            "live run currently supports at most one enabled policy bundle".to_string(),
        )),
    }
}

fn build_configured_enforcement_planner(
    config: &AgentConfig,
) -> Result<Option<ScopedEnforcementPlanner>, AgentError> {
    ScopedEnforcementPlanner::new(
        config.enforcement.mode,
        config.enforcement.selector.as_ref(),
    )
    .map(Some)
    .map_err(AgentError::Enforcement)
}

async fn export_configured_sinks(
    spool: &impl DurableSpool,
    config: &AgentConfig,
) -> Result<(), AgentError> {
    let mut failures = Vec::new();
    for exporter in &config.exporters {
        let result = match webhook_export_target_from_config(exporter) {
            Ok(target) => drain_webhook_sink(spool, &config.agent_id, target).await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            eprintln!("exporter sink {} failed: {error}", exporter.id);
            failures.push(format!("{}: {error}", exporter.id));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(AgentError::ExportDrainFailed {
            failures: failures.join("; "),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookExportTarget {
    sink: String,
    endpoint: String,
    codec: CompressionCodec,
    headers: Vec<(String, String)>,
}

impl WebhookExportTarget {
    fn replay(endpoint: String, codec: CompressionCodec) -> Self {
        Self {
            sink: "replay-webhook".to_string(),
            endpoint,
            codec,
            headers: Vec::new(),
        }
    }
}

fn webhook_export_target_from_config(
    exporter: &ExporterConfig,
) -> Result<WebhookExportTarget, AgentError> {
    match exporter.transport {
        ExporterTransport::Webhook => Ok(WebhookExportTarget {
            sink: exporter.id.clone(),
            endpoint: exporter.endpoint.clone(),
            codec: compression_codec_from_config(exporter.codec),
            headers: exporter
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        }),
        ExporterTransport::Grpc | ExporterTransport::Kafka | ExporterTransport::Otlp => {
            Err(AgentError::UnsupportedRunConfig(format!(
                "{:?} exporter is reserved but not implemented",
                exporter.transport
            )))
        }
    }
}

fn compression_codec_from_config(codec: CompressionCodecName) -> CompressionCodec {
    match codec {
        CompressionCodecName::None => CompressionCodec::None,
        CompressionCodecName::Zstd => CompressionCodec::Zstd,
        CompressionCodecName::Gzip => CompressionCodec::Gzip,
        CompressionCodecName::Deflate => CompressionCodec::Deflate,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportDrainSummary {
    batches: u64,
    committed_cursor: Option<u64>,
}

async fn drain_webhook_sink(
    spool: &impl DurableSpool,
    agent_id: &str,
    target: WebhookExportTarget,
) -> Result<(), AgentError> {
    let WebhookExportTarget {
        sink,
        endpoint,
        codec,
        headers,
    } = target;
    let exporter = WebhookExporter::with_headers(endpoint, codec, headers)?;
    drain_export_sink(spool, agent_id, &sink, codec, &exporter)
        .await
        .map(|_| ())
}

async fn drain_export_sink(
    spool: &impl DurableSpool,
    agent_id: &str,
    sink: &str,
    codec: CompressionCodec,
    exporter: &(impl ReliableExporter + ?Sized),
) -> Result<ExportDrainSummary, AgentError> {
    let mut summary = ExportDrainSummary {
        batches: 0,
        committed_cursor: None,
    };

    loop {
        let events = spool.read_export_batch(sink, EXPORT_BATCH_LIMIT)?;
        let Some(last_sequence) = events.last().map(|event| event.sequence) else {
            if summary.batches == 0 {
                println!("no spooled events to export for sink {sink}");
            }
            return Ok(summary);
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
            format!("{agent_id}:{sink}:{last_sequence}"),
            agent_id,
            codec.wire_name(),
            events
                .iter()
                .map(|event| (event.sequence, event.payload.bytes())),
        )?;
        let ack = exporter.send(&batch).await?;
        summary.batches = summary.batches.saturating_add(1);
        let committed_cursor = ack
            .committed_cursor
            .or_else(|| contiguous_cursor_from_event_ids(&batch, &ack.acked_event_ids));
        let Some(cursor) = committed_cursor else {
            println!(
                "exported sink {sink} batch {} without committed cursor; spool cursor unchanged",
                ack.batch_id
            );
            return Ok(summary);
        };

        spool.ack_export(sink, cursor)?;
        summary.committed_cursor = Some(cursor);
        println!(
            "exported sink {sink} batch {} and committed cursor {cursor}",
            ack.batch_id
        );
    }
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
    use std::{
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::TcpListener,
        path::PathBuf,
        sync::{Arc, Mutex},
        thread,
    };

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

    #[tokio::test]
    async fn configured_exporters_use_independent_sinks_and_attempt_all()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-exporters");
        let spool = FjallSpool::open(&temp)?;
        append_export_event(&spool, 1)?;
        let failing = TestWebhookServer::spawn(false)?;
        let successful = TestWebhookServer::spawn(true)?;
        let config = AgentConfig {
            agent_id: "agent-1".to_string(),
            exporters: vec![
                ExporterConfig {
                    id: "failing".to_string(),
                    transport: ExporterTransport::Webhook,
                    endpoint: failing.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::new(),
                },
                ExporterConfig {
                    id: "successful".to_string(),
                    transport: ExporterTransport::Webhook,
                    endpoint: successful.endpoint(),
                    codec: CompressionCodecName::None,
                    headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
                },
            ],
            ..AgentConfig::default()
        };
        config.validate_basic()?;

        let result = export_configured_sinks(&spool, &config).await;

        assert!(matches!(result, Err(AgentError::ExportDrainFailed { .. })));
        assert_eq!(spool.export_cursor("failing")?, 0);
        assert_eq!(spool.export_cursor("successful")?, 1);

        let request = successful.join()?;
        assert_eq!(
            request_header(&request, "x-probe-node").as_deref(),
            Some("node-a")
        );
        assert_eq!(
            request_header(&request, "x-sssa-codec").as_deref(),
            Some("none")
        );
        assert_eq!(
            request_header(&request, "idempotency-key").as_deref(),
            Some("agent-1:successful:1")
        );
        let _ = failing.join()?;
        fs::remove_dir_all(temp)?;
        Ok(())
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

    fn append_export_event(
        spool: &FjallSpool,
        monotonic_ns: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let envelope = probe_core::EventEnvelope::new(
            current_timestamp(monotonic_ns),
            replay_flow(),
            probe_core::CaptureSource::Replay,
            "test",
            probe_core::EventKind::ConnectionOpened,
        );
        let payload = serde_json::to_vec(&envelope)?;
        spool.append_export(storage::SpoolPayload::new(
            EVENT_ENVELOPE_JSON_SCHEMA,
            payload,
        ))?;
        Ok(())
    }

    fn test_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("sssa-probe-{name}-{}-{nanos}", std::process::id()))
    }

    struct TestWebhookServer {
        endpoint: String,
        request: Arc<Mutex<Option<String>>>,
        handle: thread::JoinHandle<Result<(), String>>,
    }

    impl TestWebhookServer {
        fn spawn(accepted: bool) -> Result<Self, Box<dyn std::error::Error>> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let endpoint = format!("http://{}/batches", listener.local_addr()?);
            let request = Arc::new(Mutex::new(None));
            let request_for_thread = Arc::clone(&request);
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0; 1024];
                    let read = stream
                        .read(&mut buffer)
                        .map_err(|error| error.to_string())?;
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..read]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request_text = String::from_utf8_lossy(&bytes).into_owned();
                let batch_id = request_header(&request_text, "idempotency-key")
                    .unwrap_or_else(|| "missing-batch".to_string());
                let body = serde_json::json!({
                    "batch_id": batch_id,
                    "accepted": accepted,
                    "acked_cursor": if accepted { Some(1_u64) } else { None },
                    "acked_event_ids": [],
                    "retryable_event_ids": [],
                    "reason": if accepted { None::<String> } else { Some("failed".to_string()) },
                })
                .to_string();
                let status = if accepted {
                    "200 OK"
                } else {
                    "500 Internal Server Error"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .map_err(|error| error.to_string())?;
                *request_for_thread
                    .lock()
                    .map_err(|_| "request lock poisoned".to_string())? = Some(request_text);
                Ok(())
            });
            Ok(Self {
                endpoint,
                request,
                handle,
            })
        }

        fn endpoint(&self) -> String {
            self.endpoint.clone()
        }

        fn join(self) -> Result<String, Box<dyn std::error::Error>> {
            self.handle
                .join()
                .map_err(|_| "webhook server thread panicked")?
                .map_err(|error| format!("webhook server failed: {error}"))?;
            self.request
                .lock()
                .map_err(|_| "request lock poisoned")?
                .clone()
                .ok_or_else(|| "webhook server did not capture a request".into())
        }
    }

    fn request_header(request: &str, name: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }
}

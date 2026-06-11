use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

mod admin;
mod check;
mod configured_enforcement;
mod configured_policy;
mod export;
mod plaintext_feed;
mod status;

use admin::{AdminServerConfig, spawn_admin_server};
use attribution::ProcfsSocketResolver;
use capture::{
    CaptureError, CaptureProvider, LibpcapConfig, LibpcapProvider, ProcessResolver, ReplayProvider,
    ResolvedProcess,
};
use check::build_check_report;
use clap::{Parser, Subcommand, ValueEnum};
use configured_enforcement::build_configured_enforcement;
use configured_policy::{ConfiguredPolicyError, load_configured_policy};
use enforcement::ScopedEnforcementPlanner;
use export::{ExportWorkerConfig, drain_planned_sinks, drain_replay_webhook, spawn_export_worker};
use exporter::CompressionCodec;
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelinePolicy, PipelineRunOptions};
use plaintext_feed::load_plaintext_feed_provider;
use policy::{POLICY_HOOKS, PolicyManifest, PolicyRuntime};
use probe_config::{AgentConfig, CaptureBackend};
use probe_core::{
    AddressPort, CapabilityKind, Direction, EnforcementMode, FlowContext, FlowIdentity,
    ProcessContext, ProcessIdentity, RuntimeMode, TcpConnection, Timestamp, TransportProtocol,
};
use runtime::{
    CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimeError, RuntimePlan,
};
use status::{build_status_snapshot, collect_spool_status};
use storage::FjallSpool;
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
    #[error("{0}")]
    ConfiguredPolicy(#[from] ConfiguredPolicyError),
    #[error("enforcement error: {0}")]
    Enforcement(#[from] enforcement::EnforcementError),
    #[error("proto error: {0}")]
    Proto(#[from] proto::ProtoError),
    #[error("export error: {0}")]
    Export(#[from] export::ExportDrainError),
    #[error("capture provider error: {0}")]
    Capture(#[from] CaptureError),
    #[error("plaintext feed error: {0}")]
    PlaintextFeed(#[from] plaintext_feed::PlaintextFeedLoadError),
    #[error("admin error: {0}")]
    Admin(#[from] admin::AdminError),
    #[error("{0}")]
    Check(#[from] check::CheckError),
    #[error("unsupported run config: {0}")]
    UnsupportedRunConfig(String),
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
        #[arg(long)]
        max_events: Option<u64>,
    },
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    Capabilities,
    Status {
        #[arg(long)]
        config: PathBuf,
    },
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
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), AgentError> {
    match cli.command {
        Command::Run { config, max_events } => {
            let plan = read_runtime_plan_or_default(config.as_ref())?;
            let mut provider = build_capture_provider(&plan)?;
            let mut parser_factory = Http1ParserFactory::default();
            let spool = Arc::new(FjallSpool::open(&plan.config.storage.path)?);
            let policy = load_configured_policy(&plan.config)?;
            let mut enforcement = build_configured_enforcement(&plan.config)?;
            let admin_server = admin_server_config_from_plan(&plan)
                .map(|config| {
                    spawn_admin_server(Arc::new(plan.clone()), Arc::clone(&spool), config)
                })
                .transpose()?;
            let export_worker = export_worker_config_from_plan(&plan)
                .map(|config| spawn_export_worker(Arc::clone(&spool), config));
            let mut pipeline = CapturePipeline::new(
                spool.as_ref(),
                &mut parser_factory,
                policy
                    .as_ref()
                    .map(|policy| PipelinePolicy::new(&policy.runtime, policy.selector.as_ref())),
                plan.config.config_version.clone(),
            );
            pipeline = pipeline.with_enforcement_planner(&mut enforcement.planner);
            println!(
                "agent {} running config {} capture {:?} selected {:?}",
                plan.config.agent_id,
                plan.config.config_version,
                plan.capture.mode,
                plan.capture.selected_backend
            );
            let summary_result = pipeline
                .run_provider_with_options(provider.as_mut(), PipelineRunOptions { max_events });
            if let Some(server) = admin_server {
                server.stop().await;
            }
            if let Some(worker) = export_worker {
                worker.stop().await;
            }
            let drain_result =
                drain_planned_sinks(spool.as_ref(), &plan.config.agent_id, &plan.export).await;
            let summary = match (summary_result, drain_result) {
                (Ok(summary), Ok(())) => summary,
                (Err(error), Ok(())) => return Err(error.into()),
                (Ok(_), Err(error)) => return Err(error.into()),
                (Err(pipeline_error), Err(export_error)) => {
                    eprintln!("tail export drain failed after pipeline error: {export_error}");
                    return Err(pipeline_error.into());
                }
            };
            println!(
                "agent stopped after reading {} capture events, journaling {} capture chunks, and storing {} export events",
                summary.capture_events, summary.ingress_chunks, summary.export_events
            );
        }
        Command::Check { config } => {
            let plan = read_runtime_plan(&config)?;
            let report = build_check_report(plan)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Capabilities => {
            let matrix = default_provider_registry(&AgentConfig::default()).capability_matrix();
            println!("{}", serde_json::to_string_pretty(&matrix)?);
        }
        Command::Status { config } => {
            let plan = read_runtime_plan(&config)?;
            let spool_status = collect_spool_status(&plan);
            let snapshot = build_status_snapshot(&plan, spool_status);
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
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

fn export_worker_config_from_plan(plan: &RuntimePlan) -> Option<ExportWorkerConfig> {
    ExportWorkerConfig::from_export_plan(plan.config.agent_id.clone(), &plan.export)
}

fn admin_server_config_from_plan(plan: &RuntimePlan) -> Option<AdminServerConfig> {
    plan.config.admin.enabled.then(|| AdminServerConfig {
        socket_path: plan.config.admin.socket_path.clone(),
    })
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
        CaptureProviderDescriptor::available(
            CaptureBackend::PlaintextFeed,
            CaptureProviderBuilder::PlaintextFeed,
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

fn build_capture_provider(plan: &RuntimePlan) -> Result<Box<dyn CaptureProvider>, AgentError> {
    match plan.capture.selected_backend {
        Some(CaptureBackend::PlaintextFeed) => build_plaintext_feed_provider(plan),
        _ => build_live_capture_provider(plan),
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

fn build_plaintext_feed_provider(
    plan: &RuntimePlan,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let path = plan
        .config
        .capture
        .plaintext_feed
        .path
        .as_ref()
        .ok_or_else(|| {
            AgentError::UnsupportedRunConfig(
                "plaintext_feed capture requires capture.plaintext_feed.path".to_string(),
            )
        })?;
    Ok(Box::new(load_plaintext_feed_provider(path)?))
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
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        policy.as_ref().map(PipelinePolicy::unscoped),
        "replay",
    )
    .with_enforcement_planner(&mut enforcement_planner);
    let summary = pipeline.run_provider(&mut replay_provider)?;
    println!(
        "replay pipeline journaled {} capture chunks and stored {} export events",
        summary.ingress_chunks, summary.export_events
    );

    if let Some(endpoint) = command.webhook {
        drain_replay_webhook(&spool, &command.agent_id, endpoint, command.codec).await?;
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
    use super::*;

    #[test]
    fn replay_flow_uses_synthetic_process_identity() {
        let flow = replay_flow();

        assert_eq!(flow.process.identity.pid, 0);
        assert_eq!(flow.process.identity.tgid, 0);
        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(flow.process.identity.boot_id, "replay");
    }
}

use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use capture::ReplayProvider;
use clap::{Parser, Subcommand, ValueEnum};
use enforcement::ScopedEnforcementPlanner;
use exporter::CompressionCodec;
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelinePolicy};
use policy::{POLICY_HOOKS, PolicyManifest, PolicyRuntime};
use probe_config::{AgentConfig, ConfigValidationError, default_admin_socket_path};
use probe_core::{
    AddressPort, Direction, EnforcementMode, FlowContext, FlowIdentity, ProcessContext,
    ProcessIdentity, Timestamp, TransportProtocol,
};
use probe_io::{BoundedFileError, BoundedFileErrorKind};
use runtime::EMBEDDED_PRODUCT_PROXY_COMMAND;
use serde::Serialize;
use storage::FjallSpool;

use crate::{
    artifacts::hydrate_runtime_artifact_paths,
    check::{build_check_report, build_invalid_config_report},
    error::AgentError,
    export::drain_replay_webhook,
    live_agent::{ReadinessSignal, RunOptions, run_live_agent},
    process_catalog::{ProcessCatalog, ProcessEntry},
    runtime_composition::{
        build_runtime_composition, build_runtime_composition_with_diagnostics,
        capability_matrix_for_config,
    },
    status::{build_status_snapshot, collect_spool_status},
    tui::{TuiOptions, TuiSnapshotOptions, TuiTab, run_tui, run_tui_snapshot},
};

use super::admin::{AdminCliCommand, run_admin_command};

const REPLAY_POLICY_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_MAIN_CONFIG_BYTES: u64 = 1024 * 1024;
const READY_SOCKET_ENV: &str = "TRAFFIC_PROBE_READY_SOCKET";
const CONTROL_READY_SOCKET_ENV: &str = "TRAFFIC_PROBE_CONTROL_READY_SOCKET";

#[derive(Debug, Parser)]
#[command(name = "traffic-probe")]
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
    Capabilities {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Status {
        #[arg(long)]
        config: PathBuf,
    },
    Processes {
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    Tui {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        snapshot: bool,
        #[arg(long, default_value_t = 120, requires = "snapshot")]
        width: u16,
        #[arg(long, default_value_t = 36, requires = "snapshot")]
        height: u16,
        #[arg(long, default_value = "traffic")]
        tab: CliTuiTab,
        #[arg(long, requires = "snapshot")]
        open_detail: bool,
        #[arg(long, default_value_t = 0, requires = "open_detail")]
        detail_scroll: usize,
    },
    Admin {
        #[arg(
            long,
            value_name = "SOCKET",
            help = "Admin Unix socket path; defaults to PROBE_HOME/run/admin.sock"
        )]
        socket: Option<PathBuf>,
        #[command(subcommand)]
        command: AdminCliCommand,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliTuiTab {
    Overview,
    Traffic,
    Capture,
    Processes,
    Runtime,
    Export,
    Storage,
    Enforcement,
    Tls,
}

impl From<CliTuiTab> for TuiTab {
    fn from(value: CliTuiTab) -> Self {
        match value {
            CliTuiTab::Overview => Self::Overview,
            CliTuiTab::Traffic => Self::Traffic,
            CliTuiTab::Capture => Self::Capture,
            CliTuiTab::Processes => Self::Processes,
            CliTuiTab::Runtime => Self::Runtime,
            CliTuiTab::Export => Self::Export,
            CliTuiTab::Storage => Self::Storage,
            CliTuiTab::Enforcement => Self::Enforcement,
            CliTuiTab::Tls => Self::Tls,
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

pub(crate) async fn run_from_env() -> Result<(), AgentError> {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    if args.is_empty() {
        args.push(OsString::from("traffic-probe"));
    }
    if let Some(proxy_args) = product_proxy_cli_args_from_agent_args(&args) {
        mitm_proxy::run_cli_from(proxy_args)?;
        return Ok(());
    }
    run(Cli::parse_from(args)).await
}

fn product_proxy_cli_args_from_agent_args(args: &[OsString]) -> Option<Vec<OsString>> {
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new(EMBEDDED_PRODUCT_PROXY_COMMAND)) {
        return None;
    }
    Some(
        std::iter::once(OsString::from("traffic-probe-mitm-proxy"))
            .chain(args.iter().skip(2).cloned())
            .collect(),
    )
}

async fn run(cli: Cli) -> Result<(), AgentError> {
    match cli.command {
        Command::Run { config, max_events } => {
            let config_path = config.clone();
            let agent_config = read_config_or_default(config.as_ref())?;
            run_live_agent(agent_config, run_options_from_env(max_events, config_path)?).await?;
        }
        Command::Check { config } => {
            run_check_command(&config).await?;
        }
        Command::Capabilities { config } => {
            let config = prepare_runtime_config(match config {
                Some(path) => read_config(&path)?,
                None => AgentConfig::default(),
            })?;
            let matrix = capability_matrix_for_config(&config);
            println!("{}", serde_json::to_string_pretty(&matrix)?);
        }
        Command::Status { config } => {
            let plan = read_runtime_composition(&config)?.into_plan();
            let spool_status = collect_spool_status(&plan);
            let snapshot = build_status_snapshot(&plan, spool_status);
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        Command::Processes { pid, query, limit } => {
            let snapshot = process_list_snapshot(
                &ProcessCatalog::from_proc_processes_only(),
                ProcessListFilter { pid, query, limit },
            );
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        Command::Tui {
            config,
            snapshot,
            width,
            height,
            tab,
            open_detail,
            detail_scroll,
        } => {
            if snapshot {
                run_tui_snapshot(TuiSnapshotOptions {
                    config,
                    width,
                    height,
                    tab: tab.into(),
                    open_detail,
                    detail_scroll,
                })
                .await?;
            } else {
                run_tui(TuiOptions {
                    config,
                    tab: tab.into(),
                })
                .await?;
            }
        }
        Command::Admin { socket, command } => {
            let socket = resolve_admin_socket(socket);
            run_admin_command(&socket, command).await?;
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

#[derive(Debug, Clone)]
struct ProcessListFilter {
    pid: Option<u32>,
    query: Option<String>,
    limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProcessListSnapshot {
    entries: Vec<ProcessListEntry>,
    total: usize,
    matched: usize,
    returned: usize,
    truncated: bool,
    diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProcessListEntry {
    pid: u32,
    process_key: String,
    observation_key: String,
    name: String,
    exe_path: Option<String>,
    argv: Vec<String>,
    uid: u32,
    gid: u32,
    cgroup_path: Option<String>,
}

fn process_list_snapshot(
    catalog: &ProcessCatalog,
    filter: ProcessListFilter,
) -> ProcessListSnapshot {
    let query = filter.query.as_deref().unwrap_or_default();
    let matched = catalog
        .entries()
        .iter()
        .filter(|entry| filter.pid.is_none_or(|pid| entry.pid == pid))
        .filter(|entry| entry.matches_query(query))
        .collect::<Vec<_>>();
    let entries = matched
        .iter()
        .take(filter.limit)
        .map(|entry| process_list_entry(entry))
        .collect::<Vec<_>>();
    ProcessListSnapshot {
        total: catalog.entries().len(),
        matched: matched.len(),
        returned: entries.len(),
        truncated: matched.len() > entries.len(),
        diagnostics: catalog.diagnostics().to_vec(),
        entries,
    }
}

fn process_list_entry(entry: &ProcessEntry) -> ProcessListEntry {
    ProcessListEntry {
        pid: entry.pid,
        process_key: entry.process_key.clone(),
        observation_key: entry.observation_key(),
        name: entry.name.clone(),
        exe_path: entry
            .exe_path
            .as_ref()
            .map(|path| path.display().to_string()),
        argv: entry.argv.clone(),
        uid: entry.uid,
        gid: entry.gid,
        cgroup_path: entry.cgroup_path.clone(),
    }
}

fn resolve_admin_socket(socket: Option<PathBuf>) -> PathBuf {
    socket.unwrap_or_else(default_admin_socket_path)
}

fn run_options_from_env(
    max_events: Option<u64>,
    config_path: Option<PathBuf>,
) -> Result<RunOptions, AgentError> {
    Ok(RunOptions {
        max_events,
        config_path,
        readiness: readiness_from_env(READY_SOCKET_ENV)?,
        control_readiness: readiness_from_env(CONTROL_READY_SOCKET_ENV)?,
    })
}

fn readiness_from_env(name: &'static str) -> Result<ReadinessSignal, AgentError> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(ReadinessSignal::None);
    };
    parse_ready_socket(name, value).map(ReadinessSignal::UnixSocket)
}

fn parse_ready_socket(name: &'static str, value: OsString) -> Result<PathBuf, AgentError> {
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty() {
        return Err(AgentError::InvalidReadinessSocket {
            name,
            value: path.display().to_string(),
        });
    }
    Ok(path)
}

fn read_runtime_composition(
    path: &Path,
) -> Result<crate::runtime_composition::RuntimeComposition, AgentError> {
    let config = prepare_runtime_config(read_config(path)?)?;
    build_runtime_composition(config)
}

async fn run_check_command(path: &Path) -> Result<(), AgentError> {
    let config = read_config(path)?;
    emit_check_command_output(build_check_command_output(config).await?)
}

enum CheckCommandOutput {
    Success {
        stdout: String,
    },
    InvalidConfig {
        stdout: String,
        validation: ConfigValidationError,
    },
}

impl CheckCommandOutput {
    fn stdout(&self) -> &str {
        match self {
            Self::Success { stdout } | Self::InvalidConfig { stdout, .. } => stdout,
        }
    }
}

fn emit_check_command_output(output: CheckCommandOutput) -> Result<(), AgentError> {
    println!("{}", output.stdout());
    match output {
        CheckCommandOutput::Success { .. } => Ok(()),
        CheckCommandOutput::InvalidConfig { validation, .. } => Err(AgentError::Runtime(
            runtime::RuntimeError::Validation(validation),
        )),
    }
}

async fn build_check_command_output(config: AgentConfig) -> Result<CheckCommandOutput, AgentError> {
    let config = prepare_runtime_config(config)?;
    match build_runtime_composition_with_diagnostics(config) {
        Ok(runtime) => {
            let (plan, enforcement_backend) = runtime.into_enforcement_parts();
            let report = build_check_report(plan, enforcement_backend).await?;
            Ok(CheckCommandOutput::Success {
                stdout: serde_json::to_string_pretty(&report)?,
            })
        }
        Err(error) => {
            let (error, capabilities) = error.into_parts();
            match error {
                runtime::RuntimeError::Validation(validation) => {
                    let report = build_invalid_config_report(&validation, capabilities);
                    Ok(CheckCommandOutput::InvalidConfig {
                        stdout: serde_json::to_string_pretty(&report)?,
                        validation,
                    })
                }
                error => Err(AgentError::Runtime(error)),
            }
        }
    }
}

fn prepare_runtime_config(mut config: AgentConfig) -> Result<AgentConfig, AgentError> {
    hydrate_runtime_artifact_paths(&mut config)?;
    Ok(config)
}

fn read_config_or_default(path: Option<&PathBuf>) -> Result<AgentConfig, AgentError> {
    match path {
        Some(path) => read_config(path),
        None => Ok(AgentConfig::default()),
    }
}

fn read_config(path: &Path) -> Result<AgentConfig, AgentError> {
    validate_main_config_parent(path)?;
    let content = probe_io::read_bounded_regular_file_to_string(path, MAX_MAIN_CONFIG_BYTES)
        .map_err(main_config_file_error)?;
    AgentConfig::from_toml_str(&content).map_err(AgentError::Config)
}

fn validate_main_config_parent(path: &Path) -> Result<(), AgentError> {
    let config_dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(config_dir).map_err(|source| AgentError::ReadFile {
            path: config_dir.display().to_string(),
            source,
        })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(AgentError::InvalidConfigPath {
            path: config_dir.display().to_string(),
            reason: "parent directory must be a non-symlink directory".to_string(),
        });
    }
    Ok(())
}

fn main_config_file_error(error: BoundedFileError) -> AgentError {
    match error.kind() {
        BoundedFileErrorKind::NotFound
        | BoundedFileErrorKind::Inspect
        | BoundedFileErrorKind::Open
        | BoundedFileErrorKind::Read => {
            let mut parts = error.into_parts();
            match parts.take_source() {
                Some(source) => AgentError::ReadFile {
                    path: parts.path.display().to_string(),
                    source,
                },
                None => AgentError::InvalidConfigPath {
                    path: parts.path.display().to_string(),
                    reason: "does not exist".to_string(),
                },
            }
        }
        BoundedFileErrorKind::Symlink
        | BoundedFileErrorKind::Directory
        | BoundedFileErrorKind::NotRegular => AgentError::InvalidConfigPath {
            path: error.path().display().to_string(),
            reason: "must be a non-symlink regular file".to_string(),
        },
        BoundedFileErrorKind::TooLarge => AgentError::InvalidConfigPath {
            path: error.path().display().to_string(),
            reason: format!("must not exceed {MAX_MAIN_CONFIG_BYTES} byte(s)"),
        },
    }
}

async fn replay(command: ReplayCommand) -> Result<(), AgentError> {
    let bytes = fs::read(&command.input).map_err(|source| AgentError::ReadFile {
        path: command.input.display().to_string(),
        source,
    })?;
    let policy = command.policy.as_deref().map(read_policy).transpose()?;
    let mut parser_factory = Http1ParserFactory::default();
    let spool = FjallSpool::open(command.spool)?;
    let flow = replay_flow();
    let mut replay_provider =
        ReplayProvider::new(flow.clone(), command.direction, bytes, current_timestamp(1));
    let mut enforcement_planner = ScopedEnforcementPlanner::new(command.enforcement_mode, None)?;
    let mut pipeline = CapturePipeline::new(
        &spool,
        &mut parser_factory,
        policy
            .map(PipelinePolicy::unscoped)
            .into_iter()
            .collect::<Vec<_>>(),
        "replay",
    )
    .with_enforcement_planner(&mut enforcement_planner);
    let summary = pipeline.run_provider(&mut replay_provider)?;
    println!(
        "replay pipeline journaled {} ingress records, processed {} ingress records, and stored {} export events",
        summary.ingress_records_journaled,
        summary.ingress_records_processed,
        summary.export_events_written
    );

    if let Some(endpoint) = command.webhook {
        drain_replay_webhook(&spool, &command.agent_id, endpoint, command.codec).await?;
    }

    Ok(())
}

fn read_policy(path: &Path) -> Result<PolicyRuntime, AgentError> {
    let source = probe_io::read_bounded_regular_file_to_string(path, REPLAY_POLICY_SOURCE_BYTES)
        .map_err(AgentError::ReplayPolicyFile)?;
    let id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("replay-policy")
        .to_string();
    PolicyRuntime::from_source(
        PolicyManifest {
            id,
            version: "replay".to_string(),
            hooks: POLICY_HOOKS.to_vec(),
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

fn wall_time_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
        })
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
    use std::{fs, os::unix::fs::symlink};

    use capture::{CaptureEvent, CapturedBytes};
    use probe_config::{CaptureSelection, EnforcementPolicySourceConfig, PolicyConfig};
    use probe_core::SpoolPayloadSchema;
    use storage::SpoolPayload;

    use super::*;

    fn run_cli(config: PathBuf, max_events: Option<u64>) -> Cli {
        Cli {
            command: Command::Run {
                config: Some(config),
                max_events,
            },
        }
    }

    fn check_cli(config: PathBuf) -> Cli {
        Cli {
            command: Command::Check { config },
        }
    }

    #[test]
    fn tui_cli_accepts_missing_config_path() {
        let cli = Cli::try_parse_from(["traffic-probe", "tui"]).expect("TUI config is optional");

        assert!(matches!(cli.command, Command::Tui { config: None, .. }));
    }

    #[test]
    fn tui_cli_accepts_snapshot_render_options() {
        let cli = Cli::try_parse_from([
            "traffic-probe",
            "tui",
            "--snapshot",
            "--tab",
            "traffic",
            "--width",
            "157",
            "--height",
            "45",
            "--open-detail",
            "--detail-scroll",
            "12",
        ])
        .expect("TUI snapshot options should parse");

        let Command::Tui {
            snapshot,
            width,
            height,
            tab,
            open_detail,
            detail_scroll,
            ..
        } = cli.command
        else {
            panic!("expected TUI command");
        };

        assert!(snapshot);
        assert_eq!(width, 157);
        assert_eq!(height, 45);
        assert_eq!(tab, CliTuiTab::Traffic);
        assert!(open_detail);
        assert_eq!(detail_scroll, 12);
    }

    #[test]
    fn tui_cli_accepts_initial_interactive_tab() {
        let cli = Cli::try_parse_from(["traffic-probe", "tui", "--tab", "traffic"])
            .expect("interactive TUI should accept an initial tab");

        let Command::Tui { snapshot, tab, .. } = cli.command else {
            panic!("expected TUI command");
        };

        assert!(!snapshot);
        assert_eq!(tab, CliTuiTab::Traffic);
    }

    #[test]
    fn tui_cli_rejects_snapshot_only_options_without_snapshot_mode() {
        for args in [
            &["traffic-probe", "tui", "--width", "157"][..],
            &["traffic-probe", "tui", "--height", "45"][..],
            &["traffic-probe", "tui", "--open-detail"][..],
            &["traffic-probe", "tui", "--detail-scroll", "12"][..],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn processes_cli_accepts_filters() {
        let cli = Cli::try_parse_from([
            "traffic-probe",
            "processes",
            "--pid",
            "42",
            "--query",
            "backend",
            "--limit",
            "10",
        ])
        .expect("processes command should accept filters");

        let Command::Processes { pid, query, limit } = cli.command else {
            panic!("expected processes command");
        };

        assert_eq!(pid, Some(42));
        assert_eq!(query.as_deref(), Some("backend"));
        assert_eq!(limit, 10);
    }

    #[test]
    fn process_list_snapshot_serializes_operator_contract() {
        let catalog = ProcessCatalog::from_entries([
            process_entry(41, "backend-alpha", "/usr/bin/backend-alpha"),
            process_entry(42, "backend-beta", "/app/backend-beta"),
        ])
        .with_diagnostics(["procfs process 99 failed: permission denied".to_string()]);

        let snapshot = process_list_snapshot(
            &catalog,
            ProcessListFilter {
                pid: None,
                query: Some("backend".to_string()),
                limit: 1,
            },
        );
        let output = serde_json::to_value(&snapshot).expect("snapshot should serialize");

        assert_eq!(
            output,
            serde_json::json!({
                "entries": [{
                    "pid": 41,
                    "process_key": "process-key-41",
                    "observation_key": "process:process-key-41",
                    "name": "backend-alpha",
                    "exe_path": "/usr/bin/backend-alpha",
                    "argv": ["backend-alpha"],
                    "uid": 1000,
                    "gid": 1000,
                    "cgroup_path": "system.slice/backend-alpha.service"
                }],
                "total": 2,
                "matched": 2,
                "returned": 1,
                "truncated": true,
                "diagnostics": ["procfs process 99 failed: permission denied"]
            })
        );
    }

    #[test]
    fn admin_cli_uses_runtime_default_socket_when_omitted() {
        let cli = Cli::try_parse_from(["traffic-probe", "admin", "status"])
            .expect("admin socket is optional");

        let Command::Admin { socket, command } = cli.command else {
            panic!("expected admin command");
        };

        assert!(matches!(command, AdminCliCommand::Status));
        assert_eq!(resolve_admin_socket(socket), default_admin_socket_path());
    }

    #[test]
    fn admin_tail_events_cli_parses_scan_limit_override() {
        let cli = Cli::try_parse_from([
            "traffic-probe",
            "admin",
            "tail-events",
            "--limit",
            "10",
            "--scan-limit",
            "100",
        ])
        .expect("tail-events should accept an explicit scan limit");

        let Command::Admin { command, .. } = cli.command else {
            panic!("expected admin command");
        };
        let AdminCliCommand::TailEvents {
            limit, scan_limit, ..
        } = command
        else {
            panic!("expected tail-events command");
        };

        assert_eq!(limit, 10);
        assert_eq!(scan_limit, Some(100));
    }

    #[test]
    fn internal_product_proxy_dispatch_reuses_mitm_proxy_cli_parser()
    -> Result<(), Box<dyn std::error::Error>> {
        let agent_args = [
            "traffic-probe",
            EMBEDDED_PRODUCT_PROXY_COMMAND,
            "--listen",
            "127.0.0.1:15002",
            "--feed",
            "/tmp/probe/mitm/feed.jsonl",
            "--target-recovery",
            "linux-original-destination",
            "--request-direction",
            "outbound",
            "--upstream-tls-mode",
            "auto",
            "--tls-material-root",
            "/tmp/probe/tls",
            "--tls-ca-certificate",
            "/tmp/probe/tls/mitm-ca.pem",
            "--tls-ca-private-key",
            "/tmp/probe/tls/mitm-ca.key",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();

        let proxy_args = product_proxy_cli_args_from_agent_args(&agent_args)
            .expect("internal command should dispatch to product proxy");
        let config = mitm_proxy::config_from_cli_args(proxy_args)?;

        assert_eq!(config.listen, "127.0.0.1:15002".parse()?);
        assert_eq!(
            config.target_recovery,
            mitm_proxy::TargetRecovery::LinuxOriginalDestination
        );
        assert_eq!(config.request_direction, Direction::Outbound);
        assert_eq!(config.upstream_tls_mode, mitm_proxy::UpstreamTlsMode::Auto);
        assert!(config.upstream_tls.is_some());
        assert!(matches!(
            config.tls,
            Some(mitm_proxy::TlsTerminationConfig::DynamicCa(_))
        ));
        Ok(())
    }

    #[test]
    fn ready_socket_env_rejects_empty_value() {
        assert!(matches!(
            parse_ready_socket(READY_SOCKET_ENV, OsString::from("")),
            Err(AgentError::InvalidReadinessSocket { .. })
        ));
    }

    #[test]
    fn replay_flow_uses_synthetic_process_identity() {
        let flow = replay_flow();

        assert_eq!(flow.process.identity.pid, 0);
        assert_eq!(flow.process.identity.tgid, 0);
        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(flow.process.identity.boot_id, "replay");
    }

    #[test]
    fn read_config_rejects_symlink_config_path() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("read-config-symlink")?;
        let target = temp.join("target.toml");
        let link = temp.join("agent.toml");
        fs::write(&target, "agent_id = \"probe\"\n")?;
        symlink(&target, &link)?;

        let error = read_config(&link).expect_err("symlink config path must be rejected");

        assert!(matches!(error, AgentError::InvalidConfigPath { .. }));
        assert!(error.to_string().contains("non-symlink regular file"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn read_config_rejects_symlink_config_parent() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("read-config-symlink-parent")?;
        let real_dir = temp.join("real");
        let link_dir = temp.join("config");
        fs::create_dir(&real_dir)?;
        fs::write(real_dir.join("agent.toml"), "agent_id = \"probe\"\n")?;
        symlink(&real_dir, &link_dir)?;

        let error = read_config(&link_dir.join("agent.toml"))
            .expect_err("symlink config parent must be rejected");

        assert!(matches!(error, AgentError::InvalidConfigPath { .. }));
        assert!(error.to_string().contains("non-symlink directory"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn read_config_rejects_oversized_config_file() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("read-config-oversized")?;
        let config_path = temp.join("agent.toml");
        fs::File::create(&config_path)?.set_len(MAX_MAIN_CONFIG_BYTES + 1)?;

        let error = read_config(&config_path).expect_err("oversized config must be rejected");

        assert!(matches!(error, AgentError::InvalidConfigPath { .. }));
        assert!(error.to_string().contains("must not exceed"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn run_validates_enforcement_before_probing_capture_provider()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-invalid-enforcement")?;
        let config_path = temp.join("agent.toml");
        let enforcement_path = temp.join("enforcement.toml");
        let spool_path = temp.join("spool");
        let missing_feed_path = temp.join("missing-feed.jsonl");

        fs::write(
            &enforcement_path,
            r#"
id = "managed-apps"
version = "test-version"
protective_actions = ["alert"]
"#,
        )?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(missing_feed_path);
        config.storage.path = spool_path.clone();
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: enforcement_path,
        };
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(run_cli(config_path, Some(0)))
            .await
            .expect_err("invalid enforcement manifest should fail before capture provider probe");

        assert!(
            matches!(&error, AgentError::ConfiguredEnforcement(_)),
            "unexpected error: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("not a protective enforcement action")
        );
        assert!(
            !spool_path.exists(),
            "spool must not be opened before enforcement validation passes"
        );

        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn run_validates_policy_before_probing_capture_provider()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-invalid-policy")?;
        let config_path = temp.join("agent.toml");
        let missing_policy_path = temp.join("missing-policy.bundle");
        let spool_path = temp.join("spool");
        let missing_feed_path = temp.join("missing-feed.jsonl");

        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(missing_feed_path);
        config.storage.path = spool_path.clone();
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: probe_config::PolicySourceConfig::LocalDirectory {
                path: missing_policy_path,
            },
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
        });
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(run_cli(config_path, Some(0)))
            .await
            .expect_err("invalid policy source should fail before capture provider probe");

        assert!(
            matches!(&error, AgentError::ConfiguredPolicy(_)),
            "unexpected error: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("policy source path does not exist")
        );
        assert!(
            !spool_path.exists(),
            "spool must not be opened before policy validation passes"
        );

        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn run_applies_multiple_configured_policies_in_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-multiple-policies")?;
        let config_path = temp.join("agent.toml");
        let feed_path = temp.join("feed.jsonl");
        let spool_path = temp.join("spool");
        let first_policy_path = temp.join("first.bundle");
        let second_policy_path = temp.join("second.bundle");
        fs::write(
            &feed_path,
            r#"
{"type":"bytes","timestamp":{"monotonic_ns":1,"wall_time_unix_ns":1},"connection":{"connection_id":"fixture-conn","local":{"address":"127.0.0.1","port":50000},"remote":{"address":"127.0.0.1","port":80},"protocol":"tcp","start_monotonic_ns":1,"attribution_confidence":42,"process":{"pid":123,"tgid":123,"start_time_ticks":456,"boot_id":"boot","exe_path":"/usr/bin/feed","cmdline_hash":"hash","uid":1000,"gid":1000,"name":"feed","cmdline":["feed"]}},"direction":"outbound","stream_offset":0,"bytes":[71,69,84,32,47,109,117,108,116,105,32,72,84,84,80,47,49,46,49,13,10,72,111,115,116,58,32,116,101,115,116,13,10,13,10]}
"#,
        )?;
        write_policy_bundle(
            &first_policy_path,
            "first",
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("first " .. event.kind.target)
end
"#,
        )?;
        write_policy_bundle(
            &second_policy_path,
            "second",
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("second " .. event.kind.target)
end
"#,
        )?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(feed_path);
        config.storage.path = spool_path.clone();
        config.policies = vec![
            PolicyConfig {
                id: "first".to_string(),
                source: probe_config::PolicySourceConfig::LocalDirectory {
                    path: first_policy_path,
                },
                enabled: true,
                selector: None,
                ..PolicyConfig::default()
            },
            PolicyConfig {
                id: "second".to_string(),
                source: probe_config::PolicySourceConfig::LocalDirectory {
                    path: second_policy_path,
                },
                enabled: true,
                selector: None,
                ..PolicyConfig::default()
            },
        ];
        fs::write(&config_path, toml::to_string(&config)?)?;

        run(run_cli(config_path, Some(1))).await?;

        let spool = FjallSpool::open(&spool_path)?;
        let exported = spool.read_export_batch("sink", 16)?;
        let policy_versions = exported
            .iter()
            .map(|event| serde_json::from_slice::<probe_core::EventEnvelope>(event.payload.bytes()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|envelope| matches!(envelope.kind(), probe_core::EventKind::PolicyAlert(_)))
            .filter_map(|envelope| envelope.policy_version().map(str::to_string))
            .collect::<Vec<_>>();
        assert_eq!(
            policy_versions,
            vec!["first@bundle-test", "second@bundle-test"]
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn run_rejects_unsupported_enforce_before_loading_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-unsupported-enforce-before-policy")?;
        let config_path = temp.join("agent.toml");
        let enforcement_path = temp.join("enforcement.toml");
        let missing_policy_path = temp.join("missing-policy.bundle");
        let spool_path = temp.join("spool");

        fs::write(
            &enforcement_path,
            r#"
id = "managed-apps"
version = "test-version"
protective_actions = ["deny"]
"#,
        )?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.storage.path = spool_path.clone();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: enforcement_path,
        };
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: probe_config::PolicySourceConfig::LocalDirectory {
                path: missing_policy_path,
            },
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
        });
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(run_cli(config_path, Some(0)))
            .await
            .expect_err("unsupported enforce should fail before Lua policy load");

        assert!(
            matches!(&error, AgentError::Runtime(_)),
            "unexpected error: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("at least one enforcement execution surface")
        );
        assert!(
            !spool_path.exists(),
            "spool must not be opened before runtime validation passes"
        );

        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn run_rejects_unsupported_enforce_before_reading_local_enforcement_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-unsupported-enforce-before-manifest")?;
        let config_path = temp.join("agent.toml");
        let enforcement_path = temp.join("enforcement.toml");
        let spool_path = temp.join("spool");

        fs::write(
            &enforcement_path,
            r#"
id = "managed-apps"
version = "test-version"
protective_actions = ["alert"]
"#,
        )?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.storage.path = spool_path.clone();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: enforcement_path,
        };
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(run_cli(config_path, Some(0)))
            .await
            .expect_err("unsupported enforce should fail before local manifest metadata read");

        assert!(
            matches!(&error, AgentError::Runtime(_)),
            "unexpected error: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("at least one enforcement execution surface")
        );
        assert!(
            !error
                .to_string()
                .contains("not a protective enforcement action"),
            "runtime capability failure must win over local manifest metadata errors"
        );
        assert!(
            !spool_path.exists(),
            "spool must not be opened before runtime validation passes"
        );

        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn check_reports_runtime_validation_failure_without_opening_spool()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("check-invalid-runtime")?;
        let config_path = temp.join("agent.toml");
        let enforcement_path = temp.join("enforcement.toml");
        let spool_path = temp.join("spool");

        fs::write(
            &enforcement_path,
            r#"
id = "managed-apps"
version = "test-version"
protective_actions = ["alert"]
"#,
        )?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.storage.path = spool_path.clone();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: enforcement_path,
        };
        fs::write(&config_path, toml::to_string(&config)?)?;

        let output = build_check_command_output(config).await?;
        let CheckCommandOutput::InvalidConfig { stdout, .. } = output else {
            panic!("runtime validation failure must produce invalid_config output")
        };
        let value: serde_json::Value = serde_json::from_str(&stdout)?;
        assert_eq!(value["kind"], "invalid_config");
        let reason = value["validation"]["violations"][0]["reason"]
            .as_str()
            .expect("validation reason should be a string");
        assert!(
            reason.contains("enforce mode requires at least one enforcement execution surface")
        );
        assert!(reason.contains("connection backend"));
        let states = value["capabilities"]["states"]
            .as_array()
            .expect("capability states should be an array");
        assert!(states.iter().any(|state| {
            state["kind"] == "connection_enforcement" && state["mode"] == "unavailable"
        }));
        assert!(
            !spool_path.exists(),
            "check output builder must not open spool before runtime validation passes"
        );

        let error = run(check_cli(config_path))
            .await
            .expect_err("check must fail closed when runtime validation fails");

        assert!(
            matches!(&error, AgentError::Runtime(_)),
            "unexpected error: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("at least one enforcement execution surface")
        );
        assert!(
            !spool_path.exists(),
            "check must not open spool before runtime validation passes"
        );

        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn run_validates_runtime_plan_before_fetching_remote_enforcement_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-invalid-runtime-before-remote-enforcement")?;
        let config_path = temp.join("agent.toml");
        let spool_path = temp.join("spool");

        let mut config = config_with_unopenable_libpcap(spool_path.clone());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: "http://127.0.0.1:1/enforcement".to_string(),
            max_body_bytes: None,
        };
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(run_cli(config_path, Some(0)))
            .await
            .expect_err("runtime validation must fail before remote enforcement fetch");

        assert!(
            matches!(&error, AgentError::Runtime(_)),
            "unexpected error: {error:?}"
        );
        assert!(
            error.to_string().contains("capture.selection"),
            "unexpected error message: {error}"
        );
        assert!(
            !spool_path.exists(),
            "spool must not be opened before runtime validation passes"
        );

        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn run_recovers_persisted_ingress_before_opening_capture_provider()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-ingress-recovery")?;
        let config_path = temp.join("agent.toml");
        let policy_path = temp.join("deny-recovered.bundle");
        let feed_path = temp.join("missing-feed.jsonl");
        let spool_path = temp.join("spool");
        let spool = FjallSpool::open(&spool_path)?;
        let chunk = CapturedBytes {
            timestamp: current_timestamp(1),
            flow: replay_flow(),
            origin: probe_core::CaptureOrigin::from_source(probe_core::CaptureSource::Replay),
            direction: Direction::Outbound,
            stream_offset: 0,
            bytes: b"GET /recovered-run HTTP/1.1\r\nHost: recovery.test\r\n\r\n"
                .as_slice()
                .into(),
            attribution_confidence: 0,
            degraded: false,
            degradation_reason: None,
            enforcement_evidence: probe_core::EnforcementEvidence::default(),
            enforcement_evidence_propagation: capture::EnforcementEvidencePropagation::Event,
        };
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            serde_json::to_vec(&CaptureEvent::Bytes(chunk))?,
        ))?;
        drop(spool);

        write_policy_bundle(
            &policy_path,
            "deny-recovered",
            r#"
function on_http_request_headers(_)
  return probe.verdict({
    action = "deny",
    scope = "request",
    reason = "recovered traffic should not enforce",
    confidence = 100,
  })
end
"#,
        )?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(feed_path);
        config.storage.path = spool_path.clone();
        config.enforcement.mode = EnforcementMode::DryRun;
        config.policies.push(PolicyConfig {
            id: "deny-recovered".to_string(),
            source: probe_config::PolicySourceConfig::LocalDirectory { path: policy_path },
            enabled: true,
            selector: None,
            ..PolicyConfig::default()
        });
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(run_cli(config_path, Some(0)))
            .await
            .expect_err("missing feed should fail after ingress recovery");

        assert!(
            matches!(error, AgentError::PlaintextFeed(_)),
            "unexpected error: {error:?}"
        );

        let spool = FjallSpool::open(&spool_path)?;
        let exported = spool.read_export_batch("sink", 16)?;
        let envelopes = exported
            .iter()
            .map(|event| serde_json::from_slice::<probe_core::EventEnvelope>(event.payload.bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(envelopes.iter().any(|envelope| {
            matches!(
                envelope.kind(),
                probe_core::EventKind::HttpRequestHeaders(headers)
                    if headers.target.as_deref() == Some("/recovered-run")
            )
        }));
        assert!(envelopes.iter().any(|envelope| {
            matches!(
                envelope.kind(),
                probe_core::EventKind::PolicyVerdict(verdict)
                    if verdict.action == probe_core::Action::Deny
            )
        }));
        assert!(
            envelopes.iter().all(|envelope| {
                !matches!(
                    envelope.kind(),
                    probe_core::EventKind::EnforcementDecision(_)
                )
            }),
            "ingress recovery must not run the enforcement planner"
        );

        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn config_with_unopenable_libpcap(spool_path: PathBuf) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.capture.libpcap.interface = Some("traffic-probe-missing-test-interface".to_string());
        config.storage.path = spool_path;
        config
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "traffic-probe-main-{name}-{}-{}",
            std::process::id(),
            wall_time_unix_ns()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn write_policy_bundle(path: &Path, id: &str, source: &str) -> Result<(), std::io::Error> {
        fs::create_dir_all(path)?;
        fs::write(
            path.join("manifest.toml"),
            format!(
                r#"
id = "{id}"
version = "bundle-test"
hooks = ["on_http_request_headers"]
"#
            ),
        )?;
        fs::write(path.join("main.lua"), source)?;
        Ok(())
    }

    fn process_entry(pid: u32, name: &str, exe_path: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            process_key: format!("process-key-{pid}"),
            name: name.to_string(),
            exe_path: Some(PathBuf::from(exe_path)),
            argv: vec![name.to_string()],
            uid: 1000,
            gid: 1000,
            cgroup_path: Some(format!("system.slice/{name}.service")),
        }
    }
}

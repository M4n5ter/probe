use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use capture::ReplayProvider;
use clap::{Parser, Subcommand, ValueEnum};
use enforcement::ScopedEnforcementPlanner;
use exporter::CompressionCodec;
use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelinePolicy, PipelineRunOptions, PipelineRuntimeMetrics};
use policy::PolicyRuntime;
use probe_config::{AgentConfig, PolicyConfig};
use probe_core::{
    AddressPort, Direction, EnforcementMode, FlowContext, FlowIdentity, ProcessContext,
    ProcessIdentity, Timestamp, TransportProtocol,
};
use runtime::{RuntimePlan, validate_static_runtime_config};
use storage::FjallSpool;

use crate::{
    admin::{AdminRuntimeState, AdminServerConfig, spawn_admin_server},
    capture_provider::build_capture_provider,
    capture_registry::default_provider_registry,
    check::build_check_report,
    configured_enforcement::build_configured_enforcement_with_backend,
    configured_policy::{LoadedPolicySource, load_configured_policy, load_policy_source},
    connection_enforcement::{self, ConnectionEnforcementRuntime},
    error::AgentError,
    export::{ExportWorker, ExportWorkerConfig, drain_planned_sinks, drain_replay_webhook},
    status::{build_status_snapshot, collect_spool_status},
    storage_retention::{StorageRetentionWorkerConfig, spawn_storage_retention_workers},
    tls_plaintext::TlsPlaintextRuntimeState,
};

const INGRESS_RECOVERY_BATCH_SIZE: usize = 1_024;

struct RuntimeComposition {
    plan: RuntimePlan,
    connection_enforcement: ConnectionEnforcementRuntime,
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
    Capabilities {
        #[arg(long)]
        config: Option<PathBuf>,
    },
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

pub(crate) async fn run_from_env() -> Result<(), AgentError> {
    run(Cli::parse()).await
}

async fn run(cli: Cli) -> Result<(), AgentError> {
    match cli.command {
        Command::Run { config, max_events } => {
            let agent_config = read_config_or_default(config.as_ref())?;
            validate_static_runtime_config(&agent_config)?;
            let runtime = build_runtime_composition(agent_config)?;
            let plan = runtime.plan;
            let enforcement_backend = runtime.connection_enforcement.into_backend();
            let mut enforcement =
                build_configured_enforcement_with_backend(&plan, enforcement_backend).await?;
            let policy = load_configured_policy(&plan.config)?;
            let spool = Arc::new(FjallSpool::open(&plan.config.storage.path)?);
            let mut parser_factory = Http1ParserFactory::default();
            let export_worker = export_worker_config_from_plan(&plan).map(ExportWorker::new);
            let pipeline_metrics = PipelineRuntimeMetrics::default();
            let tls_plaintext_runtime = TlsPlaintextRuntimeState::for_plan(&plan);
            let admin_runtime_state = AdminRuntimeState {
                enforcement_policy_source: enforcement.policy_source.clone(),
                export_worker: export_worker.as_ref().map(ExportWorker::runtime_state),
                pipeline: Some(pipeline_metrics.clone()),
                tls_plaintext: Some(tls_plaintext_runtime.clone()),
            };
            let admin_server = admin_server_config_from_plan(&plan)
                .map(|config| {
                    spawn_admin_server(
                        Arc::new(plan.clone()),
                        Arc::clone(&spool),
                        config,
                        admin_runtime_state.clone(),
                    )
                })
                .transpose()?;
            let export_worker = export_worker.map(|worker| worker.spawn(Arc::clone(&spool)));
            let mut storage_retention_config = storage_retention_worker_config_from_plan(&plan);
            let mut storage_retention_worker = None;
            let mut pipeline = CapturePipeline::new(
                spool.as_ref(),
                &mut parser_factory,
                policy
                    .as_ref()
                    .map(|policy| PipelinePolicy::new(&policy.runtime, policy.selector.as_ref())),
                plan.config.config_version.clone(),
            )
            .with_runtime_metrics(pipeline_metrics);
            println!(
                "agent {} running config {} capture {:?} selected {:?}",
                plan.config.agent_id,
                plan.config.config_version,
                plan.capture.mode,
                plan.capture.selected_backend
            );
            let summary_result = (|| {
                let mut summary =
                    pipeline.recover_ingress_journal_until_idle(INGRESS_RECOVERY_BATCH_SIZE)?;
                storage_retention_worker = storage_retention_config
                    .take()
                    .map(|config| spawn_storage_retention_workers(Arc::clone(&spool), config));
                let mut pipeline = pipeline.with_enforcement_planner(&mut enforcement.planner);
                let mut provider = build_capture_provider(&plan, Some(&tls_plaintext_runtime))?;
                let capture_summary = pipeline.run_provider_with_options(
                    provider.as_mut(),
                    PipelineRunOptions { max_events },
                )?;
                summary.merge(capture_summary);
                Ok::<_, AgentError>(summary)
            })();
            if let Some(server) = admin_server {
                server.stop().await;
            }
            if let Some(worker) = export_worker {
                worker.stop().await;
            }
            if let Some(worker) = storage_retention_worker {
                worker.stop().await;
            }
            let drain_result =
                drain_planned_sinks(spool.as_ref(), &plan.config.agent_id, &plan.export).await;
            let summary = match (summary_result, drain_result) {
                (Ok(summary), Ok(())) => summary,
                (Err(error), Ok(())) => return Err(error),
                (Ok(_), Err(error)) => return Err(error.into()),
                (Err(run_error), Err(export_error)) => {
                    eprintln!("tail export drain failed after run error: {export_error}");
                    return Err(run_error);
                }
            };
            println!(
                "agent stopped after reading {} capture events, journaling {} ingress records, processing {} ingress records ({} recovered), and storing {} export events",
                summary.capture_events_read,
                summary.ingress_records_journaled,
                summary.ingress_records_processed,
                summary.ingress_records_recovered,
                summary.export_events_written
            );
        }
        Command::Check { config } => {
            let runtime = read_runtime_composition(&config)?;
            let report =
                build_check_report(runtime.plan, runtime.connection_enforcement.into_backend())
                    .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Capabilities { config } => {
            let config = match config {
                Some(path) => read_config(&path)?,
                None => AgentConfig::default(),
            };
            let connection_enforcement =
                connection_enforcement::resolve(config.enforcement.backend);
            let matrix = default_provider_registry(&config, connection_enforcement.capability())
                .capability_matrix();
            println!("{}", serde_json::to_string_pretty(&matrix)?);
        }
        Command::Status { config } => {
            let plan = read_runtime_composition(&config)?.plan;
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

fn read_runtime_composition(path: &PathBuf) -> Result<RuntimeComposition, AgentError> {
    let config = read_config(path)?;
    build_runtime_composition(config)
}

fn build_runtime_composition(config: AgentConfig) -> Result<RuntimeComposition, AgentError> {
    let connection_enforcement = connection_enforcement::resolve(config.enforcement.backend);
    let registry = default_provider_registry(&config, connection_enforcement.capability());
    let plan = RuntimePlan::build(config, &registry).map_err(AgentError::Runtime)?;
    Ok(RuntimeComposition {
        plan,
        connection_enforcement,
    })
}

fn export_worker_config_from_plan(plan: &RuntimePlan) -> Option<ExportWorkerConfig> {
    ExportWorkerConfig::from_plans(plan.config.agent_id.clone(), &plan.export)
}

fn storage_retention_worker_config_from_plan(
    plan: &RuntimePlan,
) -> Option<StorageRetentionWorkerConfig> {
    StorageRetentionWorkerConfig::from_plans(&plan.export, &plan.storage)
}

fn admin_server_config_from_plan(plan: &RuntimePlan) -> Option<AdminServerConfig> {
    plan.config.admin.enabled.then(|| AdminServerConfig {
        socket_path: plan.config.admin.socket_path.clone(),
    })
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
        policy.as_ref().map(PipelinePolicy::unscoped),
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
    let source = load_policy_source("replay", &replay_policy_config(path))?;
    replay_policy_runtime(source).map_err(AgentError::Policy)
}

fn replay_policy_runtime(source: LoadedPolicySource) -> Result<PolicyRuntime, policy::PolicyError> {
    if source.require_declared_hooks {
        PolicyRuntime::from_source_with_required_hooks(source.manifest, &source.source)
    } else {
        PolicyRuntime::from_source(source.manifest, &source.source)
    }
}

fn replay_policy_config(path: &Path) -> PolicyConfig {
    let id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("replay-policy")
        .to_string();
    PolicyConfig {
        id,
        path: path.to_path_buf(),
        enabled: true,
        selector: None,
    }
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
    use std::fs;

    use capture::{CaptureEvent, CapturedBytes};
    use probe_config::{CaptureSelection, EnforcementPolicySourceConfig, PolicyConfig};
    use probe_core::SpoolPayloadSchema;
    use storage::SpoolPayload;

    use super::*;

    #[test]
    fn replay_flow_uses_synthetic_process_identity() {
        let flow = replay_flow();

        assert_eq!(flow.process.identity.pid, 0);
        assert_eq!(flow.process.identity.tgid, 0);
        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(flow.process.identity.boot_id, "replay");
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
version = "v1"
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

        let error = run(Cli {
            command: Command::Run {
                config: Some(config_path),
                max_events: Some(0),
            },
        })
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
        let missing_policy_path = temp.join("missing-policy.lua");
        let spool_path = temp.join("spool");
        let missing_feed_path = temp.join("missing-feed.jsonl");

        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(missing_feed_path);
        config.storage.path = spool_path.clone();
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            path: missing_policy_path,
            enabled: true,
            selector: None,
        });
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(Cli {
            command: Command::Run {
                config: Some(config_path),
                max_events: Some(0),
            },
        })
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
    async fn run_rejects_unsupported_enforce_before_loading_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-unsupported-enforce-before-policy")?;
        let config_path = temp.join("agent.toml");
        let missing_policy_path = temp.join("missing-policy.lua");
        let spool_path = temp.join("spool");

        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.storage.path = spool_path.clone();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            path: missing_policy_path,
            enabled: true,
            selector: None,
        });
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(Cli {
            command: Command::Run {
                config: Some(config_path),
                max_events: Some(0),
            },
        })
        .await
        .expect_err("unsupported enforce should fail before Lua policy load");

        assert!(
            matches!(&error, AgentError::Runtime(_)),
            "unexpected error: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("connection-level enforcement backend is not configured")
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
version = "v1"
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

        let error = run(Cli {
            command: Command::Run {
                config: Some(config_path),
                max_events: Some(0),
            },
        })
        .await
        .expect_err("unsupported enforce should fail before local manifest metadata read");

        assert!(
            matches!(&error, AgentError::Runtime(_)),
            "unexpected error: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("connection-level enforcement backend is not configured")
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
    async fn run_validates_runtime_plan_before_fetching_remote_enforcement_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("run-invalid-runtime-before-remote-enforcement")?;
        let config_path = temp.join("agent.toml");
        let spool_path = temp.join("spool");

        let mut config = config_with_unopenable_libpcap(spool_path.clone());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
            endpoint: "http://127.0.0.1:1/enforcement".to_string(),
        };
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(Cli {
            command: Command::Run {
                config: Some(config_path),
                max_events: Some(0),
            },
        })
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
        let policy_path = temp.join("deny-recovered.lua");
        let feed_path = temp.join("missing-feed.jsonl");
        let spool_path = temp.join("spool");
        let spool = FjallSpool::open(&spool_path)?;
        let chunk = CapturedBytes {
            timestamp: current_timestamp(1),
            flow: replay_flow(),
            source: probe_core::CaptureSource::Replay,
            provider: capture::CaptureProviderKind::Replay,
            direction: Direction::Outbound,
            stream_offset: 0,
            bytes: b"GET /recovered-run HTTP/1.1\r\nHost: recovery.test\r\n\r\n"
                .as_slice()
                .into(),
            attribution_confidence: 0,
            degraded: false,
            degradation_reason: None,
        };
        spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventJson,
            serde_json::to_vec(&CaptureEvent::Bytes(chunk))?,
        ))?;
        drop(spool);

        fs::write(
            &policy_path,
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
            path: policy_path,
            enabled: true,
            selector: None,
        });
        fs::write(&config_path, toml::to_string(&config)?)?;

        let error = run(Cli {
            command: Command::Run {
                config: Some(config_path),
                max_events: Some(0),
            },
        })
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
                &envelope.kind,
                probe_core::EventKind::HttpRequestHeaders(headers)
                    if headers.target.as_deref() == Some("/recovered-run")
            )
        }));
        assert!(envelopes.iter().any(|envelope| {
            matches!(
                &envelope.kind,
                probe_core::EventKind::PolicyVerdict(verdict)
                    if verdict.action == probe_core::Action::Deny
            )
        }));
        assert!(
            envelopes.iter().all(|envelope| {
                !matches!(
                    &envelope.kind,
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
        config.capture.libpcap.interface = Some("sssa-probe-missing-test-interface".to_string());
        config.storage.path = spool_path;
        config
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "sssa-probe-main-{name}-{}-{}",
            std::process::id(),
            wall_time_unix_ns()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}

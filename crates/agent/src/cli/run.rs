use std::{
    ffi::OsString,
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
use probe_config::AgentConfig;
use probe_core::{
    AddressPort, Direction, EnforcementMode, FlowContext, FlowIdentity, ProcessContext,
    ProcessIdentity, Timestamp, TransportProtocol,
};
use storage::FjallSpool;

use crate::{
    check::build_check_report,
    error::AgentError,
    export::drain_replay_webhook,
    live_agent::{ReadinessSignal, RunOptions, run_live_agent},
    runtime_composition::{build_runtime_composition, capability_matrix_for_config},
    status::{build_status_snapshot, collect_spool_status},
};

const REPLAY_POLICY_SOURCE_BYTES: u64 = 1024 * 1024;
const READY_SOCKET_ENV: &str = "TRAFFIC_PROBE_READY_SOCKET";

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
            run_live_agent(agent_config, run_options_from_env(max_events)?).await?;
        }
        Command::Check { config } => {
            let runtime = read_runtime_composition(&config)?;
            let (plan, enforcement_backend) = runtime.into_enforcement_parts();
            let report = build_check_report(plan, enforcement_backend).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Capabilities { config } => {
            let config = match config {
                Some(path) => read_config(&path)?,
                None => AgentConfig::default(),
            };
            let matrix = capability_matrix_for_config(&config);
            println!("{}", serde_json::to_string_pretty(&matrix)?);
        }
        Command::Status { config } => {
            let plan = read_runtime_composition(&config)?.into_plan();
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

fn run_options_from_env(max_events: Option<u64>) -> Result<RunOptions, AgentError> {
    Ok(RunOptions {
        max_events,
        readiness: readiness_from_env()?,
    })
}

fn readiness_from_env() -> Result<ReadinessSignal, AgentError> {
    let Some(value) = std::env::var_os(READY_SOCKET_ENV) else {
        return Ok(ReadinessSignal::None);
    };
    parse_ready_socket(value).map(ReadinessSignal::UnixSocket)
}

fn parse_ready_socket(value: OsString) -> Result<PathBuf, AgentError> {
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty() {
        return Err(AgentError::InvalidReadinessSocket {
            name: READY_SOCKET_ENV,
            value: path.display().to_string(),
        });
    }
    Ok(path)
}

fn read_runtime_composition(
    path: &PathBuf,
) -> Result<crate::runtime_composition::RuntimeComposition, AgentError> {
    let config = read_config(path)?;
    build_runtime_composition(config)
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
    use std::fs;

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

    #[test]
    fn ready_socket_env_rejects_empty_value() {
        assert!(matches!(
            parse_ready_socket(OsString::from("")),
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
            },
            PolicyConfig {
                id: "second".to_string(),
                source: probe_config::PolicySourceConfig::LocalDirectory {
                    path: second_policy_path,
                },
                enabled: true,
                selector: None,
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
}

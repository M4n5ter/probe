use std::{io::Write, os::unix::net::UnixStream, path::PathBuf, sync::Arc};

use enforcement::ScopedEnforcementPlanner;
use parsers::Http1ParserFactory;
use pipeline::{
    CapturePipeline, PipelinePolicySet, PipelineRunOptions, PipelineRuntimeMetrics, PipelineSummary,
};
use probe_config::AgentConfig;
use runtime::{RuntimePlan, validate_static_runtime_config};
use storage::FjallSpool;

use crate::{
    admin::{AdminRuntimeState, AdminServerConfig, spawn_admin_server},
    capture_provider::build_capture_provider,
    configured_enforcement::build_configured_enforcement_with_backend,
    configured_policy::load_configured_pipeline_policies,
    error::AgentError,
    export::{ExportDrainError, ExportWorker, ExportWorkerConfig, drain_planned_sinks},
    runtime_composition::build_runtime_composition,
    shutdown,
    storage_retention::{
        StorageRetentionWorkerConfig, StorageRetentionWorkerHandle, spawn_storage_retention_workers,
    },
    tls_plaintext::TlsPlaintextRuntimeState,
    transparent_interception::{TransparentInterceptionGuard, TransparentInterceptionRuntime},
};

const INGRESS_RECOVERY_BATCH_SIZE: usize = 1_024;

#[derive(Debug, Clone, Default)]
pub(crate) struct RunOptions {
    pub max_events: Option<u64>,
    pub readiness: ReadinessSignal,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum ReadinessSignal {
    #[default]
    None,
    UnixSocket(PathBuf),
}

pub(crate) async fn run_live_agent(
    agent_config: AgentConfig,
    options: RunOptions,
) -> Result<(), AgentError> {
    let RunOptions {
        max_events,
        readiness,
    } = options;
    validate_static_runtime_config(&agent_config)?;
    let runtime = build_runtime_composition(agent_config)?;
    let (plan, enforcement_backend, transparent_interception) = runtime.into_run_parts();
    let enforcement = build_configured_enforcement_with_backend(&plan, enforcement_backend).await?;
    let policies = load_configured_pipeline_policies(&plan.config)?;
    let spool = Arc::new(FjallSpool::open(&plan.config.storage.path)?);
    let export_worker = export_worker_config_from_plan(&plan).map(ExportWorker::new);
    let pipeline_metrics = PipelineRuntimeMetrics::default();
    let policy_set = policies.into_policy_set();
    let tls_plaintext_runtime = TlsPlaintextRuntimeState::for_plan(&plan);
    let admin_runtime_state = AdminRuntimeState {
        enforcement_policy_source: enforcement.policy_source.clone(),
        export_worker: export_worker.as_ref().map(ExportWorker::runtime_state),
        pipeline: Some(pipeline_metrics.clone()),
        policy_set: policy_set.clone(),
        tls_plaintext: Some(tls_plaintext_runtime.clone()),
        ..AdminRuntimeState::default()
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
    let storage_retention_config = storage_retention_worker_config_from_plan(&plan);
    println!(
        "agent {} running config {} capture {:?} selected {:?}",
        plan.config.agent_id,
        plan.config.config_version,
        plan.capture.mode,
        plan.capture.selected_backend
    );
    let shutdown_requested = shutdown::new_flag();
    let shutdown_signal_task = shutdown::spawn_signal_task(Arc::clone(&shutdown_requested));
    let blocking_run = BlockingCaptureRun {
        plan: plan.clone(),
        spool: Arc::clone(&spool),
        policy_set,
        enforcement_planner: enforcement.planner,
        effective_enforcement_selector: enforcement.effective_selector,
        transparent_interception,
        pipeline_metrics,
        tls_plaintext_runtime,
        storage_retention_config,
        shutdown_requested: Arc::clone(&shutdown_requested),
        max_events,
        readiness,
    };
    let blocking_run = tokio::task::spawn_blocking(|| blocking_run.run()).await;
    shutdown_signal_task.abort();
    if let Some(server) = admin_server {
        server.stop().await;
    }
    if let Some(worker) = export_worker {
        worker.stop().await;
    }
    let (summary_result, interception_cleanup_result, storage_retention_worker) = match blocking_run
    {
        Ok(output) => (
            output.summary_result,
            output.interception_cleanup_result,
            output.storage_retention_worker,
        ),
        Err(error) => (
            Err(AgentError::CaptureTaskJoin(error.to_string())),
            Ok(()),
            None,
        ),
    };
    if let Some(worker) = storage_retention_worker {
        worker.stop().await;
    }
    let drain_result =
        drain_planned_sinks(spool.as_ref(), &plan.config.agent_id, &plan.export).await;
    let summary = merge_run_results(summary_result, interception_cleanup_result, drain_result)?;
    println!(
        "agent stopped after reading {} capture events, journaling {} ingress records, processing {} ingress records ({} recovered), and storing {} export events",
        summary.capture_events_read,
        summary.ingress_records_journaled,
        summary.ingress_records_processed,
        summary.ingress_records_recovered,
        summary.export_events_written
    );
    Ok(())
}

struct BlockingCaptureRun {
    plan: RuntimePlan,
    spool: Arc<FjallSpool>,
    policy_set: PipelinePolicySet,
    enforcement_planner: ScopedEnforcementPlanner,
    effective_enforcement_selector: Option<probe_core::Selector>,
    transparent_interception: TransparentInterceptionRuntime,
    pipeline_metrics: PipelineRuntimeMetrics,
    tls_plaintext_runtime: TlsPlaintextRuntimeState,
    storage_retention_config: Option<StorageRetentionWorkerConfig>,
    shutdown_requested: shutdown::ShutdownFlag,
    max_events: Option<u64>,
    readiness: ReadinessSignal,
}

struct BlockingCaptureRunOutput {
    summary_result: Result<PipelineSummary, AgentError>,
    interception_cleanup_result:
        Result<(), crate::transparent_interception::TransparentInterceptionError>,
    storage_retention_worker: Option<StorageRetentionWorkerHandle>,
}

impl BlockingCaptureRun {
    fn run(self) -> BlockingCaptureRunOutput {
        let Self {
            plan,
            spool,
            policy_set,
            mut enforcement_planner,
            effective_enforcement_selector,
            transparent_interception,
            pipeline_metrics,
            tls_plaintext_runtime,
            mut storage_retention_config,
            shutdown_requested,
            max_events,
            readiness,
        } = self;
        let mut transparent_interception_guard = None;
        let mut storage_retention_worker = None;
        let summary_result = (|| {
            let mut parser_factory = Http1ParserFactory::default();
            let mut pipeline = CapturePipeline::new(
                spool.as_ref(),
                &mut parser_factory,
                policy_set,
                plan.config.config_version.clone(),
            )
            .with_runtime_metrics(pipeline_metrics);
            let mut summary =
                pipeline.recover_ingress_journal_until_idle(INGRESS_RECOVERY_BATCH_SIZE)?;
            if shutdown::requested(&shutdown_requested) {
                return Ok(summary);
            }
            storage_retention_worker = storage_retention_config
                .take()
                .map(|config| spawn_storage_retention_workers(Arc::clone(&spool), config));
            let mut pipeline = pipeline.with_enforcement_planner(&mut enforcement_planner);
            transparent_interception_guard =
                transparent_interception.activate(effective_enforcement_selector.as_ref())?;
            let mut provider = build_capture_provider(&plan, Some(&tls_plaintext_runtime))?;
            signal_readiness(readiness)?;
            let capture_summary = pipeline.run_provider_with_options(
                provider.as_mut(),
                PipelineRunOptions {
                    max_events,
                    shutdown_requested: Some(Arc::clone(&shutdown_requested)),
                },
            )?;
            summary.merge(capture_summary);
            Ok::<_, AgentError>(summary)
        })();
        let interception_cleanup_result =
            deactivate_transparent_interception_guard(transparent_interception_guard);
        BlockingCaptureRunOutput {
            summary_result,
            interception_cleanup_result,
            storage_retention_worker,
        }
    }
}

fn deactivate_transparent_interception_guard(
    guard: Option<TransparentInterceptionGuard>,
) -> Result<(), crate::transparent_interception::TransparentInterceptionError> {
    match guard {
        Some(guard) => guard.deactivate(),
        None => Ok(()),
    }
}

fn signal_readiness(readiness: ReadinessSignal) -> Result<(), AgentError> {
    match readiness {
        ReadinessSignal::None => Ok(()),
        ReadinessSignal::UnixSocket(path) => signal_unix_socket(path),
    }
}

fn signal_unix_socket(path: PathBuf) -> Result<(), AgentError> {
    let mut stream = UnixStream::connect(&path).map_err(|source| AgentError::SignalReadiness {
        target: path.display().to_string(),
        source,
    })?;
    stream
        .write_all(b"ready\n")
        .map_err(|source| AgentError::SignalReadiness {
            target: path.display().to_string(),
            source,
        })
}

fn merge_run_results(
    summary_result: Result<PipelineSummary, AgentError>,
    interception_cleanup_result: Result<
        (),
        crate::transparent_interception::TransparentInterceptionError,
    >,
    drain_result: Result<(), ExportDrainError>,
) -> Result<PipelineSummary, AgentError> {
    match (summary_result, interception_cleanup_result, drain_result) {
        (Ok(summary), Ok(()), Ok(())) => Ok(summary),
        (Err(error), Ok(()), Ok(())) => Err(error),
        (Ok(_), Err(error), Ok(())) => Err(error.into()),
        (Ok(_), Ok(()), Err(error)) => Err(error.into()),
        (Err(run_error), Err(cleanup_error), Ok(())) => {
            eprintln!("transparent interception cleanup failed after run error: {cleanup_error}");
            Err(run_error)
        }
        (Err(run_error), Ok(()), Err(export_error)) => {
            eprintln!("tail export drain failed after run error: {export_error}");
            Err(run_error)
        }
        (Ok(_), Err(cleanup_error), Err(export_error)) => {
            eprintln!(
                "tail export drain failed after transparent interception cleanup error: {export_error}"
            );
            Err(cleanup_error.into())
        }
        (Err(run_error), Err(cleanup_error), Err(export_error)) => {
            eprintln!("transparent interception cleanup failed after run error: {cleanup_error}");
            eprintln!("tail export drain failed after run error: {export_error}");
            Err(run_error)
        }
    }
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

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        io::{ErrorKind, Read},
        os::unix::net::UnixListener,
        sync::mpsc::{self, Receiver},
        thread,
        time::{Duration, Instant},
    };

    use probe_config::CaptureSelection;
    use rustix::fs::{CWD, Mode, mkfifoat};

    use super::*;

    #[tokio::test]
    async fn unix_socket_readiness_is_signaled_after_capture_provider_opens()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let feed_path = temp.path().join("feed.jsonl");
        mkfifoat(CWD, &feed_path, Mode::from_raw_mode(0o600))?;
        let feed_writer = OpenOptions::new().read(true).write(true).open(&feed_path)?;
        let ready_path = temp.path().join("ready.sock");
        let ready_listener = UnixListener::bind(&ready_path)?;

        let config = plaintext_feed_config(feed_path, temp.path().join("spool"));
        let readiness = ReadinessSignal::UnixSocket(ready_path);
        let (run_done_sender, run_done_receiver) = mpsc::channel();
        let run_thread = thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())
                .and_then(|runtime| {
                    runtime
                        .block_on(run_live_agent(
                            config,
                            RunOptions {
                                max_events: None,
                                readiness,
                            },
                        ))
                        .map_err(|error| error.to_string())
                });
            let _ = run_done_sender.send(result);
        });

        wait_for_ready_socket(&ready_listener, &run_done_receiver)?;
        assert!(matches!(
            run_done_receiver.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        drop(feed_writer);
        match run_done_receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(error) => {
                return Err(format!("run did not finish after feed close: {error}").into());
            }
        }
        run_thread
            .join()
            .map_err(|_| "ready socket run thread panicked")?;
        Ok(())
    }

    #[tokio::test]
    async fn unix_socket_readiness_is_not_signaled_when_provider_fails_to_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let missing_feed_path = temp.path().join("missing-feed.jsonl");
        let ready_path = temp.path().join("ready.sock");
        let ready_listener = UnixListener::bind(&ready_path)?;
        let config = plaintext_feed_config(missing_feed_path, temp.path().join("spool"));

        let error = run_live_agent(
            config,
            RunOptions {
                max_events: Some(0),
                readiness: ReadinessSignal::UnixSocket(ready_path),
            },
        )
        .await
        .expect_err("missing feed should fail before readiness is signaled");

        assert!(
            matches!(error, AgentError::PlaintextFeed(_)),
            "unexpected error: {error:?}"
        );
        ready_listener.set_nonblocking(true)?;
        assert!(matches!(
            ready_listener.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
        Ok(())
    }

    fn wait_for_ready_socket(
        listener: &UnixListener,
        run_done_receiver: &Receiver<Result<(), String>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut ready = [0_u8; 6];
                    stream.read_exact(&mut ready)?;
                    assert_eq!(&ready, b"ready\n");
                    return Ok(());
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            match run_done_receiver.try_recv() {
                Ok(Ok(())) => return Err("run finished before readiness signal".into()),
                Ok(Err(error)) => {
                    return Err(format!("run failed before readiness signal: {error}").into());
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("run thread disconnected before readiness signal".into());
                }
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for readiness signal".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn plaintext_feed_config(
        feed_path: std::path::PathBuf,
        spool_path: std::path::PathBuf,
    ) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(feed_path);
        config.storage.path = spool_path;
        config
    }
}

use std::{io::Write, os::unix::net::UnixStream, path::PathBuf, sync::Arc, time::Instant};

use parsers::Http1ParserFactory;
use pipeline::{
    CapturePipeline, IngressBacklogRecovery, PipelinePolicySet, PipelineRunOptions,
    PipelineRuntimeMetrics, PipelineSummary,
};
use probe_config::AgentConfig;
use runtime::{RuntimePlan, validate_static_runtime_config};
use storage::FjallSpool;

use crate::{
    admin::{
        AdminRuntimeState, AdminServerConfig, AdminServerHandle, PrometheusListenerConfig,
        spawn_admin_server,
    },
    artifacts::hydrate_runtime_artifact_paths,
    capture_provider::{
        CaptureProviderPreflight, CaptureProviderRuntimeState,
        build_capture_provider_with_cancellation,
    },
    configured_enforcement::{
        EnforcementRuntimeState, RuntimeEnforcementPlanner,
        build_configured_enforcement_with_backend,
    },
    configured_policy::load_configured_pipeline_policies_with_context,
    control_plane_http::{
        enforcement_policy_source_load_context_from_plan, policy_source_load_context_from_plan,
        webhook_connection_options_from_plan,
    },
    enforcement_reload_poller::{self, EnforcementReloadPollerHandle},
    enforcement_reload_watcher::{self, EnforcementReloadWatcherHandle},
    error::AgentError,
    export::{ExportDrainError, ExportWorker, drain_planned_sinks_with_webhook_connection},
    l7_mitm::{
        DurableL7MitmAuditSink, L7MitmBackendLifecycleGuard, L7MitmRuntime, start_backend_lifecycle,
    },
    policy_reload::ReloadablePolicySet,
    policy_reload_poller::{self, PolicyReloadPollerHandle},
    policy_reload_watcher::{self, PolicyReloadWatcherHandle},
    runtime_composition::build_runtime_composition,
    runtime_config_watcher::{self, RuntimeConfigWatcherContext, RuntimeConfigWatcherHandle},
    runtime_generation::{
        RuntimeGenerationExecutor, RuntimeGenerationHandoffOutcomeSnapshot, RuntimeGenerationState,
    },
    runtime_plan::RuntimePlanHandle,
    runtime_reload::{RuntimeReloadGate, config_reload::RuntimeConfigReloadOwner},
    shutdown,
    storage_retention::{StorageRetentionWorkerHandle, spawn_storage_retention_workers},
    tls_plaintext::{TlsDecryptHintRuntimeState, TlsPlaintextRuntimeState},
    transparent_interception::{
        TransparentInterceptionActivationScope, TransparentInterceptionGuard,
        TransparentInterceptionRuntime,
    },
};

use super::handoff::{
    RUNTIME_GENERATION_HANDOFF_DRAIN_POLLS, RuntimeGenerationHandoffDecision,
    RuntimeGenerationHandoffDrain,
};

const LIVE_INGRESS_RECOVERY_BATCH_SIZE: usize = 256;
const LIVE_CAPTURE_BATCH_POLLS: u64 = 8;
#[derive(Debug, Clone, Default)]
pub(crate) struct RunOptions {
    pub max_events: Option<u64>,
    pub config_path: Option<PathBuf>,
    pub readiness: ReadinessSignal,
    pub control_readiness: ReadinessSignal,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum ReadinessSignal {
    #[default]
    None,
    UnixSocket(PathBuf),
}

pub(crate) async fn run_live_agent(
    mut agent_config: AgentConfig,
    options: RunOptions,
) -> Result<(), AgentError> {
    let RunOptions {
        max_events,
        config_path,
        readiness,
        control_readiness,
    } = options;
    require_runtime_artifacts(&mut agent_config)?;
    validate_static_runtime_config(&agent_config)?;
    let runtime = build_runtime_composition(agent_config)?;
    let (plan, enforcement_backend, l7_mitm, transparent_interception) = runtime.into_run_parts();
    let l7_mitm_runtime = l7_mitm.handle();
    let tls_decrypt_hint_runtime = TlsDecryptHintRuntimeState::for_plan(&plan);
    let capture_provider_preflight =
        CaptureProviderPreflight::build(&plan, Some(&tls_decrypt_hint_runtime), &l7_mitm_runtime)?;
    let enforcement_policy_load_context = enforcement_policy_source_load_context_from_plan(&plan);
    let enforcement = build_configured_enforcement_with_backend(
        &plan,
        enforcement_backend,
        enforcement_policy_load_context,
    )
    .await?;
    let policy_load_context = policy_source_load_context_from_plan(&plan);
    let policies =
        load_configured_pipeline_policies_with_context(&plan.config, policy_load_context).await?;
    let reloadable_policies = ReloadablePolicySet::from_loaded(policies);
    let spool = Arc::new(FjallSpool::open(&plan.config.storage.path)?);
    let webhook_connection = webhook_connection_options_from_plan(&plan);
    let pipeline_metrics = PipelineRuntimeMetrics::default();
    let policy_set = reloadable_policies.policy_set();
    let (enforcement_planner, enforcement_runtime) = EnforcementRuntimeState::from_planner(
        enforcement.planner,
        enforcement.active_policy.clone(),
    );
    let tls_plaintext_runtime = TlsPlaintextRuntimeState::for_plan(&plan);
    let capture_runtime = CaptureProviderRuntimeState::default();
    let runtime_generation =
        RuntimeGenerationState::for_config_version(plan.config.config_version.clone());
    let config_apply_gate = RuntimeReloadGate::default();
    let shutdown_requested = shutdown::new_flag();
    let runtime_config_reload_owner =
        RuntimeConfigReloadOwner::for_config_path(config_path.as_deref());
    let transparent_proxy_runtime = transparent_interception.proxy_runtime_handle();
    let plan_handle = RuntimePlanHandle::new(Arc::new(plan.clone()));
    let export_worker = ExportWorker::new(plan_handle.clone(), webhook_connection);
    let admin_runtime_state = AdminRuntimeState {
        capture: capture_runtime.clone(),
        config_apply_gate: config_apply_gate.clone(),
        enforcement: Some(enforcement_runtime.clone()),
        export_worker: export_worker.runtime_state(),
        pipeline: Some(pipeline_metrics.clone()),
        policy_reload_gate: reloadable_policies.reload_gate(),
        policy_set: policy_set.clone(),
        tls_decrypt_hints: Some(tls_decrypt_hint_runtime.clone()),
        tls_plaintext: Some(tls_plaintext_runtime.clone()),
        l7_mitm: Some(l7_mitm_runtime.clone()),
        runtime_generation: Some(runtime_generation.clone()),
        runtime_config_reload_owner,
        shutdown_requested: shutdown_requested.clone(),
        transparent_proxy: Some(transparent_proxy_runtime.clone()),
        ..AdminRuntimeState::default()
    };
    let admin_server = admin_server_config_from_plan(&plan)
        .map(|config| {
            spawn_admin_server(
                plan_handle.clone(),
                Arc::clone(&spool),
                config,
                admin_runtime_state.clone(),
            )
        })
        .transpose()?;
    let mut background_services = BackgroundServices::new(admin_server);
    match runtime_config_watcher::spawn_watcher(
        config_path,
        RuntimeConfigWatcherContext {
            plan: plan_handle.clone(),
            policy_set: policy_set.clone(),
            policy_reload_gate: admin_runtime_state.policy_reload_gate.clone(),
            config_apply_gate: config_apply_gate.clone(),
            enforcement_runtime: Some(enforcement_runtime.clone()),
            enforcement_reload_gate: admin_runtime_state.enforcement_reload_gate.clone(),
            runtime_generation: runtime_generation.clone(),
        },
    ) {
        Ok(watcher) => {
            background_services.runtime_config_watcher = watcher;
        }
        Err(error) => {
            background_services.stop().await;
            return Err(error.into());
        }
    };
    match policy_reload_watcher::spawn_watcher(
        plan_handle.clone(),
        policy_set.clone(),
        admin_runtime_state.policy_reload_gate.clone(),
        config_apply_gate.clone(),
    ) {
        Ok(watcher) => {
            background_services.policy_reload_watcher = watcher;
        }
        Err(error) => {
            background_services.stop().await;
            return Err(error.into());
        }
    };
    if let Some(poller) = policy_reload_poller::spawn_poller(
        plan_handle.clone(),
        policy_set.clone(),
        admin_runtime_state.policy_reload_gate.clone(),
        config_apply_gate.clone(),
    ) {
        background_services.policy_reload_poller = Some(poller);
    }
    match enforcement_reload_watcher::spawn_watcher(
        plan_handle.clone(),
        enforcement_runtime.clone(),
        admin_runtime_state.enforcement_reload_gate.clone(),
    ) {
        Ok(watcher) => {
            background_services.enforcement_reload_watcher = watcher;
        }
        Err(error) => {
            background_services.stop().await;
            return Err(error.into());
        }
    };
    match enforcement_reload_poller::spawn_poller(
        plan_handle.clone(),
        enforcement_runtime,
        admin_runtime_state.enforcement_reload_gate.clone(),
    ) {
        Ok(Some(poller)) => {
            background_services.enforcement_reload_poller = Some(poller);
        }
        Ok(None) => {}
        Err(error) => {
            background_services.stop().await;
            return Err(error.into());
        }
    };
    let export_worker = export_worker.spawn(Arc::clone(&spool));
    println!(
        "agent {} running config {} capture {:?} selected {:?}",
        plan.config.agent_id,
        plan.config.config_version,
        plan.capture.mode,
        plan.capture.selected_backend
    );
    let shutdown_signal_task = shutdown::spawn_signal_task(shutdown_requested.clone());
    let blocking_run = BlockingCaptureRun {
        plan: plan.clone(),
        plan_handle: plan_handle.clone(),
        config_apply_gate,
        spool: Arc::clone(&spool),
        policy_set,
        enforcement_planner,
        transparent_interception_setup_scope: enforcement.transparent_interception_setup_scope,
        transparent_interception,
        pipeline_metrics,
        capture_provider_preflight,
        capture_runtime,
        tls_decrypt_hint_runtime,
        tls_plaintext_runtime,
        l7_mitm,
        runtime_generation,
        shutdown_requested: shutdown_requested.clone(),
        max_events,
        readiness,
        control_readiness,
    };
    let blocking_run = tokio::task::spawn_blocking(|| blocking_run.run()).await;
    shutdown_signal_task.abort();
    background_services.stop().await;
    export_worker.stop().await;
    let (
        summary_result,
        interception_cleanup_result,
        l7_mitm_cleanup_result,
        storage_retention_worker,
    ) = match blocking_run {
        Ok(output) => {
            let l7_mitm_cleanup_result = output.l7_mitm_cleanup_result;
            (
                output.summary_result,
                output.interception_cleanup_result,
                l7_mitm_cleanup_result,
                output.storage_retention_worker,
            )
        }
        Err(error) => (
            Err(AgentError::CaptureTaskJoin(error.to_string())),
            Ok(()),
            Ok(()),
            None,
        ),
    };
    if let Some(worker) = storage_retention_worker {
        worker.stop().await;
    }
    let tail_plan = plan_handle.snapshot();
    let drain_result = drain_planned_sinks_with_webhook_connection(
        spool.as_ref(),
        &tail_plan.config.agent_id,
        &tail_plan.export,
        &tail_plan.tls_material_store,
        webhook_connection_options_from_plan(tail_plan.as_ref()),
    )
    .await;
    let summary = merge_run_results(
        summary_result,
        interception_cleanup_result,
        l7_mitm_cleanup_result,
        drain_result,
    )?;
    println!(
        "agent stopped after reading {} capture events, journaling {} ingress records, processing {} ingress records ({} recovered), and storing {} export events",
        summary.pipeline.capture_events_read,
        summary.pipeline.ingress_records_journaled,
        summary.pipeline.ingress_records_processed,
        summary.pipeline.ingress_records_recovered,
        summary.durable_export_events_written
    );
    Ok(())
}

fn require_runtime_artifacts(config: &mut AgentConfig) -> Result<(), AgentError> {
    hydrate_runtime_artifact_paths(config)?;
    Ok(())
}

struct BackgroundServices {
    admin_server: Option<AdminServerHandle>,
    policy_reload_poller: Option<PolicyReloadPollerHandle>,
    policy_reload_watcher: Option<PolicyReloadWatcherHandle>,
    runtime_config_watcher: Option<RuntimeConfigWatcherHandle>,
    enforcement_reload_poller: Option<EnforcementReloadPollerHandle>,
    enforcement_reload_watcher: Option<EnforcementReloadWatcherHandle>,
}

impl BackgroundServices {
    fn new(admin_server: Option<AdminServerHandle>) -> Self {
        Self {
            admin_server,
            policy_reload_poller: None,
            policy_reload_watcher: None,
            runtime_config_watcher: None,
            enforcement_reload_poller: None,
            enforcement_reload_watcher: None,
        }
    }

    async fn stop(&mut self) {
        if let Some(poller) = self.enforcement_reload_poller.take() {
            poller.stop().await;
        }
        if let Some(watcher) = self.enforcement_reload_watcher.take() {
            watcher.stop().await;
        }
        if let Some(watcher) = self.runtime_config_watcher.take() {
            watcher.stop().await;
        }
        if let Some(poller) = self.policy_reload_poller.take() {
            poller.stop().await;
        }
        if let Some(watcher) = self.policy_reload_watcher.take() {
            watcher.stop().await;
        }
        if let Some(server) = self.admin_server.take() {
            server.stop().await;
        }
    }
}

struct BlockingCaptureRun {
    plan: RuntimePlan,
    plan_handle: RuntimePlanHandle,
    config_apply_gate: RuntimeReloadGate,
    spool: Arc<FjallSpool>,
    policy_set: PipelinePolicySet,
    enforcement_planner: RuntimeEnforcementPlanner,
    transparent_interception_setup_scope: Option<TransparentInterceptionActivationScope>,
    transparent_interception: TransparentInterceptionRuntime,
    pipeline_metrics: PipelineRuntimeMetrics,
    capture_provider_preflight: CaptureProviderPreflight,
    capture_runtime: CaptureProviderRuntimeState,
    tls_decrypt_hint_runtime: TlsDecryptHintRuntimeState,
    tls_plaintext_runtime: TlsPlaintextRuntimeState,
    l7_mitm: L7MitmRuntime,
    runtime_generation: RuntimeGenerationState,
    shutdown_requested: shutdown::ShutdownFlag,
    max_events: Option<u64>,
    readiness: ReadinessSignal,
    control_readiness: ReadinessSignal,
}

struct BlockingCaptureRunOutput {
    summary_result: Result<LiveAgentRunSummary, AgentError>,
    interception_cleanup_result:
        Result<(), crate::transparent_interception::TransparentInterceptionError>,
    l7_mitm_cleanup_result: Result<(), AgentError>,
    storage_retention_worker: Option<StorageRetentionWorkerHandle>,
}

struct LiveAgentRunSummary {
    pipeline: PipelineSummary,
    durable_export_events_written: u64,
}

impl BlockingCaptureRun {
    fn run(self) -> BlockingCaptureRunOutput {
        let Self {
            mut plan,
            plan_handle,
            config_apply_gate,
            spool,
            policy_set,
            mut enforcement_planner,
            transparent_interception_setup_scope,
            transparent_interception,
            pipeline_metrics,
            capture_provider_preflight,
            capture_runtime,
            tls_decrypt_hint_runtime,
            tls_plaintext_runtime,
            l7_mitm,
            runtime_generation,
            shutdown_requested,
            max_events,
            readiness,
            control_readiness,
        } = self;
        let mut active_interception_guard = ActiveInterceptionGuard::default();
        let mut storage_retention_worker = None;
        let l7_mitm_runtime = l7_mitm.handle();
        let export_event_metrics = pipeline_metrics.clone();
        let l7_mitm_audit = Arc::new(DurableL7MitmAuditSink::new(
            Arc::clone(&spool),
            plan_handle.clone(),
            pipeline_metrics.clone(),
        ));
        let startup_started = Instant::now();
        let summary_result = (|| {
            let mut parser_factory = Http1ParserFactory::default();
            let mut pipeline = CapturePipeline::new(
                spool.as_ref(),
                &mut parser_factory,
                policy_set,
                plan.config.config_version.clone(),
            )
            .with_runtime_metrics(pipeline_metrics);
            let mut ingress_recovery = pipeline.ingress_backlog_recovery()?;
            let mut summary = PipelineSummary::default();
            log_startup_stage(startup_started, "initialized pipeline");
            if signal_configured_readiness(control_readiness)? {
                log_startup_stage(startup_started, "signaled control-plane readiness");
            }
            if shutdown::requested(&shutdown_requested) {
                return Ok(summary);
            }
            let startup_recovery_caught_up = recover_startup_ingress_backlog(
                &mut pipeline,
                &mut ingress_recovery,
                &shutdown_requested,
                &mut summary,
            )?;
            log_startup_stage(startup_started, "recovered startup ingress backlog");
            if !startup_recovery_caught_up {
                return Ok(summary);
            }
            let mut pipeline = pipeline.with_enforcement_planner(&mut enforcement_planner);
            active_interception_guard.l7_mitm_backend = start_backend_lifecycle(
                &plan.enforcement.interception.mitm.backend,
                l7_mitm_runtime.clone(),
                l7_mitm_audit.clone(),
                &shutdown_requested,
            )
            .map_err(AgentError::L7MitmRuntime)?;
            log_startup_stage(startup_started, "started L7 MITM backend lifecycle");
            let built_provider = match build_capture_provider_with_cancellation(
                &plan,
                Some(&tls_plaintext_runtime),
                &l7_mitm_runtime,
                capture_provider_preflight,
                shutdown_requested.clone(),
            ) {
                Ok(provider) => provider,
                Err(AgentError::StartupCancelled(_)) => return Ok(summary),
                Err(error) => return Err(error),
            };
            log_startup_stage(startup_started, "built capture provider");
            capture_runtime.record(built_provider.runtime);
            let mut provider = capture_runtime.observe_capture_input(built_provider.provider);
            log_startup_stage(startup_started, "recorded capture runtime");
            let storage_retention_plan_handle = plan_handle.clone();
            let runtime_generation_executor = RuntimeGenerationExecutor::new(
                runtime_generation.clone(),
                plan_handle,
                config_apply_gate,
                capture_runtime.clone(),
                tls_decrypt_hint_runtime,
                tls_plaintext_runtime.clone(),
                l7_mitm_runtime.clone(),
            );
            active_interception_guard.transparent_interception =
                transparent_interception.activate(transparent_interception_setup_scope)?;
            log_startup_stage(startup_started, "activated transparent interception");
            storage_retention_worker = Some(spawn_storage_retention_workers(
                Arc::clone(&spool),
                storage_retention_plan_handle,
            ));
            log_startup_stage(startup_started, "started storage retention workers");
            if shutdown::requested(&shutdown_requested) {
                return Ok(summary);
            }
            if signal_configured_readiness(readiness)? {
                log_startup_stage(startup_started, "signaled data-plane readiness");
            }
            let mut handoff_drain = RuntimeGenerationHandoffDrain::default();
            let mut shutdown_drain_requested = false;
            loop {
                if shutdown::requested(&shutdown_requested) {
                    shutdown_drain_requested = true;
                    break;
                }
                if runtime_generation.has_pending_or_applying_reload() {
                    let Some(drain_options) = live_capture_handoff_drain_options(
                        max_events,
                        summary.capture_events_read,
                        &shutdown_requested,
                    ) else {
                        shutdown_drain_requested = shutdown::requested(&shutdown_requested);
                        break;
                    };
                    let drain_summary =
                        pipeline.drain_provider_before_handoff(provider.as_mut(), drain_options)?;
                    let provider_finished = drain_summary.pipeline.capture_provider_finished;
                    let handoff_outcome = drain_summary.outcome;
                    summary.merge(drain_summary.pipeline);
                    if provider_finished {
                        break;
                    }
                    if shutdown::requested(&shutdown_requested) {
                        shutdown_drain_requested = true;
                        break;
                    }
                    let handoff = match handoff_drain.observe(handoff_outcome) {
                        RuntimeGenerationHandoffDecision::WaitForDrain => continue,
                        RuntimeGenerationHandoffDecision::Proceed(handoff) => handoff,
                    };
                    if let RuntimeGenerationHandoffOutcomeSnapshot::Forced { after_batches } =
                        handoff
                    {
                        eprintln!(
                            "runtime generation handoff forced after {after_batches} capture drain handoff attempt(s)"
                        );
                    }
                    runtime_generation.record_capture_safe_point();
                    let _runtime_generation_result = runtime_generation_executor
                        .process_capture_safe_point(
                            &mut plan,
                            &mut provider,
                            handoff,
                            |config_version| {
                                pipeline.set_config_version(config_version);
                            },
                        );
                }
                let Some(run_options) = live_capture_run_options(
                    max_events,
                    summary.capture_events_read,
                    &shutdown_requested,
                ) else {
                    shutdown_drain_requested = shutdown::requested(&shutdown_requested);
                    break;
                };
                let capture_summary =
                    pipeline.run_provider_with_options(provider.as_mut(), run_options)?;
                let provider_finished = capture_summary.capture_provider_finished;
                summary.merge(capture_summary);
                runtime_generation.record_capture_safe_point();
                if provider_finished {
                    break;
                }
                if shutdown::requested(&shutdown_requested) {
                    shutdown_drain_requested = true;
                    break;
                }
            }
            if shutdown_drain_requested
                && let Some(drain_options) =
                    live_capture_shutdown_drain_options(max_events, summary.capture_events_read)
            {
                let drain_summary =
                    pipeline.drain_provider_before_handoff(provider.as_mut(), drain_options)?;
                summary.merge(drain_summary.pipeline);
            }
            Ok::<_, AgentError>(summary)
        })();
        let (interception_cleanup_result, l7_mitm_cleanup_result) =
            active_interception_guard.stop();
        let summary_result = summary_result.map(|pipeline| LiveAgentRunSummary {
            pipeline,
            durable_export_events_written: export_event_metrics.snapshot().export_events_written,
        });
        BlockingCaptureRunOutput {
            summary_result,
            interception_cleanup_result,
            l7_mitm_cleanup_result,
            storage_retention_worker,
        }
    }
}

fn live_capture_run_options(
    max_events: Option<u64>,
    events_read: u64,
    shutdown_requested: &shutdown::ShutdownFlag,
) -> Option<PipelineRunOptions> {
    live_capture_run_options_with_max_polls(
        max_events,
        events_read,
        shutdown_requested,
        LIVE_CAPTURE_BATCH_POLLS,
    )
}

fn live_capture_handoff_drain_options(
    max_events: Option<u64>,
    events_read: u64,
    shutdown_requested: &shutdown::ShutdownFlag,
) -> Option<PipelineRunOptions> {
    live_capture_run_options_with_max_polls(
        max_events,
        events_read,
        shutdown_requested,
        RUNTIME_GENERATION_HANDOFF_DRAIN_POLLS,
    )
}

fn live_capture_shutdown_drain_options(
    max_events: Option<u64>,
    events_read: u64,
) -> Option<PipelineRunOptions> {
    let remaining_events = max_events.map(|max_events| max_events.saturating_sub(events_read));
    if remaining_events == Some(0) {
        return None;
    }
    let mut options = PipelineRunOptions::max_polls(RUNTIME_GENERATION_HANDOFF_DRAIN_POLLS);
    options.max_events = remaining_events;
    Some(options)
}

fn live_capture_run_options_with_max_polls(
    max_events: Option<u64>,
    events_read: u64,
    shutdown_requested: &shutdown::ShutdownFlag,
    max_polls: u64,
) -> Option<PipelineRunOptions> {
    if shutdown::requested(shutdown_requested) {
        return None;
    }
    let remaining_events = max_events.map(|max_events| max_events.saturating_sub(events_read));
    if remaining_events == Some(0) {
        return None;
    }
    let mut options = PipelineRunOptions::max_polls(max_polls)
        .with_cancellation_token(shutdown_requested.clone());
    options.max_events = remaining_events;
    Some(options)
}

fn recover_startup_ingress_backlog<S>(
    pipeline: &mut CapturePipeline<'_, S>,
    backlog: &mut IngressBacklogRecovery,
    shutdown_requested: &shutdown::ShutdownFlag,
    summary: &mut PipelineSummary,
) -> Result<bool, pipeline::PipelineError>
where
    S: storage::DurableSpool,
{
    let recovered =
        recover_live_ingress_backlog_until_caught_up(pipeline, backlog, shutdown_requested)?;
    summary.merge(recovered);
    Ok(!shutdown::requested(shutdown_requested) && backlog.caught_up())
}

fn recover_live_ingress_backlog_until_caught_up<S>(
    pipeline: &mut CapturePipeline<'_, S>,
    backlog: &mut IngressBacklogRecovery,
    shutdown_requested: &shutdown::ShutdownFlag,
) -> Result<PipelineSummary, pipeline::PipelineError>
where
    S: storage::DurableSpool,
{
    let mut summary = PipelineSummary::default();
    while !backlog.caught_up() && !shutdown::requested(shutdown_requested) {
        let batch = pipeline.recover_ingress_backlog_batch(
            backlog,
            LIVE_INGRESS_RECOVERY_BATCH_SIZE,
            shutdown_requested,
        )?;
        summary.merge(batch);
    }
    Ok(summary)
}

fn signal_configured_readiness(readiness: ReadinessSignal) -> Result<bool, AgentError> {
    let configured = !matches!(readiness, ReadinessSignal::None);
    signal_readiness(readiness)?;
    Ok(configured)
}

fn log_startup_stage(started: Instant, stage: &str) {
    eprintln!(
        "agent startup {stage} after {:.3}s",
        started.elapsed().as_secs_f64()
    );
}

#[derive(Default)]
struct ActiveInterceptionGuard {
    transparent_interception: Option<TransparentInterceptionGuard>,
    l7_mitm_backend: Option<L7MitmBackendLifecycleGuard>,
}

impl ActiveInterceptionGuard {
    fn stop(
        mut self,
    ) -> (
        Result<(), crate::transparent_interception::TransparentInterceptionError>,
        Result<(), AgentError>,
    ) {
        self.stop_inner()
    }

    fn stop_inner(
        &mut self,
    ) -> (
        Result<(), crate::transparent_interception::TransparentInterceptionError>,
        Result<(), AgentError>,
    ) {
        let interception_result = match self.transparent_interception.take() {
            Some(guard) => guard.deactivate(),
            None => Ok(()),
        };
        let l7_mitm_result = match self.l7_mitm_backend.take() {
            Some(guard) => guard.stop().map_err(AgentError::L7MitmRuntime),
            None => Ok(()),
        };
        (interception_result, l7_mitm_result)
    }
}

impl Drop for ActiveInterceptionGuard {
    fn drop(&mut self) {
        let (interception_result, l7_mitm_result) = self.stop_inner();
        if let Err(error) = interception_result {
            eprintln!("transparent interception cleanup failed during drop: {error}");
        }
        if let Err(error) = l7_mitm_result {
            eprintln!("L7 MITM backend cleanup failed during drop: {error}");
        }
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
    summary_result: Result<LiveAgentRunSummary, AgentError>,
    interception_cleanup_result: Result<
        (),
        crate::transparent_interception::TransparentInterceptionError,
    >,
    l7_mitm_backend_lifecycle_cleanup_result: Result<(), AgentError>,
    drain_result: Result<(), ExportDrainError>,
) -> Result<LiveAgentRunSummary, AgentError> {
    let summary = match summary_result {
        Ok(summary) => summary,
        Err(run_error) => {
            if let Err(cleanup_error) = interception_cleanup_result {
                eprintln!(
                    "transparent interception cleanup failed after run error: {cleanup_error}"
                );
            }
            if let Err(l7_mitm_error) = l7_mitm_backend_lifecycle_cleanup_result {
                eprintln!(
                    "L7 MITM backend lifecycle cleanup failed after run error: {l7_mitm_error}"
                );
            }
            if let Err(export_error) = drain_result {
                eprintln!("tail export drain failed after run error: {export_error}");
            }
            return Err(run_error);
        }
    };
    if let Err(cleanup_error) = interception_cleanup_result {
        if let Err(l7_mitm_error) = l7_mitm_backend_lifecycle_cleanup_result {
            eprintln!(
                "L7 MITM backend lifecycle cleanup failed after transparent interception cleanup error: {l7_mitm_error}"
            );
        }
        if let Err(export_error) = drain_result {
            eprintln!("transparent interception cleanup failed: {cleanup_error}");
            eprintln!(
                "tail export drain failed after transparent interception cleanup error: {export_error}"
            );
        }
        return Err(cleanup_error.into());
    }
    if let Err(l7_mitm_error) = l7_mitm_backend_lifecycle_cleanup_result {
        if let Err(export_error) = drain_result {
            eprintln!(
                "tail export drain failed after L7 MITM backend lifecycle cleanup error: {export_error}"
            );
        }
        return Err(l7_mitm_error);
    }
    if let Err(export_error) = drain_result {
        return Err(export_error.into());
    }
    Ok(summary)
}

fn admin_server_config_from_plan(plan: &RuntimePlan) -> Option<AdminServerConfig> {
    plan.config.admin.enabled.then(|| {
        let config = AdminServerConfig::unix_socket(plan.config.admin.socket_path.clone());
        if plan.config.admin.prometheus.enabled {
            config.with_prometheus(PrometheusListenerConfig {
                listen_addr: plan.config.admin.prometheus.listen_addr,
            })
        } else {
            config
        }
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

    const READINESS_SIGNAL_TIMEOUT: Duration = Duration::from_secs(15);
    const RUN_FINISH_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn live_capture_run_options_stop_when_max_events_are_exhausted() {
        let shutdown_requested = shutdown::new_flag();

        let options = live_capture_run_options(Some(7), 7, &shutdown_requested);

        assert!(options.is_none());
    }

    #[test]
    fn live_capture_run_options_batch_provider_polls() {
        let shutdown_requested = shutdown::new_flag();

        let options = live_capture_run_options(Some(7), 5, &shutdown_requested)
            .expect("remaining events should produce a provider batch");

        assert_eq!(options.max_events, Some(2));
        assert_eq!(options.max_polls, Some(LIVE_CAPTURE_BATCH_POLLS));
    }

    #[test]
    fn live_capture_handoff_drain_options_keep_the_remaining_event_budget() {
        let shutdown_requested = shutdown::new_flag();

        let options = live_capture_handoff_drain_options(Some(7), 5, &shutdown_requested)
            .expect("remaining events should produce a handoff drain batch");

        assert_eq!(options.max_events, Some(2));
        assert_eq!(
            options.max_polls,
            Some(RUNTIME_GENERATION_HANDOFF_DRAIN_POLLS)
        );
    }

    #[test]
    fn live_capture_shutdown_drain_options_ignore_shutdown_cancellation() {
        let options = live_capture_shutdown_drain_options(Some(7), 5)
            .expect("remaining events should produce a shutdown drain batch");

        assert_eq!(options.max_events, Some(2));
        assert_eq!(
            options.max_polls,
            Some(RUNTIME_GENERATION_HANDOFF_DRAIN_POLLS)
        );
        assert!(!options.cancellation.is_cancelled());
    }

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
                                config_path: None,
                                readiness,
                                control_readiness: ReadinessSignal::None,
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
        match run_done_receiver.recv_timeout(RUN_FINISH_TIMEOUT) {
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
    async fn control_readiness_is_signaled_before_provider_open_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let missing_feed_path = temp.path().join("missing-feed.jsonl");
        let control_ready_path = temp.path().join("control-ready.sock");
        let control_ready_listener = UnixListener::bind(&control_ready_path)?;
        let data_ready_path = temp.path().join("data-ready.sock");
        let data_ready_listener = UnixListener::bind(&data_ready_path)?;
        let config = plaintext_feed_config(missing_feed_path, temp.path().join("spool"));

        let error = run_live_agent(
            config,
            RunOptions {
                max_events: Some(0),
                config_path: None,
                readiness: ReadinessSignal::UnixSocket(data_ready_path),
                control_readiness: ReadinessSignal::UnixSocket(control_ready_path),
            },
        )
        .await
        .expect_err("missing feed should fail after control readiness and before data readiness");

        assert!(
            matches!(error, AgentError::PlaintextFeed(_)),
            "unexpected error: {error:?}"
        );
        control_ready_listener.set_nonblocking(true)?;
        let (mut stream, _) = control_ready_listener.accept()?;
        let mut ready = [0_u8; 6];
        stream.read_exact(&mut ready)?;
        assert_eq!(&ready, b"ready\n");
        data_ready_listener.set_nonblocking(true)?;
        assert!(matches!(
            data_ready_listener.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
        Ok(())
    }

    fn wait_for_ready_socket(
        listener: &UnixListener,
        run_done_receiver: &Receiver<Result<(), String>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + READINESS_SIGNAL_TIMEOUT;
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

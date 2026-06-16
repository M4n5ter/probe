use std::sync::Arc;

use parsers::Http1ParserFactory;
use pipeline::{CapturePipeline, PipelineRunOptions, PipelineRuntimeMetrics, PipelineSummary};
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
    storage_retention::{StorageRetentionWorkerConfig, spawn_storage_retention_workers},
    tls_plaintext::TlsPlaintextRuntimeState,
};

const INGRESS_RECOVERY_BATCH_SIZE: usize = 1_024;

pub(crate) async fn run_live_agent(
    agent_config: AgentConfig,
    max_events: Option<u64>,
) -> Result<(), AgentError> {
    validate_static_runtime_config(&agent_config)?;
    let runtime = build_runtime_composition(agent_config)?;
    let (plan, enforcement_backend, transparent_interception) = runtime.into_run_parts();
    let mut enforcement =
        build_configured_enforcement_with_backend(&plan, enforcement_backend).await?;
    let policies = load_configured_pipeline_policies(&plan.config)?;
    let spool = Arc::new(FjallSpool::open(&plan.config.storage.path)?);
    let mut parser_factory = Http1ParserFactory::default();
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
    let mut storage_retention_config = storage_retention_worker_config_from_plan(&plan);
    let mut storage_retention_worker = None;
    let mut pipeline = CapturePipeline::new(
        spool.as_ref(),
        &mut parser_factory,
        policy_set,
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
    let mut transparent_interception_guard = None;
    let shutdown_requested = shutdown::new_flag();
    let shutdown_signal_task = shutdown::spawn_signal_task(Arc::clone(&shutdown_requested));
    let summary_result = (|| {
        let mut summary =
            pipeline.recover_ingress_journal_until_idle(INGRESS_RECOVERY_BATCH_SIZE)?;
        if shutdown::requested(&shutdown_requested) {
            return Ok(summary);
        }
        storage_retention_worker = storage_retention_config
            .take()
            .map(|config| spawn_storage_retention_workers(Arc::clone(&spool), config));
        let mut pipeline = pipeline.with_enforcement_planner(&mut enforcement.planner);
        transparent_interception_guard =
            transparent_interception.activate(enforcement.effective_selector.as_ref())?;
        let mut provider = build_capture_provider(&plan, Some(&tls_plaintext_runtime))?;
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
    shutdown_signal_task.abort();
    if let Some(server) = admin_server {
        server.stop().await;
    }
    if let Some(worker) = export_worker {
        worker.stop().await;
    }
    if let Some(worker) = storage_retention_worker {
        worker.stop().await;
    }
    let interception_cleanup_result = match transparent_interception_guard {
        Some(guard) => guard.deactivate(),
        None => Ok(()),
    };
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

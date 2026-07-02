use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use runtime::RuntimePlan;
use storage::FjallSpool;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, UnixListener, UnixStream},
    sync::Notify,
    task::JoinSet,
};

use pipeline::{PipelinePolicySet, PipelineRuntimeMetrics};

use super::{
    config_reload::plan_config_reload,
    debug_dump::AdminDebugDump,
    event_tail::{EventTailRequest, read_event_tail},
    protocol::{AdminRequest, AdminResponse, read_admin_request},
    reload::{RuntimeReloadAction, reload_action_response, reload_runtime_actions_response},
    socket::{AdminError, AdminServerConfig, bind_admin_socket, bind_prometheus_listener},
};
use crate::capture_provider::CaptureProviderRuntimeState;
use crate::configured_enforcement::EnforcementRuntimeState;
use crate::enforcement_reload::EnforcementReloadGate;
use crate::export::ExportWorkerRuntimeState;
use crate::l7_mitm::L7MitmRuntimeHandle;
use crate::policy_reload::PolicyReloadGate;
use crate::status::{
    AgentStatusSnapshot, EnforcementRuntimeStatusInput, PROMETHEUS_TEXT_CONTENT_TYPE,
    RuntimeStatusInput, build_status_snapshot_with_runtime, collect_running_spool_status,
    render_prometheus_metrics,
};
use crate::tls_plaintext::{TlsDecryptHintRuntimeState, TlsPlaintextRuntimeState};
use crate::transparent_interception::TransparentProxyRuntimeHandle;

const ADMIN_REQUEST_TIMEOUT: Duration = Duration::from_millis(500);
const ADMIN_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
pub struct AdminRuntimeState {
    pub capture: CaptureProviderRuntimeState,
    pub enforcement: Option<EnforcementRuntimeState>,
    pub enforcement_reload_gate: EnforcementReloadGate,
    pub export_worker: Option<ExportWorkerRuntimeState>,
    pub pipeline: Option<PipelineRuntimeMetrics>,
    pub policy_reload_gate: PolicyReloadGate,
    pub policy_set: PipelinePolicySet,
    pub tls_decrypt_hints: Option<TlsDecryptHintRuntimeState>,
    pub tls_plaintext: Option<TlsPlaintextRuntimeState>,
    pub l7_mitm: Option<L7MitmRuntimeHandle>,
    pub transparent_proxy: Option<TransparentProxyRuntimeHandle>,
}

pub struct AdminServerHandle {
    socket_path: PathBuf,
    #[cfg(test)]
    prometheus_listen_addr: Option<std::net::SocketAddr>,
    stop_requested: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

pub fn spawn_admin_server(
    plan: Arc<RuntimePlan>,
    spool: Arc<FjallSpool>,
    config: AdminServerConfig,
    runtime_state: AdminRuntimeState,
) -> Result<AdminServerHandle, AdminError> {
    let listener = bind_admin_socket(&config.socket_path)?;
    let prometheus_listener = match config.prometheus {
        Some(prometheus) => match bind_prometheus_listener(prometheus) {
            Ok(listener) => Some(listener),
            Err(error) => {
                let _ = fs::remove_file(&config.socket_path);
                return Err(error);
            }
        },
        None => None,
    };
    #[cfg(test)]
    let prometheus_listen_addr = prometheus_listener
        .as_ref()
        .and_then(|listener| listener.local_addr().ok());
    let stop_requested = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_shutdown = Arc::clone(&shutdown);
    let runtime_state = Arc::new(runtime_state);
    let task = tokio::spawn(async move {
        run_admin_surfaces(
            listener,
            prometheus_listener,
            plan,
            spool,
            runtime_state,
            task_stop_requested,
            task_shutdown,
        )
        .await;
    });

    Ok(AdminServerHandle {
        socket_path: config.socket_path,
        #[cfg(test)]
        prometheus_listen_addr,
        stop_requested,
        shutdown,
        task,
    })
}

impl AdminServerHandle {
    #[cfg(test)]
    pub fn prometheus_listen_addr(&self) -> Option<std::net::SocketAddr> {
        self.prometheus_listen_addr
    }

    pub async fn stop(mut self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        self.shutdown.notify_waiters();
        match tokio::time::timeout(ADMIN_SERVER_SHUTDOWN_TIMEOUT, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if !error.is_cancelled() => {
                eprintln!("admin server stopped with error: {error}");
            }
            Ok(Err(_)) => {}
            Err(_) => {
                self.task.abort();
                if let Err(error) = self.task.await
                    && !error.is_cancelled()
                {
                    eprintln!("admin server stopped with error: {error}");
                }
            }
        }
        if let Err(error) = fs::remove_file(&self.socket_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "failed to remove admin socket {}: {error}",
                self.socket_path.display()
            );
        }
    }
}

async fn run_admin_surfaces(
    listener: UnixListener,
    prometheus_listener: Option<TcpListener>,
    plan: Arc<RuntimePlan>,
    spool: Arc<FjallSpool>,
    runtime_state: Arc<AdminRuntimeState>,
    stop_requested: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
) {
    let mut surfaces = JoinSet::new();
    surfaces.spawn(accept_admin_connections(
        listener,
        Arc::clone(&plan),
        Arc::clone(&spool),
        Arc::clone(&runtime_state),
        Arc::clone(&stop_requested),
        Arc::clone(&shutdown),
    ));
    if let Some(prometheus_listener) = prometheus_listener {
        surfaces.spawn(super::prometheus::accept_connections(
            prometheus_listener,
            plan,
            spool,
            runtime_state,
            stop_requested,
            shutdown,
        ));
    }
    while let Some(result) = surfaces.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            eprintln!("admin surface task failed: {error}");
        }
    }
}

async fn accept_admin_connections(
    listener: UnixListener,
    plan: Arc<RuntimePlan>,
    spool: Arc<FjallSpool>,
    runtime_state: Arc<AdminRuntimeState>,
    stop_requested: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
) {
    let mut handlers = JoinSet::new();
    while !stop_requested.load(Ordering::Relaxed) {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let plan = Arc::clone(&plan);
                        let spool = Arc::clone(&spool);
                        let runtime_state = Arc::clone(&runtime_state);
                        handlers.spawn(async move {
                            if let Err(error) = handle_admin_connection(stream, plan, spool, runtime_state).await {
                                eprintln!("admin connection failed: {error}");
                            }
                        });
                    }
                    Err(error) => eprintln!("admin accept failed: {error}"),
                }
            }
            result = handlers.join_next(), if !handlers.is_empty() => {
                if let Some(Err(error)) = result
                    && !error.is_cancelled()
                {
                    eprintln!("admin connection task failed: {error}");
                }
            }
            () = shutdown.notified() => break,
        }
    }
    handlers.abort_all();
    while let Ok(Some(result)) =
        tokio::time::timeout(ADMIN_SERVER_SHUTDOWN_TIMEOUT, handlers.join_next()).await
    {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            eprintln!("admin connection task failed during shutdown: {error}");
        }
    }
}

async fn handle_admin_connection(
    mut stream: UnixStream,
    plan: Arc<RuntimePlan>,
    spool: Arc<FjallSpool>,
    runtime_state: Arc<AdminRuntimeState>,
) -> Result<(), std::io::Error> {
    let response =
        match tokio::time::timeout(ADMIN_REQUEST_TIMEOUT, read_admin_request(&mut stream)).await {
            Ok(Ok(request)) => {
                handle_admin_request(
                    request,
                    plan.as_ref(),
                    spool.as_ref(),
                    runtime_state.as_ref(),
                )
                .await
            }
            Ok(Err(error)) => AdminResponse::Error {
                message: error.to_string(),
            },
            Err(_) => AdminResponse::Error {
                message: format!(
                    "admin request timed out after {} ms",
                    ADMIN_REQUEST_TIMEOUT.as_millis()
                ),
            },
        };
    let mut bytes = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await
}

async fn handle_admin_request(
    request: AdminRequest,
    plan: &RuntimePlan,
    spool: &FjallSpool,
    runtime_state: &AdminRuntimeState,
) -> AdminResponse {
    match request {
        AdminRequest::ReloadPolicies => {
            reload_action_response(RuntimeReloadAction::ReloadPolicies, plan, runtime_state).await
        }
        AdminRequest::ReloadEnforcementPolicy => {
            reload_action_response(
                RuntimeReloadAction::ReloadEnforcementPolicy,
                plan,
                runtime_state,
            )
            .await
        }
        AdminRequest::ReloadRuntimeActions => {
            reload_runtime_actions_response(plan, runtime_state).await
        }
        AdminRequest::Status => {
            let snapshot = build_admin_status_snapshot(plan, spool, runtime_state);
            AdminResponse::Status {
                snapshot: Box::new(snapshot),
            }
        }
        AdminRequest::Metrics => {
            let snapshot = build_admin_status_snapshot(plan, spool, runtime_state);
            AdminResponse::Metrics {
                metrics: Box::new(snapshot.metrics),
            }
        }
        AdminRequest::PrometheusMetrics => {
            let snapshot = build_admin_status_snapshot(plan, spool, runtime_state);
            AdminResponse::PrometheusMetrics {
                content_type: PROMETHEUS_TEXT_CONTENT_TYPE,
                metrics: render_prometheus_metrics(&snapshot),
            }
        }
        AdminRequest::DebugDump => {
            let snapshot = build_admin_status_snapshot(plan, spool, runtime_state);
            AdminResponse::DebugDump {
                dump: Box::new(AdminDebugDump::new(snapshot)),
            }
        }
        AdminRequest::TailEvents {
            after_sequence,
            limit,
            selector,
        } => match read_event_tail(
            spool,
            EventTailRequest {
                after_sequence,
                limit,
                selector,
            },
        ) {
            Ok(tail) => AdminResponse::EventTail {
                tail: Box::new(tail),
            },
            Err(error) => AdminResponse::Error {
                message: error.to_string(),
            },
        },
        AdminRequest::PlanConfigReload { path } => plan_config_reload_response(plan, path).await,
    }
}

async fn plan_config_reload_response(plan: &RuntimePlan, path: PathBuf) -> AdminResponse {
    let current_config = plan.config.clone();
    match tokio::task::spawn_blocking(move || plan_config_reload(&current_config, &path)).await {
        Ok(plan) => AdminResponse::ConfigReloadPlan {
            plan: Box::new(plan),
        },
        Err(error) => AdminResponse::Error {
            message: format!("config reload planning task failed: {error}"),
        },
    }
}

pub(super) fn build_admin_status_snapshot(
    plan: &RuntimePlan,
    spool: &FjallSpool,
    runtime_state: &AdminRuntimeState,
) -> AgentStatusSnapshot {
    build_status_snapshot_with_runtime(
        plan,
        collect_running_spool_status(plan, spool),
        RuntimeStatusInput {
            capture: runtime_state.capture.snapshot(),
            capture_input: runtime_state.capture.input_activity_snapshot(),
            enforcement: runtime_state.enforcement.as_ref().map_or(
                EnforcementRuntimeStatusInput::OfflineInspect,
                |state| EnforcementRuntimeStatusInput::Runtime {
                    active_policy: Box::new(state.active_policy()),
                },
            ),
            export_worker: runtime_state
                .export_worker
                .as_ref()
                .map(ExportWorkerRuntimeState::snapshot),
            policy: Some(runtime_state.policy_set.runtime_snapshot()),
            pipeline: runtime_state
                .pipeline
                .as_ref()
                .map(PipelineRuntimeMetrics::snapshot),
            tls_decrypt_hints: runtime_state
                .tls_decrypt_hints
                .as_ref()
                .map(TlsDecryptHintRuntimeState::snapshot),
            tls_plaintext: runtime_state
                .tls_plaintext
                .as_ref()
                .map(TlsPlaintextRuntimeState::snapshot),
            l7_mitm: runtime_state
                .l7_mitm
                .as_ref()
                .map(L7MitmRuntimeHandle::snapshot),
            transparent_proxy: runtime_state
                .transparent_proxy
                .as_ref()
                .map(TransparentProxyRuntimeHandle::snapshot),
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use capture::ReplayProvider;
    use enforcement::{EnforcementPlanRequest, EnforcementPlanner, ScopedEnforcementPlanner};
    use parsers::Http1ParserFactory;
    use pipeline::{CapturePipeline, ExportEventWriter, PipelineRuntimeMetrics};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicyManifest,
        EnforcementPolicySourceConfig, ExporterConfig, LiveCaptureBackend,
    };
    use probe_core::{
        Action, AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource,
        Direction, EnforcementDecision, EnforcementMode, EnforcementOutcome, EventEnvelope,
        EventKind, FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity,
        ProcessSelector, ProtectiveActionProfile, RuntimeMode, Selector, SpoolPayloadSchema,
        Timestamp, TrafficSelector, TransportProtocol, Verdict, VerdictScope,
    };
    use runtime::{
        CaptureEvidenceMode, CapturePlanMode, CaptureProviderBuilder, CaptureProviderDescriptor,
        ProviderRegistry, RuntimePlan,
    };
    use serde_json::json;
    use storage::SpoolPayload;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    use super::*;
    use crate::configured_enforcement::LoadedEnforcementPolicySource;

    #[tokio::test]
    async fn admin_status_request_returns_running_spool_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-status")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"one",
        ))?;
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            AdminRuntimeState::default(),
        )?;

        let response = send_admin_request(&socket_path, json!({ "command": "status" })).await?;

        assert_eq!(response["kind"], json!("status"));
        assert_eq!(
            response["snapshot"]["spool"]["mode"],
            json!(RuntimeMode::Available)
        );
        assert_eq!(
            response["snapshot"]["spool"]["export_last_sequence"],
            json!(1)
        );
        assert_eq!(response["snapshot"]["exporters"][0]["cursor"], json!(0));

        let client_response =
            crate::admin::send_admin_json_request(&socket_path, crate::admin::AdminRequest::Status)
                .await?;

        assert_eq!(client_response["kind"], json!("status"));
        assert_eq!(
            client_response["snapshot"]["spool"]["export_last_sequence"],
            json!(1)
        );

        server.stop().await;
        assert!(!socket_path.exists());
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_tail_events_filters_export_events_without_advancing_sink_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-tail-events")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        ExportEventWriter::new(spool.as_ref()).append_occurrence(&request_event(80))?;
        ExportEventWriter::new(spool.as_ref()).append_occurrence(&request_event(8080))?;
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            AdminRuntimeState::default(),
        )?;

        let response = crate::admin::send_admin_json_request(
            &socket_path,
            crate::admin::AdminRequest::TailEvents {
                after_sequence: 0,
                limit: 10,
                selector: Some(Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        remote_ports: vec![8080],
                        directions: vec![Direction::Outbound],
                        ..TrafficSelector::default()
                    },
                )),
            },
        )
        .await?;

        assert_eq!(response["kind"], json!("event_tail"));
        assert_eq!(response["tail"]["scanned"], json!(2));
        assert_eq!(response["tail"]["next_after_sequence"], json!(2));
        let events = response["tail"]["events"]
            .as_array()
            .ok_or_else(|| std::io::Error::other("tail events should be an array"))?;
        assert_eq!(events.len(), 1);
        assert_eq!(
            response["tail"]["events"][0]["event"]["kind"]["target"],
            json!("/")
        );
        assert_eq!(
            response["tail"]["events"][0]["event"]["subject"]["flow"]["remote"]["port"],
            json!(8080)
        );
        assert_eq!(spool.export_cursor("primary")?, 0);

        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_debug_dump_returns_status_protocol_and_privacy_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-debug-dump")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            b"one",
        ))?;
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            AdminRuntimeState::default(),
        )?;

        let response = send_admin_request(&socket_path, json!({ "command": "debug_dump" })).await?;

        assert_eq!(response["kind"], json!("debug_dump"));
        assert_eq!(
            response["dump"]["status"]["spool"]["export_last_sequence"],
            json!(1)
        );
        assert_eq!(response["dump"]["protocol"]["framing"], json!("json_lines"));
        assert_eq!(
            response["dump"]["protocol"]["request_max_bytes"],
            json!(4096)
        );
        assert_eq!(
            response["dump"]["protocol"]["commands"],
            json!([
                { "name": "status", "mutating": false },
                { "name": "metrics", "mutating": false },
                { "name": "prometheus_metrics", "mutating": false },
                { "name": "debug_dump", "mutating": false },
                { "name": "tail_events", "mutating": false },
                { "name": "plan_config_reload", "mutating": false },
                { "name": "reload_runtime_actions", "mutating": true },
                { "name": "reload_policies", "mutating": true },
                { "name": "reload_enforcement_policy", "mutating": true },
            ])
        );
        assert_eq!(
            response["dump"]["privacy"],
            json!({
                "includes_raw_config": false,
                "includes_runtime_plan": true,
                "includes_local_paths": true,
                "includes_secret_material_bytes": false,
            })
        );
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_plan_config_reload_reports_restart_required_sections()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-config-reload-plan")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let mut config = config_with_storage_path(spool_path.clone());
        config.config_version = "current".to_string();
        let plan = Arc::new(runtime_plan_from_config(config.clone())?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            AdminRuntimeState::default(),
        )?;
        let mut candidate = config;
        candidate.config_version = "candidate".to_string();
        candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        let candidate_path = temp.join("candidate.toml");
        fs::write(&candidate_path, toml::to_string(&candidate)?)?;

        let response = send_admin_request(
            &socket_path,
            json!({
                "command": "plan_config_reload",
                "path": candidate_path,
            }),
        )
        .await?;

        assert_eq!(response["kind"], json!("config_reload_plan"));
        assert_eq!(
            response["plan"]["decision"]["kind"],
            json!("restart_required")
        );
        assert_eq!(
            response["plan"]["candidate_config_version"],
            json!("candidate")
        );
        assert!(
            response["plan"]["changed_sections"]
                .as_array()
                .expect("changed sections should be an array")
                .iter()
                .any(|change| change["section"] == json!("agent_identity"))
        );
        assert!(
            response["plan"]["changed_sections"]
                .as_array()
                .expect("changed sections should be an array")
                .iter()
                .any(|change| change["section"] == json!("capture"))
        );

        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_metrics_requests_return_json_and_prometheus_views()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-metrics")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let pipeline_metrics = PipelineRuntimeMetrics::default();
        {
            let mut parser_factory = Http1ParserFactory::default();
            let mut provider = ReplayProvider::new(
                demo_flow(),
                Direction::Outbound,
                b"GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n",
                Timestamp {
                    monotonic_ns: 1,
                    wall_time_unix_ns: 1,
                },
            );
            let mut pipeline =
                CapturePipeline::new(spool.as_ref(), &mut parser_factory, Vec::new(), "test")
                    .with_runtime_metrics(pipeline_metrics.clone());
            pipeline.run_provider(&mut provider)?;
        }
        let plan = Arc::new(runtime_plan(spool_path)?);
        let capture_runtime = CaptureProviderRuntimeState::default();
        capture_runtime.record(crate::capture_provider::CaptureProviderRuntimeSnapshot {
            selected_backend: CaptureBackend::Replay,
            plan_mode: CapturePlanMode::Replay,
            provider_runtime_mode: RuntimeMode::Available,
            evidence_mode: CaptureEvidenceMode::Nominal,
            evidence_reason: None,
            reason: None,
            open_failures: Vec::new(),
            provider: None,
        });
        let mut observed_capture_input =
            capture_runtime.observe_capture_input(Box::new(ReplayProvider::new(
                demo_flow(),
                Direction::Outbound,
                b"GET /capture-input HTTP/1.1\r\nHost: test\r\n\r\n",
                Timestamp {
                    monotonic_ns: 2,
                    wall_time_unix_ns: 2,
                },
            )));
        assert!(matches!(
            observed_capture_input.poll_next()?,
            capture::CapturePoll::Event(_)
        ));
        let transparent_proxy_runtime = crate::transparent_interception::resolve(
            plan.enforcement.interception.execution.clone(),
        )
        .proxy_runtime_handle();
        let l7_mitm_runtime = crate::l7_mitm::resolve(&plan.config).handle();
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            AdminRuntimeState {
                capture: capture_runtime,
                pipeline: Some(pipeline_metrics),
                l7_mitm: Some(l7_mitm_runtime),
                transparent_proxy: Some(transparent_proxy_runtime),
                ..AdminRuntimeState::default()
            },
        )?;

        let response = send_admin_request(&socket_path, json!({ "command": "metrics" })).await?;

        assert_eq!(response["kind"], json!("metrics"));
        assert_eq!(response["metrics"]["export"]["sink_count"], json!(1));
        assert_eq!(
            response["metrics"]["pipeline"]["capture_events_read"],
            json!(1)
        );
        assert_eq!(
            response["metrics"]["pipeline"]["export_events_written"],
            json!(1)
        );
        assert_eq!(
            response["metrics"]["pipeline"]["capture_loss"]["events"],
            json!(0)
        );
        assert_eq!(
            response["metrics"]["pipeline"]["capture_loss"]["lost_events"],
            json!(0)
        );
        assert_eq!(
            response["metrics"]["capture_input"]["polls"]["events"],
            json!(1)
        );
        assert_eq!(
            response["metrics"]["capture_input"]["last_signal"]["kind"],
            json!("event")
        );
        assert_eq!(
            response["metrics"]["l7_mitm"]["backend_health"]["mode"],
            json!("disabled")
        );
        assert_eq!(
            response["metrics"]["l7_mitm"]["plaintext_bridge"]["mode"],
            json!("not_configured")
        );
        assert_eq!(
            response["metrics"]["transparent_proxy"]["active_relays"],
            json!(0)
        );
        assert_eq!(
            response["metrics"]["transparent_proxy"]["upstream_connects"]["connect_successes"],
            json!(0)
        );

        let response = send_admin_request(&socket_path, json!({ "command": "status" })).await?;

        assert_eq!(
            response["snapshot"]["enforcement"]["interception"]["runtime_proxy"]["mode"],
            json!("disabled")
        );
        assert_eq!(
            response["snapshot"]["enforcement"]["interception"]["runtime_l7_mitm"]["backend_health"]
                ["mode"],
            json!("disabled")
        );
        assert_eq!(
            response["snapshot"]["enforcement"]["interception"]["runtime_l7_mitm"]["plaintext_bridge"]
                ["mode"],
            json!("not_configured")
        );
        assert_eq!(
            response["snapshot"]["capture"]["input_activity"]["polls"]["events"],
            json!(1)
        );

        let response =
            send_admin_request(&socket_path, json!({ "command": "prometheus_metrics" })).await?;

        assert_eq!(response["kind"], json!("prometheus_metrics"));
        assert_eq!(
            response["content_type"],
            json!(PROMETHEUS_TEXT_CONTENT_TYPE)
        );
        let metrics = response["metrics"]
            .as_str()
            .expect("prometheus metrics should be returned as text");
        assert!(metrics.contains("traffic_probe_pipeline_metrics_available 1\n"));
        assert!(metrics.contains("traffic_probe_l7_mitm_metrics_available 1\n"));
        assert!(metrics.contains("traffic_probe_transparent_proxy_metrics_available 1\n"));
        assert!(
            metrics.contains("traffic_probe_l7_mitm_backend_health_mode{mode=\"disabled\"} 1\n")
        );
        assert!(
            metrics.contains(
                "traffic_probe_l7_mitm_plaintext_bridge_mode{mode=\"not_configured\"} 1\n"
            )
        );
        assert!(metrics.contains(
            "traffic_probe_transparent_proxy_upstream_connects_total{outcome=\"success\"} 0\n"
        ));
        assert!(metrics.contains("traffic_probe_pipeline_capture_events_read_total 1\n"));
        assert!(metrics.contains("traffic_probe_capture_input_activity_available 1\n"));
        assert!(metrics.contains("traffic_probe_capture_input_polls_total{outcome=\"event\"} 1\n"));
        assert!(metrics.contains("traffic_probe_pipeline_export_events_written_total 1\n"));
        assert!(metrics.contains("traffic_probe_pipeline_capture_loss_events_total 0\n"));
        assert!(metrics.contains("traffic_probe_pipeline_capture_lost_events_total 0\n"));
        assert!(metrics.contains("traffic_probe_export_sink_lag{sink=\"primary\"} 1\n"));
        assert!(metrics.contains(
            "traffic_probe_capability_state{capability=\"replay_capture\",mode=\"available\"} 1\n"
        ));
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_status_reports_loaded_enforcement_policy_without_rereading_disk()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-loaded-enforcement-policy")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let manifest_path = temp.join("enforcement.toml");
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selectors: Default::default(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        fs::write(&manifest_path, toml::to_string(&manifest)?)?;
        let mut config = config_with_storage_path(spool_path.clone());
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path.clone(),
        };
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let runtime_state = AdminRuntimeState {
            enforcement: Some(enforcement_runtime(Some(
                LoadedEnforcementPolicySource::local(manifest_path.clone(), manifest),
            ))?),
            ..AdminRuntimeState::default()
        };
        fs::remove_file(&manifest_path)?;
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            runtime_state,
        )?;

        let response = send_admin_request(&socket_path, json!({ "command": "status" })).await?;

        assert_eq!(
            response["snapshot"]["enforcement"]["policy"]["source"]["mode"],
            json!("loaded")
        );
        assert_eq!(
            response["snapshot"]["enforcement"]["policy"]["source"]["source"]["kind"],
            json!("local")
        );
        assert_eq!(
            response["snapshot"]["enforcement"]["policy"]["source"]["source"]["path"],
            json!(manifest_path)
        );
        assert_eq!(
            response["snapshot"]["enforcement"]["policy"]["source"]["manifest"]["protective_actions"],
            json!(["deny"])
        );
        assert_eq!(response["snapshot"]["health"]["mode"], json!("available"));
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_reload_enforcement_policy_swaps_active_planner()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-enforcement-reload")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let manifest_path = temp.join("enforcement.toml");
        write_enforcement_manifest(&manifest_path, "initial", 80, Action::Deny)?;
        let mut config = config_with_storage_path(spool_path.clone());
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path.clone(),
        };
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let configured = crate::configured_enforcement::build_configured_enforcement_with_backend(
            &plan,
            None,
            crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let (mut planner_view, runtime_state) =
            EnforcementRuntimeState::from_planner(configured.planner, configured.active_policy);
        let initial_decision = enforcement_decision(&mut planner_view, Action::Deny, 80)?;
        assert_eq!(initial_decision.outcome, EnforcementOutcome::DryRun);
        assert!(initial_decision.selector_matched);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            AdminRuntimeState {
                enforcement: Some(runtime_state),
                ..AdminRuntimeState::default()
            },
        )?;
        write_enforcement_manifest(&manifest_path, "reloaded", 443, Action::Reset)?;

        let response = send_admin_request(
            &socket_path,
            json!({ "command": "reload_enforcement_policy" }),
        )
        .await?;

        assert_eq!(response["kind"], json!("enforcement_policy_reload"));
        assert_eq!(response["source"]["manifest"]["version"], json!("reloaded"));
        assert_eq!(response["effective_selector_configured"], json!(true));
        assert_eq!(response["manifest_selector_configured"], json!(true));
        assert_eq!(response["protective_actions"], json!(["reset"]));

        let old_scope_decision = enforcement_decision(&mut planner_view, Action::Deny, 80)?;
        assert_eq!(old_scope_decision.outcome, EnforcementOutcome::SelectorMiss);
        assert!(!old_scope_decision.selector_matched);

        let new_scope_decision = enforcement_decision(&mut planner_view, Action::Reset, 443)?;
        assert_eq!(new_scope_decision.outcome, EnforcementOutcome::DryRun);
        assert!(new_scope_decision.selector_matched);

        fs::write(&manifest_path, b"id = ")?;
        let failed_reload = send_admin_request(
            &socket_path,
            json!({ "command": "reload_enforcement_policy" }),
        )
        .await?;
        assert_eq!(failed_reload["kind"], json!("error"));
        assert!(
            failed_reload["message"]
                .as_str()
                .is_some_and(|message| message.contains("failed to reload enforcement policy"))
        );

        let retained_decision = enforcement_decision(&mut planner_view, Action::Reset, 443)?;
        assert_eq!(retained_decision.outcome, EnforcementOutcome::DryRun);
        assert!(retained_decision.selector_matched);

        let status = send_admin_request(&socket_path, json!({ "command": "status" })).await?;
        assert_eq!(
            status["snapshot"]["enforcement"]["policy"]["source"]["manifest"]["version"],
            json!("reloaded")
        );
        assert_eq!(
            status["snapshot"]["enforcement"]["policy"]["source"]["manifest"]["protective_actions"],
            json!(["reset"])
        );

        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_reload_runtime_actions_reports_each_action_independently()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-runtime-actions-reload")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            AdminRuntimeState::default(),
        )?;

        let response =
            send_admin_request(&socket_path, json!({ "command": "reload_runtime_actions" }))
                .await?;

        assert_eq!(response["kind"], json!("runtime_actions_reload"));
        assert_eq!(
            response["actions"][0],
            json!({
                "action": "reload_policies",
                "outcome": {
                    "result": "succeeded",
                    "loaded_count": 0,
                    "policies": [],
                    "active_set_updated": true,
                }
            })
        );
        assert_eq!(
            response["actions"][1]["action"],
            json!("reload_enforcement_policy")
        );
        assert_eq!(response["actions"][1]["outcome"]["result"], json!("failed"));
        assert!(
            response["actions"][1]["outcome"]["message"]
                .as_str()
                .is_some_and(
                    |message| message.contains("enforcement runtime state is not available")
                )
        );

        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_request_without_newline_times_out() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-timeout")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path.clone()),
            AdminRuntimeState::default(),
        )?;
        let mut stream = UnixStream::connect(&socket_path).await?;
        stream.write_all(b"{\"command\":\"status\"").await?;

        let response = read_admin_response(&mut stream).await?;

        assert_eq!(response["kind"], json!("error"));
        assert!(
            response["message"]
                .as_str()
                .is_some_and(|message| message.contains("timed out"))
        );
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    async fn send_admin_request(
        path: &Path,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(path).await?;
        let mut request_bytes = serde_json::to_vec(&request)?;
        request_bytes.push(b'\n');
        stream.write_all(&request_bytes).await?;
        read_admin_response(&mut stream).await
    }

    async fn read_admin_response(
        stream: &mut UnixStream,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut response = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let read = stream.read(&mut byte).await?;
            if read == 0 || byte[0] == b'\n' {
                break;
            }
            response.push(byte[0]);
        }
        Ok(serde_json::from_slice(&response)?)
    }

    fn runtime_plan(storage_path: PathBuf) -> Result<RuntimePlan, runtime::RuntimeError> {
        runtime_plan_from_config(config_with_storage_path(storage_path))
    }

    fn runtime_plan_from_config(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            test_platform_capabilities(),
        );
        RuntimePlan::build(config, &registry)
    }

    fn config_with_storage_path(storage_path: PathBuf) -> AgentConfig {
        AgentConfig {
            capture: probe_config::CaptureConfig {
                selection: CaptureSelection::Replay,
                ..Default::default()
            },
            storage: probe_config::StorageConfig {
                path: storage_path,
                ..Default::default()
            },
            exporters: vec![ExporterConfig {
                id: "primary".to_string(),
                transport: probe_config::ExporterTransportConfig::Webhook {
                    endpoint: "https://collector.example/batches".to_string(),
                    headers: BTreeMap::new(),
                    tls: Default::default(),
                },
                codec: probe_config::CompressionCodecName::None,
                worker: Default::default(),
            }],
            ..AgentConfig::default()
        }
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not built"),
        ]
    }

    fn enforcement_runtime(
        policy_source: Option<LoadedEnforcementPolicySource>,
    ) -> Result<EnforcementRuntimeState, enforcement::EnforcementError> {
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::AuditOnly, None)?;
        let protective_actions = policy_source
            .as_ref()
            .map_or_else(ProtectiveActionProfile::default, |source| {
                source.manifest.protective_actions.clone()
            });
        let effective_selector = policy_source
            .as_ref()
            .and_then(LoadedEnforcementPolicySource::resolved_selector)
            .cloned();
        let active_policy = crate::configured_enforcement::ActiveEnforcementPolicy::new(
            effective_selector,
            protective_actions,
            policy_source,
        )?;
        let (_, runtime_state) = EnforcementRuntimeState::from_planner(planner, active_policy);
        Ok(runtime_state)
    }

    fn write_enforcement_manifest(
        path: &Path,
        version: &str,
        remote_port: u16,
        action: Action,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: version.to_string(),
            selectors: Default::default(),
            selector: Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![remote_port],
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            )),
            protective_actions: ProtectiveActionProfile::new([action])?,
        };
        fs::write(path, toml::to_string(&manifest)?)?;
        Ok(())
    }

    fn enforcement_decision(
        planner: &mut impl EnforcementPlanner,
        action: Action,
        remote_port: u16,
    ) -> Result<EnforcementDecision, Box<dyn std::error::Error>> {
        let trigger = request_event(remote_port);
        let verdict = Verdict {
            action,
            scope: VerdictScope::Flow,
            reason: "managed policy".to_string(),
            confidence: 100,
            ttl_ms: None,
        };
        Ok(planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce enforcement audit"))
    }

    fn request_event(remote_port: u16) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow_with_remote_port(remote_port),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn demo_flow() -> FlowContext {
        demo_flow_with_remote_port(80)
    }

    fn demo_flow_with_remote_port(remote_port: u16) -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "replay".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: remote_port,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "replay".to_string(),
                cmdline: vec!["replay".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 0,
        }
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("{name}-{nanos}"));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }
}

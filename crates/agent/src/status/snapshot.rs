use std::time::{SystemTime, UNIX_EPOCH};

use pipeline::PipelineRuntimeMetricsSnapshot;
use probe_core::{CapabilityMatrix, RuntimeMode};
use runtime::RuntimePlan;
use serde::Serialize;

use crate::configured_enforcement::ActiveEnforcementPolicy;
use crate::export::ExportWorkerRuntimeSnapshot;
use crate::l7_mitm::L7MitmRuntimeSnapshot;
use crate::tls_plaintext::{TlsDecryptHintRuntimeSnapshot, TlsPlaintextRuntimeSnapshot};
use crate::transparent_interception::TransparentProxyRuntimeSnapshot;

use super::{
    capabilities::capabilities_with_runtime,
    capture::{CaptureStatusSnapshot, capture_status},
    enforcement::{
        EnforcementStatusSnapshot, enforcement_status_with_active_policy,
        enforcement_status_with_transparent_proxy,
    },
    export::{
        ExportStatusSnapshot, ExporterStatusSnapshot, export_status, exporter_statuses_with_runtime,
    },
    health::health_snapshot,
    metrics::{MetricsSnapshot, MetricsSnapshotInput, metrics_snapshot},
    policy::{PolicyStatusSnapshot, policy_status},
    spool::{SpoolStatusInput, SpoolStatusSnapshot},
    tls::{TlsStatusSnapshot, tls_status},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentStatusSnapshot {
    pub generated_unix_ns: u64,
    pub agent_id: String,
    pub config_version: String,
    pub health: HealthSnapshot,
    pub capture: CaptureStatusSnapshot,
    pub policy: PolicyStatusSnapshot,
    pub enforcement: EnforcementStatusSnapshot,
    pub tls: TlsStatusSnapshot,
    pub capabilities: CapabilityMatrix,
    pub spool: SpoolStatusSnapshot,
    pub export: ExportStatusSnapshot,
    pub exporters: Vec<ExporterStatusSnapshot>,
    pub metrics: MetricsSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthSnapshot {
    pub mode: RuntimeMode,
    pub reasons: Vec<String>,
}

#[derive(Clone, Default)]
pub struct RuntimeStatusInput {
    pub capture: Option<crate::capture_provider::CaptureProviderRuntimeSnapshot>,
    pub capture_input: Option<crate::capture_provider::CaptureInputActivityRuntimeSnapshot>,
    pub enforcement: EnforcementRuntimeStatusInput,
    pub export_worker: Option<ExportWorkerRuntimeSnapshot>,
    pub pipeline: Option<PipelineRuntimeMetricsSnapshot>,
    pub tls_decrypt_hints: Option<TlsDecryptHintRuntimeSnapshot>,
    pub tls_plaintext: Option<TlsPlaintextRuntimeSnapshot>,
    pub l7_mitm: Option<L7MitmRuntimeSnapshot>,
    pub transparent_proxy: Option<TransparentProxyRuntimeSnapshot>,
}

#[derive(Clone, Default)]
pub enum EnforcementRuntimeStatusInput {
    #[default]
    OfflineInspect,
    Runtime {
        active_policy: Box<ActiveEnforcementPolicy>,
    },
}

pub fn build_status_snapshot(plan: &RuntimePlan, spool: SpoolStatusInput) -> AgentStatusSnapshot {
    build_status_snapshot_at(plan, spool, current_unix_time_ns())
}

pub fn build_status_snapshot_with_runtime(
    plan: &RuntimePlan,
    spool: SpoolStatusInput,
    runtime: RuntimeStatusInput,
) -> AgentStatusSnapshot {
    build_status_snapshot_at_with_runtime(plan, spool, current_unix_time_ns(), runtime)
}

pub(in crate::status) fn build_status_snapshot_at(
    plan: &RuntimePlan,
    spool: SpoolStatusInput,
    generated_unix_ns: u64,
) -> AgentStatusSnapshot {
    build_status_snapshot_at_with_runtime(
        plan,
        spool,
        generated_unix_ns,
        RuntimeStatusInput::default(),
    )
}

fn build_status_snapshot_at_with_runtime(
    plan: &RuntimePlan,
    spool: SpoolStatusInput,
    generated_unix_ns: u64,
    runtime: RuntimeStatusInput,
) -> AgentStatusSnapshot {
    let spool_snapshot = spool.snapshot;
    let spool_status = SpoolStatusSnapshot {
        path: spool.path,
        mode: spool.mode,
        reason: spool.reason,
        ingress_retention: plan.storage.retention.ingress.clone(),
        ingress_last_sequence: spool_snapshot.map(|snapshot| snapshot.last_ingress_sequence),
        export_last_sequence: spool_snapshot.map(|snapshot| snapshot.last_export_sequence),
    };
    let capture = capture_status(plan, runtime.capture.clone(), runtime.capture_input.clone());
    let policy = policy_status(plan);
    let transparent_proxy = runtime.transparent_proxy.clone();
    let l7_mitm = runtime.l7_mitm.clone();
    let enforcement = match &runtime.enforcement {
        EnforcementRuntimeStatusInput::OfflineInspect => enforcement_status_with_transparent_proxy(
            plan,
            l7_mitm.clone(),
            transparent_proxy.clone(),
        ),
        EnforcementRuntimeStatusInput::Runtime { active_policy } => {
            enforcement_status_with_active_policy(
                plan,
                active_policy,
                l7_mitm.clone(),
                transparent_proxy.clone(),
            )
        }
    };
    let capabilities = capabilities_with_runtime(
        plan,
        runtime.capture.as_ref(),
        runtime.tls_plaintext.as_ref(),
    );
    let tls = tls_status(
        plan,
        &capabilities,
        runtime.tls_plaintext.clone(),
        runtime.tls_decrypt_hints.clone(),
    );
    let export = export_status(plan);
    let exporters = exporter_statuses_with_runtime(
        plan,
        &spool_status,
        &spool.export_cursors,
        runtime.export_worker.as_ref(),
    );
    let pipeline = runtime.pipeline;
    let capture_input_activity = capture.input_activity.clone();
    let capture_loss = pipeline.as_ref().map(|metrics| &metrics.capture_loss);
    let metrics = metrics_snapshot(MetricsSnapshotInput {
        capabilities: &capabilities,
        capture_input: capture_input_activity,
        spool: &spool_status,
        exporters: &exporters,
        export_worker: runtime.export_worker.as_ref(),
        l7_mitm,
        transparent_proxy,
        tls_plaintext: runtime.tls_plaintext,
        pipeline,
    });
    let health = health_snapshot(
        &capture,
        &spool_status,
        &exporters,
        &policy,
        &enforcement,
        &tls,
        capture_loss,
    );

    AgentStatusSnapshot {
        generated_unix_ns,
        agent_id: plan.config.agent_id.clone(),
        config_version: plan.config.config_version.clone(),
        health,
        capture,
        policy,
        enforcement,
        tls,
        capabilities,
        spool: spool_status,
        export,
        exporters,
        metrics,
    }
}

fn current_unix_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use super::super::plan_fixture::{
        config_with_storage_path, runtime_plan_from_config, test_dir,
    };
    use super::*;
    use probe_config::{
        CaptureBackend, CaptureSelection, EnforcementPolicyManifest, EnforcementPolicySourceConfig,
        TlsMaterialConfig, TlsMaterialKind,
    };
    use probe_core::{
        Action, CapabilityKind, CapabilityState, Direction, EnforcementMode, ProcessSelector,
        ProtectiveActionProfile, Selector, TrafficSelector,
    };
    use runtime::{
        CaptureEvidenceMode, CapturePlanMode, ExportFailureBackoffPlan, ExportWorkerPlan,
        RuntimePlan,
    };
    use serde_json::json;
    use storage::SpoolSnapshot;

    use crate::{
        capture_provider::{
            CaptureInputActivityRuntimeSnapshot, CaptureInputPollActivityRuntimeSnapshot,
            CaptureInputSignalRuntimeSnapshot, CaptureProviderRuntimeSnapshot,
        },
        configured_enforcement::ActiveEnforcementPolicy,
        tls_plaintext::{
            TlsPlaintextProviderActivityRuntimeSnapshot, TlsPlaintextProviderSignalRuntimeSnapshot,
            TlsPlaintextRuntimeMode, TlsPlaintextRuntimeSnapshot,
        },
        transparent_interception::{
            TransparentProxyHealthProbeMode, TransparentProxyRuntimeMode,
            TransparentProxyRuntimeSnapshot,
        },
    };

    #[test]
    fn status_snapshot_reports_sink_lag_and_health() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool"));
        config.storage.retention.ingress.max_age_ms = Some(120_000);
        config.storage.retention.ingress.max_records = Some(10_000);
        config.storage.retention.ingress.sweep_interval_ms = 7_000;
        config.storage.retention.ingress.prune_batch_limit = 256;
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 7,
                last_export_sequence: 5,
            },
            BTreeMap::from([("primary".to_string(), 3)]),
        );

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.generated_unix_ns, 42);
        assert_eq!(snapshot.health.mode, RuntimeMode::Available);
        assert_eq!(snapshot.spool.export_last_sequence, Some(5));
        assert_eq!(snapshot.spool.ingress_retention.max_age_ms, Some(120_000));
        assert_eq!(snapshot.spool.ingress_retention.max_records, Some(10_000));
        assert_eq!(
            snapshot.spool.ingress_retention.sweep_interval_ms.get(),
            7_000
        );
        assert_eq!(
            snapshot.spool.ingress_retention.prune_batch_limit.get(),
            256
        );
        assert_eq!(snapshot.exporters.len(), 1);
        assert_eq!(snapshot.exporters[0].cursor, Some(3));
        assert_eq!(snapshot.exporters[0].lag, Some(2));
        assert_eq!(
            snapshot.exporters[0].worker,
            ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 1_000,
                batches_per_sink_per_tick: 1,
                sink_timeout_ms: 10_000,
                failure_backoff: ExportFailureBackoffPlan {
                    initial_ms: 30_000,
                    max_ms: 300_000,
                    multiplier: 2,
                },
            }
        );
        assert_eq!(
            snapshot.exporters[0].sink_worker.batches_per_tick_override,
            None
        );
        assert_eq!(
            snapshot.exporters[0]
                .sink_worker
                .effective_batches_per_tick
                .get(),
            1
        );
        assert!(snapshot.policy.active.is_empty());
        assert!(snapshot.tls.materials.is_empty());
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(snapshot.metrics.export.backing_off_sink_count, None);
        assert!(snapshot.metrics.pipeline.is_none());
        assert_eq!(value["policy"]["mode"], json!("inactive"));
        assert_eq!(value["enforcement"]["status"], json!("audit_only"));
        assert_eq!(value["metrics"]["pipeline"], json!(null));
        assert_eq!(
            value["enforcement"]["mode_capability"]["kind"],
            json!("not_required")
        );
        assert_eq!(
            value["enforcement"]["policy"]["source"]["mode"],
            json!("not_configured")
        );
        assert_eq!(
            value["tls"]["plaintext"]["instrumentation"]["capability"]["kind"],
            json!("not_required")
        );
        assert_eq!(
            value["spool"]["ingress_retention"]["max_age_ms"],
            json!(120_000)
        );
        assert_eq!(
            value["spool"]["ingress_retention"]["max_records"],
            json!(10_000)
        );
        assert_eq!(
            value["spool"]["ingress_retention"]["sweep_interval_ms"],
            json!(7_000)
        );
        assert_eq!(
            value["spool"]["ingress_retention"]["prune_batch_limit"],
            json!(256)
        );
        assert_eq!(snapshot.metrics.export.total_lag, Some(2));
        Ok(())
    }

    #[test]
    fn status_snapshot_serializes_transparent_classifier_capabilities()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            vec![
                runtime::PlatformProbeResults::default_transparent_process_classifier(),
                runtime::PlatformProbeResults::default_transparent_flow_classifier(),
            ],
        )?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::new(),
        );

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            status_capability(&value, "transparent_process_classifier")["mode"],
            json!("unavailable")
        );
        assert_eq!(
            status_capability(&value, "transparent_process_classifier")["reason"],
            json!(
                "transparent process classifier capability is not provided by this runtime registry"
            )
        );
        assert_eq!(
            status_capability(&value, "transparent_flow_classifier")["mode"],
            json!("unavailable")
        );
        assert_eq!(
            status_capability(&value, "transparent_flow_classifier")["reason"],
            json!(
                "transparent flow classifier backend is not configured; not/ref transparent interception selectors and any selectors with classifier-only or unconstrained setup branches require flow-aware classification before rule installation"
            )
        );
        Ok(())
    }

    #[test]
    fn status_snapshot_reports_export_worker_runtime_metrics()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_exporter()?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 5,
            },
            BTreeMap::from([("primary".to_string(), 3)]),
        );
        let runtime = RuntimeStatusInput {
            export_worker: Some(ExportWorkerRuntimeSnapshot {
                sinks: BTreeMap::from([(
                    "primary".to_string(),
                    crate::export::ExportSinkWorkerRuntimeSnapshot {
                        mode: crate::export::ExportSinkWorkerRuntimeMode::BackingOff,
                        consecutive_failures: 1,
                        backoff_delay_ms: Some(30_000),
                        backoff_remaining_ms: Some(20_000),
                        last_failure_reason: Some(
                            crate::export::ExportDrainFailureReason::RemoteRejectedBatch,
                        ),
                    },
                )]),
            }),
            pipeline: Some(PipelineRuntimeMetricsSnapshot {
                capture_polls: pipeline::CapturePollRuntimeMetricsSnapshot {
                    total: 5,
                    events: 2,
                    progress: 1,
                    idle: 1,
                    finished: 1,
                },
                capture_events_read: 2,
                ingress_records_journaled: 2,
                ingress_records_recovered: 1,
                ingress_records_processed: 3,
                export_events_written: 7,
                events: pipeline::EventRuntimeMetricsSnapshot {
                    total: 7,
                    degraded: 2,
                    gaps: 1,
                },
                capture_loss: pipeline::CaptureLossRuntimeMetricsSnapshot {
                    events: 2,
                    lost_events: 11,
                },
                policy: pipeline::PolicyRuntimeMetricsSnapshot {
                    evaluations: 2,
                    selector_misses: 1,
                    alerts: 1,
                    verdicts: 1,
                    errors: 0,
                },
                enforcement: pipeline::EnforcementRuntimeMetricsSnapshot {
                    decisions: 1,
                    disabled: 0,
                    audit_only: 0,
                    dry_run: 1,
                    selector_miss: 0,
                    unsupported: 0,
                    failed: 0,
                    delegated: 0,
                    applied: 0,
                },
            }),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(&plan, spool, 42, runtime);

        assert_eq!(snapshot.metrics.export.total_lag, Some(2));
        assert_eq!(snapshot.metrics.export.backing_off_sink_count, Some(1));
        let pipeline_metrics = snapshot
            .metrics
            .pipeline
            .as_ref()
            .expect("runtime pipeline metrics should be reported");
        assert_eq!(pipeline_metrics.export_events_written, 7);
        assert_eq!(pipeline_metrics.capture_polls.progress, 1);
        assert_eq!(pipeline_metrics.policy.selector_misses, 1);
        assert_eq!(pipeline_metrics.enforcement.dry_run, 1);
        assert_eq!(
            snapshot.exporters[0]
                .runtime
                .as_ref()
                .expect("online worker runtime should be reported")
                .mode,
            crate::export::ExportSinkWorkerRuntimeMode::BackingOff
        );
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["metrics"]["export"]["backing_off_sink_count"],
            json!(1)
        );
        assert_eq!(
            value["metrics"]["pipeline"]["policy"]["selector_misses"],
            json!(1)
        );
        assert_eq!(
            value["metrics"]["pipeline"]["capture_polls"]["total"],
            json!(5)
        );
        assert_eq!(
            value["metrics"]["pipeline"]["capture_polls"]["idle"],
            json!(1)
        );
        assert_eq!(
            value["metrics"]["pipeline"]["capture_loss"]["events"],
            json!(2)
        );
        assert_eq!(value["metrics"]["pipeline"]["events"]["total"], json!(7));
        assert_eq!(value["metrics"]["pipeline"]["events"]["degraded"], json!(2));
        assert_eq!(value["metrics"]["pipeline"]["events"]["gaps"], json!(1));
        assert_eq!(
            value["metrics"]["pipeline"]["capture_loss"]["lost_events"],
            json!(11)
        );
        assert_eq!(
            value["metrics"]["pipeline"]["enforcement"]["dry_run"],
            json!(1)
        );
        assert_eq!(
            value["exporters"][0]["runtime"]["mode"],
            json!("backing_off")
        );
        Ok(())
    }

    #[test]
    fn status_snapshot_reports_capture_input_activity() -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_exporter()?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::new(),
        );
        let runtime = RuntimeStatusInput {
            capture: Some(CaptureProviderRuntimeSnapshot {
                selected_backend: CaptureBackend::Libpcap,
                plan_mode: CapturePlanMode::Live,
                provider_runtime_mode: RuntimeMode::Available,
                evidence_mode: CaptureEvidenceMode::BestEffort,
                evidence_reason: Some("libpcap stream assembly is best-effort".to_string()),
                reason: None,
                open_failures: Vec::new(),
                provider: None,
            }),
            capture_input: Some(CaptureInputActivityRuntimeSnapshot {
                polls: CaptureInputPollActivityRuntimeSnapshot {
                    total: 5,
                    events: 2,
                    progress: 1,
                    idle: 1,
                    finished: 1,
                },
                capture_events: 1,
                output_loss_events: 1,
                lost_events: 3,
                last_signal: Some(CaptureInputSignalRuntimeSnapshot::Idle {
                    sequence: 4,
                    observed_unix_ns: 99,
                }),
            }),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(&plan, spool, 42, runtime);

        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["capture"]["input_activity"]["polls"]["total"],
            json!(5)
        );
        assert_eq!(
            value["capture"]["input_activity"]["output_loss_events"],
            json!(1)
        );
        assert_eq!(value["metrics"]["capture_input"]["lost_events"], json!(3));
        assert_eq!(
            value["metrics"]["capture_input"]["last_signal"]["kind"],
            json!("idle")
        );
        assert_eq!(
            value["metrics"]["capture_input"]["last_signal"]["observed_unix_ns"],
            json!(99)
        );
        Ok(())
    }

    #[test]
    fn status_snapshot_degrades_health_for_capture_loss_metrics()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_exporter()?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::new(),
        );
        let runtime = RuntimeStatusInput {
            pipeline: Some(PipelineRuntimeMetricsSnapshot {
                capture_loss: pipeline::CaptureLossRuntimeMetricsSnapshot {
                    events: 0,
                    lost_events: 11,
                },
                ..PipelineRuntimeMetricsSnapshot::default()
            }),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(&plan, spool, 42, runtime);

        assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
        assert!(snapshot.health.reasons.iter().any(|reason| {
            reason.contains("0 loss event(s)") && reason.contains("11 lost event(s)")
        }));
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["metrics"]["pipeline"]["capture_loss"]["lost_events"],
            json!(11)
        );
        Ok(())
    }

    #[test]
    fn status_snapshot_reports_transparent_proxy_runtime_metrics()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_managed_transparent_proxy()?;
        let runtime = RuntimeStatusInput {
            enforcement: EnforcementRuntimeStatusInput::Runtime {
                active_policy: Box::new(ActiveEnforcementPolicy::new(
                    None,
                    ProtectiveActionProfile::default(),
                    None,
                )?),
            },
            transparent_proxy: Some(
                TransparentProxyRuntimeSnapshot::for_test(TransparentProxyRuntimeMode::Configured)
                    .with_relay_counts(2, 3, 5, 7, 11)
                    .with_upstream_connects(13, 17, Some("connection refused"))
                    .with_health_probe(TransparentProxyHealthProbeMode::Healthy, 19, 23, 0, None),
            ),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(
            &plan,
            available_spool_input(PathBuf::from("/tmp/traffic-probe-spool")),
            42,
            runtime,
        );

        let proxy_metrics = snapshot
            .metrics
            .transparent_proxy
            .expect("transparent proxy metrics should be reported");
        assert_eq!(proxy_metrics.active_relays, 2);
        assert_eq!(proxy_metrics.accepted_relays, 3);
        assert_eq!(proxy_metrics.rejected_relays, 5);
        assert_eq!(proxy_metrics.relay_failures, 7);
        assert_eq!(proxy_metrics.listener_failures, 11);
        assert_eq!(
            proxy_metrics.health_probe.mode,
            TransparentProxyHealthProbeMode::Healthy
        );
        assert_eq!(proxy_metrics.health_probe.check_successes, 19);
        assert_eq!(proxy_metrics.health_probe.check_failures, 23);
        assert_eq!(proxy_metrics.upstream_connects.connect_successes, 13);
        assert_eq!(proxy_metrics.upstream_connects.connect_failures, 17);
        let runtime_proxy = snapshot
            .enforcement
            .interception
            .runtime_proxy
            .as_ref()
            .expect("transparent proxy runtime should be reported");
        assert!(runtime_proxy.listener_families.is_empty());
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["enforcement"]["interception"]["runtime_proxy"]["mode"],
            json!("configured")
        );
        assert_eq!(
            value["metrics"]["transparent_proxy"]["active_relays"],
            json!(2)
        );
        assert_eq!(
            value["enforcement"]["interception"]["runtime_proxy"]["upstream_connects"]["connect_failures"],
            json!(17)
        );
        assert_eq!(
            value["metrics"]["transparent_proxy"]["health_probe"]["check_failures"],
            json!(23)
        );
        Ok(())
    }

    #[test]
    fn failed_transparent_proxy_runtime_makes_health_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_managed_transparent_proxy()?;
        let runtime = RuntimeStatusInput {
            enforcement: EnforcementRuntimeStatusInput::Runtime {
                active_policy: Box::new(ActiveEnforcementPolicy::new(
                    None,
                    ProtectiveActionProfile::default(),
                    None,
                )?),
            },
            transparent_proxy: Some(
                TransparentProxyRuntimeSnapshot::for_test(TransparentProxyRuntimeMode::Failed)
                    .with_relay_counts(0, 1, 0, 0, 1),
            ),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(
            &plan,
            available_spool_input(PathBuf::from("/tmp/traffic-probe-spool")),
            42,
            runtime,
        );

        assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("transparent proxy failed"))
        );
        Ok(())
    }

    #[test]
    fn unhealthy_transparent_proxy_health_probe_makes_health_degraded()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_managed_transparent_proxy()?;
        let runtime = RuntimeStatusInput {
            enforcement: EnforcementRuntimeStatusInput::Runtime {
                active_policy: Box::new(ActiveEnforcementPolicy::new(
                    None,
                    ProtectiveActionProfile::default(),
                    None,
                )?),
            },
            transparent_proxy: Some(
                TransparentProxyRuntimeSnapshot::for_test(TransparentProxyRuntimeMode::Running)
                    .with_health_probe(
                        TransparentProxyHealthProbeMode::Unhealthy,
                        0,
                        3,
                        3,
                        Some("connection refused"),
                    ),
            ),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(
            &plan,
            available_spool_input(PathBuf::from("/tmp/traffic-probe-spool")),
            42,
            runtime,
        );

        assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
        assert!(snapshot.health.reasons.iter().any(|reason| {
            reason.contains("transparent proxy health probe unhealthy")
                && reason.contains("connection refused")
        }));
        Ok(())
    }

    #[test]
    fn uninitialized_spool_makes_status_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_exporter()?;
        let spool = SpoolStatusInput::unavailable(
            PathBuf::from("/tmp/missing-traffic-probe-spool"),
            "spool is not initialized",
        );

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
        assert_eq!(snapshot.spool.mode, RuntimeMode::Unavailable);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| { reason.contains("spool is not initialized") })
        );
        assert_eq!(snapshot.exporters[0].mode, RuntimeMode::Unavailable);
        Ok(())
    }

    #[test]
    fn busy_spool_makes_status_degraded() -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_exporter()?;
        let spool = SpoolStatusInput::degraded(
            PathBuf::from("/tmp/busy-traffic-probe-spool"),
            "spool database is locked by another process",
        );

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
        assert_eq!(snapshot.spool.mode, RuntimeMode::Degraded);
        assert_eq!(snapshot.exporters[0].mode, RuntimeMode::Degraded);
        assert_eq!(snapshot.exporters[0].lag, None);
        Ok(())
    }

    #[test]
    fn degraded_capabilities_do_not_force_active_health() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = runtime_plan(
            PathBuf::from("/tmp/traffic-probe-spool"),
            vec![CapabilityState::degraded(
                CapabilityKind::PolicyRuntime,
                "policy state migration is not implemented",
            )],
        )?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::from([("primary".to_string(), 0)]),
        );

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.health.mode, RuntimeMode::Available);
        assert_eq!(snapshot.metrics.capabilities.degraded, 1);
        Ok(())
    }

    #[test]
    fn status_snapshot_reports_l7_mitm_as_unavailable_target_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan(
            PathBuf::from("/tmp/traffic-probe-spool"),
            vec![CapabilityState::unavailable(
                CapabilityKind::L7Mitm,
                "operator-visible L7 MITM unavailable reason",
            )],
        )?;
        let snapshot = build_status_snapshot_at(
            &plan,
            available_spool_input(PathBuf::from("/tmp/traffic-probe-spool")),
            42,
        );

        assert_eq!(
            snapshot.capabilities.mode(CapabilityKind::L7Mitm),
            RuntimeMode::Unavailable
        );
        let value = serde_json::to_value(&snapshot)?;
        let state = status_capability(&value, "l7_mitm");
        assert_eq!(state["mode"], json!("unavailable"));
        assert!(
            state["reason"]
                .as_str()
                .is_some_and(|reason| reason == "operator-visible L7 MITM unavailable reason")
        );
        Ok(())
    }

    #[test]
    fn tls_plaintext_runtime_disabled_degrades_status_capability_and_health()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool"));
        config.capture.selection = CaptureSelection::Libpcap;
        config.tls.plaintext.instrumentation.enabled = true;
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into());
        config.tls.plaintext.instrumentation.reconcile_interval_ms = 2_500;
        let plan = runtime_plan_from_config(
            config,
            vec![CapabilityState::degraded(
                CapabilityKind::LibsslUprobe,
                "libssl uprobe preflight passed but runtime remains best-effort",
            )],
        )?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::new(),
        );
        let runtime = RuntimeStatusInput {
            tls_plaintext: Some(TlsPlaintextRuntimeSnapshot::disabled(
                "libssl uprobe attach planning produced no attachable targets",
            )),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(&plan, spool, 42, runtime);

        assert_eq!(
            snapshot
                .tls
                .plaintext
                .instrumentation
                .runtime
                .as_ref()
                .expect("TLS plaintext runtime should be reported")
                .mode,
            TlsPlaintextRuntimeMode::Disabled
        );
        assert_eq!(
            snapshot.capabilities.mode(CapabilityKind::LibsslUprobe),
            RuntimeMode::Unavailable
        );
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["tls"]["plaintext"]["instrumentation"]["capability"]["mode"],
            json!("unavailable")
        );
        assert_eq!(
            value["tls"]["plaintext"]["instrumentation"]["reconcile_interval_ms"],
            json!(2500)
        );
        assert_eq!(snapshot.metrics.capabilities.unavailable, 1);
        assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("produced no attachable targets"))
        );
        Ok(())
    }

    #[test]
    fn tls_plaintext_runtime_activity_is_reported_in_status_metrics_json()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool"));
        config.capture.selection = CaptureSelection::Libpcap;
        config.tls.plaintext.instrumentation.enabled = true;
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into());
        let plan = runtime_plan_from_config(
            config,
            vec![CapabilityState::degraded(
                CapabilityKind::LibsslUprobe,
                "libssl uprobe preflight passed but runtime remains best-effort",
            )],
        )?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::new(),
        );
        let mut tls_plaintext = TlsPlaintextRuntimeSnapshot::enabled();
        tls_plaintext.provider_activity = TlsPlaintextProviderActivityRuntimeSnapshot {
            progress_signals: 2,
            capture_events: 3,
            output_loss_events: 5,
            lost_events: 17,
            last_signal: Some(TlsPlaintextProviderSignalRuntimeSnapshot::OutputLoss {
                sequence: 10,
                observed_unix_ns: 99,
                capture_timestamp: probe_core::Timestamp {
                    monotonic_ns: 7,
                    wall_time_unix_ns: 8,
                },
                lost_events: 11,
            }),
        };
        let runtime = RuntimeStatusInput {
            tls_plaintext: Some(tls_plaintext),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(&plan, spool, 42, runtime);

        let tls_metrics = snapshot
            .metrics
            .tls_plaintext
            .expect("enabled TLS plaintext runtime should expose activity metrics");
        assert_eq!(tls_metrics.provider_activity.progress_signals, 2);
        assert_eq!(tls_metrics.provider_activity.capture_events, 3);
        assert_eq!(tls_metrics.provider_activity.output_loss_events, 5);
        assert_eq!(tls_metrics.provider_activity.lost_events, 17);
        assert_eq!(
            tls_metrics
                .provider_activity
                .last_signal
                .expect("last activity signal should be projected")
                .kind,
            "output_loss"
        );
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["metrics"]["tls_plaintext"]["provider_activity"]["last_signal"]["kind"],
            json!("output_loss")
        );
        assert_eq!(
            value["metrics"]["tls_plaintext"]["provider_activity"]["lost_events"],
            json!(17)
        );
        Ok(())
    }

    #[test]
    fn tls_plaintext_runtime_not_configured_does_not_degrade_health()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::new(),
        );
        let runtime = RuntimeStatusInput {
            tls_plaintext: Some(TlsPlaintextRuntimeSnapshot::not_configured()),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(&plan, spool, 42, runtime);

        assert_eq!(snapshot.health.mode, RuntimeMode::Available);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .all(|reason| !reason.contains("TLS plaintext instrumentation"))
        );
        Ok(())
    }

    #[test]
    fn exporter_unavailability_forces_health_unavailable() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = runtime_plan_with_exporter()?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/traffic-probe-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 5,
            },
            BTreeMap::from([("primary".to_string(), 10)]),
        );

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("exporter primary"))
        );
        assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
        Ok(())
    }

    #[test]
    fn enforcement_metadata_source_degrades_overall_health()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-enforcement-metadata-health")?;
        let manifest_path = temp.join("enforcement.toml");
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: "test-version".to_string(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        };
        fs::write(&manifest_path, toml::to_string(&manifest)?)?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path,
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let snapshot =
            build_status_snapshot_at(&plan, available_spool_input(temp.join("spool")), 42);

        assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("enforcement policy") && reason.contains("metadata"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn enforcement_unavailable_source_forces_overall_health_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-enforcement-unavailable-health")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Directory {
            path: temp.join("missing-enforcement.d"),
        };
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let snapshot =
            build_status_snapshot_at(&plan, available_spool_input(temp.join("spool")), 42);

        assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("enforcement policy"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn missing_tls_decrypt_hint_does_not_change_overall_health()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-tls-decrypt-hint-health")?;
        let missing_path = temp.join("missing.keys");
        let mut config = config_with_storage_path(temp.join("spool"));
        config.tls.materials = vec![TlsMaterialConfig {
            id: Some("keylog".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: missing_path,
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let snapshot =
            build_status_snapshot_at(&plan, available_spool_input(temp.join("spool")), 42);

        assert_eq!(snapshot.health.mode, RuntimeMode::Available);
        assert!(snapshot.health.reasons.is_empty());
        assert_eq!(
            snapshot.tls.materials[0].source.mode,
            RuntimeMode::Unavailable
        );
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["tls"]["materials"][0]["purpose"],
            json!("decrypt_hint")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn available_spool_input(path: PathBuf) -> SpoolStatusInput {
        SpoolStatusInput::available(
            path,
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::from([("primary".to_string(), 0)]),
        )
    }

    fn runtime_plan_with_exporter() -> Result<RuntimePlan, runtime::RuntimeError> {
        runtime_plan(PathBuf::from("/tmp/traffic-probe-spool"), Vec::new())
    }

    fn runtime_plan_with_managed_transparent_proxy() -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool"));
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            probe_config::TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: "/tmp/traffic-probe-enforcement.toml".into(),
        };
        config.enforcement.interception.proxy = probe_config::TransparentInterceptionProxyConfig {
            mode: probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            listen_port: Some(15001),
            ..probe_config::TransparentInterceptionProxyConfig::default()
        };
        runtime_plan_from_config(
            config,
            vec![CapabilityState::available(
                CapabilityKind::TransparentInterception,
            )],
        )
    }

    fn runtime_plan(
        storage_path: PathBuf,
        capabilities: Vec<CapabilityState>,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        runtime_plan_from_config(config_with_storage_path(storage_path), capabilities)
    }

    fn status_capability<'a>(value: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
        value["capabilities"]["states"]
            .as_array()
            .expect("status capabilities should serialize as states")
            .iter()
            .find(|state| state["kind"] == json!(kind))
            .unwrap_or_else(|| panic!("missing serialized capability {kind}"))
    }
}

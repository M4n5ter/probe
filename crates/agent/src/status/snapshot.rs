use std::time::{SystemTime, UNIX_EPOCH};

use pipeline::PipelineRuntimeMetricsSnapshot;
use probe_config::{CaptureBackend, CaptureSelection};
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState, RuntimeMode};
use runtime::{CapturePlanMode, RuntimePlan};
use serde::Serialize;

use crate::configured_enforcement::ActiveEnforcementPolicy;
use crate::export::ExportWorkerRuntimeSnapshot;
use crate::tls_plaintext::{
    TlsDecryptHintRuntimeSnapshot, TlsPlaintextRuntimeMode, TlsPlaintextRuntimeSnapshot,
};
use crate::transparent_interception::TransparentProxyRuntimeSnapshot;

use super::{
    enforcement::{
        EnforcementStatusSnapshot, enforcement_status_with_active_policy,
        enforcement_status_with_transparent_proxy,
    },
    export::{
        ExportStatusSnapshot, ExporterStatusSnapshot, export_status, exporter_statuses_with_runtime,
    },
    health::health_snapshot,
    metrics::{MetricsSnapshot, metrics_snapshot},
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureStatusSnapshot {
    pub selection: CaptureSelection,
    pub selected_backend: Option<CaptureBackend>,
    pub mode: CapturePlanMode,
    pub reason: Option<String>,
}

#[derive(Clone, Default)]
pub struct RuntimeStatusInput {
    pub enforcement: EnforcementRuntimeStatusInput,
    pub export_worker: Option<ExportWorkerRuntimeSnapshot>,
    pub pipeline: Option<PipelineRuntimeMetricsSnapshot>,
    pub tls_decrypt_hints: Option<TlsDecryptHintRuntimeSnapshot>,
    pub tls_plaintext: Option<TlsPlaintextRuntimeSnapshot>,
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
    let policy = policy_status(plan);
    let transparent_proxy = runtime.transparent_proxy.clone();
    let enforcement = match &runtime.enforcement {
        EnforcementRuntimeStatusInput::OfflineInspect => {
            enforcement_status_with_transparent_proxy(plan, transparent_proxy.clone())
        }
        EnforcementRuntimeStatusInput::Runtime { active_policy } => {
            enforcement_status_with_active_policy(plan, active_policy, transparent_proxy.clone())
        }
    };
    let capabilities = capabilities_with_runtime(plan, runtime.tls_plaintext.as_ref());
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
    let metrics = metrics_snapshot(
        &capabilities,
        &spool_status,
        &exporters,
        runtime.export_worker.as_ref(),
        transparent_proxy,
        runtime.pipeline,
    );
    let health = health_snapshot(plan, &spool_status, &exporters, &policy, &enforcement, &tls);

    AgentStatusSnapshot {
        generated_unix_ns,
        agent_id: plan.config.agent_id.clone(),
        config_version: plan.config.config_version.clone(),
        health,
        capture: CaptureStatusSnapshot {
            selection: plan.capture.selection,
            selected_backend: plan.capture.selected_backend,
            mode: plan.capture.mode,
            reason: plan.capture.reason.clone(),
        },
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

fn capabilities_with_runtime(
    plan: &RuntimePlan,
    tls_plaintext: Option<&TlsPlaintextRuntimeSnapshot>,
) -> CapabilityMatrix {
    let Some(runtime) = tls_plaintext else {
        return plan.capabilities.clone();
    };
    if runtime.mode != TlsPlaintextRuntimeMode::Disabled {
        return plan.capabilities.clone();
    }
    CapabilityMatrix::new(
        plan.capabilities
            .states()
            .iter()
            .cloned()
            .map(|capability| {
                if capability.kind == CapabilityKind::LibsslUprobe {
                    CapabilityState::unavailable(
                        CapabilityKind::LibsslUprobe,
                        runtime.reason.clone().unwrap_or_else(|| {
                            "TLS plaintext instrumentation is disabled".to_string()
                        }),
                    )
                } else {
                    capability
                }
            }),
    )
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
        EnforcementPolicyManifest, EnforcementPolicySourceConfig, TlsMaterialConfig,
        TlsMaterialKind,
    };
    use probe_core::{
        Action, CapabilityKind, CapabilityState, Direction, EnforcementMode, ProcessSelector,
        ProtectiveActionProfile, Selector, TrafficSelector,
    };
    use runtime::{ExportFailureBackoffPlan, ExportWorkerPlan};
    use serde_json::json;
    use storage::SpoolSnapshot;

    use crate::{
        configured_enforcement::ActiveEnforcementPolicy,
        tls_plaintext::{TlsPlaintextRuntimeMode, TlsPlaintextRuntimeSnapshot},
        transparent_interception::{TransparentProxyRuntimeMode, TransparentProxyRuntimeSnapshot},
    };

    #[test]
    fn status_snapshot_reports_sink_lag_and_health() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
        config.storage.retention.ingress.max_age_ms = Some(120_000);
        config.storage.retention.ingress.max_records = Some(10_000);
        config.storage.retention.ingress.sweep_interval_ms = 7_000;
        config.storage.retention.ingress.prune_batch_limit = 256;
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/sssa-spool"),
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
    fn status_snapshot_reports_export_worker_runtime_metrics()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_exporter()?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/sssa-spool"),
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
                capture_events_read: 2,
                ingress_records_journaled: 2,
                ingress_records_recovered: 1,
                ingress_records_processed: 3,
                export_events_written: 7,
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
            transparent_proxy: Some(TransparentProxyRuntimeSnapshot {
                mode: TransparentProxyRuntimeMode::Configured,
                listener_families: Vec::new(),
                active_relays: 2,
                accepted_relays: 3,
                rejected_relays: 5,
                relay_failures: 7,
                listener_failures: 11,
            }),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(
            &plan,
            available_spool_input(PathBuf::from("/tmp/sssa-spool")),
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
            transparent_proxy: Some(TransparentProxyRuntimeSnapshot {
                mode: TransparentProxyRuntimeMode::Failed,
                listener_families: Vec::new(),
                active_relays: 0,
                accepted_relays: 1,
                rejected_relays: 0,
                relay_failures: 0,
                listener_failures: 1,
            }),
            ..RuntimeStatusInput::default()
        };

        let snapshot = build_status_snapshot_at_with_runtime(
            &plan,
            available_spool_input(PathBuf::from("/tmp/sssa-spool")),
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
    fn uninitialized_spool_makes_status_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_exporter()?;
        let spool = SpoolStatusInput::unavailable(
            PathBuf::from("/tmp/missing-sssa-spool"),
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
            PathBuf::from("/tmp/busy-sssa-spool"),
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
            PathBuf::from("/tmp/sssa-spool"),
            vec![CapabilityState::degraded(
                CapabilityKind::LuaJit,
                "config reload is not implemented",
            )],
        )?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/sssa-spool"),
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
    fn tls_plaintext_runtime_disabled_degrades_status_capability_and_health()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
        config.capture.selection = CaptureSelection::Libpcap;
        config.tls.plaintext.instrumentation.enabled = true;
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());
        config.tls.plaintext.instrumentation.reconcile_interval_ms = 2_500;
        let plan = runtime_plan_from_config(
            config,
            vec![CapabilityState::degraded(
                CapabilityKind::LibsslUprobe,
                "libssl uprobe preflight passed but runtime remains best-effort",
            )],
        )?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/sssa-spool"),
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
    fn tls_plaintext_runtime_not_configured_does_not_degrade_health()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/sssa-spool")),
            Vec::new(),
        )?;
        let spool = SpoolStatusInput::available(
            PathBuf::from("/tmp/sssa-spool"),
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
            PathBuf::from("/tmp/sssa-spool"),
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
        runtime_plan(PathBuf::from("/tmp/sssa-spool"), Vec::new())
    }

    fn runtime_plan_with_managed_transparent_proxy() -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
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
        config.enforcement.interception.proxy = probe_config::TransparentInterceptionProxyConfig {
            mode: probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            listen_port: Some(15001),
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
}

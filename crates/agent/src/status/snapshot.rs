use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use probe_config::{CaptureBackend, CaptureSelection};
use probe_core::{CapabilityMatrix, RuntimeMode};
use runtime::{CapturePlanMode, RuntimePlan};
use serde::Serialize;
use storage::{FjallSpool, SpoolProbe, SpoolSnapshot};

use crate::configured_enforcement::LoadedEnforcementPolicySource;

use super::{
    enforcement::{
        EnforcementStatusSnapshot, enforcement_status, enforcement_status_with_loaded_source,
    },
    export::{ExportStatusSnapshot, ExporterStatusSnapshot, export_status, exporter_statuses},
    health::health_snapshot,
    policy::{PolicyStatusSnapshot, policy_status},
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpoolStatusSnapshot {
    pub path: PathBuf,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
    pub ingress_last_sequence: Option<u64>,
    pub export_last_sequence: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    pub capabilities: CapabilityMetricsSnapshot,
    pub spool: SpoolMetricsSnapshot,
    pub export: ExportMetricsSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CapabilityMetricsSnapshot {
    pub available: u64,
    pub degraded: u64,
    pub unavailable: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SpoolMetricsSnapshot {
    pub ingress_last_sequence: Option<u64>,
    pub export_last_sequence: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExportMetricsSnapshot {
    pub sink_count: u64,
    pub total_lag: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeStatusInput {
    pub enforcement_policy_source: Option<LoadedEnforcementPolicySource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolStatusInput {
    pub path: PathBuf,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
    pub snapshot: Option<SpoolSnapshot>,
    pub export_cursors: BTreeMap<String, u64>,
}

impl SpoolStatusInput {
    pub fn available(
        path: PathBuf,
        snapshot: SpoolSnapshot,
        export_cursors: BTreeMap<String, u64>,
    ) -> Self {
        Self {
            path,
            mode: RuntimeMode::Available,
            reason: None,
            snapshot: Some(snapshot),
            export_cursors,
        }
    }

    pub fn unavailable(path: PathBuf, reason: impl Into<String>) -> Self {
        Self {
            path,
            mode: RuntimeMode::Unavailable,
            reason: Some(reason.into()),
            snapshot: None,
            export_cursors: BTreeMap::new(),
        }
    }

    pub fn degraded(path: PathBuf, reason: impl Into<String>) -> Self {
        Self {
            path,
            mode: RuntimeMode::Degraded,
            reason: Some(reason.into()),
            snapshot: None,
            export_cursors: BTreeMap::new(),
        }
    }
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

pub fn collect_spool_status(plan: &RuntimePlan) -> SpoolStatusInput {
    let path = plan.config.storage.path.clone();
    let probe = match FjallSpool::probe(&path) {
        Ok(probe) => probe,
        Err(error) => {
            return SpoolStatusInput::unavailable(
                path,
                format!("failed to inspect spool: {error}"),
            );
        }
    };

    match probe {
        SpoolProbe::Available {
            snapshot,
            export_cursors,
        } => {
            let export_cursors = plan
                .export
                .sinks
                .iter()
                .map(|sink| {
                    let cursor = export_cursors.get(&sink.id).copied().unwrap_or(0);
                    (sink.id.clone(), cursor)
                })
                .collect::<BTreeMap<_, _>>();
            SpoolStatusInput::available(path, snapshot, export_cursors)
        }
        SpoolProbe::Busy { reason } => SpoolStatusInput::degraded(path, reason),
        SpoolProbe::Missing => SpoolStatusInput::unavailable(path, "spool path does not exist"),
        SpoolProbe::Incomplete { reason } => SpoolStatusInput::unavailable(path, reason),
    }
}

pub fn collect_running_spool_status(plan: &RuntimePlan, spool: &FjallSpool) -> SpoolStatusInput {
    let path = plan.config.storage.path.clone();
    let snapshot = match spool.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return SpoolStatusInput::unavailable(
                path,
                format!("failed to inspect running spool: {error}"),
            );
        }
    };
    let mut export_cursors = BTreeMap::new();
    for sink in &plan.export.sinks {
        match spool.export_cursor(&sink.id) {
            Ok(cursor) => {
                export_cursors.insert(sink.id.clone(), cursor);
            }
            Err(error) => {
                return SpoolStatusInput::unavailable(
                    path,
                    format!(
                        "failed to inspect export cursor for sink {}: {error}",
                        sink.id
                    ),
                );
            }
        }
    }
    SpoolStatusInput::available(path, snapshot, export_cursors)
}

fn build_status_snapshot_at(
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
        ingress_last_sequence: spool_snapshot.map(|snapshot| snapshot.last_ingress_sequence),
        export_last_sequence: spool_snapshot.map(|snapshot| snapshot.last_export_sequence),
    };
    let policy = policy_status(plan);
    let enforcement = match runtime.enforcement_policy_source.as_ref() {
        Some(source) => enforcement_status_with_loaded_source(plan, Some(source)),
        None => enforcement_status(plan),
    };
    let tls = tls_status(plan);
    let export = export_status(plan);
    let exporters = exporter_statuses(plan, &spool_status, &spool.export_cursors);
    let metrics = metrics_snapshot(&plan.capabilities, &spool_status, &exporters);
    let health = health_snapshot(plan, &spool_status, &exporters, &policy, &enforcement);

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
        capabilities: plan.capabilities.clone(),
        spool: spool_status,
        export,
        exporters,
        metrics,
    }
}

fn metrics_snapshot(
    capabilities: &CapabilityMatrix,
    spool: &SpoolStatusSnapshot,
    exporters: &[ExporterStatusSnapshot],
) -> MetricsSnapshot {
    MetricsSnapshot {
        capabilities: capability_metrics(capabilities),
        spool: SpoolMetricsSnapshot {
            ingress_last_sequence: spool.ingress_last_sequence,
            export_last_sequence: spool.export_last_sequence,
        },
        export: ExportMetricsSnapshot {
            sink_count: exporters.len() as u64,
            total_lag: total_export_lag(exporters),
        },
    }
}

fn capability_metrics(capabilities: &CapabilityMatrix) -> CapabilityMetricsSnapshot {
    let mut metrics = CapabilityMetricsSnapshot {
        available: 0,
        degraded: 0,
        unavailable: 0,
    };
    for state in capabilities.states() {
        match state.mode {
            RuntimeMode::Available => metrics.available += 1,
            RuntimeMode::Degraded => metrics.degraded += 1,
            RuntimeMode::Unavailable => metrics.unavailable += 1,
        }
    }
    metrics
}

fn total_export_lag(exporters: &[ExporterStatusSnapshot]) -> Option<u64> {
    exporters.iter().try_fold(0_u64, |total, exporter| {
        exporter.lag.map(|lag| total.saturating_add(lag))
    })
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
    use std::fs;

    use super::super::snapshot_fixture::*;
    use super::*;
    use probe_config::{
        EnforcementPolicyManifest, EnforcementPolicySourceConfig, TlsMaterialConfig,
        TlsMaterialKind,
    };
    use probe_core::{Action, ProtectiveActionProfile};
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{ExportFailureBackoffPlan, ExportWorkerPlan};
    use serde_json::json;

    #[test]
    fn status_snapshot_reports_sink_lag_and_health() -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_with_exporter()?;
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
        assert!(snapshot.policy.active.is_none());
        assert!(snapshot.tls.materials.is_empty());
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(value["policy"]["mode"], json!("inactive"));
        assert_eq!(value["enforcement"]["status"], json!("audit_only"));
        assert_eq!(
            value["enforcement"]["capability"]["kind"],
            json!("not_required")
        );
        assert_eq!(
            value["enforcement"]["policy"]["source"]["mode"],
            json!("not_configured")
        );
        assert_eq!(
            value["tls"]["plaintext"]["capability"]["kind"],
            json!("not_required")
        );
        assert_eq!(snapshot.metrics.export.total_lag, Some(2));
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
                "hot reload is not implemented",
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
            version: "v1".to_string(),
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

    #[test]
    fn collect_spool_status_does_not_initialize_empty_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-empty-spool")?;
        let plan = runtime_plan(temp.clone(), Vec::new())?;

        let spool = collect_spool_status(&plan);

        assert_eq!(spool.mode, RuntimeMode::Unavailable);
        assert!(
            spool
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("marker is missing"))
        );
        assert!(temp.read_dir()?.next().is_none());
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn collect_spool_status_reports_initialized_spool_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-initialized-spool")?;
        let spool = FjallSpool::open(&temp)?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.ack_export("primary", 1)?;
        drop(spool);
        let plan = runtime_plan(temp.clone(), Vec::new())?;

        let status = collect_spool_status(&plan);
        let snapshot = build_status_snapshot_at(&plan, status, 42);

        assert_eq!(snapshot.spool.mode, RuntimeMode::Available);
        assert_eq!(snapshot.spool.export_last_sequence, Some(2));
        assert_eq!(snapshot.exporters[0].cursor, Some(1));
        assert_eq!(snapshot.exporters[0].lag, Some(1));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn collect_running_spool_status_reads_open_spool_without_probe_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-running-spool")?;
        let spool = FjallSpool::open(&temp)?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.ack_export("primary", 1)?;
        let plan = runtime_plan(temp.clone(), Vec::new())?;

        let status = collect_running_spool_status(&plan, &spool);
        let snapshot = build_status_snapshot_at(&plan, status, 42);

        assert_eq!(snapshot.spool.mode, RuntimeMode::Available);
        assert_eq!(snapshot.spool.export_last_sequence, Some(2));
        assert_eq!(snapshot.exporters[0].cursor, Some(1));
        assert_eq!(snapshot.exporters[0].lag, Some(1));
        drop(spool);
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
}

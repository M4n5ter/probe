use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use probe_config::{CaptureBackend, CaptureSelection, CompressionCodecName, ExporterTransport};
use probe_core::{CapabilityMatrix, RuntimeMode};
use runtime::{CapturePlanMode, RuntimePlan};
use serde::Serialize;
use storage::{FjallSpool, SpoolProbe, SpoolSnapshot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentStatusSnapshot {
    pub generated_unix_ns: u64,
    pub agent_id: String,
    pub config_version: String,
    pub health: HealthSnapshot,
    pub capture: CaptureStatusSnapshot,
    pub capabilities: CapabilityMatrix,
    pub spool: SpoolStatusSnapshot,
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
pub struct ExporterStatusSnapshot {
    pub id: String,
    pub transport: ExporterTransport,
    pub codec: CompressionCodecName,
    pub worker_enabled: bool,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
    pub cursor: Option<u64>,
    pub export_last_sequence: Option<u64>,
    pub lag: Option<u64>,
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

fn build_status_snapshot_at(
    plan: &RuntimePlan,
    spool: SpoolStatusInput,
    generated_unix_ns: u64,
) -> AgentStatusSnapshot {
    let spool_snapshot = spool.snapshot;
    let spool_status = SpoolStatusSnapshot {
        path: spool.path,
        mode: spool.mode,
        reason: spool.reason,
        ingress_last_sequence: spool_snapshot.map(|snapshot| snapshot.last_ingress_sequence),
        export_last_sequence: spool_snapshot.map(|snapshot| snapshot.last_export_sequence),
    };
    let exporters = exporter_statuses(plan, &spool_status, &spool.export_cursors);
    let metrics = metrics_snapshot(&plan.capabilities, &spool_status, &exporters);
    let health = health_snapshot(plan, &spool_status, &exporters);

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
        capabilities: plan.capabilities.clone(),
        spool: spool_status,
        exporters,
        metrics,
    }
}

fn exporter_statuses(
    plan: &RuntimePlan,
    spool: &SpoolStatusSnapshot,
    cursors: &BTreeMap<String, u64>,
) -> Vec<ExporterStatusSnapshot> {
    plan.export
        .sinks
        .iter()
        .map(|sink| {
            let cursor = cursors.get(&sink.id).copied();
            let export_last_sequence = spool.export_last_sequence;
            let cursor_invariant_error =
                cursor.zip(export_last_sequence).and_then(|(cursor, last)| {
                    (cursor > last).then(|| {
                        format!(
                            "export cursor {cursor} is beyond export high-water sequence {last}"
                        )
                    })
                });
            let lag = cursor
                .zip(export_last_sequence)
                .and_then(|(cursor, last)| (cursor <= last).then(|| last - cursor));
            let (mode, reason) = exporter_mode(plan, spool, sink.transport, cursor_invariant_error);

            ExporterStatusSnapshot {
                id: sink.id.clone(),
                transport: sink.transport,
                codec: sink.codec,
                worker_enabled: plan.export.worker_enabled,
                mode,
                reason,
                cursor,
                export_last_sequence,
                lag,
            }
        })
        .collect()
}

fn exporter_mode(
    plan: &RuntimePlan,
    spool: &SpoolStatusSnapshot,
    transport: ExporterTransport,
    cursor_reason: Option<String>,
) -> (RuntimeMode, Option<String>) {
    if spool.mode == RuntimeMode::Unavailable {
        return (
            RuntimeMode::Unavailable,
            spool
                .reason
                .clone()
                .or_else(|| Some("spool is unavailable".to_string())),
        );
    }
    if spool.mode == RuntimeMode::Degraded {
        return (
            RuntimeMode::Degraded,
            spool
                .reason
                .clone()
                .or_else(|| Some("spool status is degraded".to_string())),
        );
    }
    if let Some(reason) = cursor_reason {
        return (RuntimeMode::Unavailable, Some(reason));
    }
    match transport {
        ExporterTransport::Webhook => {}
        ExporterTransport::Grpc | ExporterTransport::Kafka | ExporterTransport::Otlp => {
            return (
                RuntimeMode::Unavailable,
                Some(format!(
                    "{transport:?} exporter is reserved but not implemented"
                )),
            );
        }
    }
    if !plan.export.worker_enabled {
        return (
            RuntimeMode::Degraded,
            plan.export
                .reason
                .clone()
                .or_else(|| Some("export worker is disabled".to_string())),
        );
    }
    (RuntimeMode::Available, None)
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

fn health_snapshot(
    plan: &RuntimePlan,
    spool: &SpoolStatusSnapshot,
    exporters: &[ExporterStatusSnapshot],
) -> HealthSnapshot {
    let mut reasons = Vec::new();
    let mut unavailable = false;
    let mut degraded = false;

    if plan.capture.mode == CapturePlanMode::Unavailable {
        unavailable = true;
        reasons.push(
            plan.capture
                .reason
                .clone()
                .unwrap_or_else(|| "capture plan is unavailable".to_string()),
        );
    }
    if spool.mode == RuntimeMode::Unavailable {
        unavailable = true;
        reasons.push(
            spool
                .reason
                .clone()
                .unwrap_or_else(|| "spool is unavailable".to_string()),
        );
    } else if spool.mode == RuntimeMode::Degraded {
        degraded = true;
        if let Some(reason) = &spool.reason {
            reasons.push(reason.clone());
        }
    }

    for exporter in exporters {
        match exporter.mode {
            RuntimeMode::Available => {}
            RuntimeMode::Degraded => {
                degraded = true;
                if let Some(reason) = &exporter.reason {
                    reasons.push(format!("exporter {}: {reason}", exporter.id));
                }
            }
            RuntimeMode::Unavailable => {
                unavailable = true;
                if let Some(reason) = &exporter.reason {
                    reasons.push(format!("exporter {}: {reason}", exporter.id));
                }
            }
        }
    }

    let mode = if unavailable {
        RuntimeMode::Unavailable
    } else if degraded {
        RuntimeMode::Degraded
    } else {
        RuntimeMode::Available
    };

    HealthSnapshot { mode, reasons }
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
    use std::{fs, path::Path};

    use super::*;
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection, ExporterConfig};
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};
    use storage::SpoolPayload;

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
    fn cursor_beyond_high_water_marks_exporter_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
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

        assert_eq!(snapshot.exporters[0].mode, RuntimeMode::Unavailable);
        assert_eq!(snapshot.exporters[0].lag, None);
        assert!(
            snapshot.exporters[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("beyond export high-water"))
        );
        assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
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

    fn runtime_plan_with_exporter() -> Result<RuntimePlan, runtime::RuntimeError> {
        runtime_plan(PathBuf::from("/tmp/sssa-spool"), Vec::new())
    }

    fn runtime_plan(
        storage_path: PathBuf,
        capabilities: Vec<CapabilityState>,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        let config = AgentConfig {
            agent_id: "agent-1".to_string(),
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
                transport: ExporterTransport::Webhook,
                endpoint: "https://collector.example/batches".to_string(),
                codec: CompressionCodecName::None,
                headers: BTreeMap::new(),
            }],
            ..AgentConfig::default()
        };
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            capabilities,
        );
        RuntimePlan::build(config, &registry)
    }

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new("test.schema", bytes)
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!("{name}-{}", current_unix_time_ns()));
        if Path::new(&path).exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}

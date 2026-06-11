use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

mod enforcement;
mod export;
mod health;
mod policy;
mod tls;

use enforcement::{EnforcementStatusSnapshot, enforcement_status};
use export::{ExporterStatusSnapshot, exporter_statuses};
use health::health_snapshot;
use policy::{PolicyStatusSnapshot, policy_status};
use probe_config::{CaptureBackend, CaptureSelection};
use probe_core::{CapabilityMatrix, RuntimeMode};
use runtime::{CapturePlanMode, RuntimePlan};
use serde::Serialize;
use storage::{FjallSpool, SpoolProbe, SpoolSnapshot};
use tls::{TlsStatusSnapshot, tls_status};

#[cfg(test)]
use enforcement::{EnforcementCapabilityStatusSnapshot, EnforcementStatusMode};
#[cfg(test)]
use policy::{PolicySourceCheck, PolicyStatusMode};
#[cfg(test)]
use probe_core::SpoolPayloadSchema;
#[cfg(test)]
use tls::{TlsMaterialPurpose, TlsMaterialSourceCheck, TlsPlaintextCapabilityStatusSnapshot};

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
    let spool_snapshot = spool.snapshot;
    let spool_status = SpoolStatusSnapshot {
        path: spool.path,
        mode: spool.mode,
        reason: spool.reason,
        ingress_last_sequence: spool_snapshot.map(|snapshot| snapshot.last_ingress_sequence),
        export_last_sequence: spool_snapshot.map(|snapshot| snapshot.last_export_sequence),
    };
    let policy = policy_status(plan);
    let enforcement = enforcement_status(plan);
    let tls = tls_status(plan);
    let exporters = exporter_statuses(plan, &spool_status, &spool.export_cursors);
    let metrics = metrics_snapshot(&plan.capabilities, &spool_status, &exporters);
    let health = health_snapshot(plan, &spool_status, &exporters, &policy);

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
    use std::{fs, path::Path};

    use super::*;
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, CompressionCodecName, ExporterConfig,
        ExporterTransport, PolicyConfig,
    };
    use probe_core::{CapabilityKind, CapabilityState, EnforcementMode, Selector};
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ExportWorkerPlan, ProviderRegistry,
    };
    use serde_json::json;
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
        assert_eq!(
            snapshot.exporters[0].worker,
            ExportWorkerPlan::FixedIntervalBounded {
                interval_ms: 1_000,
                batches_per_sink_per_tick: 1,
                sink_timeout_ms: 10_000,
                failure_backoff_ms: 30_000,
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
        assert_eq!(snapshot.policy.mode, PolicyStatusMode::Inactive);
        assert_eq!(
            snapshot.enforcement.status,
            EnforcementStatusMode::AuditOnly
        );
        assert_eq!(
            snapshot.enforcement.capability,
            EnforcementCapabilityStatusSnapshot::NotRequired
        );
        assert_eq!(
            snapshot.tls.plaintext.capability,
            TlsPlaintextCapabilityStatusSnapshot::NotRequired
        );
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(value["policy"]["mode"], json!("inactive"));
        assert_eq!(value["enforcement"]["status"], json!("audit_only"));
        assert_eq!(
            value["enforcement"]["capability"]["kind"],
            json!("not_required")
        );
        assert_eq!(
            value["tls"]["plaintext"]["capability"]["kind"],
            json!("not_required")
        );
        assert_eq!(snapshot.metrics.export.total_lag, Some(2));
        Ok(())
    }

    #[test]
    fn status_snapshot_reports_per_sink_exporter_worker_quota()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
        config.exporters[0].worker.batches_per_tick = Some(2);
        let plan = runtime_plan_from_config(
            config,
            vec![CapabilityState::available(
                CapabilityKind::DryRunEnforcement,
            )],
        )?;
        let spool = available_empty_spool();

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(
            snapshot.exporters[0].sink_worker.batches_per_tick_override,
            Some(2)
        );
        assert_eq!(
            snapshot.exporters[0]
                .sink_worker
                .effective_batches_per_tick
                .get(),
            2
        );
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["exporters"][0]["sink_worker"]["batches_per_tick_override"],
            json!(2)
        );
        assert_eq!(
            value["exporters"][0]["sink_worker"]["effective_batches_per_tick"],
            json!(2)
        );
        Ok(())
    }

    #[test]
    fn status_snapshot_reports_metadata_only_policy_without_loading_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-policy")?;
        let policy_path = temp.join("guard.lua");
        fs::write(&policy_path, "function on_http_request(")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            path: policy_path.clone(),
            enabled: true,
            selector: Some(Selector::default()),
        }];
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.selector = Some(Selector::default());
        let plan = runtime_plan_from_config(
            config,
            vec![CapabilityState::available(
                CapabilityKind::DryRunEnforcement,
            )],
        )?;
        let spool = available_empty_spool();

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.policy.mode, PolicyStatusMode::MetadataOnly);
        assert_eq!(snapshot.policy.configured_count, 1);
        assert_eq!(snapshot.policy.enabled_count, 1);
        let active_policy = snapshot.policy.active.as_ref().expect("active policy");
        assert_eq!(active_policy.id, "guard");
        assert_eq!(active_policy.path, policy_path);
        assert!(active_policy.selector_configured);
        assert_eq!(active_policy.source.mode, RuntimeMode::Available);
        assert_eq!(active_policy.source.check, PolicySourceCheck::MetadataOnly);
        assert_eq!(
            snapshot.enforcement.configured_mode,
            EnforcementMode::DryRun
        );
        assert_eq!(snapshot.enforcement.status, EnforcementStatusMode::DryRun);
        assert!(snapshot.enforcement.selector_configured);
        assert_eq!(
            snapshot.enforcement.capability,
            EnforcementCapabilityStatusSnapshot::Required {
                capability: CapabilityKind::DryRunEnforcement,
                mode: RuntimeMode::Available,
            }
        );
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(value["policy"]["mode"], json!("metadata_only"));
        assert_eq!(
            value["policy"]["active"]["source"]["check"],
            json!("metadata_only")
        );
        assert_eq!(value["enforcement"]["status"], json!("dry_run"));
        assert_eq!(
            value["enforcement"]["capability"]["kind"],
            json!("required")
        );
        assert_eq!(
            value["enforcement"]["capability"]["capability"],
            json!("dry_run_enforcement")
        );
        assert_eq!(
            value["enforcement"]["capability"]["mode"],
            json!("available")
        );
        assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("offline status does not load or execute"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn status_snapshot_reports_metadata_only_policy_bundle_without_loading_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-policy-bundle")?;
        let policy_path = temp.join("guard.bundle");
        fs::create_dir_all(&policy_path)?;
        fs::write(
            policy_path.join("manifest.toml"),
            r#"
id = "guard"
version = "bundle-v1"
hooks = ["on_http_request_headers"]
"#,
        )?;
        fs::write(
            policy_path.join("main.lua"),
            "function on_http_request_headers(",
        )?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            path: policy_path.clone(),
            enabled: true,
            selector: Some(Selector::default()),
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = available_empty_spool();

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.policy.mode, PolicyStatusMode::MetadataOnly);
        let active_policy = snapshot.policy.active.as_ref().expect("active policy");
        assert_eq!(active_policy.id, "guard");
        assert_eq!(active_policy.path, policy_path);
        assert!(active_policy.selector_configured);
        assert_eq!(active_policy.source.mode, RuntimeMode::Available);
        assert_eq!(active_policy.source.check, PolicySourceCheck::MetadataOnly);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("offline status does not load or execute"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn missing_policy_source_marks_status_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-missing-policy")?;
        let missing_policy = temp.join("missing.lua");
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "missing".to_string(),
            path: missing_policy,
            enabled: true,
            selector: None,
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = available_empty_spool();

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.policy.mode, PolicyStatusMode::Unavailable);
        assert!(
            snapshot
                .policy
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("does not exist"))
        );
        assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("policy: policy source path does not exist"))
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn status_snapshot_reports_metadata_only_tls_materials()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-tls-material")?;
        let material_path = temp.join("ca.pem");
        fs::write(&material_path, b"test trust anchor")?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.tls.materials = vec![probe_config::TlsMaterialConfig {
            id: Some("collector-ca".to_string()),
            kind: probe_config::TlsMaterialKind::TrustAnchor,
            path: material_path.clone(),
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = available_empty_spool();

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.tls.materials.len(), 1);
        let material = &snapshot.tls.materials[0];
        assert_eq!(material.path, material_path);
        assert_eq!(material.purpose, TlsMaterialPurpose::TrustOrIdentity);
        assert_eq!(material.source.mode, RuntimeMode::Available);
        assert_eq!(material.source.check, TlsMaterialSourceCheck::MetadataOnly);
        assert_eq!(snapshot.health.mode, RuntimeMode::Available);
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(
            value["tls"]["materials"][0]["source"]["check"],
            json!("metadata_only")
        );
        assert_eq!(
            value["tls"]["materials"][0]["purpose"],
            json!("trust_or_identity")
        );
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn missing_tls_material_is_reported_without_forcing_health()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-missing-tls-material")?;
        let missing_path = temp.join("missing.keys");
        let mut config = config_with_storage_path(temp.join("spool"));
        config.tls.materials = vec![probe_config::TlsMaterialConfig {
            id: Some("keylog".to_string()),
            kind: probe_config::TlsMaterialKind::KeyLogFile,
            path: missing_path,
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = available_empty_spool();

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        let material = &snapshot.tls.materials[0];
        assert_eq!(material.purpose, TlsMaterialPurpose::DecryptHint);
        assert_eq!(material.source.mode, RuntimeMode::Unavailable);
        assert!(
            material
                .source
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("does not exist"))
        );
        assert_eq!(snapshot.health.mode, RuntimeMode::Available);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn active_exporter_tls_material_unavailability_forces_health_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-missing-exporter-tls-material")?;
        let missing_path = temp.join("missing-ca.pem");
        let mut config = config_with_storage_path(temp.join("spool"));
        config.exporters[0].tls.trust_anchor_refs = vec!["collector-ca".to_string()];
        config.tls.materials = vec![probe_config::TlsMaterialConfig {
            id: Some("collector-ca".to_string()),
            kind: probe_config::TlsMaterialKind::TrustAnchor,
            path: missing_path,
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = available_empty_spool();

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.exporters[0].tls.mode, RuntimeMode::Unavailable);
        assert_eq!(snapshot.exporters[0].mode, RuntimeMode::Unavailable);
        let exporter_reason = snapshot.exporters[0]
            .reason
            .as_deref()
            .expect("missing TLS material should explain exporter unavailability");
        assert!(exporter_reason.contains("TLS material collector-ca"));
        assert!(exporter_reason.contains("TrustAnchor"));
        assert!(exporter_reason.contains("missing-ca.pem"));
        assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
        assert!(
            snapshot
                .health
                .reasons
                .iter()
                .any(|reason| reason.contains("exporter primary"))
        );
        fs::remove_dir_all(temp)?;
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
    fn oversized_policy_source_marks_status_unavailable() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = test_dir("status-oversized-policy")?;
        let policy_path = temp.join("guard.lua");
        let file = fs::File::create(&policy_path)?;
        file.set_len(crate::configured_policy::MAX_POLICY_SOURCE_BYTES + 1)?;
        let mut config = config_with_storage_path(temp.join("spool"));
        config.policies = vec![PolicyConfig {
            id: "guard".to_string(),
            path: policy_path,
            enabled: true,
            selector: None,
        }];
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = available_empty_spool();

        let snapshot = build_status_snapshot_at(&plan, spool, 42);

        assert_eq!(snapshot.policy.mode, PolicyStatusMode::Unavailable);
        assert!(
            snapshot
                .policy
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("exceeding"))
        );
        assert_eq!(snapshot.health.mode, RuntimeMode::Unavailable);
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

    fn runtime_plan_with_exporter() -> Result<RuntimePlan, runtime::RuntimeError> {
        runtime_plan(PathBuf::from("/tmp/sssa-spool"), Vec::new())
    }

    fn runtime_plan(
        storage_path: PathBuf,
        capabilities: Vec<CapabilityState>,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        runtime_plan_from_config(config_with_storage_path(storage_path), capabilities)
    }

    fn runtime_plan_from_config(
        config: AgentConfig,
        capabilities: Vec<CapabilityState>,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            capabilities,
        );
        RuntimePlan::build(config, &registry)
    }

    fn config_with_storage_path(storage_path: PathBuf) -> AgentConfig {
        AgentConfig {
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
                tls: Default::default(),
                worker: Default::default(),
            }],
            ..AgentConfig::default()
        }
    }

    fn available_empty_spool() -> SpoolStatusInput {
        SpoolStatusInput::available(
            PathBuf::from("/tmp/sssa-spool"),
            SpoolSnapshot {
                last_ingress_sequence: 0,
                last_export_sequence: 0,
            },
            BTreeMap::from([("primary".to_string(), 0)]),
        )
    }

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new(SpoolPayloadSchema::from_wire("test.schema"), bytes)
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

use std::collections::BTreeMap;

use probe_config::CompressionCodecName;
use probe_core::RuntimeMode;
use runtime::{
    ExportRetentionPlan, ExportSinkWorkerPlan, ExportTlsMaterialPlan, ExportWorkerPlan,
    RuntimePlan, WebhookExportSinkPlan,
};
use serde::Serialize;

use crate::export::{
    ExportDrainFailureReason, ExportSinkWorkerRuntimeMode, ExportSinkWorkerRuntimeSnapshot,
    ExportWorkerRuntimeSnapshot,
};

use super::super::{
    snapshot::SpoolStatusSnapshot,
    tls::{self, TlsMaterialSourceStatusSnapshot},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportStatusSnapshot {
    pub retention: ExportRetentionPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExporterStatusSnapshot {
    pub id: String,
    pub codec: CompressionCodecName,
    pub worker: ExportWorkerPlan,
    pub sink_worker: ExportSinkWorkerPlan,
    pub runtime: Option<ExporterRuntimeStatusSnapshot>,
    pub tls: ExporterTlsStatusSnapshot,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
    pub cursor: Option<u64>,
    pub export_last_sequence: Option<u64>,
    pub lag: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExporterRuntimeStatusSnapshot {
    pub mode: ExportSinkWorkerRuntimeMode,
    pub consecutive_failures: u64,
    pub backoff_delay_ms: Option<u64>,
    pub backoff_remaining_ms: Option<u64>,
    pub last_failure_reason: Option<ExportDrainFailureReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExporterTlsStatusSnapshot {
    pub mode: RuntimeMode,
    pub reason: Option<String>,
}

pub(in crate::status) fn export_status(plan: &RuntimePlan) -> ExportStatusSnapshot {
    ExportStatusSnapshot {
        retention: plan.storage.retention.export.clone(),
    }
}

pub(in crate::status) fn exporter_statuses_with_runtime(
    plan: &RuntimePlan,
    spool: &SpoolStatusSnapshot,
    cursors: &BTreeMap<String, u64>,
    runtime: Option<&ExportWorkerRuntimeSnapshot>,
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
            let tls = exporter_tls_status(sink);
            let (mode, reason) = exporter_mode(plan, spool, &tls, cursor_invariant_error);

            ExporterStatusSnapshot {
                id: sink.id.clone(),
                codec: sink.codec,
                worker: plan.export.worker.clone(),
                sink_worker: sink.worker.clone(),
                runtime: runtime
                    .and_then(|runtime| runtime.sinks.get(&sink.id))
                    .map(ExporterRuntimeStatusSnapshot::from),
                tls,
                mode,
                reason,
                cursor,
                export_last_sequence,
                lag,
            }
        })
        .collect()
}

pub(in crate::status) fn backing_off_exporter_count(exporters: &[ExporterStatusSnapshot]) -> u64 {
    exporters
        .iter()
        .filter(|exporter| {
            exporter
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.mode == ExportSinkWorkerRuntimeMode::BackingOff)
        })
        .count() as u64
}

impl From<&ExportSinkWorkerRuntimeSnapshot> for ExporterRuntimeStatusSnapshot {
    fn from(value: &ExportSinkWorkerRuntimeSnapshot) -> Self {
        Self {
            mode: value.mode,
            consecutive_failures: value.consecutive_failures,
            backoff_delay_ms: value.backoff_delay_ms,
            backoff_remaining_ms: value.backoff_remaining_ms,
            last_failure_reason: value.last_failure_reason,
        }
    }
}

fn exporter_mode(
    plan: &RuntimePlan,
    spool: &SpoolStatusSnapshot,
    tls: &ExporterTlsStatusSnapshot,
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
    if tls.mode == RuntimeMode::Unavailable {
        return (
            RuntimeMode::Unavailable,
            tls.reason
                .clone()
                .or_else(|| Some("exporter TLS material is unavailable".to_string())),
        );
    }
    if let Some(reason) = plan.export.worker.disabled_reason() {
        return (RuntimeMode::Degraded, Some(reason.to_string()));
    }
    (RuntimeMode::Available, None)
}

fn exporter_tls_status(sink: &WebhookExportSinkPlan) -> ExporterTlsStatusSnapshot {
    for material in sink
        .tls
        .trust_anchors
        .iter()
        .chain(&sink.tls.client_certificates)
        .chain(sink.tls.client_private_key.iter())
    {
        let source = tls::material_source_status(&material.path);
        if source.mode == RuntimeMode::Unavailable {
            return ExporterTlsStatusSnapshot {
                mode: RuntimeMode::Unavailable,
                reason: Some(exporter_tls_reason(material, &source)),
            };
        }
    }
    ExporterTlsStatusSnapshot {
        mode: RuntimeMode::Available,
        reason: None,
    }
}

fn exporter_tls_reason(
    material: &ExportTlsMaterialPlan,
    source: &TlsMaterialSourceStatusSnapshot,
) -> String {
    let path = material.path.as_path();
    source.reason.clone().map_or_else(
        || {
            format!(
                "TLS material {} ({:?}) at {} is unavailable",
                material.id,
                material.kind,
                path.display()
            )
        },
        |reason| {
            format!(
                "TLS material {} ({:?}) at {}: {reason}",
                material.id,
                material.kind,
                path.display()
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use probe_core::RuntimeMode;
    use serde_json::json;

    use super::super::super::plan_fixture::{
        config_with_storage_path, runtime_plan_from_config, test_dir,
    };
    use super::*;

    #[test]
    fn exporter_status_reports_per_sink_worker_quota() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
        config.exporters[0].worker.batches_per_tick = Some(2);
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = available_spool_status(0, 0);

        let exporters = exporter_statuses_with_runtime(
            &plan,
            &spool,
            &BTreeMap::from([("primary".to_string(), 0)]),
            None,
        );

        assert_eq!(exporters[0].sink_worker.batches_per_tick_override, Some(2));
        assert_eq!(exporters[0].sink_worker.effective_batches_per_tick.get(), 2);
        let value = serde_json::to_value(&exporters)?;
        assert_eq!(
            value[0]["sink_worker"]["batches_per_tick_override"],
            json!(2)
        );
        assert_eq!(
            value[0]["sink_worker"]["effective_batches_per_tick"],
            json!(2)
        );
        Ok(())
    }

    #[test]
    fn export_status_reports_retention_without_sinks() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
        config.exporters.clear();
        config.storage.retention.export.max_age_ms = Some(60_000);
        config.storage.retention.export.sweep_interval_ms = 5_000;
        config.storage.retention.export.prune_batch_limit = 128;
        let plan = runtime_plan_from_config(config, Vec::new())?;

        let status = export_status(&plan);

        assert_eq!(status.retention.max_age_ms, Some(60_000));
        assert_eq!(status.retention.sweep_interval_ms.get(), 5_000);
        assert_eq!(status.retention.prune_batch_limit.get(), 128);
        let value = serde_json::to_value(&status)?;
        assert_eq!(value["retention"]["max_age_ms"], json!(60_000));
        assert_eq!(value["retention"]["sweep_interval_ms"], json!(5_000));
        assert_eq!(value["retention"]["prune_batch_limit"], json!(128));
        Ok(())
    }

    #[test]
    fn exporter_status_reports_runtime_backoff_snapshot() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/sssa-spool")),
            Vec::new(),
        )?;
        let spool = available_spool_status(0, 5);
        let runtime = ExportWorkerRuntimeSnapshot {
            sinks: BTreeMap::from([(
                "primary".to_string(),
                ExportSinkWorkerRuntimeSnapshot {
                    mode: ExportSinkWorkerRuntimeMode::BackingOff,
                    consecutive_failures: 2,
                    backoff_delay_ms: Some(30_000),
                    backoff_remaining_ms: Some(25_000),
                    last_failure_reason: Some(ExportDrainFailureReason::RemoteRejectedBatch),
                },
            )]),
        };

        let exporters = exporter_statuses_with_runtime(
            &plan,
            &spool,
            &BTreeMap::from([("primary".to_string(), 3)]),
            Some(&runtime),
        );

        assert_eq!(backing_off_exporter_count(&exporters), 1);
        let runtime = exporters[0]
            .runtime
            .as_ref()
            .expect("online worker status should include sink runtime state");
        assert_eq!(runtime.mode, ExportSinkWorkerRuntimeMode::BackingOff);
        assert_eq!(runtime.consecutive_failures, 2);
        assert_eq!(runtime.backoff_remaining_ms, Some(25_000));
        let value = serde_json::to_value(&exporters)?;
        assert_eq!(value[0]["runtime"]["mode"], json!("backing_off"));
        assert_eq!(
            value[0]["runtime"]["last_failure_reason"],
            json!("remote_rejected_batch")
        );
        Ok(())
    }

    #[test]
    fn cursor_beyond_high_water_marks_exporter_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/sssa-spool")),
            Vec::new(),
        )?;
        let spool = available_spool_status(0, 5);

        let exporters = exporter_statuses_with_runtime(
            &plan,
            &spool,
            &BTreeMap::from([("primary".to_string(), 10)]),
            None,
        );

        assert_eq!(exporters[0].mode, RuntimeMode::Unavailable);
        assert_eq!(exporters[0].lag, None);
        assert!(
            exporters[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("beyond export high-water"))
        );
        Ok(())
    }

    #[test]
    fn active_exporter_tls_material_unavailability_marks_exporter_unavailable()
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
        let spool = available_spool_status(0, 0);

        let exporters = exporter_statuses_with_runtime(
            &plan,
            &spool,
            &BTreeMap::from([("primary".to_string(), 0)]),
            None,
        );

        assert_eq!(exporters[0].tls.mode, RuntimeMode::Unavailable);
        assert_eq!(exporters[0].mode, RuntimeMode::Unavailable);
        let exporter_reason = exporters[0]
            .reason
            .as_deref()
            .expect("missing TLS material should explain exporter unavailability");
        assert!(exporter_reason.contains("TLS material collector-ca"));
        assert!(exporter_reason.contains("TrustAnchor"));
        assert!(exporter_reason.contains("missing-ca.pem"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn available_spool_status(
        ingress_last_sequence: u64,
        export_last_sequence: u64,
    ) -> SpoolStatusSnapshot {
        SpoolStatusSnapshot {
            path: PathBuf::from("/tmp/sssa-spool"),
            mode: RuntimeMode::Available,
            reason: None,
            ingress_retention: Default::default(),
            ingress_last_sequence: Some(ingress_last_sequence),
            export_last_sequence: Some(export_last_sequence),
        }
    }
}

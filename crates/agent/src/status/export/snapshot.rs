use std::collections::BTreeMap;

use probe_config::{CompressionCodecName, ExporterTransport};
use probe_core::RuntimeMode;
use runtime::{
    ExportSinkPlan, ExportSinkWorkerPlan, ExportTlsMaterialPlan, ExportWorkerPlan, RuntimePlan,
};
use serde::Serialize;

use super::super::{
    snapshot::SpoolStatusSnapshot,
    tls::{self, TlsMaterialSourceStatusSnapshot},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExporterStatusSnapshot {
    pub id: String,
    pub transport: ExporterTransport,
    pub codec: CompressionCodecName,
    pub worker: ExportWorkerPlan,
    pub sink_worker: ExportSinkWorkerPlan,
    pub tls: ExporterTlsStatusSnapshot,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
    pub cursor: Option<u64>,
    pub export_last_sequence: Option<u64>,
    pub lag: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExporterTlsStatusSnapshot {
    pub mode: RuntimeMode,
    pub reason: Option<String>,
}

pub(in crate::status) fn exporter_statuses(
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
            let tls = exporter_tls_status(sink);
            let (mode, reason) =
                exporter_mode(plan, spool, sink.transport, &tls, cursor_invariant_error);

            ExporterStatusSnapshot {
                id: sink.id.clone(),
                transport: sink.transport,
                codec: sink.codec,
                worker: plan.export.worker.clone(),
                sink_worker: sink.worker.clone(),
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

fn exporter_mode(
    plan: &RuntimePlan,
    spool: &SpoolStatusSnapshot,
    transport: ExporterTransport,
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
    if let Some(reason) = plan.export.worker.disabled_reason() {
        return (RuntimeMode::Degraded, Some(reason.to_string()));
    }
    (RuntimeMode::Available, None)
}

fn exporter_tls_status(sink: &ExportSinkPlan) -> ExporterTlsStatusSnapshot {
    if sink.transport != ExporterTransport::Webhook {
        return ExporterTlsStatusSnapshot {
            mode: RuntimeMode::Available,
            reason: None,
        };
    }

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

    use super::*;
    use crate::status::snapshot_fixture::{
        config_with_storage_path, runtime_plan_from_config, test_dir,
    };

    #[test]
    fn exporter_status_reports_per_sink_worker_quota() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
        config.exporters[0].worker.batches_per_tick = Some(2);
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let spool = available_spool_status(0, 0);

        let exporters =
            exporter_statuses(&plan, &spool, &BTreeMap::from([("primary".to_string(), 0)]));

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
    fn cursor_beyond_high_water_marks_exporter_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/sssa-spool")),
            Vec::new(),
        )?;
        let spool = available_spool_status(0, 5);

        let exporters = exporter_statuses(
            &plan,
            &spool,
            &BTreeMap::from([("primary".to_string(), 10)]),
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

        let exporters =
            exporter_statuses(&plan, &spool, &BTreeMap::from([("primary".to_string(), 0)]));

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
            ingress_last_sequence: Some(ingress_last_sequence),
            export_last_sequence: Some(export_last_sequence),
        }
    }
}

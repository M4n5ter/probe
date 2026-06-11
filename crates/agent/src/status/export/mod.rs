use std::{collections::BTreeMap, path::Path};

use probe_config::{CompressionCodecName, ExporterTransport};
use probe_core::RuntimeMode;
use runtime::{ExportSinkPlan, ExportWorkerPlan, RuntimePlan};
use serde::Serialize;

use super::{
    SpoolStatusSnapshot,
    tls::{self, TlsMaterialSourceStatusSnapshot},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExporterStatusSnapshot {
    pub id: String,
    pub transport: ExporterTransport,
    pub codec: CompressionCodecName,
    pub worker: ExportWorkerPlan,
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

pub(super) fn exporter_statuses(
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

    for path in sink
        .tls
        .trust_anchors
        .iter()
        .chain(&sink.tls.client_certificates)
        .chain(sink.tls.client_private_key.iter())
    {
        let source = tls::material_source_status(path);
        if source.mode == RuntimeMode::Unavailable {
            return ExporterTlsStatusSnapshot {
                mode: RuntimeMode::Unavailable,
                reason: Some(exporter_tls_reason(path, &source)),
            };
        }
    }
    ExporterTlsStatusSnapshot {
        mode: RuntimeMode::Available,
        reason: None,
    }
}

fn exporter_tls_reason(path: &Path, source: &TlsMaterialSourceStatusSnapshot) -> String {
    source.reason.clone().map_or_else(
        || format!("TLS material {} is unavailable", path.display()),
        |reason| format!("TLS material {}: {reason}", path.display()),
    )
}

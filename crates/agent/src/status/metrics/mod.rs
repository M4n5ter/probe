use pipeline::PipelineRuntimeMetricsSnapshot;
use probe_core::{CapabilityMatrix, RuntimeMode};
use serde::Serialize;

use crate::{
    export::ExportWorkerRuntimeSnapshot, transparent_interception::TransparentProxyRuntimeSnapshot,
};

use super::{
    export::{ExporterStatusSnapshot, backing_off_exporter_count},
    spool::SpoolStatusSnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    pub capabilities: CapabilityMetricsSnapshot,
    pub spool: SpoolMetricsSnapshot,
    pub export: ExportMetricsSnapshot,
    pub transparent_proxy: Option<TransparentProxyMetricsSnapshot>,
    pub pipeline: Option<PipelineRuntimeMetricsSnapshot>,
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
    pub backing_off_sink_count: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TransparentProxyMetricsSnapshot {
    pub active_relays: u64,
    pub accepted_relays: u64,
    pub rejected_relays: u64,
    pub relay_failures: u64,
    pub listener_failures: u64,
}

pub(in crate::status) fn metrics_snapshot(
    capabilities: &CapabilityMatrix,
    spool: &SpoolStatusSnapshot,
    exporters: &[ExporterStatusSnapshot],
    export_worker: Option<&ExportWorkerRuntimeSnapshot>,
    transparent_proxy: Option<TransparentProxyRuntimeSnapshot>,
    pipeline: Option<PipelineRuntimeMetricsSnapshot>,
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
            backing_off_sink_count: export_worker.map(|_| backing_off_exporter_count(exporters)),
        },
        transparent_proxy: transparent_proxy.map(transparent_proxy_metrics),
        pipeline,
    }
}

fn transparent_proxy_metrics(
    proxy: TransparentProxyRuntimeSnapshot,
) -> TransparentProxyMetricsSnapshot {
    TransparentProxyMetricsSnapshot {
        active_relays: proxy.active_relays,
        accepted_relays: proxy.accepted_relays,
        rejected_relays: proxy.rejected_relays,
        relay_failures: proxy.relay_failures,
        listener_failures: proxy.listener_failures,
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

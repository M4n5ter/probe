use pipeline::PipelineRuntimeMetricsSnapshot;
use probe_core::{CapabilityMatrix, RuntimeMode};
use serde::Serialize;

use crate::{
    export::ExportWorkerRuntimeSnapshot,
    l7_mitm::{
        L7MitmClientTrustMaterialMode, L7MitmClientTrustMode, L7MitmPlaintextBridgeMode,
        L7MitmRuntimeSnapshot,
    },
    tcp_health::{TcpHealthMode, TcpHealthSnapshot},
    transparent_interception::TransparentProxyRuntimeSnapshot,
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
    pub l7_mitm: Option<L7MitmMetricsSnapshot>,
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
pub struct L7MitmMetricsSnapshot {
    pub backend_health: TcpHealthMetricsSnapshot,
    pub client_trust: L7MitmClientTrustMetricsSnapshot,
    pub plaintext_bridge: L7MitmPlaintextBridgeMetricsSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct L7MitmClientTrustMetricsSnapshot {
    pub mode: L7MitmClientTrustMode,
    pub material: L7MitmClientTrustMaterialMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct L7MitmPlaintextBridgeMetricsSnapshot {
    pub mode: L7MitmPlaintextBridgeMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TcpHealthMetricsSnapshot {
    pub mode: TcpHealthMode,
    pub check_successes: u64,
    pub check_failures: u64,
    pub consecutive_failures: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TransparentProxyMetricsSnapshot {
    pub health_probe: TcpHealthMetricsSnapshot,
    pub upstream_connects: TransparentProxyUpstreamConnectMetricsSnapshot,
    pub active_relays: u64,
    pub accepted_relays: u64,
    pub rejected_relays: u64,
    pub relay_failures: u64,
    pub listener_failures: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TransparentProxyUpstreamConnectMetricsSnapshot {
    pub connect_successes: u64,
    pub connect_failures: u64,
}

pub(in crate::status) fn metrics_snapshot(
    capabilities: &CapabilityMatrix,
    spool: &SpoolStatusSnapshot,
    exporters: &[ExporterStatusSnapshot],
    export_worker: Option<&ExportWorkerRuntimeSnapshot>,
    l7_mitm: Option<L7MitmRuntimeSnapshot>,
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
        l7_mitm: l7_mitm.map(l7_mitm_metrics),
        transparent_proxy: transparent_proxy.map(transparent_proxy_metrics),
        pipeline,
    }
}

fn l7_mitm_metrics(runtime: L7MitmRuntimeSnapshot) -> L7MitmMetricsSnapshot {
    L7MitmMetricsSnapshot {
        backend_health: tcp_health_metrics(runtime.backend_health),
        client_trust: L7MitmClientTrustMetricsSnapshot {
            mode: runtime.client_trust.mode,
            material: runtime.client_trust.material,
        },
        plaintext_bridge: L7MitmPlaintextBridgeMetricsSnapshot {
            mode: runtime.plaintext_bridge.mode,
        },
    }
}

fn transparent_proxy_metrics(
    proxy: TransparentProxyRuntimeSnapshot,
) -> TransparentProxyMetricsSnapshot {
    TransparentProxyMetricsSnapshot {
        health_probe: tcp_health_metrics(proxy.health_probe),
        upstream_connects: TransparentProxyUpstreamConnectMetricsSnapshot {
            connect_successes: proxy.upstream_connects.connect_successes,
            connect_failures: proxy.upstream_connects.connect_failures,
        },
        active_relays: proxy.active_relays,
        accepted_relays: proxy.accepted_relays,
        rejected_relays: proxy.rejected_relays,
        relay_failures: proxy.relay_failures,
        listener_failures: proxy.listener_failures,
    }
}

fn tcp_health_metrics(health: TcpHealthSnapshot) -> TcpHealthMetricsSnapshot {
    TcpHealthMetricsSnapshot {
        mode: health.mode,
        check_successes: health.check_successes,
        check_failures: health.check_failures,
        consecutive_failures: health.consecutive_failures,
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

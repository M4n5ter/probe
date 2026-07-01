use pipeline::PipelineRuntimeMetricsSnapshot;
use probe_core::{CapabilityMatrix, RuntimeMode};
use serde::Serialize;

use crate::{
    capture_provider::CaptureInputActivityRuntimeSnapshot,
    export::ExportWorkerRuntimeSnapshot,
    l7_mitm::{
        L7MitmClientTrustMaterialMode, L7MitmClientTrustMode, L7MitmPlaintextBridgeMode,
        L7MitmRuntimeSnapshot,
    },
    tcp_health::{TcpHealthMode, TcpHealthSnapshot},
    tls_plaintext::{
        TlsPlaintextProviderActivityRuntimeSnapshot, TlsPlaintextProviderSignalRuntimeSnapshot,
        TlsPlaintextRuntimeMode, TlsPlaintextRuntimeSnapshot,
    },
    transparent_interception::TransparentProxyRuntimeSnapshot,
};

use super::{
    export::{ExporterStatusSnapshot, backing_off_exporter_count},
    spool::SpoolStatusSnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    pub capabilities: CapabilityMetricsSnapshot,
    pub capture_input: Option<CaptureInputMetricsSnapshot>,
    pub spool: SpoolMetricsSnapshot,
    pub export: ExportMetricsSnapshot,
    pub l7_mitm: Option<L7MitmMetricsSnapshot>,
    pub transparent_proxy: Option<TransparentProxyMetricsSnapshot>,
    pub tls_plaintext: Option<TlsPlaintextMetricsSnapshot>,
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
pub struct CaptureInputMetricsSnapshot {
    pub polls: CaptureInputPollMetricsSnapshot,
    pub capture_events: u64,
    pub output_loss_events: u64,
    pub lost_events: u64,
    pub last_signal: Option<CaptureInputSignalMetricsSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CaptureInputPollMetricsSnapshot {
    pub total: u64,
    pub events: u64,
    pub progress: u64,
    pub idle: u64,
    pub finished: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CaptureInputSignalMetricsSnapshot {
    pub kind: &'static str,
    pub sequence: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextMetricsSnapshot {
    pub provider_activity: TlsPlaintextProviderActivityMetricsSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextProviderActivityMetricsSnapshot {
    pub progress_signals: u64,
    pub capture_events: u64,
    pub output_loss_events: u64,
    pub lost_events: u64,
    pub last_signal: Option<TlsPlaintextProviderSignalMetricsSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextProviderSignalMetricsSnapshot {
    pub kind: &'static str,
    pub sequence: u64,
    pub observed_unix_ns: u64,
}

pub(in crate::status) struct MetricsSnapshotInput<'a> {
    pub capabilities: &'a CapabilityMatrix,
    pub capture_input: Option<CaptureInputActivityRuntimeSnapshot>,
    pub spool: &'a SpoolStatusSnapshot,
    pub exporters: &'a [ExporterStatusSnapshot],
    pub export_worker: Option<&'a ExportWorkerRuntimeSnapshot>,
    pub l7_mitm: Option<L7MitmRuntimeSnapshot>,
    pub transparent_proxy: Option<TransparentProxyRuntimeSnapshot>,
    pub tls_plaintext: Option<TlsPlaintextRuntimeSnapshot>,
    pub pipeline: Option<PipelineRuntimeMetricsSnapshot>,
}

pub(in crate::status) fn metrics_snapshot(input: MetricsSnapshotInput<'_>) -> MetricsSnapshot {
    MetricsSnapshot {
        capabilities: capability_metrics(input.capabilities),
        capture_input: input.capture_input.map(capture_input_metrics),
        spool: SpoolMetricsSnapshot {
            ingress_last_sequence: input.spool.ingress_last_sequence,
            export_last_sequence: input.spool.export_last_sequence,
        },
        export: ExportMetricsSnapshot {
            sink_count: input.exporters.len() as u64,
            total_lag: total_export_lag(input.exporters),
            backing_off_sink_count: input
                .export_worker
                .map(|_| backing_off_exporter_count(input.exporters)),
        },
        l7_mitm: input.l7_mitm.map(l7_mitm_metrics),
        transparent_proxy: input.transparent_proxy.map(transparent_proxy_metrics),
        tls_plaintext: input.tls_plaintext.and_then(tls_plaintext_metrics),
        pipeline: input.pipeline,
    }
}

fn capture_input_metrics(
    activity: CaptureInputActivityRuntimeSnapshot,
) -> CaptureInputMetricsSnapshot {
    CaptureInputMetricsSnapshot {
        polls: CaptureInputPollMetricsSnapshot {
            total: activity.polls.total,
            events: activity.polls.events,
            progress: activity.polls.progress,
            idle: activity.polls.idle,
            finished: activity.polls.finished,
        },
        capture_events: activity.capture_events,
        output_loss_events: activity.output_loss_events,
        lost_events: activity.lost_events,
        last_signal: activity
            .last_signal
            .map(|signal| CaptureInputSignalMetricsSnapshot {
                kind: signal.kind(),
                sequence: signal.sequence(),
            }),
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

fn tls_plaintext_metrics(
    runtime: TlsPlaintextRuntimeSnapshot,
) -> Option<TlsPlaintextMetricsSnapshot> {
    if runtime.mode == TlsPlaintextRuntimeMode::NotConfigured {
        return None;
    }
    Some(TlsPlaintextMetricsSnapshot {
        provider_activity: tls_plaintext_provider_activity_metrics(runtime.provider_activity),
    })
}

fn tls_plaintext_provider_activity_metrics(
    activity: TlsPlaintextProviderActivityRuntimeSnapshot,
) -> TlsPlaintextProviderActivityMetricsSnapshot {
    TlsPlaintextProviderActivityMetricsSnapshot {
        progress_signals: activity.progress_signals,
        capture_events: activity.capture_events,
        output_loss_events: activity.output_loss_events,
        lost_events: activity.lost_events,
        last_signal: activity
            .last_signal
            .as_ref()
            .map(tls_plaintext_provider_signal_metrics),
    }
}

fn tls_plaintext_provider_signal_metrics(
    signal: &TlsPlaintextProviderSignalRuntimeSnapshot,
) -> TlsPlaintextProviderSignalMetricsSnapshot {
    TlsPlaintextProviderSignalMetricsSnapshot {
        kind: signal.kind(),
        sequence: signal.sequence(),
        observed_unix_ns: signal.observed_unix_ns(),
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

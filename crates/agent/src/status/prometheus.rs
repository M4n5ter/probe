use std::fmt::Write as _;

use probe_core::{CaptureProviderKind, RuntimeMode};

use super::metrics::{TcpHealthMetricsSnapshot, TlsPlaintextMetricsSnapshot};
use crate::{
    capture_provider::{CaptureInputSignalRuntimeSnapshot, CaptureProviderRuntimeDetailsSnapshot},
    l7_mitm::{
        L7MitmBackendHealthMode, L7MitmClientTrustMaterialMode, L7MitmClientTrustMode,
        L7MitmPlaintextBridgeMode,
    },
    status::AgentStatusSnapshot,
    tcp_health::TcpHealthMode,
    transparent_interception::TransparentProxyHealthProbeMode,
};

pub(crate) const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const RUNTIME_MODES: [RuntimeMode; 3] = [
    RuntimeMode::Available,
    RuntimeMode::Degraded,
    RuntimeMode::Unavailable,
];

const OPTIONAL_TRACEPOINT_PAIR_MODES: [RuntimeMode; 2] =
    [RuntimeMode::Available, RuntimeMode::Unavailable];

const TRANSPARENT_PROXY_HEALTH_PROBE_MODES: [TransparentProxyHealthProbeMode; 4] = [
    TransparentProxyHealthProbeMode::Disabled,
    TransparentProxyHealthProbeMode::Pending,
    TransparentProxyHealthProbeMode::Healthy,
    TransparentProxyHealthProbeMode::Unhealthy,
];

const L7_MITM_BACKEND_HEALTH_MODES: [L7MitmBackendHealthMode; 4] = [
    L7MitmBackendHealthMode::Disabled,
    L7MitmBackendHealthMode::Pending,
    L7MitmBackendHealthMode::Healthy,
    L7MitmBackendHealthMode::Unhealthy,
];

const L7_MITM_PLAINTEXT_BRIDGE_MODES: [L7MitmPlaintextBridgeMode; 5] = [
    L7MitmPlaintextBridgeMode::NotConfigured,
    L7MitmPlaintextBridgeMode::Configured,
    L7MitmPlaintextBridgeMode::Ready,
    L7MitmPlaintextBridgeMode::Active,
    L7MitmPlaintextBridgeMode::DisabledAfterError,
];

const L7_MITM_CLIENT_TRUST_MODES: [L7MitmClientTrustMode; 2] = [
    L7MitmClientTrustMode::Disabled,
    L7MitmClientTrustMode::OperatorManaged,
];

const L7_MITM_CLIENT_TRUST_MATERIAL_MODES: [L7MitmClientTrustMaterialMode; 4] = [
    L7MitmClientTrustMaterialMode::None,
    L7MitmClientTrustMaterialMode::CaCertificateAuthority,
    L7MitmClientTrustMaterialMode::LeafCertificateChain,
    L7MitmClientTrustMaterialMode::CaAndLeafCertificateChain,
];

pub(crate) fn render_prometheus_metrics(snapshot: &AgentStatusSnapshot) -> String {
    let mut output = String::new();

    write_family(
        &mut output,
        "traffic_probe_agent_info",
        "gauge",
        "Static labels describing the running agent.",
    );
    write_sample(
        &mut output,
        "traffic_probe_agent_info",
        &[
            ("agent_id", &snapshot.agent_id),
            ("config_version", &snapshot.config_version),
        ],
        1,
    );

    write_family(
        &mut output,
        "traffic_probe_status_generated_unix_time_ns",
        "gauge",
        "Unix timestamp when this status snapshot was generated, in nanoseconds.",
    );
    write_sample(
        &mut output,
        "traffic_probe_status_generated_unix_time_ns",
        &[],
        snapshot.generated_unix_ns,
    );

    write_health(&mut output, snapshot);
    write_capabilities(&mut output, snapshot);
    write_spool(&mut output, snapshot);
    write_export(&mut output, snapshot);
    write_l7_mitm(&mut output, snapshot);
    write_transparent_proxy(&mut output, snapshot);
    write_tls_plaintext(&mut output, snapshot);
    write_capture_provider(&mut output, snapshot);
    write_capture_input(&mut output, snapshot);
    write_pipeline(&mut output, snapshot);

    output
}

fn write_health(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_agent_health_mode",
        "gauge",
        "Current agent health mode as a one-hot gauge.",
    );
    for mode in RUNTIME_MODES {
        write_sample(
            output,
            "traffic_probe_agent_health_mode",
            &[("mode", mode.wire_name())],
            u64::from(snapshot.health.mode == mode),
        );
    }
}

fn write_capabilities(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_capability_modes",
        "gauge",
        "Number of capabilities by runtime mode.",
    );
    for (mode, count) in capability_counts_by_mode(snapshot) {
        write_sample(
            output,
            "traffic_probe_capability_modes",
            &[("mode", mode.wire_name())],
            count,
        );
    }

    write_family(
        output,
        "traffic_probe_capability_state",
        "gauge",
        "Per-capability runtime mode as a one-hot gauge.",
    );
    for capability in snapshot.capabilities.states() {
        for mode in RUNTIME_MODES {
            write_sample(
                output,
                "traffic_probe_capability_state",
                &[
                    ("capability", capability.kind.wire_name()),
                    ("mode", mode.wire_name()),
                ],
                u64::from(capability.mode == mode),
            );
        }
    }
}

fn capability_counts_by_mode(snapshot: &AgentStatusSnapshot) -> [(RuntimeMode, u64); 3] {
    [
        (
            RuntimeMode::Available,
            snapshot.metrics.capabilities.available,
        ),
        (
            RuntimeMode::Degraded,
            snapshot.metrics.capabilities.degraded,
        ),
        (
            RuntimeMode::Unavailable,
            snapshot.metrics.capabilities.unavailable,
        ),
    ]
}

fn write_spool(output: &mut String, snapshot: &AgentStatusSnapshot) {
    if let Some(sequence) = snapshot.metrics.spool.ingress_last_sequence {
        write_family(
            output,
            "traffic_probe_spool_ingress_last_sequence",
            "gauge",
            "Last durable ingress sequence observed in the spool.",
        );
        write_sample(
            output,
            "traffic_probe_spool_ingress_last_sequence",
            &[],
            sequence,
        );
    }

    if let Some(sequence) = snapshot.metrics.spool.export_last_sequence {
        write_family(
            output,
            "traffic_probe_spool_export_last_sequence",
            "gauge",
            "Last durable export sequence observed in the spool.",
        );
        write_sample(
            output,
            "traffic_probe_spool_export_last_sequence",
            &[],
            sequence,
        );
    }
}

fn write_export(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_export_sinks",
        "gauge",
        "Number of configured export sinks.",
    );
    write_sample(
        output,
        "traffic_probe_export_sinks",
        &[],
        snapshot.metrics.export.sink_count,
    );

    if let Some(lag) = snapshot.metrics.export.total_lag {
        write_family(
            output,
            "traffic_probe_export_total_lag",
            "gauge",
            "Total export queue lag across sinks with known cursors.",
        );
        write_sample(output, "traffic_probe_export_total_lag", &[], lag);
    }

    if let Some(count) = snapshot.metrics.export.backing_off_sink_count {
        write_family(
            output,
            "traffic_probe_export_backing_off_sinks",
            "gauge",
            "Number of export sinks currently backing off.",
        );
        write_sample(output, "traffic_probe_export_backing_off_sinks", &[], count);
    }

    let mut wrote_lag_family = false;
    for exporter in &snapshot.exporters {
        if let Some(lag) = exporter.lag {
            if !wrote_lag_family {
                write_family(
                    output,
                    "traffic_probe_export_sink_lag",
                    "gauge",
                    "Per-sink export queue lag for sinks with known cursors.",
                );
                wrote_lag_family = true;
            }
            write_sample(
                output,
                "traffic_probe_export_sink_lag",
                &[("sink", &exporter.id)],
                lag,
            );
        }
    }
}

fn write_l7_mitm(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_l7_mitm_metrics_available",
        "gauge",
        "Whether L7 MITM runtime metrics are present in this snapshot.",
    );
    write_sample(
        output,
        "traffic_probe_l7_mitm_metrics_available",
        &[],
        u64::from(snapshot.metrics.l7_mitm.is_some()),
    );

    let Some(metrics) = snapshot.metrics.l7_mitm else {
        return;
    };

    write_tcp_health(
        output,
        "traffic_probe_l7_mitm_backend_health_mode",
        "L7 MITM backend health probe mode as a one-hot gauge.",
        "traffic_probe_l7_mitm_backend_health_checks_total",
        "L7 MITM backend health probe checks by outcome.",
        &L7_MITM_BACKEND_HEALTH_MODES,
        metrics.backend_health,
    );

    write_one_hot_enum(
        output,
        "traffic_probe_l7_mitm_client_trust_mode",
        "L7 MITM client trust ownership mode as a one-hot gauge.",
        "mode",
        &L7_MITM_CLIENT_TRUST_MODES,
        metrics.client_trust.mode,
        L7MitmClientTrustMode::wire_name,
    );
    write_one_hot_enum(
        output,
        "traffic_probe_l7_mitm_client_trust_material",
        "L7 MITM client trust material shape as a one-hot gauge.",
        "material",
        &L7_MITM_CLIENT_TRUST_MATERIAL_MODES,
        metrics.client_trust.material,
        L7MitmClientTrustMaterialMode::wire_name,
    );
    write_one_hot_enum(
        output,
        "traffic_probe_l7_mitm_plaintext_bridge_mode",
        "L7 MITM plaintext bridge runtime mode as a one-hot gauge.",
        "mode",
        &L7_MITM_PLAINTEXT_BRIDGE_MODES,
        metrics.plaintext_bridge.mode,
        L7MitmPlaintextBridgeMode::wire_name,
    );
}

fn write_one_hot_enum<T>(
    output: &mut String,
    name: &str,
    help: &str,
    label: &str,
    values: &[T],
    selected: T,
    wire_name: impl Fn(T) -> &'static str,
) where
    T: Copy + PartialEq,
{
    write_family(output, name, "gauge", help);
    for value in values {
        write_sample(
            output,
            name,
            &[(label, wire_name(*value))],
            u64::from(selected == *value),
        );
    }
}

fn write_transparent_proxy(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_transparent_proxy_metrics_available",
        "gauge",
        "Whether transparent proxy runtime metrics are present in this snapshot.",
    );
    write_sample(
        output,
        "traffic_probe_transparent_proxy_metrics_available",
        &[],
        u64::from(snapshot.metrics.transparent_proxy.is_some()),
    );

    let Some(metrics) = snapshot.metrics.transparent_proxy else {
        return;
    };

    write_family(
        output,
        "traffic_probe_transparent_proxy_active_relays",
        "gauge",
        "Active managed transparent proxy relay count.",
    );
    write_sample(
        output,
        "traffic_probe_transparent_proxy_active_relays",
        &[],
        metrics.active_relays,
    );

    write_tcp_health(
        output,
        "traffic_probe_transparent_proxy_health_probe_mode",
        "Configured transparent proxy active health probe mode as a one-hot gauge.",
        "traffic_probe_transparent_proxy_health_probe_checks_total",
        "Configured transparent proxy active health probe checks by outcome.",
        &TRANSPARENT_PROXY_HEALTH_PROBE_MODES,
        metrics.health_probe,
    );

    write_family(
        output,
        "traffic_probe_transparent_proxy_upstream_connects_total",
        "counter",
        "Managed transparent proxy upstream connect attempts by outcome.",
    );
    write_sample(
        output,
        "traffic_probe_transparent_proxy_upstream_connects_total",
        &[("outcome", "success")],
        metrics.upstream_connects.connect_successes,
    );
    write_sample(
        output,
        "traffic_probe_transparent_proxy_upstream_connects_total",
        &[("outcome", "failure")],
        metrics.upstream_connects.connect_failures,
    );

    write_family(
        output,
        "traffic_probe_transparent_proxy_relays_total",
        "counter",
        "Managed transparent proxy relays by outcome.",
    );
    write_sample(
        output,
        "traffic_probe_transparent_proxy_relays_total",
        &[("outcome", "accepted")],
        metrics.accepted_relays,
    );
    write_sample(
        output,
        "traffic_probe_transparent_proxy_relays_total",
        &[("outcome", "rejected")],
        metrics.rejected_relays,
    );

    write_family(
        output,
        "traffic_probe_transparent_proxy_failures_total",
        "counter",
        "Managed transparent proxy failures by kind.",
    );
    write_sample(
        output,
        "traffic_probe_transparent_proxy_failures_total",
        &[("kind", "relay")],
        metrics.relay_failures,
    );
    write_sample(
        output,
        "traffic_probe_transparent_proxy_failures_total",
        &[("kind", "listener")],
        metrics.listener_failures,
    );
}

fn write_tls_plaintext(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_tls_plaintext_activity_metrics_available",
        "gauge",
        "Whether TLS plaintext provider activity metrics are present in this snapshot.",
    );
    write_sample(
        output,
        "traffic_probe_tls_plaintext_activity_metrics_available",
        &[],
        u64::from(snapshot.metrics.tls_plaintext.is_some()),
    );

    let Some(metrics) = snapshot.metrics.tls_plaintext else {
        return;
    };

    write_tls_plaintext_activity(output, metrics);
}

fn write_tls_plaintext_activity(output: &mut String, metrics: TlsPlaintextMetricsSnapshot) {
    let activity = metrics.provider_activity;
    write_family(
        output,
        "traffic_probe_tls_plaintext_provider_signals_total",
        "counter",
        "TLS plaintext provider activity signals by kind.",
    );
    write_sample(
        output,
        "traffic_probe_tls_plaintext_provider_signals_total",
        &[("kind", "progress")],
        activity.progress_signals,
    );
    write_sample(
        output,
        "traffic_probe_tls_plaintext_provider_signals_total",
        &[("kind", "capture_event")],
        activity.capture_events,
    );
    write_sample(
        output,
        "traffic_probe_tls_plaintext_provider_signals_total",
        &[("kind", "output_loss")],
        activity.output_loss_events,
    );

    write_family(
        output,
        "traffic_probe_tls_plaintext_lost_events_total",
        "counter",
        "TLS plaintext output ring buffer events lost by the provider.",
    );
    write_sample(
        output,
        "traffic_probe_tls_plaintext_lost_events_total",
        &[],
        activity.lost_events,
    );

    let Some(last_signal) = activity.last_signal else {
        return;
    };
    write_family(
        output,
        "traffic_probe_tls_plaintext_provider_last_signal_sequence",
        "gauge",
        "Latest TLS plaintext provider activity signal sequence.",
    );
    write_sample(
        output,
        "traffic_probe_tls_plaintext_provider_last_signal_sequence",
        &[("kind", last_signal.kind)],
        last_signal.sequence,
    );
    write_family(
        output,
        "traffic_probe_tls_plaintext_provider_last_signal_unix_time_ns",
        "gauge",
        "Unix timestamp when the latest TLS plaintext provider activity signal was observed, in nanoseconds.",
    );
    write_sample(
        output,
        "traffic_probe_tls_plaintext_provider_last_signal_unix_time_ns",
        &[("kind", last_signal.kind)],
        last_signal.observed_unix_ns,
    );
}

fn write_tcp_health(
    output: &mut String,
    mode_metric: &str,
    mode_help: &str,
    checks_metric: &str,
    checks_help: &str,
    modes: &[TcpHealthMode],
    health: TcpHealthMetricsSnapshot,
) {
    write_family(output, mode_metric, "gauge", mode_help);
    for mode in modes {
        write_sample(
            output,
            mode_metric,
            &[("mode", mode.wire_name())],
            u64::from(health.mode == *mode),
        );
    }

    write_family(output, checks_metric, "counter", checks_help);
    write_sample(
        output,
        checks_metric,
        &[("outcome", "success")],
        health.check_successes,
    );
    write_sample(
        output,
        checks_metric,
        &[("outcome", "failure")],
        health.check_failures,
    );
}

fn write_pipeline(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_pipeline_metrics_available",
        "gauge",
        "Whether online pipeline runtime metrics are present in this snapshot.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_metrics_available",
        &[],
        u64::from(snapshot.metrics.pipeline.is_some()),
    );

    let Some(metrics) = snapshot.metrics.pipeline else {
        return;
    };

    write_family(
        output,
        "traffic_probe_pipeline_capture_polls_total",
        "counter",
        "Capture provider polls observed by the running pipeline.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_capture_polls_total",
        &[("outcome", "event")],
        metrics.capture_polls.events,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_capture_polls_total",
        &[("outcome", "progress")],
        metrics.capture_polls.progress,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_capture_polls_total",
        &[("outcome", "idle")],
        metrics.capture_polls.idle,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_capture_polls_total",
        &[("outcome", "finished")],
        metrics.capture_polls.finished,
    );

    write_family(
        output,
        "traffic_probe_pipeline_capture_events_read_total",
        "counter",
        "Capture events read by the running pipeline.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_capture_events_read_total",
        &[],
        metrics.capture_events_read,
    );

    write_family(
        output,
        "traffic_probe_pipeline_ingress_records_total",
        "counter",
        "Ingress journal records by pipeline stage.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_ingress_records_total",
        &[("stage", "journaled")],
        metrics.ingress_records_journaled,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_ingress_records_total",
        &[("stage", "recovered")],
        metrics.ingress_records_recovered,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_ingress_records_total",
        &[("stage", "processed")],
        metrics.ingress_records_processed,
    );

    write_family(
        output,
        "traffic_probe_pipeline_export_events_written_total",
        "counter",
        "Export events written by the running pipeline.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_export_events_written_total",
        &[],
        metrics.export_events_written,
    );

    write_family(
        output,
        "traffic_probe_pipeline_event_envelopes_total",
        "counter",
        "Export event envelopes written by classification.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_event_envelopes_total",
        &[("class", "all")],
        metrics.events.total,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_event_envelopes_total",
        &[("class", "degraded")],
        metrics.events.degraded,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_event_envelopes_total",
        &[("class", "gap")],
        metrics.events.gaps,
    );

    write_family(
        output,
        "traffic_probe_pipeline_capture_loss_events_total",
        "counter",
        "Provider capture loss events observed by the running pipeline.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_capture_loss_events_total",
        &[],
        metrics.capture_loss.events,
    );
    write_family(
        output,
        "traffic_probe_pipeline_capture_lost_events_total",
        "counter",
        "Provider-reported capture events lost before the running pipeline could observe them.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_capture_lost_events_total",
        &[],
        metrics.capture_loss.lost_events,
    );

    write_family(
        output,
        "traffic_probe_pipeline_policy_events_total",
        "counter",
        "Policy runtime events by kind.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_policy_events_total",
        &[("kind", "evaluation")],
        metrics.policy.evaluations,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_policy_events_total",
        &[("kind", "selector_miss")],
        metrics.policy.selector_misses,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_policy_events_total",
        &[("kind", "alert")],
        metrics.policy.alerts,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_policy_events_total",
        &[("kind", "verdict")],
        metrics.policy.verdicts,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_policy_events_total",
        &[("kind", "error")],
        metrics.policy.errors,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_policy_events_total",
        &[("kind", "disabled")],
        metrics.policy.disabled,
    );

    write_family(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        "counter",
        "Enforcement decisions by outcome.",
    );
    write_sample(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        &[("outcome", "disabled")],
        metrics.enforcement.disabled,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        &[("outcome", "audit_only")],
        metrics.enforcement.audit_only,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        &[("outcome", "dry_run")],
        metrics.enforcement.dry_run,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        &[("outcome", "selector_miss")],
        metrics.enforcement.selector_miss,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        &[("outcome", "unsupported")],
        metrics.enforcement.unsupported,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        &[("outcome", "failed")],
        metrics.enforcement.failed,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        &[("outcome", "delegated")],
        metrics.enforcement.delegated,
    );
    write_sample(
        output,
        "traffic_probe_pipeline_enforcement_decisions_total",
        &[("outcome", "applied")],
        metrics.enforcement.applied,
    );

    write_family(
        output,
        "traffic_probe_pipeline_enforcement_execution_total",
        "counter",
        "Enforcement decisions by execution kind and surface.",
    );
    for sample in metrics.enforcement.execution.surface_counts() {
        write_sample(
            output,
            "traffic_probe_pipeline_enforcement_execution_total",
            &[
                ("kind", sample.surface.kind_label()),
                ("surface", sample.surface.surface_label()),
            ],
            sample.count,
        );
    }
}

fn write_capture_provider(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_ebpf_process_observation_link_ownership_metrics_available",
        "gauge",
        "Whether eBPF process observation link ownership metrics are present in this snapshot.",
    );
    let Some(CaptureProviderRuntimeDetailsSnapshot::EbpfProcessObservation {
        link_ownership,
        tracepoint_firings,
        kernel_liveness,
        optional_tracepoint_pairs,
    }) = &snapshot.capture.provider
    else {
        write_sample(
            output,
            "traffic_probe_ebpf_process_observation_link_ownership_metrics_available",
            &[],
            0,
        );
        write_family(
            output,
            "traffic_probe_ebpf_process_observation_kernel_liveness_metrics_available",
            "gauge",
            "Whether eBPF process observation kernel liveness metrics are present in this snapshot.",
        );
        write_sample(
            output,
            "traffic_probe_ebpf_process_observation_kernel_liveness_metrics_available",
            &[],
            0,
        );
        write_family(
            output,
            "traffic_probe_ebpf_process_observation_tracepoint_firing_metrics_available",
            "gauge",
            "Whether eBPF process observation tracepoint firing metrics are present in this snapshot.",
        );
        write_sample(
            output,
            "traffic_probe_ebpf_process_observation_tracepoint_firing_metrics_available",
            &[],
            0,
        );
        return;
    };
    write_sample(
        output,
        "traffic_probe_ebpf_process_observation_link_ownership_metrics_available",
        &[],
        1,
    );

    write_one_hot_enum(
        output,
        "traffic_probe_ebpf_process_observation_link_ownership_mode",
        "Userspace-held eBPF process observation tracepoint link ownership mode as a one-hot gauge; this is not per-link kernel firing liveness.",
        "mode",
        &RUNTIME_MODES,
        link_ownership.mode,
        RuntimeMode::wire_name,
    );

    write_family(
        output,
        "traffic_probe_ebpf_process_observation_owned_links",
        "gauge",
        "Total userspace-held committed eBPF process observation tracepoint link handles.",
    );
    write_sample(
        output,
        "traffic_probe_ebpf_process_observation_owned_links",
        &[],
        link_ownership.owned_link_count,
    );

    write_family(
        output,
        "traffic_probe_ebpf_process_observation_kernel_liveness_metrics_available",
        "gauge",
        "Whether eBPF process observation kernel liveness metrics are present in this snapshot.",
    );
    write_sample(
        output,
        "traffic_probe_ebpf_process_observation_kernel_liveness_metrics_available",
        &[],
        1,
    );
    write_one_hot_enum(
        output,
        "traffic_probe_ebpf_process_observation_kernel_liveness_mode",
        "Process eBPF kernel-side firing liveness mode as a one-hot gauge; unavailable means userspace link ownership is not being treated as kernel liveness proof.",
        "mode",
        &RUNTIME_MODES,
        kernel_liveness.mode,
        RuntimeMode::wire_name,
    );

    write_family(
        output,
        "traffic_probe_ebpf_process_observation_tracepoint_firing_metrics_available",
        "gauge",
        "Whether eBPF process observation tracepoint firing metrics are present in this snapshot.",
    );
    write_sample(
        output,
        "traffic_probe_ebpf_process_observation_tracepoint_firing_metrics_available",
        &[],
        1,
    );
    write_one_hot_enum(
        output,
        "traffic_probe_ebpf_process_observation_tracepoint_firing_mode",
        "Process eBPF tracepoint firing counter availability as a one-hot gauge.",
        "mode",
        &RUNTIME_MODES,
        tracepoint_firings.mode,
        RuntimeMode::wire_name,
    );
    if tracepoint_firings.mode == RuntimeMode::Available {
        write_family(
            output,
            "traffic_probe_ebpf_process_observation_tracepoint_firings_total",
            "counter",
            "Kernel-side process eBPF tracepoint handler firings observed through provider counters.",
        );
        write_sample(
            output,
            "traffic_probe_ebpf_process_observation_tracepoint_firings_total",
            &[],
            tracepoint_firings.total_firing_count,
        );
    }

    write_family(
        output,
        "traffic_probe_ebpf_process_observation_program_owned_links",
        "gauge",
        "Userspace-held committed eBPF process observation tracepoint link handles by program.",
    );
    for program in &link_ownership.programs {
        write_sample(
            output,
            "traffic_probe_ebpf_process_observation_program_owned_links",
            &[
                ("program_name", program.program_name),
                ("category", program.category),
                ("tracepoint", program.tracepoint_name),
            ],
            program.owned_link_count,
        );
    }

    if tracepoint_firings.mode == RuntimeMode::Available {
        write_family(
            output,
            "traffic_probe_ebpf_process_observation_program_tracepoint_firings_total",
            "counter",
            "Kernel-side process eBPF tracepoint handler firings by program.",
        );
        for program in &tracepoint_firings.programs {
            write_sample(
                output,
                "traffic_probe_ebpf_process_observation_program_tracepoint_firings_total",
                &[
                    ("program_name", program.program_name),
                    ("category", program.category),
                    ("tracepoint", program.tracepoint_name),
                ],
                program.firing_count,
            );
        }
    }

    write_family(
        output,
        "traffic_probe_ebpf_process_observation_optional_tracepoint_pair_mode",
        "gauge",
        "Optional eBPF process observation tracepoint pair availability as a one-hot gauge.",
    );
    for pair in optional_tracepoint_pairs {
        for mode in OPTIONAL_TRACEPOINT_PAIR_MODES {
            write_sample(
                output,
                "traffic_probe_ebpf_process_observation_optional_tracepoint_pair_mode",
                &[("family", pair.family_name), ("mode", mode.wire_name())],
                u64::from(pair.mode == mode),
            );
        }
    }
}

fn write_capture_input(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "traffic_probe_capture_input_activity_available",
        "gauge",
        "Whether capture input activity is present in this snapshot.",
    );
    write_sample(
        output,
        "traffic_probe_capture_input_activity_available",
        &[],
        u64::from(snapshot.metrics.capture_input.is_some()),
    );

    let Some(activity) = &snapshot.metrics.capture_input else {
        return;
    };

    write_family(
        output,
        "traffic_probe_capture_input_polls_total",
        "counter",
        "Capture input polls by outcome.",
    );
    write_sample(
        output,
        "traffic_probe_capture_input_polls_total",
        &[("outcome", "event")],
        activity.polls.events,
    );
    write_sample(
        output,
        "traffic_probe_capture_input_polls_total",
        &[("outcome", "progress")],
        activity.polls.progress,
    );
    write_sample(
        output,
        "traffic_probe_capture_input_polls_total",
        &[("outcome", "idle")],
        activity.polls.idle,
    );
    write_sample(
        output,
        "traffic_probe_capture_input_polls_total",
        &[("outcome", "finished")],
        activity.polls.finished,
    );

    write_family(
        output,
        "traffic_probe_capture_input_events_total",
        "counter",
        "Capture input events by class before pipeline processing.",
    );
    write_sample(
        output,
        "traffic_probe_capture_input_events_total",
        &[("class", "capture")],
        activity.capture_events,
    );
    write_sample(
        output,
        "traffic_probe_capture_input_events_total",
        &[("class", "output_loss")],
        activity.output_loss_events,
    );

    write_family(
        output,
        "traffic_probe_capture_input_lost_events_total",
        "counter",
        "Capture input reported events lost before userspace observation.",
    );
    write_sample(
        output,
        "traffic_probe_capture_input_lost_events_total",
        &[],
        activity.lost_events,
    );

    write_family(
        output,
        "traffic_probe_capture_input_provider_events_total",
        "counter",
        "Capture input events by provider and class before pipeline processing.",
    );
    for provider in CaptureProviderKind::ALL {
        let provider_activity = activity
            .providers
            .iter()
            .find(|activity| activity.provider == provider);
        write_sample(
            output,
            "traffic_probe_capture_input_provider_events_total",
            &[("provider", provider.wire_name()), ("class", "capture")],
            provider_activity.map_or(0, |activity| activity.capture_events),
        );
        write_sample(
            output,
            "traffic_probe_capture_input_provider_events_total",
            &[("provider", provider.wire_name()), ("class", "output_loss")],
            provider_activity.map_or(0, |activity| activity.output_loss_events),
        );
    }

    write_family(
        output,
        "traffic_probe_capture_input_provider_lost_events_total",
        "counter",
        "Capture input reported lost events by provider before userspace observation.",
    );
    for provider in CaptureProviderKind::ALL {
        let lost_events = activity
            .providers
            .iter()
            .find(|activity| activity.provider == provider)
            .map_or(0, |activity| activity.lost_events);
        write_sample(
            output,
            "traffic_probe_capture_input_provider_lost_events_total",
            &[("provider", provider.wire_name())],
            lost_events,
        );
    }

    write_family(
        output,
        "traffic_probe_capture_input_last_signal",
        "gauge",
        "Capture input last observed signal as a one-hot gauge.",
    );
    for kind in CaptureInputSignalRuntimeSnapshot::KINDS {
        write_sample(
            output,
            "traffic_probe_capture_input_last_signal",
            &[("kind", kind)],
            u64::from(
                activity
                    .last_signal
                    .as_ref()
                    .is_some_and(|signal| signal.kind == kind),
            ),
        );
    }
    let Some(last_signal) = &activity.last_signal else {
        return;
    };
    write_family(
        output,
        "traffic_probe_capture_input_last_signal_sequence",
        "gauge",
        "Latest capture input activity signal sequence.",
    );
    write_sample(
        output,
        "traffic_probe_capture_input_last_signal_sequence",
        &[("kind", last_signal.kind)],
        last_signal.sequence,
    );
    write_family(
        output,
        "traffic_probe_capture_input_last_signal_unix_time_ns",
        "gauge",
        "Unix timestamp when the latest capture input activity signal was observed, in nanoseconds.",
    );
    write_sample(
        output,
        "traffic_probe_capture_input_last_signal_unix_time_ns",
        &[("kind", last_signal.kind)],
        last_signal.observed_unix_ns,
    );
}

fn write_family(output: &mut String, name: &str, metric_type: &str, help: &str) {
    writeln!(output, "# HELP {name} {help}").expect("writing to String cannot fail");
    writeln!(output, "# TYPE {name} {metric_type}").expect("writing to String cannot fail");
}

fn write_sample(output: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    output.push_str(name);
    write_labels(output, labels);
    writeln!(output, " {value}").expect("writing to String cannot fail");
}

fn write_labels(output: &mut String, labels: &[(&str, &str)]) {
    if labels.is_empty() {
        return;
    }
    output.push('{');
    for (index, (name, value)) in labels.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write!(output, "{name}=\"{}\"", escape_label_value(value))
            .expect("writing to String cannot fail");
    }
    output.push('}');
}

fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use pipeline::{
        CaptureLossRuntimeMetricsSnapshot, EnforcementRuntimeMetricsSnapshot,
        EventRuntimeMetricsSnapshot, PipelineRuntimeMetricsSnapshot, PolicyRuntimeMetricsSnapshot,
    };
    use storage::SpoolSnapshot;

    use capture::{
        CaptureError, CapturePoll, CaptureProvider, CaptureProviderRuntimeDiagnostics,
        EbpfProcessObservationRuntimeDiagnostics, EbpfProcessObservationTracepointFiring,
    };
    use probe_core::CapabilityState;

    use super::super::{
        RuntimeStatusInput, build_status_snapshot, build_status_snapshot_with_runtime,
        plan_fixture::{config_with_storage_path, runtime_plan_from_config},
        spool::SpoolStatusInput,
    };
    use super::*;
    use crate::capture_provider::{
        CaptureInputActivityRuntimeSnapshot, CaptureInputPollActivityRuntimeSnapshot,
        CaptureInputProviderActivityRuntimeSnapshot, CaptureInputSignalRuntimeSnapshot,
        CaptureProviderRuntimeDetailsSnapshot, CaptureProviderRuntimeSnapshot,
        CaptureProviderRuntimeState,
    };
    use crate::l7_mitm::{
        L7MitmBackendHealthMode, L7MitmBackendHealthSnapshot, L7MitmClientTrustSnapshot,
        L7MitmPlaintextBridgeMode, L7MitmPlaintextBridgeSnapshot, L7MitmRuntimeSnapshot,
    };
    use crate::tls_plaintext::{
        TlsPlaintextProviderActivityRuntimeSnapshot, TlsPlaintextProviderSignalRuntimeSnapshot,
        TlsPlaintextRuntimeSnapshot,
    };
    use crate::transparent_interception::{
        TransparentProxyHealthProbeMode, TransparentProxyRuntimeMode,
        TransparentProxyRuntimeSnapshot,
    };
    use probe_config::CaptureBackend;
    use runtime::{CaptureEvidenceMode, CapturePlanMode};

    #[test]
    fn render_prometheus_metrics_escapes_label_values() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool"));
        config.agent_id = "agent\"\\\nnext".to_string();
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let snapshot = build_status_snapshot(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::from([("primary".to_string(), 0)]),
            ),
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains("traffic_probe_agent_info{agent_id=\"agent\\\"\\\\\\nnext\""));
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_includes_transparent_proxy_counters()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::from([("primary".to_string(), 0)]),
            ),
            RuntimeStatusInput {
                transparent_proxy: Some(
                    TransparentProxyRuntimeSnapshot::for_test(
                        TransparentProxyRuntimeMode::Configured,
                    )
                    .with_relay_counts(2, 3, 5, 7, 11)
                    .with_upstream_connects(13, 17, Some("connection refused"))
                    .with_health_probe(
                        TransparentProxyHealthProbeMode::Healthy,
                        19,
                        23,
                        0,
                        None,
                    ),
                ),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains("traffic_probe_transparent_proxy_metrics_available 1\n"));
        assert!(metrics.contains("traffic_probe_transparent_proxy_active_relays 2\n"));
        assert!(
            metrics.contains(
                "traffic_probe_transparent_proxy_health_probe_mode{mode=\"healthy\"} 1\n"
            )
        );
        assert!(metrics.contains(
            "traffic_probe_transparent_proxy_health_probe_checks_total{outcome=\"success\"} 19\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_transparent_proxy_health_probe_checks_total{outcome=\"failure\"} 23\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_transparent_proxy_upstream_connects_total{outcome=\"success\"} 13\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_transparent_proxy_upstream_connects_total{outcome=\"failure\"} 17\n"
        ));
        assert!(
            metrics
                .contains("traffic_probe_transparent_proxy_relays_total{outcome=\"accepted\"} 3\n")
        );
        assert!(
            metrics
                .contains("traffic_probe_transparent_proxy_relays_total{outcome=\"rejected\"} 5\n")
        );
        assert!(
            metrics.contains("traffic_probe_transparent_proxy_failures_total{kind=\"relay\"} 7\n")
        );
        assert!(
            metrics
                .contains("traffic_probe_transparent_proxy_failures_total{kind=\"listener\"} 11\n")
        );
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_includes_l7_mitm_backend_health_counters()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::from([("primary".to_string(), 0)]),
            ),
            RuntimeStatusInput {
                l7_mitm: Some(L7MitmRuntimeSnapshot {
                    backend_health: L7MitmBackendHealthSnapshot {
                        mode: L7MitmBackendHealthMode::Unhealthy,
                        check_successes: 5,
                        check_failures: 7,
                        consecutive_failures: 3,
                        last_failure_reason: Some("connection refused".to_string()),
                    },
                    client_trust: L7MitmClientTrustSnapshot::disabled(),
                    plaintext_bridge: L7MitmPlaintextBridgeSnapshot {
                        mode: L7MitmPlaintextBridgeMode::DisabledAfterError,
                        disable_reason: Some("feed parse error".to_string()),
                    },
                }),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert_eq!(snapshot.health.mode, RuntimeMode::Degraded);
        assert!(snapshot.health.reasons.iter().any(|reason| {
            reason.contains("L7 MITM backend health probe unhealthy")
                && reason.contains("connection refused")
                && reason.contains("L7 MITM plaintext bridge degraded")
                && reason.contains("feed parse error")
        }));
        assert!(metrics.contains("traffic_probe_l7_mitm_metrics_available 1\n"));
        assert!(
            metrics.contains("traffic_probe_l7_mitm_backend_health_mode{mode=\"unhealthy\"} 1\n")
        );
        assert!(metrics.contains("traffic_probe_l7_mitm_client_trust_mode{mode=\"disabled\"} 1\n"));
        assert!(
            metrics.contains("traffic_probe_l7_mitm_client_trust_material{material=\"none\"} 1\n")
        );
        assert!(metrics.contains(
            "traffic_probe_l7_mitm_plaintext_bridge_mode{mode=\"disabled_after_error\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_l7_mitm_backend_health_checks_total{outcome=\"success\"} 5\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_l7_mitm_backend_health_checks_total{outcome=\"failure\"} 7\n"
        ));
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_includes_tls_plaintext_activity_counters()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let mut tls_plaintext = TlsPlaintextRuntimeSnapshot::enabled();
        tls_plaintext.provider_activity = TlsPlaintextProviderActivityRuntimeSnapshot {
            progress_signals: 2,
            capture_events: 3,
            output_loss_events: 5,
            lost_events: 17,
            last_signal: Some(TlsPlaintextProviderSignalRuntimeSnapshot::OutputLoss {
                sequence: 10,
                observed_unix_ns: 99,
                capture_timestamp: probe_core::Timestamp {
                    monotonic_ns: 7,
                    wall_time_unix_ns: 8,
                },
                lost_events: 11,
            }),
        };
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::from([("primary".to_string(), 0)]),
            ),
            RuntimeStatusInput {
                tls_plaintext: Some(tls_plaintext),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains("traffic_probe_tls_plaintext_activity_metrics_available 1\n"));
        assert!(
            metrics.contains(
                "traffic_probe_tls_plaintext_provider_signals_total{kind=\"progress\"} 2\n"
            )
        );
        assert!(metrics.contains(
            "traffic_probe_tls_plaintext_provider_signals_total{kind=\"capture_event\"} 3\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_tls_plaintext_provider_signals_total{kind=\"output_loss\"} 5\n"
        ));
        assert!(metrics.contains("traffic_probe_tls_plaintext_lost_events_total 17\n"));
        assert!(metrics.contains(
            "traffic_probe_tls_plaintext_provider_last_signal_sequence{kind=\"output_loss\"} 10\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_tls_plaintext_provider_last_signal_unix_time_ns{kind=\"output_loss\"} 99\n"
        ));
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_hides_tls_plaintext_activity_when_not_configured()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::from([("primary".to_string(), 0)]),
            ),
            RuntimeStatusInput {
                tls_plaintext: Some(TlsPlaintextRuntimeSnapshot::not_configured()),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains("traffic_probe_tls_plaintext_activity_metrics_available 0\n"));
        assert!(!metrics.contains("traffic_probe_tls_plaintext_provider_signals_total"));
        assert!(!metrics.contains("traffic_probe_tls_plaintext_lost_events_total"));
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_includes_ebpf_link_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::new(),
            ),
            RuntimeStatusInput {
                capture: Some(CaptureProviderRuntimeSnapshot {
                    selected_backend: CaptureBackend::Ebpf,
                    plan_mode: CapturePlanMode::Live,
                    provider_runtime_mode: RuntimeMode::Degraded,
                    evidence_mode: CaptureEvidenceMode::BestEffort,
                    evidence_reason: Some("eBPF provider is best-effort".to_string()),
                    reason: Some("kernel observer is best-effort".to_string()),
                    open_failures: Vec::new(),
                    provider: Some(CaptureProviderRuntimeDetailsSnapshot::ebpf_process_observation(
                        capture::EbpfProcessObservationProbeSnapshot::from_link_ownership_and_optional_pairs(
                            capture::EbpfProcessObservationLinkOwnershipSnapshot::owned_by_programs([
                                    capture::EbpfProcessObservationProgramLinkOwnershipSnapshot::new(
                                        "connect_enter",
                                        "syscalls",
                                        "sys_enter_connect",
                                        1,
                                    ),
                                    capture::EbpfProcessObservationProgramLinkOwnershipSnapshot::new(
                                        "connect_exit",
                                        "syscalls",
                                        "sys_exit_connect",
                                        1,
                                    ),
                                ]),
                            [capture::EbpfProcessObservationOptionalTracepointPairSnapshot::kernel_missing(
                                capture::EBPF_PROCESS_OPTIONAL_TRACEPOINT_PAIR_SPECS[0],
                            )],
                        ),
                    )),
                }),
                capture_input: Some(CaptureInputActivityRuntimeSnapshot {
                    polls: CaptureInputPollActivityRuntimeSnapshot {
                        total: 1,
                        events: 1,
                        progress: 0,
                        idle: 0,
                        finished: 0,
                    },
                    capture_events: 0,
                    output_loss_events: 1,
                    lost_events: 3,
                    providers: vec![CaptureInputProviderActivityRuntimeSnapshot {
                        provider: probe_core::CaptureProviderKind::Ebpf,
                        capture_events: 0,
                        output_loss_events: 1,
                        lost_events: 3,
                    }],
                    last_signal: Some(CaptureInputSignalRuntimeSnapshot::OutputLoss {
                        sequence: 1,
                        observed_unix_ns: 101,
                        source: probe_core::CaptureSource::EbpfSyscall,
                        provider: probe_core::CaptureProviderKind::Ebpf,
                        event_wall_time_unix_ns: 99,
                        lost_events: 3,
                    }),
                }),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_link_ownership_metrics_available 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_link_ownership_mode{mode=\"available\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_link_ownership_mode{mode=\"unavailable\"} 0\n"
        ));
        assert!(metrics.contains("traffic_probe_ebpf_process_observation_owned_links 2\n"));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_kernel_liveness_metrics_available 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_kernel_liveness_mode{mode=\"available\"} 0\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_kernel_liveness_mode{mode=\"degraded\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_kernel_liveness_mode{mode=\"unavailable\"} 0\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_tracepoint_firing_metrics_available 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_tracepoint_firing_mode{mode=\"unavailable\"} 1\n"
        ));
        assert!(
            !metrics.contains("traffic_probe_ebpf_process_observation_tracepoint_firings_total")
        );
        assert!(
            !metrics.contains(
                "traffic_probe_ebpf_process_observation_program_tracepoint_firings_total"
            )
        );
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_program_owned_links{program_name=\"connect_enter\",category=\"syscalls\",tracepoint=\"sys_enter_connect\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_program_owned_links{program_name=\"connect_exit\",category=\"syscalls\",tracepoint=\"sys_exit_connect\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_optional_tracepoint_pair_mode{family=\"sendfile\",mode=\"available\"} 0\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_optional_tracepoint_pair_mode{family=\"sendfile\",mode=\"unavailable\"} 1\n"
        ));
        assert!(!metrics.contains(
            "traffic_probe_ebpf_process_observation_optional_tracepoint_pair_mode{family=\"sendfile\",mode=\"degraded\"}"
        ));
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_includes_available_ebpf_tracepoint_firings()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let capture_runtime = CaptureProviderRuntimeState::default();
        capture_runtime.record(CaptureProviderRuntimeSnapshot {
            selected_backend: CaptureBackend::Ebpf,
            plan_mode: CapturePlanMode::Live,
            provider_runtime_mode: RuntimeMode::Degraded,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some("eBPF provider is best-effort".to_string()),
            reason: Some("kernel observer is best-effort".to_string()),
            open_failures: Vec::new(),
            provider: Some(CaptureProviderRuntimeDetailsSnapshot::ebpf_process_observation(
                capture::EbpfProcessObservationProbeSnapshot::from_link_ownership_and_optional_pairs(
                    capture::EbpfProcessObservationLinkOwnershipSnapshot::owned_by_programs([
                        capture::EbpfProcessObservationProgramLinkOwnershipSnapshot::new(
                            "connect_enter",
                            "syscalls",
                            "sys_enter_connect",
                            1,
                        ),
                    ]),
                    [],
                ),
            )),
        });
        let mut provider =
            capture_runtime.observe_capture_input(Box::new(TracepointFiringDiagnosticProvider));
        assert_eq!(provider.poll_next()?, CapturePoll::Progress);

        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::new(),
            ),
            RuntimeStatusInput {
                capture: capture_runtime.snapshot(),
                capture_input: capture_runtime.input_activity_snapshot(),
                ..RuntimeStatusInput::default()
            },
        );

        let provider = serde_json::to_value(&snapshot.capture.provider)?;
        assert_eq!(
            provider["tracepoint_firings"]["mode"],
            serde_json::json!("available")
        );
        assert_eq!(provider["tracepoint_firings"]["total_firing_count"], 3);
        assert_eq!(
            provider["kernel_liveness"]["mode"],
            serde_json::json!("degraded")
        );

        let metrics = render_prometheus_metrics(&snapshot);
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_tracepoint_firing_mode{mode=\"available\"} 1\n"
        ));
        assert!(
            metrics.contains("traffic_probe_ebpf_process_observation_tracepoint_firings_total 3\n")
        );
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_program_tracepoint_firings_total{program_name=\"connect_enter\",category=\"syscalls\",tracepoint=\"sys_enter_connect\"} 3\n"
        ));
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_hides_ebpf_link_ownership_when_provider_details_are_absent()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::new(),
            ),
            RuntimeStatusInput {
                capture: Some(CaptureProviderRuntimeSnapshot {
                    selected_backend: CaptureBackend::Libpcap,
                    plan_mode: CapturePlanMode::Live,
                    provider_runtime_mode: RuntimeMode::Available,
                    evidence_mode: CaptureEvidenceMode::BestEffort,
                    evidence_reason: Some("libpcap stream assembly is best-effort".to_string()),
                    reason: None,
                    open_failures: Vec::new(),
                    provider: None,
                }),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_link_ownership_metrics_available 0\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_kernel_liveness_metrics_available 0\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_tracepoint_firing_metrics_available 0\n"
        ));
        assert!(!metrics.contains("traffic_probe_ebpf_process_observation_kernel_liveness_mode{"));
        assert!(!metrics.contains("traffic_probe_ebpf_process_observation_owned_links"));
        assert!(!metrics.contains("traffic_probe_ebpf_process_observation_program_owned_links"));
        assert!(
            !metrics.contains(
                "traffic_probe_ebpf_process_observation_program_tracepoint_firings_total"
            )
        );
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_reports_unavailable_ebpf_link_ownership_when_unreported()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::new(),
            ),
            RuntimeStatusInput {
                capture: Some(CaptureProviderRuntimeSnapshot {
                    selected_backend: CaptureBackend::Ebpf,
                    plan_mode: CapturePlanMode::Live,
                    provider_runtime_mode: RuntimeMode::Degraded,
                    evidence_mode: CaptureEvidenceMode::BestEffort,
                    evidence_reason: Some("eBPF provider is best-effort".to_string()),
                    reason: Some("kernel observer is best-effort".to_string()),
                    open_failures: Vec::new(),
                    provider: Some(
                        CaptureProviderRuntimeDetailsSnapshot::ebpf_process_observation(
                            capture::EbpfProcessObservationProbeSnapshot::unreported(),
                        ),
                    ),
                }),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_link_ownership_metrics_available 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_link_ownership_mode{mode=\"available\"} 0\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_link_ownership_mode{mode=\"unavailable\"} 1\n"
        ));
        assert!(metrics.contains("traffic_probe_ebpf_process_observation_owned_links 0\n"));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_kernel_liveness_metrics_available 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_kernel_liveness_mode{mode=\"unavailable\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_tracepoint_firing_metrics_available 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_ebpf_process_observation_tracepoint_firing_mode{mode=\"unavailable\"} 1\n"
        ));
        assert!(
            !metrics.contains("traffic_probe_ebpf_process_observation_tracepoint_firings_total")
        );
        assert!(!metrics.contains("traffic_probe_ebpf_process_observation_program_owned_links{"));
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_includes_capture_input_activity_counters()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::new(),
            ),
            RuntimeStatusInput {
                capture: Some(CaptureProviderRuntimeSnapshot {
                    selected_backend: CaptureBackend::Ebpf,
                    plan_mode: CapturePlanMode::Live,
                    provider_runtime_mode: RuntimeMode::Degraded,
                    evidence_mode: CaptureEvidenceMode::BestEffort,
                    evidence_reason: Some("eBPF provider is best-effort".to_string()),
                    reason: Some("kernel observer is best-effort".to_string()),
                    open_failures: Vec::new(),
                    provider: None,
                }),
                capture_input: Some(CaptureInputActivityRuntimeSnapshot {
                    polls: CaptureInputPollActivityRuntimeSnapshot {
                        total: 5,
                        events: 2,
                        progress: 1,
                        idle: 1,
                        finished: 1,
                    },
                    capture_events: 1,
                    output_loss_events: 1,
                    lost_events: 3,
                    providers: vec![
                        CaptureInputProviderActivityRuntimeSnapshot {
                            provider: probe_core::CaptureProviderKind::Libpcap,
                            capture_events: 1,
                            output_loss_events: 0,
                            lost_events: 0,
                        },
                        CaptureInputProviderActivityRuntimeSnapshot {
                            provider: probe_core::CaptureProviderKind::Ebpf,
                            capture_events: 0,
                            output_loss_events: 1,
                            lost_events: 3,
                        },
                    ],
                    last_signal: Some(CaptureInputSignalRuntimeSnapshot::OutputLoss {
                        sequence: 4,
                        observed_unix_ns: 101,
                        source: probe_core::CaptureSource::EbpfSyscall,
                        provider: probe_core::CaptureProviderKind::Ebpf,
                        event_wall_time_unix_ns: 99,
                        lost_events: 3,
                    }),
                }),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains("traffic_probe_capture_input_activity_available 1\n"));
        assert!(metrics.contains("traffic_probe_capture_input_polls_total{outcome=\"event\"} 2\n"));
        assert!(
            metrics.contains("traffic_probe_capture_input_polls_total{outcome=\"progress\"} 1\n")
        );
        assert!(metrics.contains("traffic_probe_capture_input_polls_total{outcome=\"idle\"} 1\n"));
        assert!(
            metrics.contains("traffic_probe_capture_input_polls_total{outcome=\"finished\"} 1\n")
        );
        assert!(
            metrics.contains("traffic_probe_capture_input_events_total{class=\"capture\"} 1\n")
        );
        assert!(
            metrics.contains("traffic_probe_capture_input_events_total{class=\"output_loss\"} 1\n")
        );
        assert!(metrics.contains("traffic_probe_capture_input_lost_events_total 3\n"));
        assert!(metrics.contains(
            "traffic_probe_capture_input_provider_events_total{provider=\"libpcap\",class=\"capture\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_capture_input_provider_events_total{provider=\"ebpf\",class=\"output_loss\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_capture_input_provider_lost_events_total{provider=\"ebpf\"} 3\n"
        ));
        assert!(
            metrics.contains("traffic_probe_capture_input_last_signal{kind=\"output_loss\"} 1\n")
        );
        assert!(metrics.contains("traffic_probe_capture_input_last_signal{kind=\"event\"} 0\n"));
        assert!(metrics.contains(
            "traffic_probe_capture_input_last_signal_sequence{kind=\"output_loss\"} 4\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_capture_input_last_signal_unix_time_ns{kind=\"output_loss\"} 101\n"
        ));
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_includes_capture_loss_counters()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::from([("primary".to_string(), 0)]),
            ),
            RuntimeStatusInput {
                pipeline: Some(PipelineRuntimeMetricsSnapshot {
                    capture_polls: pipeline::CapturePollRuntimeMetricsSnapshot {
                        total: 6,
                        events: 3,
                        progress: 1,
                        idle: 1,
                        finished: 1,
                    },
                    capture_events_read: 3,
                    ingress_records_journaled: 3,
                    ingress_records_recovered: 0,
                    ingress_records_processed: 3,
                    export_events_written: 2,
                    events: EventRuntimeMetricsSnapshot {
                        total: 2,
                        degraded: 1,
                        gaps: 1,
                    },
                    capture_loss: CaptureLossRuntimeMetricsSnapshot {
                        events: 2,
                        lost_events: 17,
                    },
                    policy: PolicyRuntimeMetricsSnapshot {
                        evaluations: 4,
                        selector_misses: 1,
                        alerts: 1,
                        verdicts: 1,
                        errors: 3,
                        disabled: 1,
                    },
                    enforcement: EnforcementRuntimeMetricsSnapshot::default(),
                }),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(
            metrics.contains("traffic_probe_pipeline_capture_polls_total{outcome=\"event\"} 3\n")
        );
        assert!(
            metrics
                .contains("traffic_probe_pipeline_capture_polls_total{outcome=\"progress\"} 1\n")
        );
        assert!(
            metrics.contains("traffic_probe_pipeline_capture_polls_total{outcome=\"idle\"} 1\n")
        );
        assert!(
            metrics
                .contains("traffic_probe_pipeline_capture_polls_total{outcome=\"finished\"} 1\n")
        );
        assert!(metrics.contains("traffic_probe_pipeline_capture_loss_events_total 2\n"));
        assert!(metrics.contains("traffic_probe_pipeline_capture_lost_events_total 17\n"));
        assert!(
            metrics.contains("traffic_probe_pipeline_event_envelopes_total{class=\"all\"} 2\n")
        );
        assert!(
            metrics
                .contains("traffic_probe_pipeline_event_envelopes_total{class=\"degraded\"} 1\n")
        );
        assert!(
            metrics.contains("traffic_probe_pipeline_event_envelopes_total{class=\"gap\"} 1\n")
        );
        assert!(
            metrics.contains("traffic_probe_pipeline_policy_events_total{kind=\"disabled\"} 1\n")
        );
        Ok(())
    }

    #[test]
    fn render_prometheus_metrics_includes_enforcement_outcome_counters()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(
            config_with_storage_path(PathBuf::from("/tmp/traffic-probe-spool")),
            Vec::new(),
        )?;
        let snapshot = build_status_snapshot_with_runtime(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/traffic-probe-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::from([("primary".to_string(), 0)]),
            ),
            RuntimeStatusInput {
                pipeline: Some(PipelineRuntimeMetricsSnapshot {
                    enforcement: EnforcementRuntimeMetricsSnapshot {
                        decisions: 8,
                        disabled: 1,
                        audit_only: 1,
                        dry_run: 1,
                        selector_miss: 1,
                        unsupported: 1,
                        failed: 1,
                        delegated: 1,
                        applied: 1,
                        execution: pipeline::EnforcementExecutionRuntimeMetricsSnapshot {
                            connection_backend:
                                pipeline::ConnectionBackendExecutionRuntimeMetricsSnapshot {
                                    decisions: 1,
                                    linux_socket_destroy: 1,
                                },
                            proxy_side_hook:
                                pipeline::ProxySideHookExecutionRuntimeMetricsSnapshot {
                                    decisions: 1,
                                    l7_mitm: 1,
                                },
                        },
                    },
                    ..PipelineRuntimeMetricsSnapshot::default()
                }),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        for outcome in [
            "disabled",
            "audit_only",
            "dry_run",
            "selector_miss",
            "unsupported",
            "failed",
            "delegated",
            "applied",
        ] {
            assert!(metrics.contains(&format!(
                "traffic_probe_pipeline_enforcement_decisions_total{{outcome=\"{outcome}\"}} 1\n"
            )));
        }
        assert!(metrics.contains(
            "traffic_probe_pipeline_enforcement_execution_total{kind=\"connection_backend\",surface=\"linux_socket_destroy\"} 1\n"
        ));
        assert!(metrics.contains(
            "traffic_probe_pipeline_enforcement_execution_total{kind=\"proxy_side_hook\",surface=\"l7_mitm\"} 1\n"
        ));
        Ok(())
    }

    struct TracepointFiringDiagnosticProvider;

    impl CaptureProvider for TracepointFiringDiagnosticProvider {
        fn name(&self) -> &'static str {
            "tracepoint-firing-diagnostic"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Progress)
        }

        fn runtime_diagnostics(&mut self) -> CaptureProviderRuntimeDiagnostics {
            CaptureProviderRuntimeDiagnostics::from_ebpf_process_observation(
                EbpfProcessObservationRuntimeDiagnostics {
                    tracepoint_firings: Ok(vec![EbpfProcessObservationTracepointFiring {
                        program_name: "connect_enter",
                        category: "syscalls",
                        tracepoint_name: "sys_enter_connect",
                        firing_count: 3,
                    }]),
                },
            )
        }
    }
}

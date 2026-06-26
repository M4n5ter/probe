use std::fmt::Write as _;

use probe_core::RuntimeMode;

use super::metrics::TcpHealthMetricsSnapshot;
use crate::{
    l7_mitm::{L7MitmBackendHealthMode, L7MitmPlaintextBridgeMode},
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

    write_family(
        output,
        "traffic_probe_l7_mitm_plaintext_bridge_mode",
        "gauge",
        "L7 MITM plaintext bridge runtime mode as a one-hot gauge.",
    );
    for mode in L7_MITM_PLAINTEXT_BRIDGE_MODES {
        write_sample(
            output,
            "traffic_probe_l7_mitm_plaintext_bridge_mode",
            &[("mode", mode.wire_name())],
            u64::from(metrics.plaintext_bridge.mode == mode),
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
        &[("outcome", "applied")],
        metrics.enforcement.applied,
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
        PipelineRuntimeMetricsSnapshot, PolicyRuntimeMetricsSnapshot,
    };
    use storage::SpoolSnapshot;

    use super::super::{
        RuntimeStatusInput, build_status_snapshot, build_status_snapshot_with_runtime,
        plan_fixture::{config_with_storage_path, runtime_plan_from_config},
        spool::SpoolStatusInput,
    };
    use super::*;
    use crate::l7_mitm::{
        L7MitmBackendHealthMode, L7MitmBackendHealthSnapshot, L7MitmPlaintextBridgeMode,
        L7MitmPlaintextBridgeSnapshot, L7MitmRuntimeSnapshot,
    };
    use crate::transparent_interception::{
        TransparentProxyHealthProbeMode, TransparentProxyRuntimeMode,
        TransparentProxyRuntimeSnapshot,
    };

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
                    capture_events_read: 3,
                    ingress_records_journaled: 3,
                    ingress_records_recovered: 0,
                    ingress_records_processed: 3,
                    export_events_written: 2,
                    capture_loss: CaptureLossRuntimeMetricsSnapshot {
                        events: 2,
                        lost_events: 17,
                    },
                    policy: PolicyRuntimeMetricsSnapshot::default(),
                    enforcement: EnforcementRuntimeMetricsSnapshot::default(),
                }),
                ..RuntimeStatusInput::default()
            },
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains("traffic_probe_pipeline_capture_loss_events_total 2\n"));
        assert!(metrics.contains("traffic_probe_pipeline_capture_lost_events_total 17\n"));
        Ok(())
    }
}

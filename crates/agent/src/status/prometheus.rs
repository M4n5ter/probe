use std::fmt::Write as _;

use probe_core::RuntimeMode;

use crate::status::AgentStatusSnapshot;

pub(crate) const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const RUNTIME_MODES: [RuntimeMode; 3] = [
    RuntimeMode::Available,
    RuntimeMode::Degraded,
    RuntimeMode::Unavailable,
];

pub(crate) fn render_prometheus_metrics(snapshot: &AgentStatusSnapshot) -> String {
    let mut output = String::new();

    write_family(
        &mut output,
        "sssa_agent_info",
        "gauge",
        "Static labels describing the running agent.",
    );
    write_sample(
        &mut output,
        "sssa_agent_info",
        &[
            ("agent_id", &snapshot.agent_id),
            ("config_version", &snapshot.config_version),
        ],
        1,
    );

    write_family(
        &mut output,
        "sssa_status_generated_unix_time_ns",
        "gauge",
        "Unix timestamp when this status snapshot was generated, in nanoseconds.",
    );
    write_sample(
        &mut output,
        "sssa_status_generated_unix_time_ns",
        &[],
        snapshot.generated_unix_ns,
    );

    write_health(&mut output, snapshot);
    write_capabilities(&mut output, snapshot);
    write_spool(&mut output, snapshot);
    write_export(&mut output, snapshot);
    write_pipeline(&mut output, snapshot);

    output
}

fn write_health(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "sssa_agent_health_mode",
        "gauge",
        "Current agent health mode as a one-hot gauge.",
    );
    for mode in RUNTIME_MODES {
        write_sample(
            output,
            "sssa_agent_health_mode",
            &[("mode", mode.wire_name())],
            u64::from(snapshot.health.mode == mode),
        );
    }
}

fn write_capabilities(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "sssa_capability_modes",
        "gauge",
        "Number of capabilities by runtime mode.",
    );
    for (mode, count) in capability_counts_by_mode(snapshot) {
        write_sample(
            output,
            "sssa_capability_modes",
            &[("mode", mode.wire_name())],
            count,
        );
    }

    write_family(
        output,
        "sssa_capability_state",
        "gauge",
        "Per-capability runtime mode as a one-hot gauge.",
    );
    for capability in snapshot.capabilities.states() {
        for mode in RUNTIME_MODES {
            write_sample(
                output,
                "sssa_capability_state",
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
            "sssa_spool_ingress_last_sequence",
            "gauge",
            "Last durable ingress sequence observed in the spool.",
        );
        write_sample(output, "sssa_spool_ingress_last_sequence", &[], sequence);
    }

    if let Some(sequence) = snapshot.metrics.spool.export_last_sequence {
        write_family(
            output,
            "sssa_spool_export_last_sequence",
            "gauge",
            "Last durable export sequence observed in the spool.",
        );
        write_sample(output, "sssa_spool_export_last_sequence", &[], sequence);
    }
}

fn write_export(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "sssa_export_sinks",
        "gauge",
        "Number of configured export sinks.",
    );
    write_sample(
        output,
        "sssa_export_sinks",
        &[],
        snapshot.metrics.export.sink_count,
    );

    if let Some(lag) = snapshot.metrics.export.total_lag {
        write_family(
            output,
            "sssa_export_total_lag",
            "gauge",
            "Total export queue lag across sinks with known cursors.",
        );
        write_sample(output, "sssa_export_total_lag", &[], lag);
    }

    if let Some(count) = snapshot.metrics.export.backing_off_sink_count {
        write_family(
            output,
            "sssa_export_backing_off_sinks",
            "gauge",
            "Number of export sinks currently backing off.",
        );
        write_sample(output, "sssa_export_backing_off_sinks", &[], count);
    }

    let mut wrote_lag_family = false;
    for exporter in &snapshot.exporters {
        if let Some(lag) = exporter.lag {
            if !wrote_lag_family {
                write_family(
                    output,
                    "sssa_export_sink_lag",
                    "gauge",
                    "Per-sink export queue lag for sinks with known cursors.",
                );
                wrote_lag_family = true;
            }
            write_sample(
                output,
                "sssa_export_sink_lag",
                &[("sink", &exporter.id)],
                lag,
            );
        }
    }
}

fn write_pipeline(output: &mut String, snapshot: &AgentStatusSnapshot) {
    write_family(
        output,
        "sssa_pipeline_metrics_available",
        "gauge",
        "Whether online pipeline runtime metrics are present in this snapshot.",
    );
    write_sample(
        output,
        "sssa_pipeline_metrics_available",
        &[],
        u64::from(snapshot.metrics.pipeline.is_some()),
    );

    let Some(metrics) = snapshot.metrics.pipeline else {
        return;
    };

    write_family(
        output,
        "sssa_pipeline_capture_events_read_total",
        "counter",
        "Capture events read by the running pipeline.",
    );
    write_sample(
        output,
        "sssa_pipeline_capture_events_read_total",
        &[],
        metrics.capture_events_read,
    );

    write_family(
        output,
        "sssa_pipeline_ingress_records_total",
        "counter",
        "Ingress journal records by pipeline stage.",
    );
    write_sample(
        output,
        "sssa_pipeline_ingress_records_total",
        &[("stage", "journaled")],
        metrics.ingress_records_journaled,
    );
    write_sample(
        output,
        "sssa_pipeline_ingress_records_total",
        &[("stage", "recovered")],
        metrics.ingress_records_recovered,
    );
    write_sample(
        output,
        "sssa_pipeline_ingress_records_total",
        &[("stage", "processed")],
        metrics.ingress_records_processed,
    );

    write_family(
        output,
        "sssa_pipeline_export_events_written_total",
        "counter",
        "Export events written by the running pipeline.",
    );
    write_sample(
        output,
        "sssa_pipeline_export_events_written_total",
        &[],
        metrics.export_events_written,
    );

    write_family(
        output,
        "sssa_pipeline_policy_events_total",
        "counter",
        "Policy runtime events by kind.",
    );
    write_sample(
        output,
        "sssa_pipeline_policy_events_total",
        &[("kind", "evaluation")],
        metrics.policy.evaluations,
    );
    write_sample(
        output,
        "sssa_pipeline_policy_events_total",
        &[("kind", "selector_miss")],
        metrics.policy.selector_misses,
    );
    write_sample(
        output,
        "sssa_pipeline_policy_events_total",
        &[("kind", "alert")],
        metrics.policy.alerts,
    );
    write_sample(
        output,
        "sssa_pipeline_policy_events_total",
        &[("kind", "verdict")],
        metrics.policy.verdicts,
    );
    write_sample(
        output,
        "sssa_pipeline_policy_events_total",
        &[("kind", "error")],
        metrics.policy.errors,
    );

    write_family(
        output,
        "sssa_pipeline_enforcement_decisions_total",
        "counter",
        "Enforcement decisions by outcome.",
    );
    write_sample(
        output,
        "sssa_pipeline_enforcement_decisions_total",
        &[("outcome", "disabled")],
        metrics.enforcement.disabled,
    );
    write_sample(
        output,
        "sssa_pipeline_enforcement_decisions_total",
        &[("outcome", "audit_only")],
        metrics.enforcement.audit_only,
    );
    write_sample(
        output,
        "sssa_pipeline_enforcement_decisions_total",
        &[("outcome", "dry_run")],
        metrics.enforcement.dry_run,
    );
    write_sample(
        output,
        "sssa_pipeline_enforcement_decisions_total",
        &[("outcome", "selector_miss")],
        metrics.enforcement.selector_miss,
    );
    write_sample(
        output,
        "sssa_pipeline_enforcement_decisions_total",
        &[("outcome", "unsupported")],
        metrics.enforcement.unsupported,
    );
    write_sample(
        output,
        "sssa_pipeline_enforcement_decisions_total",
        &[("outcome", "failed")],
        metrics.enforcement.failed,
    );
    write_sample(
        output,
        "sssa_pipeline_enforcement_decisions_total",
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

    use storage::SpoolSnapshot;

    use super::super::{
        build_status_snapshot,
        plan_fixture::{config_with_storage_path, runtime_plan_from_config},
        snapshot::SpoolStatusInput,
    };
    use super::*;

    #[test]
    fn render_prometheus_metrics_escapes_label_values() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config_with_storage_path(PathBuf::from("/tmp/sssa-spool"));
        config.agent_id = "agent\"\\\nnext".to_string();
        let plan = runtime_plan_from_config(config, Vec::new())?;
        let snapshot = build_status_snapshot(
            &plan,
            SpoolStatusInput::available(
                PathBuf::from("/tmp/sssa-spool"),
                SpoolSnapshot {
                    last_ingress_sequence: 0,
                    last_export_sequence: 0,
                },
                BTreeMap::from([("primary".to_string(), 0)]),
            ),
        );

        let metrics = render_prometheus_metrics(&snapshot);

        assert!(metrics.contains("sssa_agent_info{agent_id=\"agent\\\"\\\\\\nnext\""));
        Ok(())
    }
}

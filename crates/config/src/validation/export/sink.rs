use std::collections::HashSet;

use crate::{
    ConfigViolation, ExporterConfig, TlsConfig,
    validation::export::{headers, tls},
};

const REPLAY_WEBHOOK_SINK_ID: &str = "replay-webhook";

pub(in crate::validation) fn validate_exporters(
    exporters: &[ExporterConfig],
    tls_config: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    let tls_materials_by_id = crate::tls::materials_by_id(tls_config);
    let mut ids = HashSet::new();
    for exporter in exporters {
        if exporter.id.trim().is_empty() {
            violations.push(ConfigViolation {
                field: "exporters.id".to_string(),
                reason: "exporter id cannot be empty".to_string(),
            });
        }
        if exporter.id == REPLAY_WEBHOOK_SINK_ID {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.id", exporter.id),
                reason: "exporter id is reserved for replay CLI webhook output".to_string(),
            });
        }
        if !exporter.id.is_empty() && !ids.insert(exporter.id.as_str()) {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.id", exporter.id),
                reason: "exporter id must be unique because it is used as the sink cursor key"
                    .to_string(),
            });
        }
        for (name, value) in &exporter.headers {
            headers::validate_header(exporter, name, value, violations);
        }
        if exporter.endpoint.trim().is_empty() {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.endpoint", exporter.id),
                reason: "webhook endpoint cannot be empty".to_string(),
            });
        }
        if exporter.worker.batches_per_tick == Some(0) {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.worker.batches_per_tick", exporter.id),
                reason: "exporter worker batches_per_tick must be positive when set".to_string(),
            });
        }
        tls::validate_exporter_tls(exporter, &tls_materials_by_id, violations);
    }
}

use std::{collections::BTreeMap, path::PathBuf};

use probe_core::RuntimeMode;
use runtime::{IngressRetentionPlan, RuntimePlan};
use serde::Serialize;
use storage::{FjallSpool, SpoolProbe, SpoolSnapshot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpoolStatusSnapshot {
    pub path: PathBuf,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
    pub ingress_retention: IngressRetentionPlan,
    pub ingress_last_sequence: Option<u64>,
    pub export_last_sequence: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolStatusInput {
    pub(in crate::status) path: PathBuf,
    pub(in crate::status) mode: RuntimeMode,
    pub(in crate::status) reason: Option<String>,
    pub(in crate::status) snapshot: Option<SpoolSnapshot>,
    pub(in crate::status) export_cursors: BTreeMap<String, u64>,
}

impl SpoolStatusInput {
    pub fn available(
        path: PathBuf,
        snapshot: SpoolSnapshot,
        export_cursors: BTreeMap<String, u64>,
    ) -> Self {
        Self {
            path,
            mode: RuntimeMode::Available,
            reason: None,
            snapshot: Some(snapshot),
            export_cursors,
        }
    }

    pub fn unavailable(path: PathBuf, reason: impl Into<String>) -> Self {
        Self {
            path,
            mode: RuntimeMode::Unavailable,
            reason: Some(reason.into()),
            snapshot: None,
            export_cursors: BTreeMap::new(),
        }
    }

    pub fn degraded(path: PathBuf, reason: impl Into<String>) -> Self {
        Self {
            path,
            mode: RuntimeMode::Degraded,
            reason: Some(reason.into()),
            snapshot: None,
            export_cursors: BTreeMap::new(),
        }
    }
}

pub fn collect_spool_status(plan: &RuntimePlan) -> SpoolStatusInput {
    let path = plan.config.storage.path.clone();
    let probe = match FjallSpool::probe(&path) {
        Ok(probe) => probe,
        Err(error) => {
            return SpoolStatusInput::unavailable(
                path,
                format!("failed to inspect spool: {error}"),
            );
        }
    };

    match probe {
        SpoolProbe::Available {
            snapshot,
            export_cursors,
        } => {
            let export_cursors = plan
                .export
                .sinks
                .iter()
                .map(|sink| {
                    let cursor = export_cursors.get(sink.id()).copied().unwrap_or(0);
                    (sink.id().to_string(), cursor)
                })
                .collect::<BTreeMap<_, _>>();
            SpoolStatusInput::available(path, snapshot, export_cursors)
        }
        SpoolProbe::Busy { reason } => SpoolStatusInput::degraded(path, reason),
        SpoolProbe::Missing => SpoolStatusInput::unavailable(path, "spool path does not exist"),
        SpoolProbe::Incomplete { reason } => SpoolStatusInput::unavailable(path, reason),
    }
}

pub fn collect_running_spool_status(plan: &RuntimePlan, spool: &FjallSpool) -> SpoolStatusInput {
    let path = plan.config.storage.path.clone();
    let snapshot = match spool.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return SpoolStatusInput::unavailable(
                path,
                format!("failed to inspect running spool: {error}"),
            );
        }
    };
    let mut export_cursors = BTreeMap::new();
    for sink in &plan.export.sinks {
        match spool.export_cursor(sink.id()) {
            Ok(cursor) => {
                export_cursors.insert(sink.id().to_string(), cursor);
            }
            Err(error) => {
                return SpoolStatusInput::unavailable(
                    path,
                    format!(
                        "failed to inspect export cursor for sink {}: {error}",
                        sink.id()
                    ),
                );
            }
        }
    }
    SpoolStatusInput::available(path, snapshot, export_cursors)
}

#[cfg(test)]
mod tests {
    use probe_core::SpoolPayloadSchema;
    use storage::SpoolPayload;

    use super::super::plan_fixture::{
        config_with_storage_path, runtime_plan_from_config, test_dir,
    };
    use super::*;
    use crate::status::snapshot::build_status_snapshot_at;

    #[test]
    fn collect_spool_status_does_not_initialize_empty_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-empty-spool")?;
        let plan =
            runtime_plan_from_config(config_with_storage_path(temp.to_path_buf()), Vec::new())?;

        let spool = collect_spool_status(&plan);

        assert_eq!(spool.mode, RuntimeMode::Unavailable);
        assert!(
            spool
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("marker is missing"))
        );
        assert!(temp.read_dir()?.next().is_none());
        Ok(())
    }

    #[test]
    fn collect_spool_status_reports_initialized_spool_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-initialized-spool")?;
        let spool = FjallSpool::open(&temp)?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.ack_export("primary", 1)?;
        drop(spool);
        let plan =
            runtime_plan_from_config(config_with_storage_path(temp.to_path_buf()), Vec::new())?;

        let status = collect_spool_status(&plan);
        let snapshot = build_status_snapshot_at(&plan, status, 42);

        assert_eq!(snapshot.spool.mode, RuntimeMode::Available);
        assert_eq!(snapshot.spool.export_last_sequence, Some(2));
        assert_eq!(snapshot.exporters[0].cursor, Some(1));
        assert_eq!(snapshot.exporters[0].lag, Some(1));
        Ok(())
    }

    #[test]
    fn collect_running_spool_status_reads_open_spool_without_probe_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("status-running-spool")?;
        let spool = FjallSpool::open(&temp)?;
        spool.append_export(test_payload(b"one"))?;
        spool.append_export(test_payload(b"two"))?;
        spool.ack_export("primary", 1)?;
        let plan =
            runtime_plan_from_config(config_with_storage_path(temp.to_path_buf()), Vec::new())?;

        let status = collect_running_spool_status(&plan, &spool);
        let snapshot = build_status_snapshot_at(&plan, status, 42);

        assert_eq!(snapshot.spool.mode, RuntimeMode::Available);
        assert_eq!(snapshot.spool.export_last_sequence, Some(2));
        assert_eq!(snapshot.exporters[0].cursor, Some(1));
        assert_eq!(snapshot.exporters[0].lag, Some(1));
        Ok(())
    }

    fn test_payload(bytes: &[u8]) -> SpoolPayload {
        SpoolPayload::new(SpoolPayloadSchema::EventEnvelopeSubjectOriginJson, bytes)
    }
}

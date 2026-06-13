use attribution::{AttributionError, ProcessAttributor, ProcfsAttributor};
use capture::{
    LibsslUprobeAttachPlan, LibsslUprobeAttachPlanningReport, LibsslUprobeTargetDiscovery,
    plan_libssl_uprobes_for_processes,
};
use probe_core::CompiledSelector;

use crate::error::AgentError;

pub(super) struct LibsslUprobeAttachPlanner {
    source: LibsslUprobeAttachPlannerSource,
}

impl LibsslUprobeAttachPlanner {
    pub(super) fn new(selector: Option<CompiledSelector>) -> Self {
        Self {
            source: LibsslUprobeAttachPlannerSource::Procfs { selector },
        }
    }

    #[cfg(test)]
    pub(super) fn from_results(
        results: impl IntoIterator<Item = LibsslUprobeAttachPlanResult>,
    ) -> Self {
        Self {
            source: LibsslUprobeAttachPlannerSource::Static {
                results: std::cell::RefCell::new(results.into_iter().collect()),
            },
        }
    }

    pub(super) fn plan(&self) -> Result<LibsslUprobeAttachPlanResult, AgentError> {
        match &self.source {
            LibsslUprobeAttachPlannerSource::Procfs { selector } => {
                let report = build_libssl_uprobe_attach_planning_report(selector.as_ref())?;
                Ok(attach_plan_result_from_report(report))
            }
            #[cfg(test)]
            LibsslUprobeAttachPlannerSource::Static { results } => Ok(results
                .borrow_mut()
                .pop_front()
                .expect("static attach planner result exhausted")),
        }
    }
}

enum LibsslUprobeAttachPlannerSource {
    Procfs {
        selector: Option<CompiledSelector>,
    },
    #[cfg(test)]
    Static {
        results: std::cell::RefCell<std::collections::VecDeque<LibsslUprobeAttachPlanResult>>,
    },
}

pub(super) type LibsslUprobeAttachPlanResult =
    Result<LibsslUprobeAttachPlan, LibsslUprobeAttachPlanBlocked>;

#[derive(Debug)]
pub(super) struct LibsslUprobeAttachPlanBlocked {
    reason: String,
}

impl LibsslUprobeAttachPlanBlocked {
    #[cfg(test)]
    pub(super) fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub(super) fn into_reason(self) -> String {
        self.reason
    }
}

fn build_libssl_uprobe_attach_planning_report(
    selector: Option<&CompiledSelector>,
) -> Result<LibsslUprobeAttachPlanningReport, AgentError> {
    let attributor = ProcfsAttributor::new();
    attributor.probe()?;
    let processes = attributor
        .process_ids()?
        .into_iter()
        .filter_map(|pid| identify_attach_candidate_process(&attributor, pid).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(plan_libssl_uprobes_for_processes(
        processes,
        selector,
        &LibsslUprobeTargetDiscovery::default(),
    ))
}

fn identify_attach_candidate_process(
    attributor: &ProcfsAttributor,
    pid: u32,
) -> Result<Option<probe_core::ProcessContext>, AttributionError> {
    attributor.identify_if_present(pid)
}

fn attach_plan_result_from_report(
    report: LibsslUprobeAttachPlanningReport,
) -> LibsslUprobeAttachPlanResult {
    if report.attach_plan.has_attachable_probes() {
        return Ok(report.attach_plan);
    }

    if let Some(reason) = blocking_planning_reason(&report) {
        return Err(LibsslUprobeAttachPlanBlocked { reason });
    }

    Ok(report.attach_plan)
}

#[cfg(test)]
pub(super) fn empty_attach_plan() -> LibsslUprobeAttachPlan {
    LibsslUprobeAttachPlan::from_discovery_reports(Vec::new())
}

fn blocking_planning_reason(report: &LibsslUprobeAttachPlanningReport) -> Option<String> {
    let mut reasons = report
        .planning_errors
        .iter()
        .map(|error| format!("planning error: {error}"))
        .chain(
            report
                .attach_plan
                .degraded_reasons()
                .iter()
                .map(|reason| format!("discovery degradation: {reason}")),
        );
    let first = reasons.next()?;
    let remaining = reasons.count();
    let suffix = if remaining == 0 {
        String::new()
    } else {
        format!("; {remaining} additional reason(s)")
    };
    Some(format!(
        "libssl uprobe attach planning produced no attachable targets; first {first}{suffix}"
    ))
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, path::PathBuf};

    use capture::LibsslUprobeAttachPlanningError;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn planning_result_keeps_empty_error_free_report_available() {
        let plan = attach_plan_result_from_report(empty_report())
            .expect("empty error-free planning report should remain available");

        assert!(plan.processes().is_empty());
    }

    #[test]
    fn planning_result_blocks_empty_report_with_planning_errors() {
        let mut report = empty_report();
        report
            .planning_errors
            .push(LibsslUprobeAttachPlanningError::ReadMaps {
                pid: 7,
                path: PathBuf::from("/proc/7/maps"),
                kind: ErrorKind::PermissionDenied,
                reason: "permission denied".to_string(),
            });

        let reason = attach_plan_result_from_report(report)
            .expect_err("empty planning report with errors must block startup enablement")
            .into_reason();

        assert!(reason.contains("produced no attachable targets"));
        assert!(reason.contains("/proc/7/maps"));
    }

    #[test]
    fn process_scan_skips_disappearing_processes() -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let boot = proc.path().join("boot_id");
        std::fs::write(&boot, "boot\n")?;
        std::fs::create_dir(proc.path().join("7"))?;
        let attributor = ProcfsAttributor::with_paths(proc.path(), &boot);

        let process = identify_attach_candidate_process(&attributor, 7)?;

        assert!(process.is_none());
        Ok(())
    }

    #[test]
    fn process_scan_skips_invalid_process_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let boot = proc.path().join("boot_id");
        std::fs::write(&boot, "boot\n")?;
        std::fs::create_dir(proc.path().join("7"))?;
        std::fs::write(proc.path().join("7/stat"), "invalid stat\n")?;
        let attributor = ProcfsAttributor::with_paths(proc.path(), &boot);

        let process = identify_attach_candidate_process(&attributor, 7)?;

        assert!(process.is_none());
        Ok(())
    }

    #[test]
    fn process_scan_preserves_global_procfs_dependency_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let boot = proc.path().join("missing_boot_id");
        let pid_dir = proc.path().join("7");
        std::fs::create_dir(&pid_dir)?;
        std::fs::write(
            pid_dir.join("stat"),
            "7 (curl) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        )?;
        std::fs::write(pid_dir.join("status"), "Tgid:\t7\nUid:\t1000\nGid:\t1000\n")?;
        std::fs::write(pid_dir.join("cmdline"), b"curl\0")?;
        std::fs::write(pid_dir.join("cgroup"), "0::/user.slice\n")?;
        std::os::unix::fs::symlink("/usr/bin/curl", pid_dir.join("exe"))?;
        let attributor = ProcfsAttributor::with_paths(proc.path(), &boot);

        let error = identify_attach_candidate_process(&attributor, 7)
            .expect_err("global boot id read failure must not be treated as a per-pid race");

        assert!(matches!(
            error,
            AttributionError::Read { path, .. } if path.ends_with("missing_boot_id")
        ));
        Ok(())
    }

    fn empty_report() -> LibsslUprobeAttachPlanningReport {
        LibsslUprobeAttachPlanningReport {
            attach_plan: empty_attach_plan(),
            scanned_processes: 0,
            selector_misses: Vec::new(),
            duplicate_processes: Vec::new(),
            planning_errors: Vec::new(),
        }
    }
}

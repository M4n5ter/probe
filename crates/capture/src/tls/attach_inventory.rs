use std::{collections::BTreeSet, io::ErrorKind, num::NonZeroU32, path::PathBuf};

use probe_core::{CompiledSelector, ProcessContext, ProcessGeneration, ProcessIdentity};
use thiserror::Error;

use super::{
    LibsslUprobeAttachPlan, LibsslUprobeDiscoveryError, LibsslUprobeProcessGenerationFailure,
    LibsslUprobeTargetDiscovery, LibsslUprobeTargetDiscoveryReport,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachPlanningReport {
    pub attach_plan: LibsslUprobeAttachPlan,
    pub scanned_processes: usize,
    pub selector_misses: Vec<ProcessGeneration>,
    pub duplicate_processes: Vec<ProcessGeneration>,
    pub planning_errors: Vec<LibsslUprobeAttachPlanningError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LibsslUprobeAttachPlanningError {
    #[error("cannot plan libssl uprobes for process with unknown or synthetic pid {pid}")]
    UnattachablePid { pid: u32 },
    #[error("cannot plan libssl uprobes for pid {pid} without process generation")]
    UnverifiedProcessGeneration { pid: u32 },
    #[error("failed to read proc maps for pid {pid} at {path}: {reason}")]
    ReadMaps {
        pid: u32,
        path: PathBuf,
        kind: ErrorKind,
        reason: String,
    },
    #[error("invalid proc maps line {line_number} for pid {pid}: {reason}")]
    InvalidMaps {
        pid: u32,
        line_number: usize,
        reason: String,
    },
    #[error("failed to verify process generation for pid {pid}: {reason}")]
    ProcessGeneration {
        pid: u32,
        reason: LibsslUprobeProcessGenerationFailure,
    },
    #[error(
        "libssl uprobe discovery saw pid {pid} starttime {discovered_start_time_ticks} while selector matched starttime {expected_start_time_ticks}"
    )]
    ProcessGenerationMismatch {
        pid: u32,
        expected_start_time_ticks: u64,
        discovered_start_time_ticks: u64,
    },
    #[error(
        "libssl uprobe discovery returned process generation for pid {process_pid} while planning pid {requested_pid}"
    )]
    ProcessPidMismatch {
        requested_pid: u32,
        process_pid: u32,
    },
}

pub fn plan_libssl_uprobes_for_processes(
    processes: impl IntoIterator<Item = ProcessContext>,
    selector: Option<&CompiledSelector>,
    discovery: &LibsslUprobeTargetDiscovery,
) -> LibsslUprobeAttachPlanningReport {
    plan_libssl_uprobes_for_processes_with(processes, selector, |pid| {
        discovery.discover_for_pid(pid.get())
    })
}

fn plan_libssl_uprobes_for_processes_with(
    processes: impl IntoIterator<Item = ProcessContext>,
    selector: Option<&CompiledSelector>,
    mut discover: impl FnMut(
        NonZeroU32,
    )
        -> Result<LibsslUprobeTargetDiscoveryReport, LibsslUprobeDiscoveryError>,
) -> LibsslUprobeAttachPlanningReport {
    let mut scanned_processes = 0;
    let mut selector_misses = Vec::new();
    let mut duplicate_processes = Vec::new();
    let mut planned_generations = BTreeSet::new();
    let mut reports = Vec::new();
    let mut planning_errors = Vec::new();

    for process in processes {
        scanned_processes += 1;
        let pid = process.identity.pid;
        let process_generation = process.identity.generation();
        if selector.is_some_and(|selector| !selector.may_match_process(&process)) {
            selector_misses.push(process_generation);
            continue;
        }
        let Some(pid) = NonZeroU32::new(pid) else {
            planning_errors.push(LibsslUprobeAttachPlanningError::UnattachablePid { pid });
            continue;
        };
        if process.identity.start_time_ticks == 0 {
            planning_errors.push(
                LibsslUprobeAttachPlanningError::UnverifiedProcessGeneration { pid: pid.get() },
            );
            continue;
        }
        if !planned_generations.insert(process_generation) {
            duplicate_processes.push(process_generation);
            continue;
        }
        match discover(pid) {
            Ok(report) => match validate_discovery_report(&process.identity, pid, report) {
                Ok(report) => reports.push(report),
                Err(error) => planning_errors.push(error),
            },
            Err(error) => planning_errors.push(LibsslUprobeAttachPlanningError::from(error)),
        }
    }

    LibsslUprobeAttachPlanningReport {
        attach_plan: LibsslUprobeAttachPlan::from_discovery_reports(reports),
        scanned_processes,
        selector_misses,
        duplicate_processes,
        planning_errors,
    }
}

fn validate_discovery_report(
    expected_process: &ProcessIdentity,
    requested_pid: NonZeroU32,
    report: LibsslUprobeTargetDiscoveryReport,
) -> Result<LibsslUprobeTargetDiscoveryReport, LibsslUprobeAttachPlanningError> {
    let requested_pid = requested_pid.get();
    let discovered_process = report.process();
    if discovered_process.pid != requested_pid {
        return Err(LibsslUprobeAttachPlanningError::ProcessPidMismatch {
            requested_pid,
            process_pid: discovered_process.pid,
        });
    }
    if discovered_process.start_time_ticks != expected_process.start_time_ticks {
        return Err(LibsslUprobeAttachPlanningError::ProcessGenerationMismatch {
            pid: requested_pid,
            expected_start_time_ticks: expected_process.start_time_ticks,
            discovered_start_time_ticks: discovered_process.start_time_ticks,
        });
    }
    Ok(report)
}

impl From<LibsslUprobeDiscoveryError> for LibsslUprobeAttachPlanningError {
    fn from(error: LibsslUprobeDiscoveryError) -> Self {
        match error {
            LibsslUprobeDiscoveryError::ReadMaps { pid, path, source } => Self::ReadMaps {
                pid,
                path,
                kind: source.kind(),
                reason: source.to_string(),
            },
            LibsslUprobeDiscoveryError::InvalidMaps {
                pid,
                line_number,
                reason,
            } => Self::InvalidMaps {
                pid,
                line_number,
                reason,
            },
            LibsslUprobeDiscoveryError::ProcessGeneration { pid, reason } => {
                Self::ProcessGeneration { pid, reason }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, io::ErrorKind, path::PathBuf};

    use probe_core::{ProcessIdentity, ProcessSelector, Selector, TrafficSelector};

    use super::*;
    use crate::tls::LibsslUprobeProcessVerifier;
    use crate::{
        LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
        LibsslUprobeDegradationReason, LibsslUprobeSymbol, LibsslUprobeSymbolFailure,
        LibsslUprobeTarget,
    };

    #[test]
    fn attach_planning_uses_process_selector_as_a_prefilter()
    -> Result<(), Box<dyn std::error::Error>> {
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["managed".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let discovery = StaticDiscovery::new([(7, discovery_report(7))]).with_error(8);

        let report = plan_libssl_uprobes_for_processes_with(
            [process(7, "managed"), process(8, "other")],
            Some(&selector),
            |pid| discovery.discover_for_pid(pid),
        );

        assert_eq!(report.scanned_processes, 2);
        assert_eq!(report.selector_misses, vec![process_generation(8, 1)]);
        assert!(report.planning_errors.is_empty());
        assert_eq!(report.attach_plan.processes().len(), 1);
        assert_eq!(report.attach_plan.processes()[0].pid(), 7);
        Ok(())
    }

    #[test]
    fn attach_planning_keeps_discovery_errors_without_stopping_other_processes() {
        let discovery = StaticDiscovery::new([(7, discovery_report(7))]).with_error(8);

        let report = plan_libssl_uprobes_for_processes_with(
            [process(7, "managed"), process(8, "managed")],
            None,
            |pid| discovery.discover_for_pid(pid),
        );

        assert_eq!(report.scanned_processes, 2);
        assert!(report.selector_misses.is_empty());
        assert_eq!(report.attach_plan.processes().len(), 1);
        assert_eq!(
            report.planning_errors,
            vec![LibsslUprobeAttachPlanningError::ReadMaps {
                pid: 8,
                path: PathBuf::from("/proc/8/maps"),
                kind: ErrorKind::NotFound,
                reason: "maps disappeared".to_string(),
            }]
        );
    }

    #[test]
    fn attach_planning_rejects_processes_without_attachable_pids() {
        let discovery = StaticDiscovery::new([(7, discovery_report(7))]);

        let report = plan_libssl_uprobes_for_processes_with([process(0, "managed")], None, |pid| {
            discovery.discover_for_pid(pid)
        });

        assert!(report.attach_plan.processes().is_empty());
        assert_eq!(
            report.planning_errors,
            vec![LibsslUprobeAttachPlanningError::UnattachablePid { pid: 0 }]
        );
    }

    #[test]
    fn attach_planning_rejects_processes_without_verified_generation() {
        let discovery = StaticDiscovery::new([(7, discovery_report(7))]);

        let report = plan_libssl_uprobes_for_processes_with(
            [process_with_start_time(7, "managed", 0)],
            None,
            |pid| discovery.discover_for_pid(pid),
        );

        assert!(report.attach_plan.processes().is_empty());
        assert_eq!(
            report.planning_errors,
            vec![LibsslUprobeAttachPlanningError::UnverifiedProcessGeneration { pid: 7 }]
        );
    }

    #[test]
    fn attach_planning_rejects_discovery_for_reused_pid_generation() {
        let discovery = StaticDiscovery::new([(7, discovery_report_with_start_time(7, 2))]);

        let report = plan_libssl_uprobes_for_processes_with(
            [process_with_start_time(7, "managed", 1)],
            None,
            |pid| discovery.discover_for_pid(pid),
        );

        assert!(report.attach_plan.processes().is_empty());
        assert_eq!(
            report.planning_errors,
            vec![LibsslUprobeAttachPlanningError::ProcessGenerationMismatch {
                pid: 7,
                expected_start_time_ticks: 1,
                discovered_start_time_ticks: 2,
            }]
        );
    }

    #[test]
    fn attach_planning_deduplicates_repeated_process_generations() {
        let discovery = StaticDiscovery::new([(7, discovery_report(7))]);

        let report = plan_libssl_uprobes_for_processes_with(
            [process(7, "managed"), process(7, "managed")],
            None,
            |pid| discovery.discover_for_pid(pid),
        );

        assert_eq!(report.scanned_processes, 2);
        assert_eq!(report.duplicate_processes, vec![process_generation(7, 1)]);
        assert!(report.planning_errors.is_empty());
        assert_eq!(report.attach_plan.processes().len(), 1);
    }

    #[test]
    fn attach_planning_merges_discovery_degradation_reasons() {
        let discovery = StaticDiscovery::new([
            (7, discovery_report(7)),
            (8, discovery_report_with_degradation(8)),
        ]);

        let report = plan_libssl_uprobes_for_processes_with(
            [process(7, "managed"), process(8, "managed")],
            None,
            |pid| discovery.discover_for_pid(pid),
        );

        let target_pids: Vec<u32> = report
            .attach_plan
            .processes()
            .iter()
            .map(|process| process.pid())
            .collect();
        assert_eq!(target_pids, vec![7, 8]);
        assert_eq!(report.attach_plan.processes().len(), 2);
        assert_eq!(
            report.attach_plan.degraded_reasons(),
            &[degradation_reason(8)]
        );
    }

    #[test]
    fn attach_planning_rejects_discovery_process_generation_for_the_wrong_pid() {
        let wrong_process = discovery_report_with_targets(9, 1, vec![target(7)], Vec::new());
        let discovery = StaticDiscovery::new([(7, wrong_process)]);

        let report = plan_libssl_uprobes_for_processes_with([process(7, "managed")], None, |pid| {
            discovery.discover_for_pid(pid)
        });

        assert!(report.attach_plan.processes().is_empty());
        assert_eq!(
            report.planning_errors,
            vec![LibsslUprobeAttachPlanningError::ProcessPidMismatch {
                requested_pid: 7,
                process_pid: 9,
            }]
        );
    }

    struct StaticDiscovery {
        reports: BTreeMap<u32, LibsslUprobeTargetDiscoveryReport>,
        error_pids: Vec<u32>,
    }

    impl StaticDiscovery {
        fn new(
            reports: impl IntoIterator<Item = (u32, LibsslUprobeTargetDiscoveryReport)>,
        ) -> Self {
            Self {
                reports: reports.into_iter().collect(),
                error_pids: Vec::new(),
            }
        }

        fn with_error(mut self, pid: u32) -> Self {
            self.error_pids.push(pid);
            self
        }

        fn discover_for_pid(
            &self,
            pid: NonZeroU32,
        ) -> Result<LibsslUprobeTargetDiscoveryReport, LibsslUprobeDiscoveryError> {
            let pid = pid.get();
            if self.error_pids.contains(&pid) {
                return Err(LibsslUprobeDiscoveryError::ReadMaps {
                    pid,
                    path: PathBuf::from(format!("/proc/{pid}/maps")),
                    source: std::io::Error::new(std::io::ErrorKind::NotFound, "maps disappeared"),
                });
            }
            Ok(self
                .reports
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| discovery_report_with_targets(pid, 1, Vec::new(), Vec::new())))
        }
    }

    fn discovery_report(pid: u32) -> LibsslUprobeTargetDiscoveryReport {
        discovery_report_with_start_time(pid, 1)
    }

    fn discovery_report_with_start_time(
        pid: u32,
        start_time_ticks: u64,
    ) -> LibsslUprobeTargetDiscoveryReport {
        discovery_report_with_targets(pid, start_time_ticks, vec![target(pid)], Vec::new())
    }

    fn discovery_report_with_targets(
        pid: u32,
        start_time_ticks: u64,
        targets: Vec<LibsslUprobeTarget>,
        degraded_reasons: Vec<LibsslUprobeDegradationReason>,
    ) -> LibsslUprobeTargetDiscoveryReport {
        LibsslUprobeTargetDiscoveryReport::new(
            process_generation(pid, start_time_ticks),
            process_verifier(),
            targets,
            degraded_reasons,
        )
    }

    fn process_generation(pid: u32, start_time_ticks: u64) -> ProcessGeneration {
        ProcessGeneration {
            pid,
            start_time_ticks,
        }
    }

    fn process_verifier() -> LibsslUprobeProcessVerifier {
        LibsslUprobeProcessVerifier::new("/proc")
    }

    fn discovery_report_with_degradation(pid: u32) -> LibsslUprobeTargetDiscoveryReport {
        discovery_report_with_targets(pid, 1, vec![target(pid)], vec![degradation_reason(pid)])
    }

    fn target(pid: u32) -> LibsslUprobeTarget {
        LibsslUprobeTarget {
            library: mapped_library(pid),
            library_kind: LibsslLibraryKind::OpenSslLike,
            executable_mappings: vec![LibsslExecutableMapping {
                start_address: 0x1000,
                end_address: 0x2000,
                file_offset: 0,
            }],
            symbols: vec![LibsslUprobeSymbol::SslRead],
        }
    }

    fn degradation_reason(pid: u32) -> LibsslUprobeDegradationReason {
        LibsslUprobeDegradationReason::SymbolResolutionFailed {
            mapped_path: PathBuf::from(format!("/usr/lib/{pid}/libssl.so")),
            reason: LibsslUprobeSymbolFailure::ReadLibrary {
                path: PathBuf::from(format!("/proc/{pid}/root/usr/lib/libssl.so")),
                reason: "permission denied".to_string(),
            },
        }
    }

    fn mapped_library(pid: u32) -> LibsslMappedLibrary {
        LibsslMappedLibrary {
            mapped_path: PathBuf::from(format!("/usr/lib/{pid}/libssl.so")),
            read_path: PathBuf::from(format!("/proc/{pid}/root/usr/lib/libssl.so")),
            identity: LibsslMappedFileIdentity {
                device_major: 8,
                device_minor: 1,
                inode: u64::from(pid),
            },
            deleted: false,
        }
    }

    fn process(pid: u32, name: &str) -> ProcessContext {
        process_with_start_time(pid, name, 1)
    }

    fn process_with_start_time(pid: u32, name: &str, start_time_ticks: u64) -> ProcessContext {
        let identity = ProcessIdentity {
            pid,
            tgid: pid,
            start_time_ticks,
            boot_id: "boot".to_string(),
            exe_path: format!("/usr/bin/{name}"),
            cmdline_hash: format!("hash-{pid}"),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        ProcessContext {
            identity,
            name: name.to_string(),
            cmdline: vec![
                name.to_string(),
                "--tenant".to_string(),
                "managed".to_string(),
            ],
        }
    }
}

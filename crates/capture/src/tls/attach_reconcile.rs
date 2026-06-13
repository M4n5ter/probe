use std::collections::BTreeSet;

use super::{LibsslUprobeAttachPlan, LibsslUprobeAttachTargetId};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::tls) struct LibsslUprobeAttachState {
    targets: BTreeSet<LibsslUprobeAttachTargetId>,
}

impl LibsslUprobeAttachState {
    pub(in crate::tls) fn from_targets(
        targets: impl IntoIterator<Item = LibsslUprobeAttachTargetId>,
    ) -> Self {
        Self {
            targets: targets.into_iter().collect(),
        }
    }

    pub(in crate::tls) fn reconcile(
        &self,
        next_plan: &LibsslUprobeAttachPlan,
    ) -> LibsslUprobeReconcileReport {
        let next_targets = next_plan.target_ids().collect::<BTreeSet<_>>();
        let new_targets = next_targets
            .difference(&self.targets)
            .cloned()
            .collect::<Vec<_>>();
        let retained_targets = next_targets
            .intersection(&self.targets)
            .cloned()
            .collect::<Vec<_>>();
        let stale_targets = self
            .targets
            .difference(&next_targets)
            .cloned()
            .collect::<Vec<_>>();
        let new_target_set = new_targets.iter().cloned().collect::<BTreeSet<_>>();
        let attach_plan = next_plan.filter_targets(|target| new_target_set.contains(target));

        LibsslUprobeReconcileReport {
            attach_plan,
            new_targets,
            retained_targets,
            stale_targets,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tls) struct LibsslUprobeReconcileReport {
    pub(in crate::tls) attach_plan: LibsslUprobeAttachPlan,
    pub(in crate::tls) new_targets: Vec<LibsslUprobeAttachTargetId>,
    pub(in crate::tls) retained_targets: Vec<LibsslUprobeAttachTargetId>,
    pub(in crate::tls) stale_targets: Vec<LibsslUprobeAttachTargetId>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use probe_core::ProcessGeneration;

    use super::*;
    use crate::tls::{
        LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
        LibsslUprobeAttachPlan, LibsslUprobeProcessVerifier, LibsslUprobeSymbol,
        LibsslUprobeTarget, LibsslUprobeTargetDiscoveryReport,
    };

    #[test]
    fn reconcile_from_empty_attaches_every_discovered_target() {
        let next_plan = attach_plan([7, 8]);

        let report = LibsslUprobeAttachState::default().reconcile(&next_plan);

        assert_eq!(target_pids(&report.new_targets), vec![7, 8]);
        assert!(report.retained_targets.is_empty());
        assert!(report.stale_targets.is_empty());
        assert_eq!(plan_pids(&report.attach_plan), vec![7, 8]);
    }

    #[test]
    fn reconcile_attaches_only_new_targets_and_retains_existing_targets() {
        let current = attach_state(&attach_plan([7]));
        let next_plan = attach_plan([7, 8]);

        let report = current.reconcile(&next_plan);

        assert_eq!(target_pids(&report.new_targets), vec![8]);
        assert_eq!(target_pids(&report.retained_targets), vec![7]);
        assert!(report.stale_targets.is_empty());
        assert_eq!(plan_pids(&report.attach_plan), vec![8]);
    }

    #[test]
    fn reconcile_reports_stale_targets_without_reattaching_retained_targets() {
        let current = attach_state(&attach_plan([7, 9]));
        let next_plan = attach_plan([7]);

        let report = current.reconcile(&next_plan);

        assert!(report.new_targets.is_empty());
        assert_eq!(target_pids(&report.retained_targets), vec![7]);
        assert_eq!(target_pids(&report.stale_targets), vec![9]);
        assert!(report.attach_plan.processes().is_empty());
    }

    #[test]
    fn reconcile_treats_changed_library_identity_as_stale_and_new() {
        let current = attach_state(&attach_plan_for_process(7, [100]));
        let next_plan = attach_plan_for_process(7, [200]);

        let report = current.reconcile(&next_plan);

        assert_eq!(target_keys(&report.new_targets), vec![(7, 200)]);
        assert!(report.retained_targets.is_empty());
        assert_eq!(target_keys(&report.stale_targets), vec![(7, 100)]);
        assert_eq!(plan_target_keys(&report.attach_plan), vec![(7, 200)]);
    }

    #[test]
    fn reconcile_attaches_new_library_without_reattaching_retained_library() {
        let current = attach_state(&attach_plan_for_process(7, [100]));
        let next_plan = attach_plan_for_process(7, [100, 200]);

        let report = current.reconcile(&next_plan);

        assert_eq!(target_keys(&report.new_targets), vec![(7, 200)]);
        assert_eq!(target_keys(&report.retained_targets), vec![(7, 100)]);
        assert!(report.stale_targets.is_empty());
        assert_eq!(plan_target_keys(&report.attach_plan), vec![(7, 200)]);
    }

    fn attach_plan(pids: impl IntoIterator<Item = u32>) -> LibsslUprobeAttachPlan {
        LibsslUprobeAttachPlan::from_discovery_reports(pids.into_iter().map(discovery_report))
    }

    fn attach_state(plan: &LibsslUprobeAttachPlan) -> LibsslUprobeAttachState {
        LibsslUprobeAttachState::from_targets(plan.target_ids())
    }

    fn attach_plan_for_process(
        pid: u32,
        library_inodes: impl IntoIterator<Item = u64>,
    ) -> LibsslUprobeAttachPlan {
        LibsslUprobeAttachPlan::from_discovery_report(discovery_report_with_libraries(
            pid,
            library_inodes,
        ))
    }

    fn discovery_report(pid: u32) -> LibsslUprobeTargetDiscoveryReport {
        discovery_report_with_libraries(pid, [u64::from(pid)])
    }

    fn discovery_report_with_libraries(
        pid: u32,
        library_inodes: impl IntoIterator<Item = u64>,
    ) -> LibsslUprobeTargetDiscoveryReport {
        LibsslUprobeTargetDiscoveryReport::new(
            process_generation(pid),
            LibsslUprobeProcessVerifier::new("/proc"),
            library_inodes
                .into_iter()
                .map(|inode| LibsslUprobeTarget {
                    library: mapped_library(pid, inode),
                    library_kind: LibsslLibraryKind::OpenSslLike,
                    executable_mappings: vec![LibsslExecutableMapping {
                        start_address: 0x1000,
                        end_address: 0x2000,
                        file_offset: 0,
                    }],
                    symbols: vec![LibsslUprobeSymbol::SslRead],
                })
                .collect(),
            Vec::new(),
        )
    }

    fn process_generation(pid: u32) -> ProcessGeneration {
        ProcessGeneration {
            pid,
            start_time_ticks: u64::from(pid) * 100,
        }
    }

    fn mapped_library(pid: u32, inode: u64) -> LibsslMappedLibrary {
        LibsslMappedLibrary {
            mapped_path: PathBuf::from(format!("/usr/lib/{pid}/libssl-{inode}.so")),
            read_path: PathBuf::from(format!("/proc/{pid}/root/usr/lib/libssl-{inode}.so")),
            identity: LibsslMappedFileIdentity {
                device_major: 8,
                device_minor: 1,
                inode,
            },
            deleted: false,
        }
    }

    fn plan_pids(plan: &LibsslUprobeAttachPlan) -> Vec<u32> {
        plan.processes()
            .iter()
            .map(|process| process.pid())
            .collect()
    }

    fn target_pids(targets: &[LibsslUprobeAttachTargetId]) -> Vec<u32> {
        targets.iter().map(|target| target.process.pid).collect()
    }

    fn plan_target_keys(plan: &LibsslUprobeAttachPlan) -> Vec<(u32, u64)> {
        plan.processes()
            .iter()
            .flat_map(|process| {
                process
                    .targets()
                    .iter()
                    .map(|target| (process.pid(), target.library.identity.inode))
            })
            .collect()
    }

    fn target_keys(targets: &[LibsslUprobeAttachTargetId]) -> Vec<(u32, u64)> {
        targets
            .iter()
            .map(|target| (target.process.pid, target.library.identity.inode))
            .collect()
    }
}

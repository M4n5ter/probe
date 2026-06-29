use std::collections::BTreeMap;

use aya::Ebpf;

use crate::tls::{LibsslUprobeAttachLinkOwnershipSnapshot, LibsslUprobeAttachTargetId};

use super::super::error::LibsslUprobeAttachError;
use super::uprobe::{
    AttachedLibsslUprobe, detach_attached_uprobes_for_target, record_first_detach_error,
};

#[derive(Default)]
pub(super) struct LibsslUprobeAttachedLinks {
    links_by_target: BTreeMap<LibsslUprobeAttachTargetId, Vec<AttachedLibsslUprobe>>,
}

impl LibsslUprobeAttachedLinks {
    pub(super) fn targets(&self) -> impl Iterator<Item = LibsslUprobeAttachTargetId> + '_ {
        self.links_by_target.keys().cloned()
    }

    pub(super) fn target_link_ownership(
        &self,
        target: &LibsslUprobeAttachTargetId,
    ) -> LibsslUprobeAttachLinkOwnershipSnapshot {
        let Some(links) = self.links_by_target.get(target) else {
            return LibsslUprobeAttachLinkOwnershipSnapshot::unreported();
        };
        link_ownership_snapshot(links)
    }

    pub(super) fn detach_targets_best_effort(
        &mut self,
        ebpf: &mut Ebpf,
        targets: impl IntoIterator<Item = LibsslUprobeAttachTargetId>,
    ) -> Result<(), LibsslUprobeAttachError> {
        let mut first_error = None;
        for target in targets {
            let Some(links) = self.links_by_target.remove(&target) else {
                continue;
            };
            if let Err(error) = detach_attached_uprobes_for_target(ebpf, &target, links) {
                record_first_detach_error(&mut first_error, error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn detach_all_best_effort(
        &mut self,
        ebpf: &mut Ebpf,
    ) -> Result<(), LibsslUprobeAttachError> {
        let links_by_target = std::mem::take(&mut self.links_by_target);
        let mut first_error = None;
        for (target, links) in links_by_target.into_iter().rev() {
            if let Err(error) = detach_attached_uprobes_for_target(ebpf, &target, links) {
                record_first_detach_error(&mut first_error, error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn push_recipe_links(
        &mut self,
        target: LibsslUprobeAttachTargetId,
        mut links: Vec<AttachedLibsslUprobe>,
    ) {
        if links.is_empty() {
            return;
        }
        self.links_by_target
            .entry(target)
            .or_default()
            .append(&mut links);
    }
}

fn link_ownership_snapshot(
    links: &[AttachedLibsslUprobe],
) -> LibsslUprobeAttachLinkOwnershipSnapshot {
    link_ownership_snapshot_from_program_names(links.iter().map(|link| link.program_name))
}

fn link_ownership_snapshot_from_program_names(
    program_names: impl IntoIterator<Item = &'static str>,
) -> LibsslUprobeAttachLinkOwnershipSnapshot {
    let mut link_counts_by_program = BTreeMap::new();
    for program_name in program_names {
        *link_counts_by_program.entry(program_name).or_insert(0) += 1;
    }
    LibsslUprobeAttachLinkOwnershipSnapshot::owned_by_program_counts(link_counts_by_program)
}

#[cfg(test)]
#[test]
fn link_ownership_snapshot_counts_committed_program_links() {
    let ownership = link_ownership_snapshot_from_program_names([
        "tls_write_entry",
        "tls_read_entry",
        "tls_write_entry",
        "tls_fd_entry",
    ]);

    assert!(ownership.is_reported());
    assert_eq!(ownership.owned_link_count(), 4);
    let programs = ownership.into_programs();
    assert_eq!(
        programs
            .iter()
            .map(|program| (program.program_name(), program.owned_link_count()))
            .collect::<Vec<_>>(),
        vec![
            ("tls_fd_entry", 1),
            ("tls_read_entry", 1),
            ("tls_write_entry", 2)
        ]
    );
}

#[cfg(test)]
#[test]
fn link_ownership_snapshot_without_committed_links_is_unreported() {
    let ownership = link_ownership_snapshot_from_program_names([]);

    assert!(!ownership.is_reported());
    assert_eq!(ownership.owned_link_count(), 0);
    assert!(ownership.into_programs().is_empty());
}

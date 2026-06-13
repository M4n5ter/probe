use std::collections::BTreeMap;

use aya::Ebpf;

use crate::tls::LibsslUprobeAttachTargetId;

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

    pub(super) fn target_count(&self) -> usize {
        self.links_by_target.len()
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

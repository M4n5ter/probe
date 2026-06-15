use std::collections::BTreeSet;

use aya::Ebpf;

use super::{
    links::LibsslUprobeAttachedLinks,
    target::{
        BestEffortTargetPlan, CommittedLibsslUprobeTargetAttach, TargetAttachOutcome,
        attach_best_effort_target_uprobes,
    },
    uprobe::attach_recipe_uprobes,
};
use crate::tls::plaintext::attach::{
    error::LibsslUprobeAttachError, recipe::LibsslUprobeAttachRecipeRequest,
    summary::LibsslUprobeAttachSummary,
};

#[derive(Default)]
pub(in crate::tls::plaintext) struct LibsslUprobeAttachSession {
    loaded_programs: BTreeSet<&'static str>,
    attached_links: LibsslUprobeAttachedLinks,
}

impl LibsslUprobeAttachSession {
    pub(in crate::tls::plaintext) fn attached_targets(
        &self,
    ) -> impl Iterator<Item = crate::tls::LibsslUprobeAttachTargetId> + '_ {
        self.attached_links.targets()
    }

    pub(in crate::tls::plaintext) fn attach_uprobes(
        &mut self,
        ebpf: &mut Ebpf,
        recipes: &[LibsslUprobeAttachRecipeRequest],
        policy: AttachFailurePolicy,
    ) -> Result<LibsslUprobeAttachSummary, LibsslUprobeAttachError> {
        match policy {
            AttachFailurePolicy::Strict => self.attach_uprobes_strict(ebpf, recipes),
            AttachFailurePolicy::BestEffort => self.attach_uprobes_best_effort(ebpf, recipes),
        }
    }

    fn attach_uprobes_strict(
        &mut self,
        ebpf: &mut Ebpf,
        recipes: &[LibsslUprobeAttachRecipeRequest],
    ) -> Result<LibsslUprobeAttachSummary, LibsslUprobeAttachError> {
        let mut summary = LibsslUprobeAttachSummary::from_recipes(recipes);
        for recipe in recipes {
            match attach_recipe_uprobes(ebpf, &mut self.loaded_programs, recipe) {
                Ok(links) => {
                    let target = recipe.target_id();
                    summary.record_committed_target(target.clone());
                    self.attached_links.push_recipe_links(target, links);
                }
                Err(error) => {
                    self.detach_all_best_effort(ebpf)?;
                    return Err(error.into_error());
                }
            }
        }
        Ok(summary)
    }

    fn attach_uprobes_best_effort(
        &mut self,
        ebpf: &mut Ebpf,
        recipes: &[LibsslUprobeAttachRecipeRequest],
    ) -> Result<LibsslUprobeAttachSummary, LibsslUprobeAttachError> {
        let mut summary = LibsslUprobeAttachSummary::from_recipes(recipes);
        for target_plan in BestEffortTargetPlan::from_recipes(recipes) {
            let outcome = match attach_best_effort_target_uprobes(
                ebpf,
                &mut self.loaded_programs,
                recipes,
                &target_plan,
                &mut summary,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.detach_all_best_effort(ebpf)?;
                    return Err(error);
                }
            };
            if let TargetAttachOutcome::Committed(committed_target) = outcome {
                self.retain_committed_target(&mut summary, committed_target);
            }
        }
        Ok(summary)
    }

    fn retain_committed_target(
        &mut self,
        summary: &mut LibsslUprobeAttachSummary,
        committed_target: CommittedLibsslUprobeTargetAttach,
    ) {
        let target = committed_target.target;
        summary.record_committed_target(target.clone());
        for successful_recipe in committed_target.recipes {
            self.attached_links
                .push_recipe_links(target.clone(), successful_recipe.links);
        }
    }

    pub(in crate::tls::plaintext) fn detach_all_best_effort(
        &mut self,
        ebpf: &mut Ebpf,
    ) -> Result<(), LibsslUprobeAttachError> {
        self.attached_links.detach_all_best_effort(ebpf)
    }

    pub(in crate::tls::plaintext) fn detach_targets_best_effort(
        &mut self,
        ebpf: &mut Ebpf,
        targets: impl IntoIterator<Item = crate::tls::LibsslUprobeAttachTargetId>,
    ) -> Result<(), LibsslUprobeAttachError> {
        self.attached_links
            .detach_targets_best_effort(ebpf, targets)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tls::plaintext) enum AttachFailurePolicy {
    Strict,
    BestEffort,
}

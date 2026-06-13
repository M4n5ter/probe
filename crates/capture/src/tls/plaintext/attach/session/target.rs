use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use aya::Ebpf;

use super::super::{
    error::LibsslUprobeAttachError,
    recipe::{
        LibsslUprobeAttachRecipeRequest, best_effort_attach_rank, is_fd_association, is_plaintext,
    },
    summary::LibsslUprobeAttachSummary,
};
use super::uprobe::{AttachedLibsslUprobe, attach_recipe_uprobes, rollback_attached_uprobes};
use crate::tls::LibsslUprobeAttachTargetId;

pub(super) struct BestEffortTargetPlan {
    target: LibsslUprobeAttachTargetId,
    recipe_indices: Vec<usize>,
}

impl BestEffortTargetPlan {
    pub(super) fn from_recipes(recipes: &[LibsslUprobeAttachRecipeRequest]) -> Vec<Self> {
        Self::recipe_groups(recipes)
            .into_iter()
            .filter_map(|mut group| {
                group.has_readiness_basis(recipes).then(|| {
                    group.recipe_indices.sort_by_key(|recipe_index| {
                        (
                            best_effort_attach_rank(&recipes[*recipe_index]),
                            *recipe_index,
                        )
                    });
                    Self {
                        target: group.target,
                        recipe_indices: group.recipe_indices,
                    }
                })
            })
            .collect()
    }

    fn recipe_groups(
        recipes: &[LibsslUprobeAttachRecipeRequest],
    ) -> Vec<BestEffortTargetRecipeGroup> {
        let mut group_indexes = BTreeMap::new();
        let mut groups = Vec::<BestEffortTargetRecipeGroup>::new();
        for (recipe_index, recipe) in recipes.iter().enumerate() {
            let target = recipe.target_id();
            let next_group_index = groups.len();
            let group_index = match group_indexes.entry(target.clone()) {
                Entry::Occupied(entry) => *entry.get(),
                Entry::Vacant(entry) => {
                    entry.insert(next_group_index);
                    groups.push(BestEffortTargetRecipeGroup {
                        target,
                        recipe_indices: Vec::new(),
                    });
                    next_group_index
                }
            };
            groups[group_index].recipe_indices.push(recipe_index);
        }
        groups
    }

    fn recipe_indices(&self) -> &[usize] {
        &self.recipe_indices
    }
}

struct BestEffortTargetRecipeGroup {
    target: LibsslUprobeAttachTargetId,
    recipe_indices: Vec<usize>,
}

impl BestEffortTargetRecipeGroup {
    fn has_readiness_basis(&self, recipes: &[LibsslUprobeAttachRecipeRequest]) -> bool {
        self.recipe_indices
            .iter()
            .any(|recipe_index| is_fd_association(&recipes[*recipe_index]))
            && self
                .recipe_indices
                .iter()
                .any(|recipe_index| is_plaintext(&recipes[*recipe_index]))
    }
}

pub(super) enum TargetAttachOutcome {
    Committed(CommittedLibsslUprobeTargetAttach),
    Skipped,
}

pub(super) struct CommittedLibsslUprobeTargetAttach {
    pub(super) target: LibsslUprobeAttachTargetId,
    pub(super) recipes: Vec<SuccessfulLibsslUprobeRecipeAttach>,
}

pub(super) struct SuccessfulLibsslUprobeRecipeAttach {
    pub(super) links: Vec<AttachedLibsslUprobe>,
}

#[derive(Default)]
struct TargetAttachTransaction {
    successful_recipes: Vec<SuccessfulLibsslUprobeRecipeAttach>,
    readiness: TargetAttachReadiness,
    has_stateful_success: bool,
    has_failed_partial_state_effect: bool,
    first_failure: Option<LibsslUprobeAttachError>,
}

#[derive(Default)]
struct TargetAttachReadiness {
    fd_association_attached: bool,
    plaintext_attached: bool,
}

impl TargetAttachReadiness {
    fn record(&mut self, recipe: &LibsslUprobeAttachRecipeRequest) {
        self.fd_association_attached |= is_fd_association(recipe);
        self.plaintext_attached |= is_plaintext(recipe);
    }

    fn is_ready(&self) -> bool {
        self.fd_association_attached && self.plaintext_attached
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetAttachDecision {
    Commit,
    SkipClean,
    AbortUnsafePartial,
}

pub(super) fn attach_best_effort_target_uprobes(
    ebpf: &mut Ebpf,
    loaded_programs: &mut BTreeSet<&'static str>,
    recipes: &[LibsslUprobeAttachRecipeRequest],
    target_plan: &BestEffortTargetPlan,
    summary: &mut LibsslUprobeAttachSummary,
) -> Result<TargetAttachOutcome, LibsslUprobeAttachError> {
    let mut transaction = TargetAttachTransaction::default();
    for &recipe_index in target_plan.recipe_indices() {
        let recipe = &recipes[recipe_index];
        match attach_recipe_uprobes(ebpf, loaded_programs, recipe) {
            Ok(links) => {
                transaction.record_success(recipe, links);
            }
            Err(recipe_error) => {
                let failure_kind = BestEffortAttachFailureKind::classify(&recipe_error.error);
                let failed_partial_state_effect = recipe_error.partial_state_effect;
                let continue_after_failure = failure_kind
                    == BestEffortAttachFailureKind::AttachFailed
                    && !is_fd_association(recipe)
                    && !failed_partial_state_effect;
                let error = recipe_error.into_error();
                summary.record_failure(&error);
                transaction.record_failure(error, failed_partial_state_effect);
                match failure_kind {
                    BestEffortAttachFailureKind::TargetStale => {
                        return transaction.rollback_for_skip_or_fail(ebpf, target_plan);
                    }
                    BestEffortAttachFailureKind::AttachFailed if continue_after_failure => {}
                    BestEffortAttachFailureKind::AttachFailed => {
                        return transaction.rollback_for_skip_or_fail(ebpf, target_plan);
                    }
                    BestEffortAttachFailureKind::Fatal => {
                        return transaction.rollback_and_fail(ebpf);
                    }
                }
            }
        }
    }
    transaction.finish(ebpf, target_plan)
}

impl TargetAttachTransaction {
    fn record_success(
        &mut self,
        recipe: &LibsslUprobeAttachRecipeRequest,
        links: Vec<AttachedLibsslUprobe>,
    ) {
        self.readiness.record(recipe);
        self.has_stateful_success = true;
        self.successful_recipes
            .push(SuccessfulLibsslUprobeRecipeAttach { links });
    }

    fn record_failure(&mut self, error: LibsslUprobeAttachError, partial_state_effect: bool) {
        self.has_failed_partial_state_effect |= partial_state_effect;
        if self.first_failure.is_none() {
            self.first_failure = Some(error);
        }
    }

    fn finish(
        self,
        ebpf: &mut Ebpf,
        target_plan: &BestEffortTargetPlan,
    ) -> Result<TargetAttachOutcome, LibsslUprobeAttachError> {
        if self.decision() == TargetAttachDecision::Commit {
            return Ok(TargetAttachOutcome::Committed(
                self.into_committed_target(target_plan),
            ));
        }
        self.rollback_for_skip_or_fail(ebpf, target_plan)
    }

    fn decision(&self) -> TargetAttachDecision {
        if self.readiness.is_ready() && !self.has_failed_partial_state_effect {
            TargetAttachDecision::Commit
        } else if self.has_stateful_success || self.has_failed_partial_state_effect {
            TargetAttachDecision::AbortUnsafePartial
        } else {
            TargetAttachDecision::SkipClean
        }
    }

    fn rollback_for_skip_or_fail(
        self,
        ebpf: &mut Ebpf,
        target_plan: &BestEffortTargetPlan,
    ) -> Result<TargetAttachOutcome, LibsslUprobeAttachError> {
        let decision = self.decision();
        let error =
            self.first_failure
                .unwrap_or_else(|| LibsslUprobeAttachError::UnsafePartialTarget {
                    pid: target_plan.target.process.pid,
                    target_path: target_plan.target.library.read_path.clone(),
                    reason: "target did not reach fd association plus plaintext readiness",
                });
        rollback_successful_target_recipes(ebpf, self.successful_recipes)?;
        if decision == TargetAttachDecision::AbortUnsafePartial {
            return Err(error);
        }
        Ok(TargetAttachOutcome::Skipped)
    }

    fn rollback_and_fail(
        self,
        ebpf: &mut Ebpf,
    ) -> Result<TargetAttachOutcome, LibsslUprobeAttachError> {
        let error = self
            .first_failure
            .expect("fatal rollback should preserve original failure");
        rollback_successful_target_recipes(ebpf, self.successful_recipes)?;
        Err(error)
    }

    fn into_committed_target(
        self,
        target_plan: &BestEffortTargetPlan,
    ) -> CommittedLibsslUprobeTargetAttach {
        CommittedLibsslUprobeTargetAttach {
            target: target_plan.target.clone(),
            recipes: self.successful_recipes,
        }
    }
}

fn rollback_successful_target_recipes(
    ebpf: &mut Ebpf,
    successful_recipes: Vec<SuccessfulLibsslUprobeRecipeAttach>,
) -> Result<(), LibsslUprobeAttachError> {
    rollback_attached_uprobes(
        ebpf,
        successful_recipes
            .into_iter()
            .flat_map(|recipe| recipe.links)
            .collect(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BestEffortAttachFailureKind {
    TargetStale,
    AttachFailed,
    Fatal,
}

impl BestEffortAttachFailureKind {
    fn classify(error: &LibsslUprobeAttachError) -> Self {
        match error {
            LibsslUprobeAttachError::AttachTarget { .. }
            | LibsslUprobeAttachError::AttachProcess { .. } => Self::TargetStale,
            LibsslUprobeAttachError::Attach { .. } => Self::AttachFailed,
            LibsslUprobeAttachError::EmptyAttachPlan
            | LibsslUprobeAttachError::InvalidTargetPid { .. }
            | LibsslUprobeAttachError::MissingProgram { .. }
            | LibsslUprobeAttachError::Program { .. }
            | LibsslUprobeAttachError::ProgramKind { .. }
            | LibsslUprobeAttachError::RollbackAttach { .. }
            | LibsslUprobeAttachError::Detach { .. }
            | LibsslUprobeAttachError::UnsafePartialTarget { .. } => Self::Fatal,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use probe_core::{Direction, ProcessGeneration};

    use crate::{
        LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary, LibsslUprobeAttachPlan,
        LibsslUprobeSymbol, LibsslUprobeSymbolRole, LibsslUprobeTarget,
        LibsslUprobeTargetDiscoveryReport, tls::LibsslUprobeProcessVerifier,
    };

    use crate::tls::plaintext::attach::recipe::attach_recipes_from_plan;

    use super::*;

    #[test]
    fn best_effort_attach_order_skips_unready_targets_and_attaches_plaintext_last()
    -> Result<(), Box<dyn std::error::Error>> {
        let ready_library = mapped_library("/usr/lib/libssl-ready.so.3");
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![
                target(
                    "/usr/lib/libssl-ready.so.3",
                    vec![
                        LibsslUprobeSymbol::SslRead,
                        LibsslUprobeSymbol::SslFree,
                        LibsslUprobeSymbol::SslSetFd,
                        LibsslUprobeSymbol::SslWrite,
                    ],
                ),
                target(
                    "/usr/lib/libssl-plaintext-only.so.3",
                    vec![LibsslUprobeSymbol::SslRead],
                ),
                target(
                    "/usr/lib/libssl-fd-only.so.3",
                    vec![LibsslUprobeSymbol::SslSetFd],
                ),
            ],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;

        let target_plans = BestEffortTargetPlan::from_recipes(&recipes);
        let ordered_recipes = target_plans[0]
            .recipe_indices()
            .iter()
            .map(|recipe_index| &recipes[*recipe_index])
            .collect::<Vec<_>>();
        let ordered_semantics = ordered_recipes
            .iter()
            .map(|recipe| recipe.semantic)
            .collect::<Vec<_>>();

        assert_eq!(target_plans.len(), 1);
        assert!(
            ordered_recipes
                .iter()
                .all(|recipe| recipe.library == ready_library)
        );
        assert_eq!(
            ordered_semantics,
            vec![
                LibsslUprobeSymbolRole::FdAssociation,
                LibsslUprobeSymbolRole::StateCleanup,
                LibsslUprobeSymbolRole::Plaintext {
                    direction: Direction::Inbound,
                },
                LibsslUprobeSymbolRole::Plaintext {
                    direction: Direction::Outbound,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn target_transaction_aborts_after_failed_partial_state_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![target(
                "/usr/lib/libssl.so.3",
                vec![
                    LibsslUprobeSymbol::SslSetFd,
                    LibsslUprobeSymbol::SslRead,
                    LibsslUprobeSymbol::SslWrite,
                ],
            )],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let fd_recipe = recipes
            .iter()
            .position(is_fd_association)
            .expect("fixture should include fd association recipe");
        let plaintext_recipe = recipes
            .iter()
            .position(is_plaintext)
            .expect("fixture should include plaintext recipe");
        let mut transaction = TargetAttachTransaction::default();

        transaction.record_success(&recipes[fd_recipe], Vec::new());
        transaction.record_success(&recipes[plaintext_recipe], Vec::new());
        transaction.record_failure(LibsslUprobeAttachError::EmptyAttachPlan, true);

        assert_eq!(
            transaction.decision(),
            TargetAttachDecision::AbortUnsafePartial
        );
        Ok(())
    }

    fn mapped_library(path: &str) -> LibsslMappedLibrary {
        let mapped_path = PathBuf::from(path);
        LibsslMappedLibrary {
            read_path: Path::new("/proc/42/root").join(path.trim_start_matches('/')),
            mapped_path,
            identity: LibsslMappedFileIdentity {
                device_major: 8,
                device_minor: 1,
                inode: 100,
            },
            deleted: false,
        }
    }

    fn target(path: &str, symbols: Vec<LibsslUprobeSymbol>) -> LibsslUprobeTarget {
        LibsslUprobeTarget {
            library: mapped_library(path),
            library_kind: LibsslLibraryKind::OpenSslLike,
            executable_mappings: Vec::new(),
            symbols,
        }
    }

    fn discovery_report(
        pid: u32,
        targets: Vec<LibsslUprobeTarget>,
    ) -> LibsslUprobeTargetDiscoveryReport {
        LibsslUprobeTargetDiscoveryReport::new(
            process_generation(pid),
            process_verifier(),
            targets,
            Vec::new(),
        )
    }

    fn process_generation(pid: u32) -> ProcessGeneration {
        ProcessGeneration {
            pid,
            start_time_ticks: u64::from(pid) * 100,
        }
    }

    fn process_verifier() -> LibsslUprobeProcessVerifier {
        LibsslUprobeProcessVerifier::new("/proc")
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use aya::{
    Ebpf,
    programs::{ProbeKind, ProgramError, UProbe, uprobe::UProbeLinkId},
};
use probe_core::ProcessGeneration;
use thiserror::Error;

use crate::tls::{
    LibsslMappedLibrary, LibsslUprobeAttachKind, LibsslUprobeAttachPlan, LibsslUprobeAttachPoint,
    LibsslUprobeAttachTargetId, LibsslUprobeProcessGenerationFailure, LibsslUprobeProcessVerifier,
    LibsslUprobeSymbolFailure, LibsslUprobeSymbolRole,
    discovery::{verify_current_mapped_library_identity, verify_current_process_generation},
};

#[derive(Debug, Error)]
pub(in crate::tls::plaintext) enum LibsslUprobeAttachError {
    #[error("libssl uprobe attach plan has no attachable probes")]
    EmptyAttachPlan,
    #[error("libssl uprobe target pid {pid} cannot be represented as a Linux pid_t")]
    InvalidTargetPid { pid: u32 },
    #[error("eBPF TLS plaintext object is missing program {name}")]
    MissingProgram { name: &'static str },
    #[error("failed to {action} eBPF TLS plaintext program {name}: {source}")]
    Program {
        name: &'static str,
        action: &'static str,
        source: Box<ProgramError>,
    },
    #[error("eBPF TLS plaintext program {name} has {actual} kind, expected {expected:?}")]
    ProgramKind {
        name: &'static str,
        actual: &'static str,
        expected: LibsslUprobeAttachKind,
    },
    #[error(
        "failed to attach eBPF TLS plaintext program {program_name} to {library_symbol} for pid {pid} at {target_path}: {source}"
    )]
    Attach {
        program_name: &'static str,
        library_symbol: &'static str,
        pid: u32,
        target_path: PathBuf,
        source: Box<ProgramError>,
    },
    #[error("failed to rollback eBPF TLS plaintext attach for program {program_name}: {source}")]
    RollbackAttach {
        program_name: &'static str,
        source: Box<ProgramError>,
    },
    #[error(
        "failed to detach eBPF TLS plaintext program {program_name} from pid {pid} at {target_path}: {source}"
    )]
    Detach {
        program_name: &'static str,
        pid: u32,
        target_path: PathBuf,
        source: Box<ProgramError>,
    },
    #[error("libssl uprobe attach target for pid {pid} is no longer valid: {source}")]
    AttachTarget {
        pid: u32,
        source: Box<LibsslUprobeSymbolFailure>,
    },
    #[error("libssl uprobe attach target process for pid {pid} is no longer valid: {source}")]
    AttachProcess {
        pid: u32,
        source: Box<LibsslUprobeProcessGenerationFailure>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tls::plaintext) struct LibsslUprobeAttachRecipeRequest {
    library: LibsslMappedLibrary,
    process: ProcessGeneration,
    process_verifier: LibsslUprobeProcessVerifier,
    semantic: LibsslUprobeSymbolRole,
    pid: i32,
    attach_points: Vec<LibsslUprobeAttachPointRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LibsslUprobeAttachPointRequest {
    program_name: &'static str,
    library_symbol: &'static str,
    offset: u64,
    kind: LibsslUprobeAttachKind,
}

impl LibsslUprobeAttachRecipeRequest {
    fn target_id(&self) -> LibsslUprobeAttachTargetId {
        LibsslUprobeAttachTargetId::new(self.process, self.library.clone())
    }
}

#[derive(Default)]
pub(in crate::tls::plaintext) struct LibsslUprobeAttachSession {
    loaded_programs: BTreeSet<&'static str>,
    attached_links: LibsslUprobeAttachedLinks,
}

impl LibsslUprobeAttachSession {
    pub(in crate::tls::plaintext) fn attach_uprobes(
        &mut self,
        ebpf: &mut Ebpf,
        recipes: &[LibsslUprobeAttachRecipeRequest],
        policy: AttachFailurePolicy,
    ) -> Result<LibsslUprobeAttachSummary, LibsslUprobeAttachError> {
        let mut summary = LibsslUprobeAttachSummary::from_recipes(recipes);
        for (recipe_index, recipe) in recipes.iter().enumerate() {
            match attach_recipe_uprobes(ebpf, &mut self.loaded_programs, recipe) {
                Ok(links) => {
                    let target = summary.record_recipe_attached(recipe_index);
                    self.attached_links.push_recipe_links(target, links);
                }
                Err(error) => match policy {
                    AttachFailurePolicy::Strict => return Err(error),
                    AttachFailurePolicy::BestEffort if is_best_effort_attach_failure(&error) => {
                        summary.record_failure(&error);
                    }
                    AttachFailurePolicy::BestEffort => return Err(error),
                },
            }
        }
        Ok(summary)
    }

    pub(in crate::tls::plaintext) fn detach_all_best_effort(
        &mut self,
        ebpf: &mut Ebpf,
    ) -> Result<(), LibsslUprobeAttachError> {
        self.attached_links.detach_all_best_effort(ebpf)
    }
}

#[derive(Default)]
struct LibsslUprobeAttachedLinks {
    links_by_target: BTreeMap<LibsslUprobeAttachTargetId, Vec<AttachedLibsslUprobe>>,
}

impl LibsslUprobeAttachedLinks {
    pub(in crate::tls::plaintext) fn detach_all_best_effort(
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

    fn push_recipe_links(
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

struct AttachedLibsslUprobe {
    program_name: &'static str,
    link_id: UProbeLinkId,
}

pub(in crate::tls::plaintext) fn attach_recipes_from_plan(
    plan: &LibsslUprobeAttachPlan,
) -> Result<Vec<LibsslUprobeAttachRecipeRequest>, LibsslUprobeAttachError> {
    let mut requests = Vec::new();
    for process in plan.processes() {
        let pid = attachable_pid(process.pid())?;
        for target in process.targets() {
            for recipe in &target.recipes {
                requests.push(attach_recipe_request_from_plan(
                    target.library.clone(),
                    process.process(),
                    process.process_verifier().clone(),
                    recipe.semantic(),
                    pid,
                    recipe
                        .attach_points()
                        .into_iter()
                        .map(attach_point_request_from_plan)
                        .collect(),
                ));
            }
        }
    }
    if requests.is_empty() {
        return Err(LibsslUprobeAttachError::EmptyAttachPlan);
    }
    Ok(requests)
}

fn attachable_pid(pid: u32) -> Result<i32, LibsslUprobeAttachError> {
    if pid == 0 {
        return Err(LibsslUprobeAttachError::InvalidTargetPid { pid });
    }
    i32::try_from(pid).map_err(|_| LibsslUprobeAttachError::InvalidTargetPid { pid })
}

fn attach_recipe_request_from_plan(
    library: LibsslMappedLibrary,
    process: ProcessGeneration,
    process_verifier: LibsslUprobeProcessVerifier,
    semantic: LibsslUprobeSymbolRole,
    pid: i32,
    attach_points: Vec<LibsslUprobeAttachPointRequest>,
) -> LibsslUprobeAttachRecipeRequest {
    LibsslUprobeAttachRecipeRequest {
        library,
        process,
        process_verifier,
        semantic,
        pid,
        attach_points,
    }
}

fn attach_point_request_from_plan(
    point: LibsslUprobeAttachPoint,
) -> LibsslUprobeAttachPointRequest {
    LibsslUprobeAttachPointRequest {
        program_name: point.program_name,
        library_symbol: point.library_symbol,
        offset: point.offset,
        kind: point.kind,
    }
}

fn is_best_effort_attach_failure(error: &LibsslUprobeAttachError) -> bool {
    matches!(
        error,
        LibsslUprobeAttachError::Attach { .. }
            | LibsslUprobeAttachError::AttachTarget { .. }
            | LibsslUprobeAttachError::AttachProcess { .. }
    )
}

fn attach_recipe_uprobes(
    ebpf: &mut Ebpf,
    loaded_programs: &mut BTreeSet<&'static str>,
    recipe: &LibsslUprobeAttachRecipeRequest,
) -> Result<Vec<AttachedLibsslUprobe>, LibsslUprobeAttachError> {
    attach_target_is_current(recipe)?;

    let mut attached = Vec::new();
    for point in &recipe.attach_points {
        if let Err(error) =
            attach_single_uprobe(ebpf, loaded_programs, recipe, point, &mut attached)
        {
            rollback_attached_uprobes(ebpf, attached)?;
            return Err(error);
        }
    }
    Ok(attached)
}

fn attach_single_uprobe(
    ebpf: &mut Ebpf,
    loaded_programs: &mut BTreeSet<&'static str>,
    recipe: &LibsslUprobeAttachRecipeRequest,
    point: &LibsslUprobeAttachPointRequest,
    attached: &mut Vec<AttachedLibsslUprobe>,
) -> Result<(), LibsslUprobeAttachError> {
    let program = uprobe_program_mut(ebpf, point.program_name)?;
    if !uprobe_kind_matches_attach_kind(program.kind(), point.kind) {
        return Err(LibsslUprobeAttachError::ProgramKind {
            name: point.program_name,
            actual: probe_kind_label(program.kind()),
            expected: point.kind,
        });
    }
    if !loaded_programs.contains(point.program_name) {
        program
            .load()
            .map_err(|source| LibsslUprobeAttachError::Program {
                name: point.program_name,
                action: "load",
                source: Box::new(source),
            })?;
        loaded_programs.insert(point.program_name);
    }
    let link_id = program
        .attach(
            Some(point.library_symbol),
            point.offset,
            &recipe.library.read_path,
            Some(recipe.pid),
        )
        .map_err(|source| LibsslUprobeAttachError::Attach {
            program_name: point.program_name,
            library_symbol: point.library_symbol,
            pid: recipe.process.pid,
            target_path: recipe.library.read_path.clone(),
            source: Box::new(source),
        })?;
    attached.push(AttachedLibsslUprobe {
        program_name: point.program_name,
        link_id,
    });
    Ok(())
}

fn rollback_attached_uprobes(
    ebpf: &mut Ebpf,
    attached: Vec<AttachedLibsslUprobe>,
) -> Result<(), LibsslUprobeAttachError> {
    for attached in attached.into_iter().rev() {
        uprobe_program_mut(ebpf, attached.program_name)?
            .detach(attached.link_id)
            .map_err(|source| LibsslUprobeAttachError::RollbackAttach {
                program_name: attached.program_name,
                source: Box::new(source),
            })?;
    }
    Ok(())
}

fn detach_attached_uprobes_for_target(
    ebpf: &mut Ebpf,
    target: &LibsslUprobeAttachTargetId,
    attached: Vec<AttachedLibsslUprobe>,
) -> Result<(), LibsslUprobeAttachError> {
    let mut first_error = None;
    for attached in attached.into_iter().rev() {
        let result =
            match uprobe_program_mut(ebpf, attached.program_name) {
                Ok(program) => program.detach(attached.link_id).map_err(|source| {
                    LibsslUprobeAttachError::Detach {
                        program_name: attached.program_name,
                        pid: target.process.pid,
                        target_path: target.library.read_path.clone(),
                        source: Box::new(source),
                    }
                }),
                Err(error) => Err(error),
            };
        if let Err(error) = result {
            record_first_detach_error(&mut first_error, error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

fn record_first_detach_error(
    first_error: &mut Option<LibsslUprobeAttachError>,
    error: LibsslUprobeAttachError,
) {
    if first_error.is_none() {
        *first_error = Some(error);
    }
}

fn uprobe_program_mut<'a>(
    ebpf: &'a mut Ebpf,
    program_name: &'static str,
) -> Result<&'a mut UProbe, LibsslUprobeAttachError> {
    let program = ebpf
        .program_mut(program_name)
        .ok_or(LibsslUprobeAttachError::MissingProgram { name: program_name })?;
    program
        .try_into()
        .map_err(|source| LibsslUprobeAttachError::Program {
            name: program_name,
            action: "cast",
            source: Box::new(source),
        })
}

fn attach_target_is_current(
    recipe: &LibsslUprobeAttachRecipeRequest,
) -> Result<(), LibsslUprobeAttachError> {
    if let Err(source) = verify_current_process_generation(recipe.process, &recipe.process_verifier)
    {
        return Err(LibsslUprobeAttachError::AttachProcess {
            pid: recipe.process.pid,
            source: Box::new(source),
        });
    }
    if let Err(source) = verify_current_mapped_library_identity(&recipe.library) {
        return Err(LibsslUprobeAttachError::AttachTarget {
            pid: recipe.process.pid,
            source: Box::new(source),
        });
    }
    Ok(())
}

fn uprobe_kind_matches_attach_kind(actual: ProbeKind, expected: LibsslUprobeAttachKind) -> bool {
    matches!(
        (actual, expected),
        (ProbeKind::UProbe, LibsslUprobeAttachKind::Entry)
            | (ProbeKind::URetProbe, LibsslUprobeAttachKind::Return)
    )
}

pub(in crate::tls::plaintext) struct LibsslUprobeAttachSummary {
    recipes: Vec<LibsslUprobeRecipeAttachProgress>,
    first_failure_reason: Option<String>,
    failure_count: usize,
}

impl LibsslUprobeAttachSummary {
    fn from_recipes(recipes: &[LibsslUprobeAttachRecipeRequest]) -> Self {
        let recipes = recipes
            .iter()
            .map(|recipe| LibsslUprobeRecipeAttachProgress {
                target: recipe.target_id(),
                semantic: recipe.semantic,
                complete: false,
            })
            .collect();
        Self {
            recipes,
            first_failure_reason: None,
            failure_count: 0,
        }
    }

    fn record_recipe_attached(&mut self, recipe_index: usize) -> LibsslUprobeAttachTargetId {
        let recipe = self
            .recipes
            .get_mut(recipe_index)
            .expect("recipe index should come from the attach recipe list");
        recipe.complete = true;
        recipe.target.clone()
    }

    fn record_failure(&mut self, error: &LibsslUprobeAttachError) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.first_failure_reason
            .get_or_insert_with(|| error.to_string());
    }

    pub(in crate::tls::plaintext) fn has_resolvable_plaintext_recipe(&self) -> bool {
        self.recipes.iter().any(|recipe| {
            recipe.complete
                && matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. })
                && self.has_complete_fd_association_for(&recipe.target)
        })
    }

    fn has_complete_fd_association_for(&self, target: &LibsslUprobeAttachTargetId) -> bool {
        self.recipes.iter().any(|recipe| {
            recipe.complete
                && recipe.target == *target
                && recipe.semantic == LibsslUprobeSymbolRole::FdAssociation
        })
    }

    pub(in crate::tls::plaintext) fn unresolvable_plaintext_reason(&self) -> String {
        if self
            .recipes
            .iter()
            .any(|recipe| matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. }))
        {
            let mut reason = "libssl uprobe best-effort attach did not complete any same-target fd association plus plaintext recipe set".to_string();
            if let Some(first_failure_reason) = &self.first_failure_reason {
                reason.push_str("; first attach failure: ");
                reason.push_str(first_failure_reason);
                if self.failure_count > 1 {
                    reason.push_str(&format!(
                        "; additional attach failures: {}",
                        self.failure_count - 1
                    ));
                }
            }
            reason
        } else {
            "libssl uprobe attach plan did not contain a plaintext recipe".to_string()
        }
    }
}

struct LibsslUprobeRecipeAttachProgress {
    target: LibsslUprobeAttachTargetId,
    semantic: LibsslUprobeSymbolRole,
    complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tls::plaintext) enum AttachFailurePolicy {
    Strict,
    BestEffort,
}

fn probe_kind_label(kind: ProbeKind) -> &'static str {
    match kind {
        ProbeKind::KProbe => "kprobe",
        ProbeKind::KRetProbe => "kretprobe",
        ProbeKind::UProbe => "uprobe",
        ProbeKind::URetProbe => "uretprobe",
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use probe_core::{Direction, ProcessGeneration};

    use crate::{
        LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
        LibsslUprobeProcessGenerationFailure, LibsslUprobeSymbol, LibsslUprobeTarget,
        LibsslUprobeTargetDiscoveryReport,
    };

    use super::*;

    #[test]
    fn attach_recipes_preserve_plan_pid_path_symbol_and_kind()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: vec![LibsslExecutableMapping {
                    start_address: 0x1000,
                    end_address: 0x2000,
                    file_offset: 0,
                }],
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));

        let recipes = attach_recipes_from_plan(&plan)?;

        assert_eq!(
            recipes,
            vec![LibsslUprobeAttachRecipeRequest {
                library: mapped_library("/usr/lib/libssl.so.3"),
                process: process_generation(42),
                process_verifier: process_verifier(),
                semantic: LibsslUprobeSymbolRole::Plaintext {
                    direction: Direction::Inbound,
                },
                pid: 42,
                attach_points: vec![
                    LibsslUprobeAttachPointRequest {
                        program_name: LibsslUprobeSymbol::SslRead.entry_program_name(),
                        library_symbol: "SSL_read",
                        offset: 0,
                        kind: LibsslUprobeAttachKind::Entry,
                    },
                    LibsslUprobeAttachPointRequest {
                        program_name: LibsslUprobeSymbol::SslRead
                            .return_program_name()
                            .expect("SSL_read should have a return probe"),
                        library_symbol: "SSL_read",
                        offset: 0,
                        kind: LibsslUprobeAttachKind::Return,
                    },
                ],
            }]
        );
        Ok(())
    }

    #[test]
    fn attach_summary_requires_same_target_fd_association_and_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslSetFd, LibsslUprobeSymbol::SslRead],
            }],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let lifecycle_recipe = recipes
            .iter()
            .position(|recipe| recipe.semantic == LibsslUprobeSymbolRole::FdAssociation)
            .expect("fixture should include lifecycle recipe");
        let plaintext_recipe = recipes
            .iter()
            .position(|recipe| matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. }))
            .expect("fixture should include plaintext recipe");
        let mut summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        summary.record_recipe_attached(lifecycle_recipe);
        assert!(!summary.has_resolvable_plaintext_recipe());

        summary.record_recipe_attached(plaintext_recipe);
        assert!(summary.has_resolvable_plaintext_recipe());
        Ok(())
    }

    #[test]
    fn attach_summary_rejects_plaintext_without_fd_association()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let plaintext_recipe = recipes
            .iter()
            .position(|recipe| matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. }))
            .expect("fixture should include plaintext recipe");
        let mut summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        summary.record_recipe_attached(plaintext_recipe);

        assert!(!summary.has_resolvable_plaintext_recipe());
        assert!(
            summary
                .unresolvable_plaintext_reason()
                .contains("same-target fd association plus plaintext recipe set")
        );
        Ok(())
    }

    #[test]
    fn attach_summary_disabled_reason_preserves_first_attach_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let mut summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        summary.record_failure(&LibsslUprobeAttachError::AttachProcess {
            pid: 42,
            source: Box::new(LibsslUprobeProcessGenerationFailure::Changed {
                path: PathBuf::from("/proc/42/stat"),
                expected_start_time_ticks: 7,
                actual_start_time_ticks: 8,
            }),
        });

        let reason = summary.unresolvable_plaintext_reason();
        assert!(reason.contains("did not complete any same-target fd association"));
        assert!(reason.contains("first attach failure"));
        assert!(reason.contains("process stat /proc/42/stat no longer matches expected starttime"));
        Ok(())
    }

    #[test]
    fn attach_recipes_reject_empty_plan() {
        let error = attach_recipes_from_plan(&LibsslUprobeAttachPlan::from_discovery_reports([]))
            .expect_err("empty plan must not load a TLS uprobe probe");

        assert!(matches!(error, LibsslUprobeAttachError::EmptyAttachPlan));
    }

    #[test]
    fn attach_recipes_reject_pid_that_cannot_fit_pid_t() {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            i32::MAX as u32 + 1,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));

        let error = attach_recipes_from_plan(&plan)
            .expect_err("pid outside pid_t range must fail before aya attach");

        assert!(matches!(
            error,
            LibsslUprobeAttachError::InvalidTargetPid { pid }
                if pid == i32::MAX as u32 + 1
        ));
    }

    #[test]
    fn attach_recipes_reject_pid_zero() {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            0,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));

        let error =
            attach_recipes_from_plan(&plan).expect_err("pid zero must not reach aya attach");

        assert!(matches!(
            error,
            LibsslUprobeAttachError::InvalidTargetPid { pid: 0 }
        ));
    }

    #[test]
    fn attach_kind_matches_aya_uprobe_kind() {
        assert!(uprobe_kind_matches_attach_kind(
            ProbeKind::UProbe,
            LibsslUprobeAttachKind::Entry
        ));
        assert!(uprobe_kind_matches_attach_kind(
            ProbeKind::URetProbe,
            LibsslUprobeAttachKind::Return
        ));
        assert!(!uprobe_kind_matches_attach_kind(
            ProbeKind::UProbe,
            LibsslUprobeAttachKind::Return
        ));
        assert!(!uprobe_kind_matches_attach_kind(
            ProbeKind::URetProbe,
            LibsslUprobeAttachKind::Entry
        ));
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

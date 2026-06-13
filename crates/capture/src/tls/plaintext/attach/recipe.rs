use probe_core::ProcessGeneration;

use crate::tls::{
    LibsslMappedLibrary, LibsslUprobeAttachKind, LibsslUprobeAttachPlan, LibsslUprobeAttachPoint,
    LibsslUprobeAttachTargetId, LibsslUprobeProcessVerifier, LibsslUprobeSymbolRole,
};

use super::error::LibsslUprobeAttachError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tls::plaintext) struct LibsslUprobeAttachRecipeRequest {
    pub(super) library: LibsslMappedLibrary,
    pub(super) process: ProcessGeneration,
    pub(super) process_verifier: LibsslUprobeProcessVerifier,
    pub(super) semantic: LibsslUprobeSymbolRole,
    pub(super) pid: i32,
    pub(super) attach_points: Vec<LibsslUprobeAttachPointRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LibsslUprobeAttachPointRequest {
    pub(super) program_name: &'static str,
    pub(super) library_symbol: &'static str,
    pub(super) offset: u64,
    pub(super) kind: LibsslUprobeAttachKind,
}

impl LibsslUprobeAttachRecipeRequest {
    pub(super) fn target_id(&self) -> LibsslUprobeAttachTargetId {
        LibsslUprobeAttachTargetId::new(self.process, self.library.clone())
    }
}

pub(in crate::tls::plaintext) enum LibsslUprobeAttachWork {
    None,
    Recipes(Vec<LibsslUprobeAttachRecipeRequest>),
}

impl LibsslUprobeAttachWork {
    pub(in crate::tls::plaintext) fn as_recipes(&self) -> &[LibsslUprobeAttachRecipeRequest] {
        match self {
            Self::None => &[],
            Self::Recipes(recipes) => recipes,
        }
    }

    pub(in crate::tls::plaintext) fn is_empty(&self) -> bool {
        matches!(self, Self::None)
    }
}

pub(in crate::tls::plaintext) fn strict_attach_work_from_plan(
    plan: &LibsslUprobeAttachPlan,
) -> Result<LibsslUprobeAttachWork, LibsslUprobeAttachError> {
    Ok(LibsslUprobeAttachWork::Recipes(attach_recipes_from_plan(
        plan,
    )?))
}

pub(in crate::tls::plaintext) fn best_effort_attach_work_from_plan(
    plan: &LibsslUprobeAttachPlan,
) -> Result<LibsslUprobeAttachWork, LibsslUprobeAttachError> {
    match attach_recipes_from_plan(plan) {
        Ok(recipes) => Ok(LibsslUprobeAttachWork::Recipes(recipes)),
        Err(LibsslUprobeAttachError::EmptyAttachPlan) => Ok(LibsslUprobeAttachWork::None),
        Err(error) => Err(error),
    }
}

pub(super) fn best_effort_attach_rank(recipe: &LibsslUprobeAttachRecipeRequest) -> u8 {
    match recipe.semantic {
        LibsslUprobeSymbolRole::FdAssociation => 0,
        LibsslUprobeSymbolRole::StateReset | LibsslUprobeSymbolRole::StateCleanup => 1,
        LibsslUprobeSymbolRole::Plaintext { .. } => 2,
    }
}

pub(super) fn is_fd_association(recipe: &LibsslUprobeAttachRecipeRequest) -> bool {
    recipe.semantic == LibsslUprobeSymbolRole::FdAssociation
}

pub(super) fn is_plaintext(recipe: &LibsslUprobeAttachRecipeRequest) -> bool {
    matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. })
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use probe_core::{Direction, ProcessGeneration};

    use crate::{
        LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
        LibsslUprobeSymbol, LibsslUprobeTarget, LibsslUprobeTargetDiscoveryReport,
        tls::LibsslUprobeProcessVerifier,
    };

    use super::*;

    #[test]
    fn attach_recipes_preserve_plan_pid_path_symbol_and_kind()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![target_with_mappings(
                "/usr/lib/libssl.so.3",
                vec![LibsslUprobeSymbol::SslRead],
                vec![LibsslExecutableMapping {
                    start_address: 0x1000,
                    end_address: 0x2000,
                    file_offset: 0,
                }],
            )],
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
    fn attach_recipes_reject_empty_plan() {
        let error = attach_recipes_from_plan(&LibsslUprobeAttachPlan::from_discovery_reports([]))
            .expect_err("empty plan must not load a TLS uprobe probe");

        assert!(matches!(error, LibsslUprobeAttachError::EmptyAttachPlan));
    }

    #[test]
    fn best_effort_attach_work_allows_empty_plan() -> Result<(), Box<dyn std::error::Error>> {
        let work =
            best_effort_attach_work_from_plan(&LibsslUprobeAttachPlan::from_discovery_reports([]))?;

        assert!(work.is_empty());
        assert!(work.as_recipes().is_empty());
        Ok(())
    }

    #[test]
    fn attach_recipes_reject_pid_that_cannot_fit_pid_t() {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            i32::MAX as u32 + 1,
            vec![target(
                "/usr/lib/libssl.so.3",
                vec![LibsslUprobeSymbol::SslRead],
            )],
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
            vec![target(
                "/usr/lib/libssl.so.3",
                vec![LibsslUprobeSymbol::SslRead],
            )],
        ));

        let error =
            attach_recipes_from_plan(&plan).expect_err("pid zero must not reach aya attach");

        assert!(matches!(
            error,
            LibsslUprobeAttachError::InvalidTargetPid { pid: 0 }
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

    fn target(path: &str, symbols: Vec<LibsslUprobeSymbol>) -> LibsslUprobeTarget {
        target_with_mappings(path, symbols, Vec::new())
    }

    fn target_with_mappings(
        path: &str,
        symbols: Vec<LibsslUprobeSymbol>,
        executable_mappings: Vec<LibsslExecutableMapping>,
    ) -> LibsslUprobeTarget {
        LibsslUprobeTarget {
            library: mapped_library(path),
            library_kind: LibsslLibraryKind::OpenSslLike,
            executable_mappings,
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

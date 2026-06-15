use probe_core::ProcessGeneration;

use super::{
    LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedLibrary, LibsslUprobeDegradationReason,
    LibsslUprobeProcessVerifier, LibsslUprobeSymbol, LibsslUprobeSymbolRole,
    LibsslUprobeTargetDiscoveryReport,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachPlan {
    processes: Vec<LibsslUprobeAttachProcess>,
    degraded_reasons: Vec<LibsslUprobeDegradationReason>,
}

impl LibsslUprobeAttachPlan {
    pub fn from_discovery_report(report: LibsslUprobeTargetDiscoveryReport) -> Self {
        Self::from_discovery_reports([report])
    }

    pub fn from_discovery_reports(
        reports: impl IntoIterator<Item = LibsslUprobeTargetDiscoveryReport>,
    ) -> Self {
        let mut processes = Vec::new();
        let mut degraded_reasons = Vec::new();
        for report in reports {
            let (process, process_verifier, targets, reasons) = report.into_attach_parts();
            degraded_reasons.extend(reasons);
            if !targets.is_empty() {
                processes.push(LibsslUprobeAttachProcess::from_discovered(
                    process,
                    process_verifier,
                    targets,
                ));
            }
        }
        Self {
            processes,
            degraded_reasons,
        }
    }

    pub fn probe_count(&self) -> usize {
        self.processes
            .iter()
            .flat_map(|process| process.targets.iter())
            .flat_map(|target| target.recipes.iter())
            .map(LibsslUprobeAttachRecipe::attach_point_count)
            .sum()
    }

    pub fn has_attachable_probes(&self) -> bool {
        self.probe_count() > 0
    }

    pub fn processes(&self) -> &[LibsslUprobeAttachProcess] {
        &self.processes
    }

    pub fn degraded_reasons(&self) -> &[LibsslUprobeDegradationReason] {
        &self.degraded_reasons
    }

    pub(in crate::tls) fn target_ids(
        &self,
    ) -> impl Iterator<Item = LibsslUprobeAttachTargetId> + '_ {
        self.processes.iter().flat_map(|process| {
            process.targets.iter().map(|target| {
                LibsslUprobeAttachTargetId::new(process.process, target.library.clone())
            })
        })
    }

    pub(in crate::tls) fn filter_targets(
        &self,
        mut include: impl FnMut(&LibsslUprobeAttachTargetId) -> bool,
    ) -> Self {
        let processes = self
            .processes
            .iter()
            .filter_map(|process| {
                let targets = process
                    .targets
                    .iter()
                    .filter(|target| {
                        include(&LibsslUprobeAttachTargetId::new(
                            process.process,
                            target.library.clone(),
                        ))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                (!targets.is_empty()).then(|| LibsslUprobeAttachProcess {
                    process: process.process,
                    targets,
                    process_verifier: process.process_verifier.clone(),
                })
            })
            .collect();
        Self {
            processes,
            degraded_reasons: self.degraded_reasons.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibsslUprobeAttachTargetId {
    pub process: ProcessGeneration,
    pub library: LibsslMappedLibrary,
}

impl LibsslUprobeAttachTargetId {
    pub(in crate::tls) fn new(process: ProcessGeneration, library: LibsslMappedLibrary) -> Self {
        Self { process, library }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachTargetSnapshot {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub mapped_path: std::path::PathBuf,
    pub read_path: std::path::PathBuf,
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u64,
    pub deleted: bool,
}

impl From<LibsslUprobeAttachTargetId> for LibsslUprobeAttachTargetSnapshot {
    fn from(target: LibsslUprobeAttachTargetId) -> Self {
        Self {
            pid: target.process.pid,
            start_time_ticks: target.process.start_time_ticks,
            mapped_path: target.library.mapped_path,
            read_path: target.library.read_path,
            device_major: target.library.identity.device_major,
            device_minor: target.library.identity.device_minor,
            inode: target.library.identity.inode,
            deleted: target.library.deleted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachProcess {
    process: ProcessGeneration,
    targets: Vec<LibsslUprobeAttachTarget>,
    process_verifier: LibsslUprobeProcessVerifier,
}

impl LibsslUprobeAttachProcess {
    fn from_discovered(
        process: ProcessGeneration,
        process_verifier: LibsslUprobeProcessVerifier,
        targets: Vec<super::LibsslUprobeTarget>,
    ) -> Self {
        Self {
            process,
            process_verifier,
            targets: targets
                .into_iter()
                .map(LibsslUprobeAttachTarget::from_discovered)
                .collect(),
        }
    }

    pub fn pid(&self) -> u32 {
        self.process.pid
    }

    pub fn process(&self) -> ProcessGeneration {
        self.process
    }

    pub fn targets(&self) -> &[LibsslUprobeAttachTarget] {
        &self.targets
    }

    pub(in crate::tls) fn process_verifier(&self) -> &LibsslUprobeProcessVerifier {
        &self.process_verifier
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachTarget {
    pub library: LibsslMappedLibrary,
    pub library_kind: LibsslLibraryKind,
    pub executable_mappings: Vec<LibsslExecutableMapping>,
    pub recipes: Vec<LibsslUprobeAttachRecipe>,
}

impl LibsslUprobeAttachTarget {
    fn from_discovered(target: super::LibsslUprobeTarget) -> Self {
        Self {
            library: target.library,
            library_kind: target.library_kind,
            executable_mappings: target.executable_mappings,
            recipes: target
                .symbols
                .into_iter()
                .map(LibsslUprobeAttachRecipe::from_symbol)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachRecipe {
    pub symbol: LibsslUprobeSymbol,
}

impl LibsslUprobeAttachRecipe {
    pub fn from_symbol(symbol: LibsslUprobeSymbol) -> Self {
        Self { symbol }
    }

    pub fn function_name(&self) -> &'static str {
        self.symbol.as_str()
    }

    pub fn semantic(&self) -> LibsslUprobeSymbolRole {
        LibsslUprobeSymbolRole::from_ebpf_role(self.symbol.role())
    }

    pub fn attach_points(&self) -> Vec<LibsslUprobeAttachPoint> {
        let mut points = Vec::with_capacity(self.attach_point_count());
        points.push(self.attach_point(
            LibsslUprobeAttachKind::Entry,
            self.symbol.entry_program_name(),
        ));
        if let Some(program_name) = self.symbol.return_program_name() {
            points.push(self.attach_point(LibsslUprobeAttachKind::Return, program_name));
        }
        points
    }

    pub fn attach_point_count(&self) -> usize {
        1 + usize::from(self.symbol.return_program_name().is_some())
    }

    fn attach_point(
        &self,
        kind: LibsslUprobeAttachKind,
        program_name: &'static str,
    ) -> LibsslUprobeAttachPoint {
        LibsslUprobeAttachPoint {
            library_symbol: self.symbol.as_str(),
            program_name,
            kind,
            semantic: self.semantic(),
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibsslUprobeAttachPoint {
    pub library_symbol: &'static str,
    pub program_name: &'static str,
    pub kind: LibsslUprobeAttachKind,
    pub semantic: LibsslUprobeSymbolRole,
    pub offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibsslUprobeAttachKind {
    Entry,
    Return,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ebpf_abi::{
        EBPF_TLS_SSL_CLEAR_EXIT_PROGRAM_NAME, EBPF_TLS_SSL_CLEAR_PROGRAM_NAME,
        EBPF_TLS_SSL_FREE_PROGRAM_NAME, EBPF_TLS_SSL_READ_ENTER_PROGRAM_NAME,
        EBPF_TLS_SSL_READ_EXIT_PROGRAM_NAME, EBPF_TLS_SSL_SET_FD_EXIT_PROGRAM_NAME,
        EBPF_TLS_SSL_SET_FD_PROGRAM_NAME, EBPF_TLS_SSL_WRITE_EX_ENTER_PROGRAM_NAME,
        EBPF_TLS_SSL_WRITE_EX_EXIT_PROGRAM_NAME,
    };
    use probe_core::{Direction, ProcessGeneration};

    use super::*;
    use crate::{
        LibsslExecutableMapping, LibsslMappedFileIdentity, LibsslUprobeDegradationReason,
        LibsslUprobeSymbolFailure, LibsslUprobeTarget,
    };

    #[test]
    fn attach_plan_maps_libssl_symbols_to_probe_kind_and_direction() {
        let report = discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: vec![LibsslExecutableMapping {
                    start_address: 0x1000,
                    end_address: 0x2000,
                    file_offset: 0,
                }],
                symbols: vec![
                    LibsslUprobeSymbol::SslSetFd,
                    LibsslUprobeSymbol::SslClear,
                    LibsslUprobeSymbol::SslFree,
                    LibsslUprobeSymbol::SslRead,
                    LibsslUprobeSymbol::SslWrite,
                    LibsslUprobeSymbol::SslReadEx,
                    LibsslUprobeSymbol::SslWriteEx,
                ],
            }],
            Vec::new(),
        );

        let plan = LibsslUprobeAttachPlan::from_discovery_report(report);

        assert!(plan.has_attachable_probes());
        assert_eq!(plan.probe_count(), 13);
        assert_eq!(plan.processes().len(), 1);
        let planned_process = &plan.processes()[0];
        assert_eq!(planned_process.pid(), 42);
        assert_eq!(planned_process.process(), process_generation(42));
        assert_eq!(planned_process.targets().len(), 1);
        let target = &planned_process.targets()[0];
        assert_eq!(
            target.recipes,
            vec![
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslSetFd,
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslClear,
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslFree,
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslRead,
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslWrite,
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslReadEx,
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslWriteEx,
                },
            ]
        );
        assert_eq!(target.recipes[0].function_name(), "SSL_set_fd");
        assert_eq!(target.recipes[6].function_name(), "SSL_write_ex");
        assert_recipe(
            &target.recipes[0],
            LibsslUprobeSymbolRole::FdAssociation,
            &[
                attach_point(
                    "SSL_set_fd",
                    EBPF_TLS_SSL_SET_FD_PROGRAM_NAME,
                    LibsslUprobeAttachKind::Entry,
                    LibsslUprobeSymbolRole::FdAssociation,
                ),
                attach_point(
                    "SSL_set_fd",
                    EBPF_TLS_SSL_SET_FD_EXIT_PROGRAM_NAME,
                    LibsslUprobeAttachKind::Return,
                    LibsslUprobeSymbolRole::FdAssociation,
                ),
            ],
        );
        assert_recipe(
            &target.recipes[1],
            LibsslUprobeSymbolRole::StateReset,
            &[
                attach_point(
                    "SSL_clear",
                    EBPF_TLS_SSL_CLEAR_PROGRAM_NAME,
                    LibsslUprobeAttachKind::Entry,
                    LibsslUprobeSymbolRole::StateReset,
                ),
                attach_point(
                    "SSL_clear",
                    EBPF_TLS_SSL_CLEAR_EXIT_PROGRAM_NAME,
                    LibsslUprobeAttachKind::Return,
                    LibsslUprobeSymbolRole::StateReset,
                ),
            ],
        );
        assert_recipe(
            &target.recipes[2],
            LibsslUprobeSymbolRole::StateCleanup,
            &[attach_point(
                "SSL_free",
                EBPF_TLS_SSL_FREE_PROGRAM_NAME,
                LibsslUprobeAttachKind::Entry,
                LibsslUprobeSymbolRole::StateCleanup,
            )],
        );
        assert_recipe(
            &target.recipes[3],
            plaintext(Direction::Inbound),
            &[
                attach_point(
                    "SSL_read",
                    EBPF_TLS_SSL_READ_ENTER_PROGRAM_NAME,
                    LibsslUprobeAttachKind::Entry,
                    plaintext(Direction::Inbound),
                ),
                attach_point(
                    "SSL_read",
                    EBPF_TLS_SSL_READ_EXIT_PROGRAM_NAME,
                    LibsslUprobeAttachKind::Return,
                    plaintext(Direction::Inbound),
                ),
            ],
        );
        assert_recipe(
            &target.recipes[6],
            plaintext(Direction::Outbound),
            &[
                attach_point(
                    "SSL_write_ex",
                    EBPF_TLS_SSL_WRITE_EX_ENTER_PROGRAM_NAME,
                    LibsslUprobeAttachKind::Entry,
                    plaintext(Direction::Outbound),
                ),
                attach_point(
                    "SSL_write_ex",
                    EBPF_TLS_SSL_WRITE_EX_EXIT_PROGRAM_NAME,
                    LibsslUprobeAttachKind::Return,
                    plaintext(Direction::Outbound),
                ),
            ],
        );
    }

    #[test]
    fn attach_plan_preserves_discovery_degradation_reasons() {
        let reason = LibsslUprobeDegradationReason::SymbolResolutionFailed {
            mapped_path: PathBuf::from("/usr/lib/libssl.so.3"),
            reason: LibsslUprobeSymbolFailure::ParseLibrary {
                path: PathBuf::from("/proc/7/root/usr/lib/libssl.so.3"),
                reason: "bad elf".to_string(),
            },
        };
        let report = discovery_report(7, Vec::new(), vec![reason.clone()]);

        let plan = LibsslUprobeAttachPlan::from_discovery_report(report);

        assert!(!plan.has_attachable_probes());
        assert_eq!(plan.degraded_reasons(), &[reason]);
    }

    fn discovery_report(
        pid: u32,
        targets: Vec<LibsslUprobeTarget>,
        degraded_reasons: Vec<LibsslUprobeDegradationReason>,
    ) -> LibsslUprobeTargetDiscoveryReport {
        LibsslUprobeTargetDiscoveryReport::new(
            process_generation(pid),
            process_verifier(),
            targets,
            degraded_reasons,
        )
    }

    fn mapped_library(path: &str) -> LibsslMappedLibrary {
        LibsslMappedLibrary {
            mapped_path: PathBuf::from(path),
            read_path: PathBuf::from("/proc/42/root").join(path.trim_start_matches('/')),
            identity: LibsslMappedFileIdentity {
                device_major: 8,
                device_minor: 1,
                inode: 100,
            },
            deleted: false,
        }
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

    fn plaintext(direction: Direction) -> LibsslUprobeSymbolRole {
        LibsslUprobeSymbolRole::Plaintext { direction }
    }

    fn attach_point(
        library_symbol: &'static str,
        program_name: &'static str,
        kind: LibsslUprobeAttachKind,
        semantic: LibsslUprobeSymbolRole,
    ) -> LibsslUprobeAttachPoint {
        LibsslUprobeAttachPoint {
            library_symbol,
            program_name,
            kind,
            semantic,
            offset: 0,
        }
    }

    fn assert_recipe(
        recipe: &LibsslUprobeAttachRecipe,
        semantic: LibsslUprobeSymbolRole,
        attach_points: &[LibsslUprobeAttachPoint],
    ) {
        assert_eq!(recipe.semantic(), semantic);
        assert_eq!(recipe.attach_points(), attach_points);
    }
}

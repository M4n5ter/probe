use super::{
    LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedLibrary, LibsslUprobeDegradationReason,
    LibsslUprobeSymbol, LibsslUprobeSymbolRole, LibsslUprobeTargetDiscoveryReport,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachPlan {
    pub targets: Vec<LibsslUprobeAttachTarget>,
    pub degraded_reasons: Vec<LibsslUprobeDegradationReason>,
}

impl LibsslUprobeAttachPlan {
    pub fn from_discovery_report(report: LibsslUprobeTargetDiscoveryReport) -> Self {
        Self::from_discovery_reports([report])
    }

    pub fn from_discovery_reports(
        reports: impl IntoIterator<Item = LibsslUprobeTargetDiscoveryReport>,
    ) -> Self {
        let mut targets = Vec::new();
        let mut degraded_reasons = Vec::new();
        for report in reports {
            degraded_reasons.extend(report.degraded_reasons);
            targets.extend(
                report
                    .targets
                    .into_iter()
                    .map(LibsslUprobeAttachTarget::from),
            );
        }
        Self {
            targets,
            degraded_reasons,
        }
    }

    pub fn probe_count(&self) -> usize {
        self.targets
            .iter()
            .flat_map(|target| target.recipes.iter())
            .map(LibsslUprobeAttachRecipe::attach_point_count)
            .sum()
    }

    pub fn has_attachable_probes(&self) -> bool {
        self.probe_count() > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachTarget {
    pub pid: u32,
    pub library: LibsslMappedLibrary,
    pub library_kind: LibsslLibraryKind,
    pub executable_mappings: Vec<LibsslExecutableMapping>,
    pub recipes: Vec<LibsslUprobeAttachRecipe>,
}

impl From<super::LibsslUprobeTarget> for LibsslUprobeAttachTarget {
    fn from(target: super::LibsslUprobeTarget) -> Self {
        Self {
            pid: target.pid,
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
    use probe_core::Direction;

    use super::*;
    use crate::{
        LibsslExecutableMapping, LibsslMappedFileIdentity, LibsslUprobeDegradationReason,
        LibsslUprobeSymbolFailure, LibsslUprobeTarget,
    };

    #[test]
    fn attach_plan_maps_libssl_symbols_to_probe_kind_and_direction() {
        let report = LibsslUprobeTargetDiscoveryReport {
            pid: 42,
            targets: vec![LibsslUprobeTarget {
                pid: 42,
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
            degraded_reasons: Vec::new(),
        };

        let plan = LibsslUprobeAttachPlan::from_discovery_report(report);

        assert!(plan.has_attachable_probes());
        assert_eq!(plan.probe_count(), 13);
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].pid, 42);
        assert_eq!(
            plan.targets[0].recipes,
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
        assert_eq!(plan.targets[0].recipes[0].function_name(), "SSL_set_fd");
        assert_eq!(plan.targets[0].recipes[6].function_name(), "SSL_write_ex");
        assert_recipe(
            &plan.targets[0].recipes[0],
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
            &plan.targets[0].recipes[1],
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
            &plan.targets[0].recipes[2],
            LibsslUprobeSymbolRole::StateCleanup,
            &[attach_point(
                "SSL_free",
                EBPF_TLS_SSL_FREE_PROGRAM_NAME,
                LibsslUprobeAttachKind::Entry,
                LibsslUprobeSymbolRole::StateCleanup,
            )],
        );
        assert_recipe(
            &plan.targets[0].recipes[3],
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
            &plan.targets[0].recipes[6],
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
        let report = LibsslUprobeTargetDiscoveryReport {
            pid: 7,
            targets: Vec::new(),
            degraded_reasons: vec![reason.clone()],
        };

        let plan = LibsslUprobeAttachPlan::from_discovery_report(report);

        assert!(!plan.has_attachable_probes());
        assert_eq!(plan.degraded_reasons, vec![reason]);
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
